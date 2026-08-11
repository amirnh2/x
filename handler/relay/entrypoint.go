package relay

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/mux"
	metrics "github.com/go-gost/x/metrics/wrapper"
)

// tcpListener is the internal TCP listener used in BIND mode.
//
// Wrapping layers (outermost first):
//   - proxyproto.WrapListener — PROXY protocol support
//   - metrics.WrapListener — connection metrics
//   - admission.WrapListener — access control (allow/deny lists)
//   - raw net.Listener
//
// This is a simplified version of the standard listener wrapping chain from
// x/config/parsing/service/parse.go.
type tcpListener struct {
	ln      net.Listener
	options listener.Options
}

func newTCPListener(ln net.Listener, opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tcpListener{
		ln:      ln,
		options: options,
	}
}

func (l *tcpListener) Init(md md.Metadata) (err error) {
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Service, l.options.Admission, ln)
	l.ln = ln

	return
}

func (l *tcpListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tcpListener) Close() error {
	return l.ln.Close()
}

// tcpHandler is the internal handler for BIND mode.
//
// When an inbound connection arrives at the listen port created by bindTCP,
// this handler forwards it back to the requesting client over a mux stream.
//
// Flow:
//  1. Gets a free stream from the mux session (session.GetConn()).
//  2. Encodes the inbound peer address as a relay.AddrFeature on the stream.
//  3. Writes a relay.Response (StatusOK).
//  4. Bidirectional Pipe (inbound conn ↔ mux stream).
//
// This is the core mechanism for reverse-proxy / tunnel traversal:
// the client that requested BIND receives forwarded connections as
// streams on the mux session.
type tcpHandler struct {
	session  mux.Session
	bindAddr string // registry key: the reuseport endpoint address (e.g. [::]:9596)
	sticky   bool   // pixelated: peek+route this endpoint (worker ws only); else plain forward
	options  handler.Options
}

func newTCPHandler(session mux.Session, bindAddr string, sticky bool, opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tcpHandler{
		session:  session,
		bindAddr: bindAddr,
		sticky:   sticky,
		options:  options,
	}
}

func (h *tcpHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *tcpHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	// pixelated fork: sticky egress routing. Peek the (cleartext, TLS already
	// terminated by nginx) ws/HTTP head for the real client IP and config Host,
	// then route to a consistently-chosen worker. The peeked bytes are replayed
	// so the tunneled stream stays byte-exact. Falls back to h.session (the
	// worker whose reuseport socket accepted this conn) when routing is disabled,
	// the pool is empty, or the request can't be parsed.
	sess := h.session
	var head []byte
	if h.sticky {
		// Peek the head; if it's a routable HTTP request, steer to the matching
		// worker. Anything else — non-HTTP, or HTTP without X-Real-IP/Host — falls
		// straight through to plain forwarding. The fork never drops or alters
		// traffic it can't route, so behaviour stays identical to stock gost.
		var clientIP, host string
		head, clientIP, host = peekHTTPHead(conn)
		if clientIP != "" || host != "" {
			if s := egress.pick(h.bindAddr, clientIP+"|"+host); s != nil {
				sess = s
			}
		}
	}

	// Get a stream from the chosen mux session.
	cc, err := sess.GetConn()
	if err != nil {
		// The chosen worker's session vanished between pick and GetConn; retry
		// on the local session before giving up.
		if sess != h.session {
			log.Warnf("egress: chosen session unavailable (%v), falling back", err)
			cc, err = h.session.GetConn()
		}
		if err != nil {
			log.Error(err)
			return err
		}
	}
	defer cc.Close()

	// Encode the peer address as an AddrFeature sent to the client through relay.
	af := &relay.AddrFeature{}
	af.ParseFrom(conn.RemoteAddr().String())
	resp := relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: []relay.Feature{af},
	}
	if _, err := resp.WriteTo(cc); err != nil {
		log.Error(err)
		return err
	}

	// Replay the peeked head (if any) ahead of the live stream.
	var src net.Conn = conn
	if len(head) > 0 {
		src = &preReadConn{Conn: conn, pre: head}
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Pipe(ctx, src, cc)
	log.WithFields(map[string]any{"duration": time.Since(t)}).
		Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
	return nil
}