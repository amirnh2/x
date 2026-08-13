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

// maxForwardRetries bounds how many workers one connection will try before it
// gives up and plain-forwards through the accepting session. Keeps a bad moment
// (or a broad outage) from turning into a retry storm.
const maxForwardRetries = 3

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

	// pixelated fork: sticky egress routing + failover. Peek the (cleartext, TLS
	// already terminated by nginx) ws/HTTP head for the real client IP and config
	// Host, then route to a consistently-chosen worker. If that worker's v2ray is
	// down the forward fast-fails (the tunnel stream closes right after the head)
	// and we retry the next-best worker; a worker that fails repeatedly is
	// circuit-broken out of the pool so its load spreads to the others until it
	// recovers — the old per-connection lottery's resilience, on top of sticky
	// routing. Non-routable traffic (non-HTTP, or no X-Real-IP/Host) and any
	// pool-exhaustion fall through to plain forwarding — identical to stock gost.
	var head []byte
	var key string
	routed := false
	if h.sticky {
		var clientIP, host string
		head, clientIP, host = peekHTTPHead(conn)
		if clientIP != "" || host != "" {
			key = clientIP + "|" + host
			routed = true
		}
	}

	if routed {
		tried := make(map[string]bool)
		for attempt := 0; attempt < maxForwardRetries; attempt++ {
			sess, workerID := egress.pickExcluding(h.bindAddr, key, tried)
			if sess == nil {
				break // pool can't serve this connection → plain forward below
			}
			cc, err := sess.GetConn()
			if err != nil {
				// Session vanished (race with deregistration), not a v2ray fault:
				// try another worker without counting it against the breaker.
				tried[workerID] = true
				continue
			}
			firstUp, ok := h.forwardProbe(cc, conn.RemoteAddr(), head)
			if !ok {
				// The worker's v2ray refused the forward: count it and move on.
				egress.markFail(h.bindAddr, workerID)
				tried[workerID] = true
				cc.Close()
				continue
			}
			egress.markOK(h.bindAddr, workerID)

			// Committed. The head is already written to cc; firstUp (if any) is the
			// worker's first response and must reach the client ahead of the stream.
			var upstream net.Conn = cc
			if len(firstUp) > 0 {
				upstream = &preReadConn{Conn: cc, pre: firstUp}
			}
			t := time.Now()
			log.Debugf("%s <-> %s (worker %s, try %d)", conn.RemoteAddr(), cc.RemoteAddr(), workerID, attempt)
			xnet.Pipe(ctx, conn, upstream)
			log.WithFields(map[string]any{"duration": time.Since(t)}).
				Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
			cc.Close()
			return nil
		}
		log.Warnf("egress: no worker could serve %s (tried %d), plain-forwarding", key, maxForwardRetries)
	}

	// Plain forward through the session that accepted this connection (stock gost).
	cc, err := h.session.GetConn()
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

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

	var src net.Conn = conn
	if len(head) > 0 {
		src = &preReadConn{Conn: conn, pre: head}
	}
	xnet.Pipe(ctx, src, cc)
	return nil
}

// forwardProbe writes the relay response and the peeked head into the worker
// stream, then reads the first upstream byte to tell a live v2ray (it answers —
// e.g. the ws 101 — promptly) from a dead one (the worker can't dial v2ray and
// closes the stream → immediate EOF). It returns the first upstream bytes to
// replay to the client, and ok=false only on a fast forward-failure.
//
// For the ws handshake the client waits for that first response before sending
// more, so reading it here adds no latency and never stalls the client. A v2ray
// that ACCEPTS but never answers (hung, not refused — rare; a dead one refuses
// instantly) would block here until the mux keepalive closes the session; a
// per-stream read deadline would cap that, but the mux stream wrapper doesn't
// expose one (it leaks to the shared conn), so it's left for later.
func (h *tcpHandler) forwardProbe(cc net.Conn, clientAddr net.Addr, head []byte) (firstUp []byte, ok bool) {
	af := &relay.AddrFeature{}
	af.ParseFrom(clientAddr.String())
	resp := relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: []relay.Feature{af},
	}
	if _, err := resp.WriteTo(cc); err != nil {
		return nil, false
	}
	if len(head) > 0 {
		if _, err := cc.Write(head); err != nil {
			return nil, false
		}
	}

	b := make([]byte, 16<<10)
	n, err := cc.Read(b)
	if n > 0 {
		return b[:n:n], true // v2ray answered (even a 4xx is a live response)
	}
	if err != nil {
		return nil, false // stream closed before any byte → forward failed
	}
	return nil, true // 0 bytes, no error (unusual) → commit with nothing buffered
}