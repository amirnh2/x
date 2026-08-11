package relay

// pixelated fork — sticky egress routing for reuseport BIND endpoints.
//
// Problem: every out-worker opens many rtcp BINDs on the same Iran port
// (SO_REUSEPORT). nginx dials that port from localhost, so the kernel picks a
// reuseport socket by 4-tuple hash — a per-connection lottery, blind to the end
// user and to which config (Host) they chose. Switching config changes nothing.
//
// Fix: the accepted connection carries, in cleartext (nginx terminated TLS), the
// real client IP (X-Real-IP) and the config domain (Host). We peek those, then
// forward to a worker chosen by rendezvous hash of (clientIP|host) over the live
// worker set — stable per user+config, disjoint-ish per config, and only ~1/N of
// users move when the worker set changes. Within the chosen worker we still fan
// connections across its many mux sessions (CF tunnels), so the many-sessions
// behavior is untouched — a worker's egress IP is the same on all its sessions.
//
// Workers are grouped by the "user" they present in the relay auth feature
// (the generator sets it to the worker's public IP). With no user set, every
// session lands in one group and routing degrades to the existing lottery — so
// deploying this binary before the generator sets per-worker user is a no-op,
// not a regression.

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"

	"github.com/go-gost/x/internal/util/mux"
)

// stickyEnabled is OPT-IN: the fork behaves exactly like stock gost unless
// GOST_STICKY_EGRESS is explicitly set to a truthy value (1/true/yes/on) in the
// relay's environment. So this binary is safe to reuse for anything else — no
// peek, no routing, no surprise — until sticky egress is deliberately enabled.
var stickyEnabled = func() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GOST_STICKY_EGRESS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}()

// maxPeek caps how many header bytes we read before giving up (slowloris guard).
const maxPeek = 64 << 10

// peekTimeout bounds the header read. Non-HTTP is rejected from its first bytes
// (see startsLikeHTTP), so this never fires on real traffic — it only caps a peer
// that connects and sends nothing (half-open), which a deadline-less read pins.
const peekTimeout = 3 * time.Second

// httpMethodPrefixes are the "METHOD " tokens an HTTP request line can begin with
// (the ws upgrade is always GET). Used to reject non-HTTP from the first bytes.
var httpMethodPrefixes = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "),
	[]byte("CONNECT "), []byte("TRACE "),
}

// startsLikeHTTP reports whether buf is — or, while still shorter than a method
// token, could still become — the start of an HTTP request line.
func startsLikeHTTP(buf []byte) bool {
	for _, m := range httpMethodPrefixes {
		if len(buf) < len(m) {
			if bytes.HasPrefix(m, buf) {
				return true
			}
		} else if bytes.HasPrefix(buf, m) {
			return true
		}
	}
	return false
}

// egressRegistry holds the live mux sessions of every worker that has BIND'd a
// given endpoint address, grouped by worker id, so an accepted connection can be
// routed to a consistently-chosen worker instead of whichever reuseport socket
// happened to accept it.
type egressRegistry struct {
	mu sync.RWMutex
	// bindAddr -> workerID -> set of live sessions
	pools map[string]map[string]map[mux.Session]struct{}
}

var egress = &egressRegistry{pools: make(map[string]map[string]map[mux.Session]struct{})}

func (r *egressRegistry) add(addr, workerID string, s mux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	byWorker := r.pools[addr]
	if byWorker == nil {
		byWorker = make(map[string]map[mux.Session]struct{})
		r.pools[addr] = byWorker
	}
	set := byWorker[workerID]
	if set == nil {
		set = make(map[mux.Session]struct{})
		byWorker[workerID] = set
	}
	set[s] = struct{}{}
}

func (r *egressRegistry) remove(addr, workerID string, s mux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	byWorker := r.pools[addr]
	if byWorker == nil {
		return
	}
	if set := byWorker[workerID]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(byWorker, workerID)
		}
	}
	if len(byWorker) == 0 {
		delete(r.pools, addr)
	}
}

// pick chooses a live session for addr:
//  1. rendezvous (HRW) hash of key over worker ids — the top worker is stable per
//     key and only ~1/N of keys move when the worker set changes;
//  2. any live session of that worker — Go's randomized map iteration spreads
//     connections across the worker's many CF tunnels.
//
// Returns nil if the pool is empty or the chosen worker has no live session
// right now (rare race with deregistration); the caller then falls back to the
// session that accepted the connection.
func (r *egressRegistry) pick(addr, key string) mux.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	byWorker := r.pools[addr]
	if len(byWorker) == 0 {
		return nil
	}

	var bestWorker string
	var bestScore uint64
	found := false
	for workerID := range byWorker {
		score := xxhash.Sum64String(workerID + "\x00" + key)
		if !found || score > bestScore || (score == bestScore && workerID > bestWorker) {
			found, bestWorker, bestScore = true, workerID, score
		}
	}
	if !found {
		return nil
	}
	for s := range byWorker[bestWorker] {
		if !s.IsClosed() {
			return s
		}
	}
	return nil
}

// peekHTTPHead reads the request head (up to and including the end-of-headers
// marker) without discarding it: the returned bytes are replayed to the worker
// so the tunneled stream stays byte-exact. It parses the real client IP
// (nginx's X-Real-IP, falling back to the first X-Forwarded-For hop) and the
// Host. On any error it returns whatever was read plus empty fields, and the
// caller forwards without routing.
func peekHTTPHead(conn net.Conn) (head []byte, clientIP, host string) {
	conn.SetReadDeadline(time.Now().Add(peekTimeout))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for len(buf) < maxPeek {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Fast path: the instant the bytes can't be an HTTP request line, stop
			// and forward — don't wait for a \r\n\r\n that a non-HTTP protocol will
			// never send. Only genuine HTTP reads on to the end of the headers.
			if !startsLikeHTTP(buf) {
				return buf, "", ""
			}
			if bytes.Contains(buf, []byte("\r\n\r\n")) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	head = buf

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		return // not HTTP / no complete head within the deadline: caller forwards as-is
	}
	host = req.Host
	clientIP = req.Header.Get("X-Real-IP")
	if clientIP == "" {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				clientIP = strings.TrimSpace(xff[:i])
			} else {
				clientIP = strings.TrimSpace(xff)
			}
		}
	}
	return
}

// preReadConn replays already-consumed head bytes before the live stream, so a
// peeked connection can still be piped verbatim.
type preReadConn struct {
	net.Conn
	pre []byte
	off int
}

func (c *preReadConn) Read(b []byte) (int, error) {
	if c.off < len(c.pre) {
		n := copy(b, c.pre[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}
