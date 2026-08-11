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

// stickyEnabled is an off-switch: set GOST_STICKY_EGRESS=0 in the relay's
// environment to fall back to plain per-bind forwarding without a rebuild.
var stickyEnabled = os.Getenv("GOST_STICKY_EGRESS") != "0"

// maxPeek caps how many header bytes we read before giving up (slowloris guard).
const maxPeek = 64 << 10

// peekTimeout bounds the header read. Real ws traffic from nginx arrives at once,
// so this never fires on the happy path; it only caps half-open / stalled peers
// that connect but never send, which a deadline-less read would pin for minutes.
const peekTimeout = 3 * time.Second

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
func peekHTTPHead(conn net.Conn) (head []byte, clientIP, host string, isHTTP bool) {
	conn.SetReadDeadline(time.Now().Add(peekTimeout))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for len(buf) < maxPeek {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
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
		return // isHTTP=false: no complete request head within the deadline/cap
	}
	isHTTP = true
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
