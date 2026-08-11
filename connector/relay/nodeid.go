package relay

// pixelated fork: stable per-worker identity for sticky egress routing.
//
// When the `nodeID` metadata flag is set on a relay connector, the worker
// announces this id as the relay auth "user" (see bind.go). The sticky relay
// handler on the entry side groups a worker's many tunnels by it, so a user
// stays pinned to one worker (stable egress) instead of the reuseport lottery.
//
// The id must be unique per live worker and stable across process restarts. We
// use the box's own egress IP, determined locally with no external service: a
// UDP "dial" to a public address only resolves the default-route source address
// (no packets are sent). If that fails (e.g. no default route), we fall back to
// a random per-process string. Computed once and cached.

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
)

var (
	nodeIDOnce sync.Once
	nodeIDVal  string
)

func nodeID() string {
	nodeIDOnce.Do(func() {
		if ip := localEgressIP(); ip != "" {
			nodeIDVal = ip
			return
		}
		b := make([]byte, 8)
		if _, err := rand.Read(b); err == nil {
			nodeIDVal = "rnd-" + hex.EncodeToString(b)
		} else {
			nodeIDVal = "rnd-unknown"
		}
	})
	return nodeIDVal
}

// localEgressIP returns the source address the kernel would use for the default
// route, without contacting anything. Empty if it cannot be determined.
func localEgressIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok &&
		ua.IP != nil && !ua.IP.IsUnspecified() && !ua.IP.IsLoopback() {
		return ua.IP.String()
	}
	return ""
}
