package vless

import (
	"net"
	"sync/atomic"

	"github.com/vgate-project/vgate-server/model"
)

// trafficStat holds per-user upload/download counters. The counters are
// accessed with sync/atomic helpers so callers can update them without
// holding the Server mutex on the fast path.
type trafficStat struct {
	email string
	up    int64
	down  int64
}

// countingConn wraps a net.Conn to transparently account traffic against
// the owning user's trafficStat.
type countingConn struct {
	net.Conn
	uuid   [16]byte
	server *Server
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.server.addTraffic(c.uuid, int64(n), 0)
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.server.addTraffic(c.uuid, 0, int64(n))
	}
	return n, err
}

func (s *Server) addTraffic(uuid [16]byte, up, down int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userTraffic[uuid] == nil {
		email := ""
		if user, ok := s.users[uuid]; ok {
			email = user.Email
		}
		s.userTraffic[uuid] = &trafficStat{email: email}
	}
	atomic.AddInt64(&s.userTraffic[uuid].up, up)
	atomic.AddInt64(&s.userTraffic[uuid].down, down)
}

// GetAndResetTraffic atomically reads and resets each user's traffic counters,
// returning the incremental (delta) traffic accumulated since the previous
// invocation. The returned values are per-user deltas — never cumulative
// totals — so they are safe to feed directly into ReportTraffic.
func (s *Server) GetAndResetTraffic() []model.UserTraffic {
	s.mu.Lock()
	defer s.mu.Unlock()

	traffic := make([]model.UserTraffic, 0, len(s.userTraffic))
	for uuid, stat := range s.userTraffic {
		up := atomic.SwapInt64(&stat.up, 0)
		down := atomic.SwapInt64(&stat.down, 0)
		if up > 0 || down > 0 {
			email := stat.email
			if email == "" {
				// Try to get it again if it was missing
				if user, ok := s.users[uuid]; ok {
					email = user.Email
					stat.email = email
				}
			}
			if email != "" {
				traffic = append(traffic, model.UserTraffic{
					Email: email,
					Up:    up,
					Down:  down,
				})
			}
		} else {
			// No traffic this time.
			// If user is also gone from active users, we can delete the stat entry.
			if _, ok := s.users[uuid]; !ok {
				delete(s.userTraffic, uuid)
			}
		}
	}
	return traffic
}
