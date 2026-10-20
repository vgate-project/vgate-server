package vless

import (
	"net"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"

	"github.com/vgate-project/vgate-server/model"
)

// trafficKey identifies one accounting bucket: a user on a specific entry
// point. The empty node means the real node itself; non-empty values are
// virtual child node IDs resolved from the Reality short ID the client
// connected with.
type trafficKey struct {
	uuid [16]byte
	node string
}

// trafficStat holds per-user-per-entry upload/download counters. The counters
// are accessed with sync/atomic helpers so callers can update them without
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
	node   string // entry point (virtual child node ID); "" = this node
	server *Server
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.server.addTraffic(c.uuid, c.node, int64(n), 0)
		c.server.applyLimits(c.uuid, n, 0)
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.server.addTraffic(c.uuid, c.node, 0, int64(n))
		c.server.applyLimits(c.uuid, 0, n)
	}
	return n, err
}

func (s *Server) addTraffic(uuid [16]byte, node string, up, down int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := trafficKey{uuid: uuid, node: node}
	if s.userTraffic[key] == nil {
		email := ""
		if user, ok := s.users[uuid]; ok {
			email = user.Email
		}
		s.userTraffic[key] = &trafficStat{email: email}
	}
	atomic.AddInt64(&s.userTraffic[key].up, up)
	atomic.AddInt64(&s.userTraffic[key].down, down)
	// Local quota enforcement: every counted chunk also accrues against the
	// user's /usage snapshot, cutting the user the moment the effective
	// remaining hits zero (no-op without a snapshot).
	if n := up + down; n > 0 {
		s.accrueQuotaLocked(uuid, s.userTraffic[key].email, n)
	}
}

// accountReader wraps a buf.Reader and reports each chunk's byte count via
// fn as the chunk is read. Unlike a SizeCounter tallied once at copy end,
// this feeds addTraffic incrementally, so bytes flowing through a live
// Vision/Mux connection are visible to reporting (and quota enforcement)
// before the connection closes. Used on paths where the conn cannot be
// wrapped by countingConn (Vision requires the raw *tls.Conn/*reality.Conn).
type accountReader struct {
	buf.Reader
	fn func(int64)
}

func (r *accountReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.fn(int64(mb.Len()))
	}
	return mb, err
}

// accountWriter is the WriteMultiBuffer counterpart of accountReader.
type accountWriter struct {
	buf.Writer
	fn func(int64)
}

func (w *accountWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !mb.IsEmpty() {
		w.fn(int64(mb.Len()))
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// nodeForShortID resolves the virtual child node owning a Reality short ID.
// Unknown or empty short IDs return "" — the caller attributes the traffic to
// this (real) node.
func (s *Server) nodeForShortID(sid [8]byte) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sidNode[sid]
}

// GetAndResetTraffic atomically reads and resets each user/entry-point traffic
// counter, returning the incremental (delta) traffic accumulated since the
// previous invocation. The returned values are per deltas — never cumulative
// totals — so they are safe to feed directly into ReportTraffic.
func (s *Server) GetAndResetTraffic() []model.UserTraffic {
	s.mu.Lock()
	defer s.mu.Unlock()

	traffic := make([]model.UserTraffic, 0, len(s.userTraffic))
	for key, stat := range s.userTraffic {
		up := atomic.SwapInt64(&stat.up, 0)
		down := atomic.SwapInt64(&stat.down, 0)
		if up > 0 || down > 0 {
			email := stat.email
			if email == "" {
				// Try to get it again if it was missing
				if user, ok := s.users[key.uuid]; ok {
					email = user.Email
					stat.email = email
				}
			}
			if email != "" {
				traffic = append(traffic, model.UserTraffic{
					Email:  email,
					NodeID: key.node,
					Up:     up,
					Down:   down,
				})
			}
		} else {
			// No traffic this time.
			// If user is also gone from active users, we can delete the stat entry.
			if _, ok := s.users[key.uuid]; !ok {
				delete(s.userTraffic, key)
			}
		}
	}
	return traffic
}
