package vless

import (
	"context"
	"net"

	"golang.org/x/time/rate"
)

// rateBucket pairs a token bucket with the exact rate it was built for, so we
// can decide (in UpdateUsers) whether a per-user bucket can be reused across a
// hot-reload without re-parsing the bucket's float rate (which is subject to
// rounding).
type rateBucket struct {
	b    *rate.Limiter
	rate int64
}

// newRateBucket builds a token-bucket rate limiter for the given rate in
// bytes/sec. A rate <= 0 means "unlimited" and returns nil.
func newRateBucket(rateBytesPerSec int64) *rateBucket {
	if rateBytesPerSec <= 0 {
		return nil
	}
	return &rateBucket{b: newBucket(rateBytesPerSec), rate: rateBytesPerSec}
}

// newBucket builds the underlying token bucket for rate in bytes/sec. The
// burst capacity is clamped to [1MiB, 8MiB]: a floor of 1MiB guarantees a
// single read/write (<= ~32KiB) always fits within capacity, and the cap
// bounds the memory used per bucket.
func newBucket(rateBytesPerSec int64) *rate.Limiter {
	const minBurst = 1 << 20 // 1 MiB
	const maxBurst = 8 << 20 // 8 MiB
	burst := rateBytesPerSec
	if burst < minBurst {
		burst = minBurst
	}
	if burst > maxBurst {
		burst = maxBurst
	}
	return rate.NewLimiter(rate.Limit(rateBytesPerSec), int(burst))
}

// applyLimits shapes the given upload/download byte counts for a user against
// the node-global and per-user token buckets. up/down are the number of bytes
// just transferred in each direction; either may be 0. Applying both the
// global and the per-user bucket yields min(global, user) semantics. It is a
// no-op when no relevant limit is configured.
//
// The bucket pointers are copied under the read lock and the (potentially
// blocking) Wait happens afterwards, so we never hold the Server mutex while
// shaping. A bucket replaced by a later UpdateConfig/UpdateUsers only affects
// new connections; in-flight connections keep shaping against the snapshot
// they grabbed here.
func (s *Server) applyLimits(uuid [16]byte, up, down int) {
	if up <= 0 && down <= 0 {
		return
	}
	s.mu.RLock()
	gu, gd := s.globalULimiter, s.globalDLimiter
	uu, ud := s.userULimiters[uuid], s.userDLimiters[uuid]
	s.mu.RUnlock()

	wait := func(rb *rateBucket, n int) {
		if rb == nil || rb.b == nil || n <= 0 {
			return
		}
		// Guard against n exceeding the burst: lim.Wait tolerates n > burst,
		// but clamping keeps any single op's latency bounded (and matches the
		// previous behavior). Reads/writes are <= ~32KiB, well under the 1MiB
		// burst floor, so this never triggers in practice.
		tokens := n
		if tokens > rb.b.Burst() {
			tokens = rb.b.Burst()
		}
		// WaitN blocks until `tokens` are available (tokens replenish at the
		// bucket's rate, so it never blocks indefinitely for a positive rate).
		// context.Background() preserves the old blocking semantics; a
		// connection-scoped context could be threaded in later to unblock on
		// socket close.
		_ = rb.b.WaitN(context.Background(), tokens)
	}
	wait(gu, up)
	wait(uu, up)
	wait(gd, down)
	wait(ud, down)
}

// rateLimitedConn wraps a net.Conn to shape throughput without accounting
// traffic (used by the xtls-rprx-vision path, which counts bytes separately
// via buf.CountSize). Write = upload (client→destination), Read = download
// (destination→client).
type rateLimitedConn struct {
	net.Conn
	server *Server
	uuid   [16]byte
}

func (c *rateLimitedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.server.applyLimits(c.uuid, 0, n)
	}
	return n, err
}

func (c *rateLimitedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.server.applyLimits(c.uuid, n, 0)
	}
	return n, err
}

func (c *rateLimitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
