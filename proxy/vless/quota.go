package vless

// Local quota enforcement. The manager remains the authoritative gate (its
// /users filter drops over-quota users and UpdateUsers then closes their
// connections), but that loop is pull-based with a sync-interval granularity
// and only sees bytes the node has already reported. The /usage snapshots
// applied here add a node-local second layer: the effective remaining is the
// manager-side remaining at snapshot time minus this node's un-reported
// accrual, checked on every counted chunk, so a user crossing the cap is cut
// within bytes-in-flight rather than minutes.
//
// Multi-node semantics: each node only knows its own accrual since the
// snapshot, so a user active on several entry points can overshoot by up to
// one sync interval of the other nodes' throughput. That bound is accepted
// in exchange for not needing global real-time accounting.

import (
	"sync/atomic"

	"github.com/vgate-project/vgate-server/model"

	log "github.com/sirupsen/logrus"
)

// quotaState is one user's local enforcement state. Fields are written under
// s.mu (ApplyUsage, the cut transition) except accrual, which is updated
// atomically from the traffic hot path.
type quotaState struct {
	quota   int64 // effective cap in bytes; -1 = unlimited (enforcement off)
	base    int64 // manager-side used bytes at snapshot time
	accrual int64 // this node's bytes since the snapshot (atomic)
	cut     bool  // locally cut: connections closed, new ones rejected
}

// ApplyUsage replaces the quota snapshots from a manager /usage response.
// Users no longer present in the payload (or unknown emails) lose their
// state, which turns enforcement off for them. A user whose snapshot is
// already over the cap (e.g. the admin lowered a quota) is marked cut here;
// one whose headroom was restored (renewal, bonus purchase) is re-admitted.
// Callers should only invoke this right after a successful traffic report,
// so that base includes everything this node has sent so far.
func (s *Server) ApplyUsage(usage []model.UserUsage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	emailUUID := make(map[string][16]byte, len(s.users))
	for uuid, u := range s.users {
		emailUUID[u.Email] = uuid
	}

	newQuota := make(map[[16]byte]*quotaState, len(usage))
	for _, u := range usage {
		uuid, ok := emailUUID[u.Email]
		if !ok {
			continue // not in this node's user set; nothing to enforce
		}
		qs := &quotaState{quota: u.QuotaBytes, base: u.UsedBytes}
		if u.QuotaBytes >= 0 && u.QuotaBytes-u.UsedBytes <= 0 {
			qs.cut = true
		}
		newQuota[uuid] = qs
	}
	s.userQuota = newQuota
}

// userOverQuotaLocked reports whether the user is currently locally cut.
// Caller must hold s.mu (read or write).
func (s *Server) userOverQuotaLocked(uuid [16]byte) bool {
	qs, ok := s.userQuota[uuid]
	return ok && qs.cut
}

// userOverQuota is the handshake gate: reject new connections of a locally
// cut user before they are registered.
func (s *Server) userOverQuota(uuid [16]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.userOverQuotaLocked(uuid)
}

// accrueQuotaLocked adds n locally-counted bytes to the user's accrual and,
// when the effective remaining hits zero, cuts the user: her connections are
// closed and new handshakes rejected until a later snapshot restores
// headroom. Called from addTraffic with s.mu held; closing conns under s.mu
// mirrors UpdateUsers' removal path.
func (s *Server) accrueQuotaLocked(uuid [16]byte, email string, n int64) {
	qs, ok := s.userQuota[uuid]
	if !ok || qs.quota < 0 || n <= 0 {
		return
	}
	remaining := qs.quota - qs.base - atomic.AddInt64(&qs.accrual, n)
	if remaining > 0 || qs.cut {
		return
	}
	qs.cut = true
	conns := s.userConns[uuid]
	log.Warnf("User %s crossed traffic quota locally (cap %d, manager-used %d, node accrual %d); closing %d connections",
		email, qs.quota, qs.base, qs.accrual, len(conns))
	for conn := range conns {
		conn.Close()
	}
}
