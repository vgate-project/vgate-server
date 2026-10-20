package vless

import (
	"net"
	"testing"

	"github.com/vgate-project/vgate-server/model"
)

// TestLocalQuotaCutAndReAdmit covers the local quota enforcement lifecycle:
// applying a snapshot, crossing the cap via addTraffic closes the user's
// live connections and rejects new handshakes, and a later snapshot with
// restored headroom re-admits the user with a zeroed accrual.
func TestLocalQuotaCutAndReAdmit(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 1
	cred := "550e8400-e29b-41d4-a716-446655440000"
	s.users[uuid] = model.User{ID: cred, Email: "u@example.com"}

	// A live connection registered as the handler would.
	client, serverEnd := net.Pipe()
	defer client.Close()
	s.addConn(uuid, serverEnd)

	s.ApplyUsage([]model.UserUsage{{Email: "u@example.com", QuotaBytes: 100, UsedBytes: 90}})

	// Under the cap: traffic flows, connection stays open.
	s.addTraffic(uuid, "", 5, 0)
	if s.userOverQuota(uuid) {
		t.Fatal("user cut before crossing the cap")
	}
	// Crossing: the remaining 5 bytes are exceeded, the conn is closed and
	// new handshakes are rejected.
	s.addTraffic(uuid, "", 0, 10)
	if !s.userOverQuota(uuid) {
		t.Fatal("user not cut after crossing the cap")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("expected the live connection to be closed on cut")
	}

	// Renewal: a fresh snapshot with headroom re-admits and resets accrual.
	s.ApplyUsage([]model.UserUsage{{Email: "u@example.com", QuotaBytes: 1000, UsedBytes: 200}})
	if s.userOverQuota(uuid) {
		t.Fatal("user still cut after snapshot restored headroom")
	}
	qs := s.userQuota[uuid]
	if qs.accrual != 0 {
		t.Errorf("accrual after re-apply = %d, want 0 (snapshot includes reported bytes)", qs.accrual)
	}
	serverEnd.Close()
}

// TestLocalQuotaUnlimitedAndUnknown covers the two enforcement-off cases: an
// unlimited (-1) snapshot never cuts, and a user without any snapshot (or one
// whose email is not in the node's user set) is ignored entirely.
func TestLocalQuotaUnlimitedAndUnknown(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 2
	s.users[uuid] = model.User{Email: "unlim@example.com"}
	var stranger [16]byte
	stranger[0] = 3

	s.ApplyUsage([]model.UserUsage{
		{Email: "unlim@example.com", QuotaBytes: -1, UsedBytes: 1 << 40},
		{Email: "not-on-this-node@example.com", QuotaBytes: 10, UsedBytes: 0},
	})
	s.addTraffic(uuid, "", 1<<20, 1<<20)
	s.addTraffic(stranger, "", 1<<20, 1<<20)
	if s.userOverQuota(uuid) || s.userOverQuota(stranger) {
		t.Error("unlimited / snapshot-less users must never be cut")
	}
	if _, ok := s.userQuota[stranger]; ok {
		t.Error("usage for a user outside the node's user set must be ignored")
	}
}

// TestLocalQuotaAlreadyOverAtApply verifies that a snapshot arriving with the
// user already over the cap (e.g. the admin lowered a quota) marks the user
// cut immediately, without waiting for new traffic.
func TestLocalQuotaAlreadyOverAtApply(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 4
	s.users[uuid] = model.User{Email: "over@example.com"}

	s.ApplyUsage([]model.UserUsage{{Email: "over@example.com", QuotaBytes: 100, UsedBytes: 500}})
	if !s.userOverQuota(uuid) {
		t.Fatal("user not cut despite snapshot already over the cap")
	}
}

// TestUpdateUsersClearsQuotaState verifies the enforcement state is dropped
// together with the user, so a returning user starts from a fresh snapshot.
func TestUpdateUsersClearsQuotaState(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 5
	s.users[uuid] = model.User{Email: "gone@example.com"}
	s.ApplyUsage([]model.UserUsage{{Email: "gone@example.com", QuotaBytes: 10, UsedBytes: 0}})

	s.UpdateUsers(nil) // empty set: everyone removed
	if _, ok := s.userQuota[uuid]; ok {
		t.Error("quota state survived user removal")
	}
}
