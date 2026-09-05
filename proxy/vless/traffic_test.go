package vless

import (
	"encoding/hex"
	"testing"

	"github.com/vgate-project/vgate-server/model"
)

// TestTrafficAccountingPerEntryNode verifies that traffic counters are kept
// per (user, entry point): the real node and each virtual child accumulate
// independently, and GetAndResetTraffic emits one delta per bucket.
func TestTrafficAccountingPerEntryNode(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 1
	s.users[uuid] = model.User{Email: "u@example.com"}

	s.addTraffic(uuid, "", 10, 0)
	s.addTraffic(uuid, "", 5, 0)
	s.addTraffic(uuid, "c1", 7, 3)

	stats := s.GetAndResetTraffic()
	byNode := map[string]model.UserTraffic{}
	for _, st := range stats {
		if st.Email != "u@example.com" {
			t.Errorf("unexpected email %q", st.Email)
		}
		byNode[st.NodeID] = st
	}
	if got := byNode[""]; got.Up != 15 || got.Down != 0 {
		t.Errorf("real-node bucket = %+v, want up 15 / down 0", got)
	}
	got, ok := byNode["c1"]
	if !ok {
		t.Fatalf("no bucket for virtual child c1: %+v", byNode)
	}
	if got.Up != 7 || got.Down != 3 {
		t.Errorf("c1 bucket = %+v, want up 7 / down 3", got)
	}

	// Counters were reset.
	if again := s.GetAndResetTraffic(); len(again) != 0 {
		t.Errorf("second GetAndResetTraffic = %+v, want empty", again)
	}
}

// TestNodeForShortID verifies the sid → virtual child mapping built from the
// config (hex keys zero-padded to 8 bytes, matching the reality library's
// ClientShortId representation) and the unknown-sid fallback.
func TestNodeForShortID(t *testing.T) {
	s := NewServer()
	s.UpdateConfig(&model.Config{
		Port: 443,
		TrafficSIDs: []model.TrafficSID{
			{NodeID: "c1", SID: "1234abcd"},
			{NodeID: "c2", SID: "BEEFCAFE"}, // upper-case input must be normalized
			{NodeID: "bad", SID: "zzzz"},    // invalid hex skipped
		},
	})

	var key [8]byte
	b, _ := hex.DecodeString("1234abcd")
	copy(key[:], b)
	if got := s.nodeForShortID(key); got != "c1" {
		t.Errorf("nodeForShortID(1234abcd) = %q, want c1", got)
	}
	var key2 [8]byte
	b2, _ := hex.DecodeString("beefcafe")
	copy(key2[:], b2)
	if got := s.nodeForShortID(key2); got != "c2" {
		t.Errorf("nodeForShortID(beefcafe) = %q, want c2", got)
	}
	if got := s.nodeForShortID([8]byte{}); got != "" {
		t.Errorf("empty sid → %q, want empty (real node)", got)
	}
	var unknown [8]byte
	unknown[0] = 0xff
	if got := s.nodeForShortID(unknown); got != "" {
		t.Errorf("unknown sid → %q, want empty (real node)", got)
	}
}
