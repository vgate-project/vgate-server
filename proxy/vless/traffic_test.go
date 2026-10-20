package vless

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/buf"

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

// staticReader yields the given buffers once, then errors. It drives the
// accountReader/accountWriter tests without a network.
type staticReader struct {
	mbs []buf.MultiBuffer
}

func (r *staticReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.mbs) == 0 {
		return nil, errors.New("closed")
	}
	mb := r.mbs[0]
	r.mbs = r.mbs[1:]
	return mb, nil
}

// TestAccountReaderWriterChunkCallbacks verifies the chunk-level accounting
// hooks used by the Vision paths: every non-empty chunk invokes fn with its
// byte count as it flows, so addTraffic sees bytes while a connection is
// still open (the regression anchor for the deferred-accounting bug where a
// SizeCounter was only flushed at copy end).
func TestAccountReaderWriterChunkCallbacks(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 1
	s.users[uuid] = model.User{Email: "u@example.com"}

	sr := &staticReader{mbs: []buf.MultiBuffer{
		buf.MultiBuffer{buf.FromBytes(make([]byte, 100))},
		buf.MultiBuffer{buf.FromBytes(make([]byte, 50))},
	}}
	ar := &accountReader{Reader: sr, fn: func(n int64) { s.addTraffic(uuid, "", n, 0) }}

	if _, err := ar.ReadMultiBuffer(); err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if _, err := ar.ReadMultiBuffer(); err != nil {
		t.Fatalf("read 2: %v", err)
	}
	// Both chunks are already accounted — no connection close involved.
	stats := s.GetAndResetTraffic()
	if len(stats) != 1 || stats[0].Up != 150 {
		t.Errorf("after two chunks, stats = %+v, want one entry with up 150", stats)
	}
	if _, err := ar.ReadMultiBuffer(); err == nil {
		t.Error("expected error on exhausted reader")
	}
	if again := s.GetAndResetTraffic(); len(again) != 0 {
		t.Errorf("stats after error read = %+v, want empty (error chunk adds nothing)", again)
	}
}

// TestAccountWriterChunkCallback is the WriteMultiBuffer counterpart.
func TestAccountWriterChunkCallback(t *testing.T) {
	s := NewServer()
	var uuid [16]byte
	uuid[0] = 2
	s.users[uuid] = model.User{Email: "w@example.com"}

	pipe := &passthroughWriter{}
	aw := &accountWriter{Writer: pipe, fn: func(n int64) { s.addTraffic(uuid, "", 0, n) }}
	if err := aw.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(make([]byte, 42))}); err != nil {
		t.Fatalf("write: %v", err)
	}
	stats := s.GetAndResetTraffic()
	if len(stats) != 1 || stats[0].Down != 42 {
		t.Errorf("stats = %+v, want one entry with down 42", stats)
	}
}

// passthroughWriter accepts and discards buffers.
type passthroughWriter struct{}

func (w *passthroughWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
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
