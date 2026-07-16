package vless

import (
	"context"
	"testing"
	"time"
)

func TestNewBucket(t *testing.T) {
	if rb := newRateBucket(0); rb != nil {
		t.Fatal("rate 0 should be unlimited (nil bucket)")
	}
	if rb := newRateBucket(-100); rb != nil {
		t.Fatal("negative rate should be unlimited (nil bucket)")
	}
	b := newBucket(1 << 20) // 1 MiB/s → floor capacity
	if b == nil {
		t.Fatal("positive rate should produce a bucket")
	}
	if b.Burst() != 1<<20 {
		t.Fatalf("capacity floor wrong: got %d, want %d", b.Burst(), 1<<20)
	}
	b2 := newBucket(100 << 20) // high rate → capped capacity
	if b2.Burst() != 8<<20 {
		t.Fatalf("capacity cap wrong: got %d, want %d", b2.Burst(), 8<<20)
	}
	rb := newRateBucket(100 << 20)
	if rb == nil || rb.rate != 100<<20 {
		t.Fatalf("rateBucket rate wrong: got %v", rb)
	}
	if rb.b.Burst() != 8<<20 {
		t.Fatalf("rateBucket capacity cap wrong: got %d, want %d", rb.b.Burst(), 8<<20)
	}
}

func TestApplyLimitsUnlimited(t *testing.T) {
	s := &Server{} // every bucket nil → unlimited
	uuid := [16]byte{1}
	start := time.Now()
	// A huge request must not block when no limit is configured.
	s.applyLimits(uuid, 100<<20, 100<<20)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("unlimited applyLimits should not block")
	}
}

func TestApplyLimitsShapesGlobal(t *testing.T) {
	rb := newRateBucket(1 << 20) // 1 MiB/s, capacity 1 MiB
	rb.b.WaitN(context.Background(), rb.b.Burst()) // drain the initial burst so the next consume must wait
	s := &Server{globalULimiter: rb}
	uuid := [16]byte{1}

	start := time.Now()
	s.applyLimits(uuid, int(rb.b.Burst()), 0) // upload a full bucket's worth
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond {
		t.Fatalf("global upload limit not enforced: %d bytes took %v at 1 MiB/s (want >= ~1s)",
			rb.b.Burst(), elapsed)
	}
}
