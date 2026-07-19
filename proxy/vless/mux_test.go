package vless

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// readWithTimeout reads one MultiBuffer from r, failing the test (via the
// returned error) if nothing arrives within 5s so a broken full-cone path
// cannot hang the suite forever.
func readWithTimeout(t *testing.T, r buf.Reader) (buf.MultiBuffer, error) {
	t.Helper()
	type result struct {
		mb  buf.MultiBuffer
		err error
	}
	ch := make(chan result, 1)
	go func() {
		mb, err := r.ReadMultiBuffer()
		ch <- result{mb: mb, err: err}
	}()
	select {
	case res := <-ch:
		return res.mb, res.err
	case <-time.After(5 * time.Second):
		return nil, context.DeadlineExceeded
	}
}

// TestDialDispatcherUDPFullCone verifies the XUDP full-cone behaviour of
// dialDispatcher.Dispatch for UDP destinations:
//  1. A datagram sent through the link reaches the destination (basic relay).
//  2. The echo reply is delivered back through the link AND carries the
//     source address in b.UDP — required by the client's XUDPConn to rebuild
//     the full-cone mapping. (The pre-fix connected net.Dial path set b.UDP
//     to nil.)
//  3. A datagram sent from a DIFFERENT source to the dispatcher's local port
//     is still delivered. This is the defining full-cone property: an
//     unconnected UDP socket accepts replies from any address. A connected
//     socket would silently drop it, so this assertion guards against a
//     regression to net.Dial("udp", dest).
func TestDialDispatcherUDPFullCone(t *testing.T) {
	// Destination "server A": a UDP echo server.
	aConn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer aConn.Close()
	aAddr := aConn.LocalAddr().(*stdnet.UDPAddr)

	// Channel for A to report the dispatcher's local port (learned from the
	// source of the first datagram it receives).
	dispatcherPortCh := make(chan int, 1)
	go func() {
		buf := make([]byte, 1500)
		n, src, err := aConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dispatcherPortCh <- src.Port // dispatcher's ephemeral local port
		_, _ = aConn.WriteToUDP(buf[:n], src)
	}()

	d := &dialDispatcher{}
	link, err := d.Dispatch(context.Background(), net.Destination{
		Network: net.Network_UDP,
		Address: net.ParseAddress("127.0.0.1"),
		Port:    net.Port(aAddr.Port),
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	// 1. Send a datagram to A through the link.
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
		t.Fatalf("write to link: %v", err)
	}

	// 2. Read the echo; it must carry b.UDP stamped with A's address.
	mb, err := readWithTimeout(t, link.Reader)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if len(mb) != 1 {
		t.Fatalf("expected 1 buffer, got %d", len(mb))
	}
	if string(mb[0].Bytes()) != "hello" {
		t.Fatalf("echo payload wrong: got %q", string(mb[0].Bytes()))
	}
	if mb[0].UDP == nil {
		t.Fatal("reply b.UDP is nil — source address was not stamped (full-cone mapping would break)")
	}
	if got := mb[0].UDP.Address.String(); got != "127.0.0.1" {
		t.Fatalf("reply b.UDP address wrong: got %q, want 127.0.0.1", got)
	}
	if int(mb[0].UDP.Port) != aAddr.Port {
		t.Fatalf("reply b.UDP port wrong: got %d, want %d", int(mb[0].UDP.Port), aAddr.Port)
	}

	// 3. Full-cone: a datagram from a DIFFERENT source (server B) addressed to
	// the dispatcher's local port must still be delivered.
	dispatcherPort := <-dispatcherPortCh
	bConn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer bConn.Close()
	bAddr := bConn.LocalAddr().(*stdnet.UDPAddr)
	if _, err := bConn.WriteToUDP([]byte("fromB"), &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: dispatcherPort}); err != nil {
		t.Fatalf("B write: %v", err)
	}

	mb2, err := readWithTimeout(t, link.Reader)
	if err != nil {
		// A connected socket would drop B's packet, so this times out — that
		// is exactly the regression this test guards against.
		t.Fatalf("read from off-path source (full-cone): %v", err)
	}
	if len(mb2) != 1 {
		t.Fatalf("expected 1 buffer, got %d", len(mb2))
	}
	if string(mb2[0].Bytes()) != "fromB" {
		t.Fatalf("off-path payload wrong: got %q", string(mb2[0].Bytes()))
	}
	if mb2[0].UDP == nil {
		t.Fatal("off-path reply b.UDP is nil")
	}
	if int(mb2[0].UDP.Port) != bAddr.Port {
		t.Fatalf("off-path b.UDP port wrong: got %d, want %d", int(mb2[0].UDP.Port), bAddr.Port)
	}
}
