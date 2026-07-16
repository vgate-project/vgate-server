package vless

// Vision (xtls-rprx-vision) inbound support.
//
// This file wires xray-core's Vision reader/writer into vgate's VLESS server.
// The protocol stack is, from outer to inner:
//
//	TCP → TLS/Reality → VLESS encoding → Vision (this file)
//
// Vision is a VLESS *flow* (not a transport): it pads the VLESS body to hide
// traffic signatures and, when the inner traffic is TLS 1.3, switches to
// direct raw-copy for throughput. It only works when the outer conn is
// *crypto/tls.Conn (TLS 1.3) or *github.com/xtls/reality.Conn.
//
// The xray-core leaf packages are imported directly (Path 1): we reuse
// proxy.NewVisionReader/NewVisionWriter/NewTrafficState and the thin conn
// wrappers transport/internet/tls.Conn and transport/internet/reality.Conn.
// We do NOT bootstrap a core.Instance — these are plain constructors.
//
// The central trick is the conn-type adapter: xray's proxy.UnwrapRawConn only
// recognizes xray's own *tls.Conn / *reality.Conn wrapper types, but vgate
// produces stdlib *crypto/tls.Conn and standalone *github.com/xtls/reality.Conn.
// We wrap vgate's conn in the matching xray type so UnwrapRawConn (used in the
// direct-copy path) reaches the raw TCP conn. The reflection peek of
// input/rawInput targets the stdlib/standalone conn directly (vgate's conn IS
// that type), whereas xray's inbound peeks .Conn (because xray's wrapper holds
// the stdlib conn). Both reach the same target fields.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"
	"unsafe"

	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"

	log "github.com/sirupsen/logrus"
)

// setupVisionConn wraps conn in the xray-recognized conn type and peeks its
// internal input/rawInput buffers. Mirrors proxy/vless/inbound/inbound.go:1110-1125
// but targets the stdlib/standalone conn directly (vgate's conn IS that type,
// not xray's wrapper).
//
// conn must be either *crypto/tls.Conn (TLS 1.3 required) or
// *github.com/xtls/reality.Conn. The returned wrapped conn behaves identically
// to the original for reads/writes but is recognized by proxy.UnwrapRawConn.
func setupVisionConn(conn net.Conn) (wrapped net.Conn, input *bytes.Reader, rawInput *bytes.Buffer, err error) {
	switch typed := conn.(type) {
	case *tls.Conn:
		if typed.ConnectionState().Version != tls.VersionTLS13 {
			return nil, nil, nil, fmt.Errorf("xtls-rprx-vision requires outer TLS 1.3, got 0x%x", typed.ConnectionState().Version)
		}
		wrapped = &xraytls.Conn{Conn: typed}
		t := reflect.TypeOf(typed).Elem() // crypto/tls.Conn (input/rawInput are direct fields)
		p := uintptr(unsafe.Pointer(typed))
		input, rawInput, err = peekBuffers(t, p)
		return
	case *reality.Conn:
		wrapped = &xrayreality.Conn{Conn: typed}
		t := reflect.TypeOf(typed).Elem() // standalone reality.Conn (input/rawInput are direct fields)
		p := uintptr(unsafe.Pointer(typed))
		input, rawInput, err = peekBuffers(t, p)
		return
	default:
		return nil, nil, nil, fmt.Errorf("xtls-rprx-vision only supports TLS and REALITY directly, got %T", conn)
	}
}

// peekBuffers returns pointers to the input/rawInput fields of a tls/reality
// conn struct via reflection. t is the struct type (e.g. crypto/tls.Conn),
// p is the base pointer to the struct instance.
func peekBuffers(t reflect.Type, p uintptr) (*bytes.Reader, *bytes.Buffer, error) {
	inputField, ok := t.FieldByName("input")
	if !ok {
		return nil, nil, errors.New("vision: target conn has no input field")
	}
	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return nil, nil, errors.New("vision: target conn has no rawInput field")
	}
	input := (*bytes.Reader)(unsafe.Pointer(p + inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Pointer(p + rawInputField.Offset))
	return input, rawInput, nil
}

// handleTCPVision relays a TCP destination using Vision reader/writer.
//
//	rawConn     — the underlying *crypto/tls.Conn / *reality.Conn (Vision wraps this)
//	destAddr    — destination host:port
//	initialData — bytes already read after the VLESS header (buf[curr:n])
//	uuid        — user UUID, for traffic accounting and Vision traffic-state init
//
// The caller's countingConn MUST NOT be passed to Vision: proxy.UnwrapRawConn
// does not recognize vgate's countingConn type, so direct-copy would read/write
// through the TLS layer (re-encrypting raw inner TLS records → corruption).
// Traffic is counted via buf.CountSize + s.addTraffic instead.
func (s *Server) handleTCPVision(rawConn net.Conn, destAddr string, initialData []byte, uuid [16]byte) {
	wrapped, input, rawInput, err := setupVisionConn(rawConn)
	if err != nil {
		log.Errorf("vision setup failed from %s: %v", rawConn.RemoteAddr(), err)
		return
	}

	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Errorf("vision: failed to dial destination %s: %v", destAddr, err)
		return
	}
	defer destConn.Close()

	// Wrap the destination connection with the speed limiter (node-global +
	// per-user). The client-side rawConn is intentionally NOT wrapped: Vision's
	// UnwrapRawConn requires the exact *tls.Conn/*reality.Conn type. Wrapping
	// destConn shapes the user's total throughput without touching the TLS
	// framing on the client side.
	limitedDest := &rateLimitedConn{Conn: destConn, server: s, uuid: uuid}

	// Vision traffic state. The UserUUID is shared between reader and writer:
	// the writer prefixes the first padding block with it, and the reader
	// checks it to detect padding blocks vs raw passthrough.
	trafficState := proxy.NewTrafficState(uuid[:])
	ctx := context.Background()

	// Uplink: client → destination. isUplink=true (server reading client→server).
	// initialData is prepended so the VisionReader sees the bytes already read
	// after the VLESS header (the client's first Vision padding block lives there).
	combined := io.MultiReader(bytes.NewReader(initialData), wrapped)
	uplinkReader := proxy.NewVisionReader(buf.NewReader(combined), trafficState, true, ctx, wrapped, input, rawInput, nil)

	// Downlink: destination → client. isUplink=false (server writing server→client).
	downlinkWriter := proxy.NewVisionWriter(buf.NewWriter(wrapped), trafficState, false, ctx, wrapped, nil, nil)

	destReader := buf.NewReader(limitedDest)
	destWriter := buf.NewWriter(limitedDest)

	var upCount, downCount buf.SizeCounter
	errChan := make(chan error, 2)
	go func() {
		errChan <- buf.Copy(uplinkReader, destWriter, buf.CountSize(&upCount))
	}()
	go func() {
		errChan <- buf.Copy(destReader, downlinkWriter, buf.CountSize(&downCount))
	}()
	<-errChan // first side to finish closes the relay

	// Account traffic (replaces countingConn for the Vision path).
	s.addTraffic(uuid, upCount.Size, downCount.Size)
}
