package vless

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	xrayvless "github.com/xtls/xray-core/proxy/vless"
	xrayencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	"google.golang.org/protobuf/proto"
)

var copyBufPool = sync.Pool{
	New: func() any {
		return new(make([]byte, 32*1024))
	},
}

// closeWrite half-closes conn's write side if it supports CloseWrite
// (e.g. *net.TCPConn, *tls.Conn, *countingConn). It is a safe no-op when the
// underlying net.Conn does not implement CloseWrite.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// handleConnection performs the VLESS handshake on the incoming connection
// and dispatches the payload to either the TCP forwarder or the UDP
// forwarder depending on the command byte.
//
// Wire layout (inside the v2 tunnel when decryption is configured):
//
//	Version(1) + UUID(16) + AddonsLen(1) + Addons(N) + Cmd(1) + Port(2) + AddrType(1) + Addr(N) + Payload
//
// When s.decryption is non-nil, the conn is first wrapped in a
// *encryption.CommonConn via Handshake. All subsequent reads/writes (VLESS
// header parse, response write, payload relay) go through the wrapping conn
// and are transparently AEAD-encrypted/decrypted.
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// VLESS v2: if decryption is configured, wrap the conn in an AEAD tunnel
	// before parsing the VLESS v0 header. The wrap is transport-level — the
	// standard VLESS header travels inside the tunnel unchanged.
	if s.decryption != nil {
		dc, err := s.decryption.Handshake(conn, nil) // nil fallback: vgate has no HTTP fallback
		if err != nil {
			log.Warnf("VLESS v2 handshake failed from %s: %v", conn.RemoteAddr(), err)
			return
		}
		conn = dc
	}

	// 1. Read Request Header
	buf := make([]byte, 512)
	n, err := io.ReadAtLeast(conn, buf, 1+16+1)
	if err != nil {
		return
	}

	// 1.1 Version
	if buf[0] != Version {
		log.Errorf("Invalid VLESS version: %d", buf[0])
		return
	}

	// 1.2 UUID
	var uuid [16]byte
	copy(uuid[:], buf[1:17])
	s.mu.RLock()
	_, ok := s.users[uuid]
	s.mu.RUnlock()
	if !ok {
		log.Warnf("Unauthorized VLESS connection from %s", conn.RemoteAddr())
		return
	}

	// 1.2.1 Register connection and start counting traffic
	s.addConn(uuid, conn)
	defer s.removeConn(uuid, conn)
	s.addTraffic(uuid, int64(n), 0)
	c := &countingConn{Conn: conn, uuid: uuid, server: s}

	// 1.3 Addons — decode protobuf to extract flow (was: skip N bytes).
	// The addons bytes are a protobuf-encoded encoding.Addons message;
	// flow == "xtls-rprx-vision" activates the Vision flow.
	addonsLen := int(buf[17])
	var flow string
	if addonsLen > 0 {
		var addons xrayencoding.Addons
		if err := proto.Unmarshal(buf[18:18+addonsLen], &addons); err != nil {
			return
		}
		flow = addons.Flow
	}
	curr := 18 + addonsLen
	if n < curr+1+2+1 {
		// Need more data
		n2, err := io.ReadAtLeast(c, buf[n:], curr+1+2+1-n)
		if err != nil {
			return
		}
		n += n2
	}

	// 1.4 Command
	cmd := buf[curr]
	curr++

	switch cmd {
	case CmdMux:
		// Mux.Cool: no port/address follows the command byte — the
		// remaining bytes are the head of the Mux frame stream.
		if !s.enableMux {
			log.Errorf("VLESS CommandMux is disabled; rejecting from %s", conn.RemoteAddr())
			return
		}
		// 2. Response: Version(1) + AddonsLen(1) + Addons(0)
		if _, err = c.Write([]byte{Version, 0}); err != nil {
			return
		}
		s.handleMux(c, buf[curr:n], uuid)
		return
	case CmdTCP, CmdUDP:
		// continue with the standard single-target parse below
	default:
		log.Errorf("Unsupported VLESS command: %d", cmd)
		return
	}

	// 1.5 Port
	destPort := binary.BigEndian.Uint16(buf[curr : curr+2])
	curr += 2

	// 1.6 Address
	addrType := buf[curr]
	curr++
	var destAddr string
	switch addrType {
	case AddrTypeIPv4:
		destAddr = net.IP(buf[curr : curr+4]).String()
		curr += 4
	case AddrTypeDomain:
		domainLen := int(buf[curr])
		curr++
		destAddr = string(buf[curr : curr+domainLen])
		curr += domainLen
	case AddrTypeIPv6:
		destAddr = net.IP(buf[curr : curr+16]).String()
		curr += 16
	default:
		log.Errorf("Invalid address type: %d", addrType)
		return
	}

	fullAddr := net.JoinHostPort(destAddr, strconv.Itoa(int(destPort)))
	log.Infof("VLESS proxying to %s", fullAddr)

	// Vision (xtls-rprx-vision) preconditions. Vision is a VLESS flow that
	// pads the body and switches to direct raw-copy for TLS 1.3 inner
	// traffic. It requires the outer conn to be *crypto/tls.Conn (TLS 1.3)
	// or *github.com/xtls/reality.Conn, and is incompatible with the v2
	// AEAD encryption layer (which hides the TLS conn from Vision's
	// UnwrapRawConn). See vision.go for details.
	isVision := flow == xrayvless.XRV
	if isVision {
		s.mu.RLock()
		allowedFlow := s.vless.Flow
		s.mu.RUnlock()
		if allowedFlow != xrayvless.XRV {
			log.Warnf("xtls-rprx-vision requested but not allowed by server config from %s", conn.RemoteAddr())
			return
		}
		if cmd == CmdUDP {
			log.Errorf("xtls-rprx-vision does not support UDP")
			return
		}
		if s.decryption != nil {
			log.Errorf("xtls-rprx-vision + v2 decryption is not supported together")
			return
		}
	}

	// 2. Response: Version(1) + AddonsLen(1) + Addons(0)
	// (matches xray's EncodeResponseHeader with empty addons — Vision's
	// response addons are empty too, so this is correct for both paths.)
	if _, err = c.Write([]byte{Version, 0}); err != nil {
		return
	}

	// 3. Forward Traffic
	if isVision {
		// Pass the raw conn (not the countingConn) — Vision's UnwrapRawConn
		// must see the underlying *tls.Conn / *reality.Conn. Traffic is
		// counted via buf.CountSize inside handleTCPVision.
		s.handleTCPVision(conn, fullAddr, buf[curr:n], uuid)
		return
	}
	if cmd == CmdTCP {
		s.handleTCP(c, fullAddr, buf[curr:n])
	} else {
		s.handleUDP(c, fullAddr, buf[curr:n])
	}
}

// handleTCP dials the destination over TCP and relays traffic bidirectionally.
// initialData is any payload byte read together with the VLESS header.
func (s *Server) handleTCP(c net.Conn, destAddr string, initialData []byte) {
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Errorf("Failed to dial destination %s: %v", destAddr, err)
		return
	}
	defer destConn.Close()

	// Handle initial data if any
	if len(initialData) > 0 {
		if _, err = destConn.Write(initialData); err != nil {
			return
		}
	}

	errChan := make(chan error, 2)

	// client -> destination
	go func() {
		bufp := copyBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(destConn, c, *bufp)
		copyBufPool.Put(bufp)
		// Client finished sending: half-close toward destination so its
		// read sees EOF and the dest->client copy below can return.
		closeWrite(destConn)
		errChan <- err
	}()

	// destination -> client
	go func() {
		bufp := copyBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(c, destConn, *bufp)
		copyBufPool.Put(bufp)
		// Destination finished sending: half-close toward client.
		closeWrite(c)
		errChan <- err
	}()

	<-errChan
}

// CloseWrite half-closes the underlying connection's write side, enabling
// proper TCP half-close propagation in the relay. No-op when the underlying
// net.Conn does not implement CloseWrite (e.g. some transport wrappers).
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
