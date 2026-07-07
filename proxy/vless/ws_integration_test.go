package vless

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/model"
)

// TestVLESSOverWebSocket runs a full end-to-end scenario: a VLESS inbound
// listens using the WebSocket transport, a client performs the HTTP
// upgrade + VLESS handshake through raw framing, and payload data is
// echoed by a local TCP destination.
//
// This proves that the transport abstraction lets VLESS speak identically
// over any registered transport without changes to the handler code.
func TestVLESSOverWebSocket(t *testing.T) {
	// 1. Local TCP echo target that the VLESS server will forward to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()

	// 2. Bring up the VLESS server bound to a WS transport on port 0.
	//    Because Server always self-picks the port from model.Config, we
	//    pre-reserve a port and free it right away — cheap and reliable
	//    since we then hand the number to Server.UpdateConfig.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	server := NewServer()
	server.UpdateUsers([]model.User{
		{ID: uuid, Email: "ws@test", ExpireAt: time.Now().Add(time.Hour)},
	})
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "ws",
			Security: "none",
			Settings: map[string]interface{}{"path": "/vless"},
		},
	})
	go server.Start()

	// Wait until the WS listener is really bound.
	if !waitForPort(port, 2*time.Second) {
		t.Fatalf("VLESS ws listener did not bind on port %d", port)
	}

	// 3. Dial the VLESS server and perform the WebSocket handshake.
	tcp, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer tcp.Close()

	key := make([]byte, 16)
	rand.Read(key)
	secKey := base64.StdEncoding.EncodeToString(key)
	req := "GET /vless HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + secKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := tcp.Write([]byte(req)); err != nil {
		t.Fatalf("send upgrade: %v", err)
	}
	br := bufio.NewReader(tcp)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// 4. Build the VLESS request (Version + UUID + AddonsLen + Cmd + Port
	//    + AddrType + Addr) followed by the initial payload, and send it
	//    inside a single masked WebSocket binary frame.
	echoAddr := echoLn.Addr().(*net.TCPAddr)
	uuidBytes, err := ParseUUID(uuid)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	var payload bytes.Buffer
	payload.WriteByte(Version)
	payload.Write(uuidBytes[:])
	payload.WriteByte(0) // AddonsLen
	payload.WriteByte(CmdTCP)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(echoAddr.Port))
	payload.Write(portBuf[:])
	payload.WriteByte(AddrTypeIPv4)
	payload.Write(echoAddr.IP.To4())
	hello := []byte("hello-vless-over-ws")
	payload.Write(hello)

	if err := writeMaskedFrame(tcp, 0x2, payload.Bytes()); err != nil {
		t.Fatalf("write vless frame: %v", err)
	}

	// 5. Expect a WebSocket frame from the server carrying:
	//    - VLESS response header (Version + AddonsLen=0), 2 bytes
	//    - Echoed payload
	//    They may arrive coalesced in one frame or split across several;
	//    read until we have accumulated 2 + len(hello) bytes.
	tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	var got bytes.Buffer
	for got.Len() < 2+len(hello) {
		_, frame, err := readUnmaskedFrame(br)
		if err != nil {
			t.Fatalf("read frame: %v (buffered=%d)", err, got.Len())
		}
		got.Write(frame)
	}
	buf := got.Bytes()
	if buf[0] != Version || buf[1] != 0 {
		t.Fatalf("bad vless response header: %v", buf[:2])
	}
	if !bytes.Equal(buf[2:2+len(hello)], hello) {
		t.Fatalf("echo mismatch: got %q want %q", buf[2:2+len(hello)], hello)
	}
}

// waitForPort polls a TCP connect until success or timeout.
func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// writeMaskedFrame emits a masked (client-style) WebSocket binary frame.
func writeMaskedFrame(w io.Writer, op byte, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x80|op)
	ln := len(payload)
	switch {
	case ln < 126:
		hdr = append(hdr, 0x80|byte(ln))
	case ln <= 0xffff:
		hdr = append(hdr, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(hdr[len(hdr)-2:], uint16(ln))
	default:
		hdr = append(hdr, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(hdr[len(hdr)-8:], uint64(ln))
	}
	var mask [4]byte
	rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, ln)
	for i := 0; i < ln; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

// readUnmaskedFrame reads one server-side (unmasked) WebSocket frame.
func readUnmaskedFrame(r io.Reader) (byte, []byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, nil, err
	}
	op := b[0] & 0x0f
	ln := uint64(b[1] & 0x7f)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = binary.BigEndian.Uint64(ext[:])
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return op, payload, nil
}
