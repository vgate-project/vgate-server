package vless

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/model"
)

// TestVLESSOverXHTTP runs a full end-to-end scenario: a VLESS inbound listens
// using the XHTTP transport, a client performs the VLESS handshake split
// across a packet-up POST (uplink) and a stream-down GET (downlink), and
// payload data is echoed by a local TCP destination.
//
// This is the mode real Xray-core HTTP/1.1 / HTTP/2 clients use: a long-lived
// GET carries the downlink as a streamed response body, and numbered POST
// chunks carry the uplink (reassembled server-side by sequence number).
func TestVLESSOverXHTTP(t *testing.T) {
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

	// 2. Bring up the VLESS server bound to an xhttp transport on port 0.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	server := NewServer()
	server.UpdateUsers([]model.User{
		{ID: uuid, Email: "xhttp@test", ExpireAt: time.Now().Add(time.Hour)},
	})
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "xhttp",
			Security: "none",
			Settings: map[string]interface{}{"path": "/xhttp"},
		},
	})
	go server.Start()

	if !waitForPort(port, 2*time.Second) {
		t.Fatalf("VLESS xhttp listener did not bind on port %d", port)
	}

	echoAddr := echoLn.Addr().(*net.TCPAddr)
	uuidBytes, err := ParseUUID(uuid)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}

	// 3. Build the VLESS request: Version + UUID + AddonsLen + Cmd + Port +
	//    AddrType + Addr, followed by the initial payload. This whole blob is
	//    sent as the body of a single packet-up POST (seq=0).
	var vlessReq bytes.Buffer
	vlessReq.WriteByte(Version)
	vlessReq.Write(uuidBytes[:])
	vlessReq.WriteByte(0) // AddonsLen
	vlessReq.WriteByte(CmdTCP)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(echoAddr.Port))
	vlessReq.Write(portBuf[:])
	vlessReq.WriteByte(AddrTypeIPv4)
	vlessReq.Write(echoAddr.IP.To4())
	hello := []byte("hello-vless-over-xhttp")
	vlessReq.Write(hello)

	sessionID := "test-session-0"
	padding := strings.Repeat("X", 100) // must be within default [100, 1000]

	// 4. Open the stream-down GET first. The server blocks waiting for uplink
	//    data to arrive via the uploadQueue, so the GET response body won't
	//    have any bytes until we POST the VLESS request.
	getPath := "/xhttp/" + sessionID + "?x_padding=" + padding
	getReq := "GET " + getPath + " HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n\r\n"
	getConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial GET: %v", err)
	}
	defer getConn.Close()
	if _, err := getConn.Write([]byte(getReq)); err != nil {
		t.Fatalf("send GET: %v", err)
	}
	getBR := bufio.NewReader(getConn)
	getResp, err := http.ReadResponse(getBR, nil)
	if err != nil {
		t.Fatalf("read GET response: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", getResp.StatusCode)
	}

	// 5. POST the VLESS request as packet-up chunk seq=0.
	postPath := "/xhttp/" + sessionID + "/0?x_padding=" + padding
	postReq := "POST " + postPath + " HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: " + strconv.Itoa(vlessReq.Len()) + "\r\n\r\n"
	postConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial POST: %v", err)
	}
	defer postConn.Close()
	if _, err := postConn.Write([]byte(postReq)); err != nil {
		t.Fatalf("send POST headers: %v", err)
	}
	if _, err := postConn.Write(vlessReq.Bytes()); err != nil {
		t.Fatalf("send POST body: %v", err)
	}
	postBR := bufio.NewReader(postConn)
	postResp, err := http.ReadResponse(postBR, nil)
	if err != nil {
		t.Fatalf("read POST response: %v", err)
	}
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("POST expected 200, got %d", postResp.StatusCode)
	}
	postResp.Body.Close()

	// 6. Read the downlink from the GET response body. The server's VLESS
	//    handler writes the VLESS response header (Version + AddonsLen=0, 2
	//    bytes) followed by the echoed payload. They may arrive coalesced or
	//    split across flushes; read until we have 2 + len(hello) bytes.
	//    Read from getResp.Body (not the raw bufio.Reader) so chunked
	//    transfer-encoding framing is decoded for us.
	getConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got bytes.Buffer
	buf := make([]byte, 256)
	for got.Len() < 2+len(hello) {
		n, err := getResp.Body.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err != nil {
			t.Fatalf("read downlink: %v (buffered=%d want=%d)", err, got.Len(), 2+len(hello))
		}
	}
	out := got.Bytes()
	if out[0] != Version || out[1] != 0 {
		t.Fatalf("bad vless response header: %v", out[:2])
	}
	if !bytes.Equal(out[2:2+len(hello)], hello) {
		t.Fatalf("echo mismatch: got %q want %q", out[2:2+len(hello)], hello)
	}
}
