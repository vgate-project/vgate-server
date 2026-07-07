package ws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/transport"

	"github.com/gorilla/websocket"
)

func TestTransportRegistration(t *testing.T) {
	got, err := transport.Get("ws")
	if err != nil {
		t.Fatalf("transport.Get(\"ws\"): %v", err)
	}
	if got.Name() != "ws" {
		t.Fatalf("Name() = %q, want %q", got.Name(), "ws")
	}
}

// TestListenAndEcho tests end-to-end: a gorilla/websocket client connects,
// sends a message, and receives the echo. Verifies the full adapter wiring
// (config decoding, ListenWS call, callback→net.Listener bridge, security=none).
func TestListenAndEcho(t *testing.T) {
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := transport.Listen(context.Background(), transport.StreamConfig{
		Network:  "ws",
		Security: "none",
		Settings: map[string]interface{}{"path": "/ws"},
	}, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Echo server: accept conns, echo via io.Copy.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	// Client: connect via gorilla/websocket.
	url := "ws://127.0.0.1:" + strconv.Itoa(port) + "/ws"
	dialer := &websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-ws-echo")
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestListenTLS tests the TLS-secured path.
func TestListenTLS(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := transport.Listen(context.Background(), transport.StreamConfig{
		Network:  "ws",
		Security: "tls",
		Settings: map[string]interface{}{"path": "/ws"},
		SecuritySettings: map[string]interface{}{
			"cert_pem":    certPEM,
			"key_pem":     keyPEM,
			"min_version": "1.2",
		},
	}, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	url := "wss://127.0.0.1:" + strconv.Itoa(port) + "/ws"
	dialer := &websocket.Dialer{
		HandshakeTimeout: 3 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-ws-tls")
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestListenRejectsWrongPath verifies that requests to a wrong path
// receive a 404 (or non-101) response.
func TestListenRejectsWrongPath(t *testing.T) {
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := transport.Listen(context.Background(), transport.StreamConfig{
		Network:  "ws",
		Security: "none",
		Settings: map[string]interface{}{"path": "/expected"},
	}, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// gorilla returns an error for non-101 responses.
	url := "ws://127.0.0.1:" + strconv.Itoa(port) + "/wrong"
	_, resp, err := (&websocket.Dialer{HandshakeTimeout: 3 * time.Second}).Dial(url, nil)
	if err == nil {
		t.Fatal("expected error for wrong path, got nil")
	}
	if resp != nil && resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("expected non-101 status for wrong path")
	}
}

func generateSelfSignedCert() (certPEM, keyPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vgate-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}
