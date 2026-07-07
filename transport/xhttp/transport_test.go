package xhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/transport"
)

// TestTransportRegistration verifies the xhttp transport self-registers
// under the name "xhttp" in the global transport registry.
func TestTransportRegistration(t *testing.T) {
	got, err := transport.Get("xhttp")
	if err != nil {
		t.Fatalf("transport.Get(\"xhttp\"): %v", err)
	}
	if got.Name() != "xhttp" {
		t.Fatalf("Name() = %q, want %q", got.Name(), "xhttp")
	}
}

// TestListenStreamOne tests the stream-one mode: a client sends a GET
// (no session ID), the server writes a fixed response. This verifies the
// full adapter wiring (config decoding via protojson, ListenXH call,
// callback→net.Listener bridge, response writing).
//
// Note: we test with a fixed response rather than echoing the request body
// because Go's http.Server closes request.Body when the handler commits
// the response (WriteHeader+Flush) before reading the body. Real xray
// clients use the splithttp dialer which handles this correctly.
func TestListenStreamOne(t *testing.T) {
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := transport.Listen(context.Background(), transport.StreamConfig{
		Network:  "xhttp",
		Security: "none",
		Settings: map[string]interface{}{
			"path":            "/xhttp",
			"x_padding_bytes": map[string]any{"from": 1, "to": 1000},
		},
	}, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	response := "hello-xhttp-stream-one"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Write([]byte(response))
				c.Close()
			}()
		}
	}()

	padding := make([]byte, 16)
	rand.Read(padding)
	paddingStr := base64.RawURLEncoding.EncodeToString(padding)

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/xhttp/?x_padding=" + paddingStr
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != response {
		t.Fatalf("response mismatch: got %q, want %q", string(body), response)
	}
}

// TestListenTLS tests the TLS-secured path: the adapter builds an xray
// *tls.Config protobuf from vgate's security settings, splithttp applies
// TLS internally, and a TLS client can connect and receive a response.
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
		Network:  "xhttp",
		Security: "tls",
		Settings: map[string]interface{}{
			"path":            "/xhttp",
			"x_padding_bytes": map[string]any{"from": 1, "to": 1000},
		},
		SecuritySettings: map[string]interface{}{
			"cert_pem":    certPEM,
			"key_pem":     keyPEM,
			"min_version": "1.3",
		},
	}, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	response := "hello-xhttp-tls"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Write([]byte(response))
				c.Close()
			}()
		}
	}()

	padding := make([]byte, 16)
	rand.Read(padding)
	paddingStr := base64.RawURLEncoding.EncodeToString(padding)

	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/xhttp/?x_padding=" + paddingStr
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != response {
		t.Fatalf("response mismatch: got %q, want %q", string(body), response)
	}
}

// TestListenRejectsWrongPath verifies that requests to a wrong path
// receive a 404 response.
func TestListenRejectsWrongPath(t *testing.T) {
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := transport.Listen(context.Background(), transport.StreamConfig{
		Network:  "xhttp",
		Security: "none",
		Settings: map[string]interface{}{
			"path":            "/expected",
			"x_padding_bytes": map[string]any{"from": 1, "to": 1000},
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
			c.Close()
		}
	}()

	padding := make([]byte, 16)
	rand.Read(padding)
	paddingStr := base64.RawURLEncoding.EncodeToString(padding)

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/wrong?x_padding=" + paddingStr
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// generateSelfSignedCert creates a self-signed ECDSA P-256 TLS certificate
// for local testing. Returns PEM-encoded cert and key as strings.
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
