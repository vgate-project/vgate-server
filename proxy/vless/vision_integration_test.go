package vless

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/model"

	xrayvless "github.com/xtls/xray-core/proxy/vless"
	xrayencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	"google.golang.org/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

// TestManualServeVision boots a real VLESS inbound secured with TLS 1.3 so
// third-party clients (Xray-core, v2rayN, v2rayNG, Nekoray, sing-box, ...)
// can connect to it with flow=xtls-rprx-vision for end-to-end testing.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeVision -timeout 0 ./vless
//
// Optional environment variables (in addition to those understood by
// TestManualServe):
//
//	VLESS_TEST_PORT - listen port (default 10091)
//
// Once running, point a VLESS client at the share link printed to the log
// with flow=xtls-rprx-vision:
//
//	vless://<uuid>@<host>:<port>?type=tcp&security=tls&allowInsecure=1&flow=xtls-rprx-vision&encryption=none#vgate-vision-test
func TestManualServeVision(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS+Vision+TLS server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10091
	if v := os.Getenv("VLESS_TEST_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_PORT %q: %v", v, err)
		}
		port = p
	}

	uuid := os.Getenv("VLESS_TEST_UUID")
	if uuid == "" {
		uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	}

	email := os.Getenv("VLESS_TEST_EMAIL")
	if email == "" {
		email = "tester@vgate.local"
	}

	host := os.Getenv("VLESS_TEST_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	if _, err := ParseUUID(uuid); err != nil {
		t.Fatalf("invalid VLESS_TEST_UUID %q: %v", uuid, err)
	}

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	server := NewServer()
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "tcp",
			Security: "tls",
			TLSConfig: &model.TLSConfig{
				CertPEM:    certPEM,
				KeyPEM:     keyPEM,
				MinVersion: "1.3", // Vision requires TLS 1.3
			},
		},
	})
	server.UpdateUsers([]model.User{
		{
			ID:       uuid,
			Email:    email,
			Level:    0,
			ExpireAt: time.Now().Add(365 * 24 * time.Hour),
		},
	})

	go server.Start()

	shareURL := "vless://" + uuid + "@" + host + ":" + strconv.Itoa(port) +
		"?type=tcp&security=tls&allowInsecure=1&flow=xtls-rprx-vision&encryption=none#vgate-vision-test"

	log.Info("=====================================================================")
	log.Info("VLESS+Vision (TLS 1.3) test server is running.")
	log.Infof("  Listen : 0.0.0.0:%d", port)
	log.Infof("  UUID   : %s", uuid)
	log.Infof("  Email  : %s", email)
	log.Info("Client share link (copy into your VLESS client):")
	log.Infof("  %s", shareURL)
	log.Info("Note: flow=xtls-rprx-vision requires TLS 1.3. The cert is self-signed,")
	log.Info("so set allowInsecure=1 / skip cert verification on the client.")
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS+Vision test server")
}

// TestManualServeVisionReality boots a real VLESS inbound secured with
// Reality so third-party clients can connect with flow=xtls-rprx-vision
// for end-to-end testing. Reality always uses TLS 1.3, satisfying Vision's
// TLS 1.3 requirement automatically.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeVisionReality -timeout 0 ./vless
func TestManualServeVisionReality(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS+Vision+Reality server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10092
	if v := os.Getenv("VLESS_TEST_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_PORT %q: %v", v, err)
		}
		port = p
	}

	uuid := os.Getenv("VLESS_TEST_UUID")
	if uuid == "" {
		uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	}

	email := os.Getenv("VLESS_TEST_EMAIL")
	if email == "" {
		email = "tester@vgate.local"
	}

	host := os.Getenv("VLESS_TEST_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	if _, err := ParseUUID(uuid); err != nil {
		t.Fatalf("invalid VLESS_TEST_UUID %q: %v", uuid, err)
	}

	target := os.Getenv("VLESS_TEST_TARGET")
	if target == "" {
		target = "aws.amazon.com:443"
	}

	var serverNames []string
	if v := os.Getenv("VLESS_TEST_SNI"); v != "" {
		serverNames = splitCSV(v)
	} else {
		serverNames = []string{"aws.amazon.com"}
	}

	var shortIDs []string
	if v := os.Getenv("VLESS_TEST_SHORT_IDS"); v != "" {
		shortIDs = splitCSV(v)
	} else {
		shortIDs = []string{""}
	}

	privB64 := os.Getenv("VLESS_TEST_PRIVATE_KEY")
	var pubB64 string
	if privB64 == "" {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate x25519 key: %v", err)
		}
		privB64 = base64.RawURLEncoding.EncodeToString(key.Bytes())
		pubB64 = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	} else {
		raw, err := base64.RawURLEncoding.DecodeString(privB64)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_PRIVATE_KEY %q: %v", privB64, err)
		}
		if len(raw) != 32 {
			t.Fatalf("invalid VLESS_TEST_PRIVATE_KEY: must be 32 bytes (43 base64url chars), got %d", len(raw))
		}
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_PRIVATE_KEY: %v", err)
		}
		pubB64 = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}

	server := NewServer()
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "tcp",
			Security: "reality",
			RealityConfig: &model.RealityConfig{
				Show:       true,
				Target:     target,
				ServerName: serverNames[0],
				PrivateKey: privB64,
				ShortIds:   shortIDs,
			},
		},
	})
	server.UpdateUsers([]model.User{
		{
			ID:       uuid,
			Email:    email,
			Level:    0,
			ExpireAt: time.Now().Add(365 * 24 * time.Hour),
		},
	})

	go server.Start()

	sni := serverNames[0]
	sid := shortIDs[0]
	shareURL := "vless://" + uuid + "@" + host + ":" + strconv.Itoa(port) +
		"?type=tcp&security=reality&pbk=" + pubB64 +
		"&fp=chrome&sni=" + sni + "&sid=" + sid +
		"&flow=xtls-rprx-vision&encryption=none#vgate-vision-reality-test"

	log.Info("=====================================================================")
	log.Info("VLESS+Vision+Reality test server is running.")
	log.Infof("  Listen     : 0.0.0.0:%d", port)
	log.Infof("  UUID       : %s", uuid)
	log.Infof("  Email      : %s", email)
	log.Infof("  Target     : %s", target)
	log.Infof("  SNI        : %v", serverNames)
	log.Infof("  ShortIDs   : %v", shortIDs)
	log.Infof("  PrivateKey : %s", privB64)
	log.Infof("  PublicKey  : %s", pubB64)
	log.Info("Client share link (copy into your VLESS client):")
	log.Infof("  %s", shareURL)
	log.Info("Note: flow=xtls-rprx-vision. Reality always uses TLS 1.3, satisfying Vision's requirement.")
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS+Vision+Reality test server")
}

// TestVisionRejectedOverWS verifies that Vision flow is rejected when the
// transport is WebSocket (not TLS/Reality directly). Vision requires the
// outer conn to be *crypto/tls.Conn or *github.com/xtls/reality.Conn;
// a WebSocket-framed conn is neither, so setupVisionConn returns an error
// and the connection is closed without forwarding to the destination.
func TestVisionRejectedOverWS(t *testing.T) {
	// 1. Local TCP echo target (should never be reached).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	echoReached := make(chan struct{}, 1)
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			echoReached <- struct{}{}
			c.Close()
		}
	}()

	// 2. vgate server on WS transport (no security).
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	server := NewServer()
	server.UpdateUsers([]model.User{
		{ID: uuid, Email: "vision-ws@test", ExpireAt: time.Now().Add(time.Hour)},
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

	if !waitForPort(port, 2*time.Second) {
		t.Fatalf("VLESS ws listener did not bind on port %d", port)
	}

	// 3. Dial and perform WebSocket upgrade.
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

	// 4. Build VLESS request with flow=xtls-rprx-vision targeting the echo server.
	echoAddr := echoLn.Addr().(*net.TCPAddr)
	uuidBytes, err := ParseUUID(uuid)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	addonsBytes, err := proto.Marshal(&xrayencoding.Addons{Flow: xrayvless.XRV})
	if err != nil {
		t.Fatalf("marshal addons: %v", err)
	}
	var payload bytes.Buffer
	payload.WriteByte(Version)
	payload.Write(uuidBytes[:])
	payload.WriteByte(byte(len(addonsBytes)))
	payload.Write(addonsBytes)
	payload.WriteByte(CmdTCP)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(echoAddr.Port))
	payload.Write(portBuf[:])
	payload.WriteByte(AddrTypeIPv4)
	payload.Write(echoAddr.IP.To4())
	payload.Write([]byte("hello-vision-over-ws"))

	if err := writeMaskedFrame(tcp, 0x2, payload.Bytes()); err != nil {
		t.Fatalf("write vless frame: %v", err)
	}

	// 5. The server should reject the Vision flow (WebSocket is not
	// TLS/Reality directly) and close without forwarding to the echo target.
	select {
	case <-echoReached:
		t.Fatal("Vision over WS should have been rejected, but the echo target was reached")
	case <-time.After(2 * time.Second):
		// Expected: the server logged an error and closed the connection.
	}
}

// generateSelfSignedCert creates a self-signed ECDSA P-256 TLS certificate
// suitable for local testing. Returns PEM-encoded cert and key.
func generateSelfSignedCert() (certPEM, keyPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "vgate-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}
