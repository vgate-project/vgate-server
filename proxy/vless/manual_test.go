package vless

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgate-project/vgate-server/model"

	log "github.com/sirupsen/logrus"
)

// TestManualServe boots a real VLESS inbound so third-party clients
// (Xray-core, v2rayN, v2rayNG, Nekoray, sing-box, ...) can connect to
// it for end-to-end testing.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServe -timeout 0 ./vless
//
// Optional environment variables:
//
//	VLESS_TEST_PORT  - listen port (default 10086)
//	VLESS_TEST_UUID  - user UUID   (default b831381d-6324-4d53-ad4f-8cda48b30811)
//	VLESS_TEST_EMAIL - user email  (default tester@vgate.local)
//	VLESS_TEST_HOST  - host used in the printed share link (default 127.0.0.1)
//
// Once running, point a VLESS client at the share link printed to the
// log, e.g.:
//
//	vless://<uuid>@<host>:<port>?type=tcp&security=none&encryption=none#vgate-test
func TestManualServe(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10086
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

	// Validate UUID up-front so we fail fast with a clear message.
	if _, err := ParseUUID(uuid); err != nil {
		t.Fatalf("invalid VLESS_TEST_UUID %q: %v", uuid, err)
	}

	// Bootstrap the server with the desired port and user set.
	server := NewServer()
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Security: "none",
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

	// Start accepting connections in the background.
	go server.Start()

	shareURL := "vless://" + uuid + "@" + host + ":" + strconv.Itoa(port) +
		"?type=tcp&security=none&encryption=none#vgate-test"

	log.Info("=====================================================================")
	log.Info("VLESS test server is running.")
	log.Infof("  Listen : 0.0.0.0:%d", port)
	log.Infof("  UUID   : %s", uuid)
	log.Infof("  Email  : %s", email)
	log.Info("Client share link (copy into your VLESS client):")
	log.Infof("  %s", shareURL)
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	// Block until interrupted so the operator has time to run a real
	// VLESS client against the listener.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS test server")
}

// TestManualServeReality boots a real VLESS inbound secured with
// Reality so third-party clients (Xray-core, v2rayN, v2rayNG, Nekoray,
// sing-box, ...) can connect to it for end-to-end testing.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeReality -timeout 0 ./vless
//
// Optional environment variables (in addition to those understood by
// TestManualServe):
//
//	VLESS_TEST_PORT        - listen port (default 10087)
//	VLESS_TEST_PRIVATE_KEY - X25519 private key in base64url (default: generated on the fly)
//	VLESS_TEST_TARGET      - Reality fallback destination (default www.microsoft.com:443)
//	VLESS_TEST_SNI         - Reality SNI, comma-separated (default www.microsoft.com)
//	VLESS_TEST_SHORT_IDS   - Reality short IDs, comma-separated hex (default "")
//
// Once running, point a VLESS client at the share link printed to the
// log, e.g.:
//
//	vless://<uuid>@<host>:<port>?type=tcp&security=reality&pbk=<pubkey>&fp=chrome&sni=<sni>&sid=<shortid>&encryption=none#vgate-test
func TestManualServeReality(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS+Reality server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10087
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

	// Validate UUID up-front so we fail fast with a clear message.
	if _, err := ParseUUID(uuid); err != nil {
		t.Fatalf("invalid VLESS_TEST_UUID %q: %v", uuid, err)
	}

	// Reality-specific configuration.
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
		// Allow the empty short ID by default so a client can connect
		// without specifying `sid`.
		shortIDs = []string{""}
	}

	// X25519 private key. If not supplied, generate one on the fly and
	// print the matching public key so the operator can paste it into a
	// client config. If supplied, derive the public key from it so the
	// share link is still correct.
	//
	// Encoded with base64.RawURLEncoding (no padding) to match the
	// format emitted by `xray x25519` and consumed by DecodeRealityConfig.
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

	// Bootstrap the server with the desired port, user set, and Reality security.
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

	// Start accepting connections in the background.
	go server.Start()

	// Build a share link with all the Reality-specific query params.
	// Use the first SNI and first short ID for the share link; clients
	// only support a single value for each.
	sni := serverNames[0]
	sid := shortIDs[0]
	shareURL := "vless://" + uuid + "@" + host + ":" + strconv.Itoa(port) +
		"?type=tcp&security=reality&pbk=" + pubB64 +
		"&fp=chrome&sni=" + sni + "&sid=" + sid +
		"&encryption=none#vgate-reality-test"

	log.Info("=====================================================================")
	log.Info("VLESS+Reality test server is running.")
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
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	// Block until interrupted so the operator has time to run a real
	// VLESS client against the listener.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS+Reality test server")
}

// TestManualServeXHTTP boots a real VLESS inbound using the XHTTP transport
// so third-party clients (Xray-core, v2rayN, v2rayNG, Nekoray, sing-box, ...)
// can connect to it for end-to-end testing.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeXHTTP -timeout 0 ./vless
//
// Optional environment variables:
//
//	VLESS_TEST_PORT  - listen port (default 10088)
//	VLESS_TEST_UUID  - user UUID   (default b831381d-6324-4d53-ad4f-8cda48b30811)
//	VLESS_TEST_EMAIL - user email  (default tester@vgate.local)
//	VLESS_TEST_HOST  - host used in the printed share link (default 127.0.0.1)
//	VLESS_TEST_PATH  - xhttp path   (default /xhttp)
//
// Once running, point a VLESS client at the share link printed to the
// log, e.g.:
//
//	vless://<uuid>@<host>:<port>?type=xhttp&mode=auto&path=/xhttp&security=none&encryption=none#vgate-xhttp-test
func TestManualServeXHTTP(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS+XHTTP server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10088
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

	xpath := os.Getenv("VLESS_TEST_PATH")
	if xpath == "" {
		xpath = "/xhttp"
	}

	if _, err := ParseUUID(uuid); err != nil {
		t.Fatalf("invalid VLESS_TEST_UUID %q: %v", uuid, err)
	}

	server := NewServer()
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "xhttp",
			Security: "none",
			Settings: map[string]interface{}{"path": xpath},
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
		"?type=xhttp&mode=auto&path=" + xpath +
		"&security=none&encryption=none#vgate-xhttp-test"

	log.Info("=====================================================================")
	log.Info("VLESS+XHTTP test server is running.")
	log.Infof("  Listen : 0.0.0.0:%d", port)
	log.Infof("  UUID   : %s", uuid)
	log.Infof("  Email  : %s", email)
	log.Infof("  Path   : %s", xpath)
	log.Info("Client share link (copy into your VLESS client):")
	log.Infof("  %s", shareURL)
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS+XHTTP test server")
}

// TestManualServeXHTTPReality boots a real VLESS inbound using the XHTTP
// transport secured with Reality, so third-party clients can connect to it
// for end-to-end testing.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeXHTTPReality -timeout 0 ./vless
//
// Optional environment variables (in addition to those understood by
// TestManualServeXHTTP):
//
//	VLESS_TEST_PORT        - listen port (default 10089)
//	VLESS_TEST_PRIVATE_KEY - X25519 private key in base64url (default: generated on the fly)
//	VLESS_TEST_TARGET      - Reality fallback destination (default aws.amazon.com:443)
//	VLESS_TEST_SNI         - Reality SNI, comma-separated (default aws.amazon.com)
//	VLESS_TEST_SHORT_IDS   - Reality short IDs, comma-separated hex (default "")
//
// Once running, point a VLESS client at the share link printed to the
// log, e.g.:
//
//	vless://<uuid>@<host>:<port>?type=xhttp&mode=auto&path=/xhttp&security=reality&pbk=<pubkey>&fp=chrome&sni=<sni>&sid=<shortid>&encryption=none#vgate-xhttp-reality-test
func TestManualServeXHTTPReality(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS+XHTTP+Reality server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10089
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

	xpath := os.Getenv("VLESS_TEST_PATH")
	if xpath == "" {
		xpath = "/xhttp"
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
			Network:  "xhttp",
			Security: "reality",
			Settings: map[string]interface{}{"path": xpath},
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
		"?type=xhttp&mode=auto&path=" + xpath +
		"&security=reality&pbk=" + pubB64 +
		"&fp=chrome&sni=" + sni + "&sid=" + sid +
		"&encryption=none#vgate-xhttp-reality-test"

	log.Info("=====================================================================")
	log.Info("VLESS+XHTTP+Reality test server is running.")
	log.Infof("  Listen     : 0.0.0.0:%d", port)
	log.Infof("  UUID       : %s", uuid)
	log.Infof("  Email      : %s", email)
	log.Infof("  Path       : %s", xpath)
	log.Infof("  Target     : %s", target)
	log.Infof("  SNI        : %v", serverNames)
	log.Infof("  ShortIDs   : %v", shortIDs)
	log.Infof("  PrivateKey : %s", privB64)
	log.Infof("  PublicKey  : %s", pubB64)
	log.Info("Client share link (copy into your VLESS client):")
	log.Infof("  %s", shareURL)
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS+XHTTP+Reality test server")
}

// splitCSV splits a comma-separated string into a trimmed slice of
// entries. An empty input yields a single empty string, which matches
// Reality's notion of "allow empty short ID".
func splitCSV(s string) []string {
	if s == "" {
		return []string{""}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// TestManualServeV2 boots a real VLESS inbound with v2 decryption enabled,
// so third-party Xray-core clients can connect to it for end-to-end testing
// of the ML-KEM-768 + X25519 + AEAD tunnel.
//
// It is SKIPPED by default because it blocks indefinitely. To enable,
// export VLESS_MANUAL_TEST=1 and run it explicitly:
//
//	VLESS_MANUAL_TEST=1 go test -v -run TestManualServeV2 -timeout 0 ./vless
//
// Optional environment variables:
//
//	VLESS_TEST_PORT        - listen port (default 10090)
//	VLESS_TEST_UUID        - user UUID   (default b831381d-6324-4d53-ad4f-8cda48b30811)
//	VLESS_TEST_EMAIL       - user email  (default tester@vgate.local)
//	VLESS_TEST_HOST        - host used in the printed share link (default 127.0.0.1)
//	VLESS_TEST_NFS_PRIVKEY - base64url X25519 private key for the NFS key (default: generated on the fly)
//
// Once running, point an Xray-core client (v25+) at the share link printed
// to the log. The share link uses `encryption=v2` so the client wraps the
// VLESS connection in the v2 AEAD tunnel.
//
//	vless://<uuid>@<host>:<port>?type=tcp&security=none&encryption=v2&pbk=<nfs_pubkey>#vgate-v2-test
//
// The client side needs the NFS *public* key (pbk), derived from the NFS
// private key. The server prints both. The client also needs the matching
// `decryption` field set in its outbound VLESS account config (the same
// base64url string as the server's `Decryption` field).
func TestManualServeV2(t *testing.T) {
	if os.Getenv("VLESS_MANUAL_TEST") != "1" {
		t.Skip("Skipping manual VLESS v2 server test. Set VLESS_MANUAL_TEST=1 to enable.")
	}

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	port := 10090
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

	// NFS private key (X25519, 32 bytes). If not supplied, generate one
	// on the fly and print the matching public key.
	privB64 := os.Getenv("VLESS_TEST_NFS_PRIVKEY")
	var pubB64 string
	if privB64 == "" {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate x25519 nfs key: %v", err)
		}
		privB64 = base64.RawURLEncoding.EncodeToString(key.Bytes())
		pubB64 = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	} else {
		raw, err := base64.RawURLEncoding.DecodeString(privB64)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_NFS_PRIVKEY %q: %v", privB64, err)
		}
		if len(raw) != 32 {
			t.Fatalf("invalid VLESS_TEST_NFS_PRIVKEY: must be 32 bytes (43 base64url chars), got %d", len(raw))
		}
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatalf("invalid VLESS_TEST_NFS_PRIVKEY: %v", err)
		}
		pubB64 = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}

	server := NewServer()
	server.UpdateConfig(&model.Config{
		Port: port,
		Stream: model.Stream{
			Network:  "tcp",
			Security: "none",
		},
		VLESS: model.VLESS{
			Decryption: privB64,
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
		"?type=tcp&security=none&encryption=v2&pbk=" + pubB64 + "#vgate-v2-test"

	log.Info("=====================================================================")
	log.Info("VLESS v2 (decryption) test server is running.")
	log.Infof("  Listen        : 0.0.0.0:%d", port)
	log.Infof("  UUID          : %s", uuid)
	log.Infof("  Email         : %s", email)
	log.Infof("  NFS PrivateKey: %s", privB64)
	log.Infof("  NFS PublicKey : %s", pubB64)
	log.Info("Client share link (copy into Xray-core v25+ client):")
	log.Infof("  %s", shareURL)
	log.Infof("  (client outbound account also needs: \"encryption\": \"%s\")", privB64)
	log.Info("Press Ctrl+C to stop.")
	log.Info("=====================================================================")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down VLESS v2 test server")
}
