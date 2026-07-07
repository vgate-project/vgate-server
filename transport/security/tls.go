// Package security implements the TLS and Reality security layers that
// wrap a raw transport listener. It mirrors xray-core's approach where
// security is independent of transport — you can have TLS over TCP,
// TLS over WebSocket, Reality over TCP, etc.
package security

import (
	"crypto/tls"
	"fmt"
	"net"
)

// TLSConfig holds typed TLS server configuration decoded from the
// opaque SecuritySettings map in transport.StreamConfig.
type TLSConfig struct {
	ServerName       string
	CertFile         string
	KeyFile          string
	CertPEM          string
	KeyPEM           string
	ALPN             []string
	MinVersion       uint16
	MaxVersion       uint16
	RejectUnknownSNI bool
}

// tlsVersionMap maps version strings (as used in JSON config) to
// crypto/tls version constants.
var tlsVersionMap = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

// DecodeTLSConfig extracts typed TLS configuration from the opaque
// security settings map. It handles type coercion for fields coming
// from JSON deserialization.
func DecodeTLSConfig(raw map[string]interface{}) (*TLSConfig, error) {
	if raw == nil {
		return nil, fmt.Errorf("security/tls: no settings provided")
	}
	cfg := &TLSConfig{}

	if v, ok := raw["server_name"].(string); ok {
		cfg.ServerName = v
	}
	if v, ok := raw["cert_file"].(string); ok {
		cfg.CertFile = v
	}
	if v, ok := raw["key_file"].(string); ok {
		cfg.KeyFile = v
	}
	if v, ok := raw["cert_pem"].(string); ok {
		cfg.CertPEM = v
	}
	if v, ok := raw["key_pem"].(string); ok {
		cfg.KeyPEM = v
	}
	if v, ok := raw["alpn"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				cfg.ALPN = append(cfg.ALPN, s)
			}
		}
	}
	if v, ok := raw["min_version"].(string); ok {
		if ver, ok2 := tlsVersionMap[v]; ok2 {
			cfg.MinVersion = ver
		} else {
			return nil, fmt.Errorf("security/tls: unknown min_version %q", v)
		}
	}
	if v, ok := raw["max_version"].(string); ok {
		if ver, ok2 := tlsVersionMap[v]; ok2 {
			cfg.MaxVersion = ver
		} else {
			return nil, fmt.Errorf("security/tls: unknown max_version %q", v)
		}
	}
	if v, ok := raw["reject_unknown_sni"].(bool); ok {
		cfg.RejectUnknownSNI = v
	}

	return cfg, nil
}

// BuildTLSConfig converts our TLSConfig into a crypto/tls.Config ready
// for use with tls.NewListener.
func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tc := &tls.Config{
		ServerName: cfg.ServerName,
		NextProtos: cfg.ALPN,
		MinVersion: cfg.MinVersion,
		MaxVersion: cfg.MaxVersion,
	}

	// Load certificate + key (file paths or inline PEM).
	var cert tls.Certificate
	var err error
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	} else if cfg.CertPEM != "" && cfg.KeyPEM != "" {
		cert, err = tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
	} else {
		return nil, fmt.Errorf("security/tls: no certificate/key provided (need cert_file+key_file or cert_pem+key_pem)")
	}
	if err != nil {
		return nil, fmt.Errorf("security/tls: failed to load certificate: %w", err)
	}
	tc.Certificates = []tls.Certificate{cert}

	// If no MinVersion set, enforce TLS 1.2 as minimum (security best practice).
	if cfg.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS12
	}

	// Default ALPN to ["h2", "http/1.1"] when the user did not specify one,
	// matching Xray-core's tls/config.go. This lets HTTP-based transports
	// (xhttp) negotiate HTTP/2 with clients that offer it.
	if len(tc.NextProtos) == 0 {
		tc.NextProtos = []string{"h2", "http/1.1"}
	}

	if cfg.RejectUnknownSNI {
		expected := cfg.ServerName
		tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if expected != "" && hello.ServerName != expected {
				return nil, fmt.Errorf("security/tls: rejected unknown SNI %q", hello.ServerName)
			}
			return nil, nil
		}
	}

	return tc, nil
}

// WrapTLS wraps a raw net.Listener with TLS, returning a listener that
// yields tls.Conn connections after the TLS handshake completes.
func WrapTLS(ln net.Listener, raw map[string]interface{}) (net.Listener, error) {
	cfg, err := DecodeTLSConfig(raw)
	if err != nil {
		return nil, err
	}
	tc, err := BuildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, tc), nil
}
