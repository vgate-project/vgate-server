package security

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/xtls/reality"
)

// RealityConfig holds typed Reality server configuration decoded from
// the opaque SecuritySettings map in transport.StreamConfig.
type RealityConfig struct {
	Show         bool
	Target       string
	Xver         byte
	ServerNames  map[string]bool
	PrivateKey   []byte
	ShortIds     map[[8]byte]bool
	MinClientVer []byte
	MaxClientVer []byte
	MaxTimeDiff  time.Duration
}

// DecodeRealityConfig extracts typed Reality configuration from the
// opaque security settings map.
func DecodeRealityConfig(raw map[string]interface{}) (*RealityConfig, error) {
	if raw == nil {
		return nil, fmt.Errorf("security/reality: no settings provided")
	}
	cfg := &RealityConfig{
		ServerNames: make(map[string]bool),
		ShortIds:    make(map[[8]byte]bool),
	}

	if v, ok := raw["show"].(bool); ok {
		cfg.Show = v
	}
	if v, ok := raw["target"].(string); ok {
		cfg.Target = v
	} else {
		return nil, fmt.Errorf("security/reality: target (fallback destination) is required")
	}

	// Xver: PROXY protocol version (0, 1, 2)
	if v, ok := raw["xver"]; ok {
		switch tv := v.(type) {
		case int:
			cfg.Xver = byte(tv)
		case float64:
			cfg.Xver = byte(tv)
		default:
			return nil, fmt.Errorf("security/reality: xver must be an integer")
		}
	}

	// ServerName: allowed SNI (required)
	if v, ok := raw["server_name"].(string); ok {
		cfg.ServerNames[v] = true
	}
	if len(cfg.ServerNames) == 0 {
		return nil, fmt.Errorf("security/reality: server_name is required")
	}

	// PrivateKey: X25519 private key in base64url (no padding), matching
	// the format emitted by `xray x25519` (required)
	if v, ok := raw["private_key"].(string); ok {
		key, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("security/reality: failed to decode private_key base64: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("security/reality: private_key must be 32 bytes (43 base64url chars)")
		}
		cfg.PrivateKey = key
	} else {
		return nil, fmt.Errorf("security/reality: private_key is required")
	}

	// ShortIds: allowed short IDs in hex (required, can include "" for empty)
	if v, ok := raw["short_ids"].([]interface{}); ok {
		for _, item := range v {
			s, ok2 := item.(string)
			if !ok2 {
				continue
			}
			if s == "" {
				cfg.ShortIds[[8]byte{}] = true
				continue
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("security/reality: failed to decode short_id hex %q: %w", s, err)
			}
			if len(b) > 8 {
				return nil, fmt.Errorf("security/reality: short_id must be at most 8 bytes (16 hex chars)")
			}
			var sid [8]byte
			copy(sid[:], b)
			cfg.ShortIds[sid] = true
		}
	}
	if len(cfg.ShortIds) == 0 {
		// Default to allowing empty short ID
		cfg.ShortIds[[8]byte{}] = true
	}

	// MinClientVer / MaxClientVer: version strings like "1.8.0"
	if v, ok := raw["min_client_ver"].(string); ok && v != "" {
		cfg.MinClientVer = parseClientVer(v)
	}
	if v, ok := raw["max_client_ver"].(string); ok && v != "" {
		cfg.MaxClientVer = parseClientVer(v)
	}

	// MaxTimeDiff: milliseconds
	if v, ok := raw["max_time_diff"]; ok {
		switch tv := v.(type) {
		case int:
			cfg.MaxTimeDiff = time.Duration(tv) * time.Millisecond
		case float64:
			cfg.MaxTimeDiff = time.Duration(tv) * time.Millisecond
		}
	}

	return cfg, nil
}

// parseClientVer converts a version string "x.y.z" to a byte slice
// suitable for reality.Config.MinClientVer/MaxClientVer.
func parseClientVer(v string) []byte {
	// Simple parsing: split by '.', convert each part to byte.
	// E.g., "1.8.24" → []byte{1, 8, 24}
	parts := make([]byte, 0, 3)
	for i := 0; i < len(v); i++ {
		start := i
		for i < len(v) && v[i] != '.' {
			i++
		}
		n := 0
		for j := start; j < i; j++ {
			n = n*10 + int(v[j]-'0')
		}
		parts = append(parts, byte(n))
	}
	return parts
}

// BuildRealityConfig converts our RealityConfig into a reality.Config
// ready for use with reality.NewListener.
func BuildRealityConfig(cfg *RealityConfig) (*reality.Config, error) {
	// DialContext is used by the reality server to open a connection to the
	// fallback target (cfg.Target) whenever a probe/unauthenticated client is
	// detected. It must be non-nil; otherwise reality will nil-panic when it
	// tries to forward traffic to the target server.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	rc := &reality.Config{
		Show:         cfg.Show,
		Type:         "tcp",
		Dest:         cfg.Target,
		Xver:         cfg.Xver,
		ServerNames:  cfg.ServerNames,
		PrivateKey:   cfg.PrivateKey,
		ShortIds:     cfg.ShortIds,
		MinClientVer: cfg.MinClientVer,
		MaxClientVer: cfg.MaxClientVer,
		MaxTimeDiff:  cfg.MaxTimeDiff,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		SessionTicketsDisabled: true,
	}
	return rc, nil
}

// WrapReality wraps a raw net.Listener with Reality. Only authenticated
// connections emerge from Accept(); unauthenticated ones are silently
// forwarded to the target server (anti-probing).
func WrapReality(ln net.Listener, raw map[string]interface{}) (net.Listener, error) {
	cfg, err := DecodeRealityConfig(raw)
	if err != nil {
		return nil, err
	}
	rc, err := BuildRealityConfig(cfg)
	if err != nil {
		return nil, err
	}
	return reality.NewListener(ln, rc), nil
}
