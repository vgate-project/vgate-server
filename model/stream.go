package model

// Stream mirrors xray-core's streamSettings block: it selects the
// transport layer (raw TCP, WebSocket, ...), the security layer (TLS,
// Reality, none), and carries transport/security-specific parameters.
//
// The security layer wraps the raw transport listener. For example,
// Security="tls" + Network="ws" means: first create a WS listener,
// then wrap it with TLS — i.e. TLS over WebSocket.
type Stream struct {
	Network       string         `json:"network,omitempty"`
	Settings      map[string]any `json:"settings,omitempty"`
	Security      string         `json:"security"` // Must be "none", "tls", or "reality"; no default — explicit choice required
	TLSConfig     *TLSConfig     `json:"tls_settings,omitempty"`
	RealityConfig *RealityConfig `json:"reality_settings,omitempty"`
}

// TLSConfig holds server-side (inbound) TLS configuration.
// Certificate/key can be provided as file paths (CertFile/KeyFile) or
// inline PEM text (CertPEM/KeyPEM).
type TLSConfig struct {
	ServerName       string   `json:"server_name,omitempty"`
	CertFile         string   `json:"cert_file,omitempty"`
	KeyFile          string   `json:"key_file,omitempty"`
	CertPEM          string   `json:"cert_pem,omitempty"`
	KeyPEM           string   `json:"key_pem,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	MinVersion       string   `json:"min_version,omitempty"` // "1.0", "1.1", "1.2", "1.3"
	MaxVersion       string   `json:"max_version,omitempty"`
	RejectUnknownSNI bool     `json:"reject_unknown_sni,omitempty"`
}

// RealityConfig holds server-side (inbound) Reality configuration.
// Reality is a TLS variant that masquerades as a real website — only
// authenticated clients get through; unauthenticated probes are
// silently forwarded to the target.
type RealityConfig struct {
	Show         bool     `json:"show,omitempty"`
	Target       string   `json:"target,omitempty"`      // Fallback destination (e.g. "example.com:443"); required
	Xver         int      `json:"xver,omitempty"`        // PROXY protocol version (0, 1, 2)
	ServerName   string   `json:"server_name,omitempty"` // Allowed SNI; required
	PrivateKey   string   `json:"private_key,omitempty"` // X25519 private key (base64url, no padding); required
	ShortIds     []string `json:"short_ids,omitempty"`   // Allowed short IDs (hex strings); can include ""
	MinClientVer string   `json:"min_client_ver,omitempty"`
	MaxClientVer string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff  int      `json:"max_time_diff,omitempty"` // Milliseconds
}
