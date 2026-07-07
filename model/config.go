package model

// Config represents the configuration pulled from the frontend
type Config struct {
	Port   int    `json:"port"`
	Stream Stream `json:"stream"`
	VLESS  VLESS  `json:"vless,omitempty"`
}

// VLESS holds VLESS-protocol-specific inbound settings, independent of the
// transport (Stream) layer. Currently this is the v2 decryption configuration
// that wraps the connection in an AEAD tunnel before the VLESS v0 header is
// parsed.
type VLESS struct {
	// Decryption is a "."-separated list of base64url-encoded NFS server
	// private keys (X25519 32-byte private key, or ML-KEM-768 64-byte
	// decapsulation key seed). An empty string or "none" disables v2
	// decryption (the inbound speaks plaintext VLESS v0).
	Decryption string `json:"decryption,omitempty"`

	// XorMode controls XOR-stream obfuscation of the KEM ciphertexts and
	// (optionally) the whole connection. 0 = off, 1 = mask KEM ciphertexts,
	// 2 = also wrap the connection in XorConn.
	XorMode uint32 `json:"xor_mode,omitempty"`

	// SecondsFrom / SecondsTo define the 0-RTT session ticket lifetime
	// window in seconds. Both zero disables 0-RTT (1-RTT only).
	SecondsFrom int64 `json:"seconds_from,omitempty"`
	SecondsTo   int64 `json:"seconds_to,omitempty"`

	// Padding is a "."-separated padding spec ("pct-min-max" triples
	// alternating length-specs and gap-specs). An empty string uses the
	// defaults ({100,111,1111}/{50,0,3333} lengths, {75,0,111} gaps).
	Padding string `json:"padding,omitempty"`

	// Flow activates VLESS flow-controlled features like xtls-rprx-vision.
	Flow string `json:"flow,omitempty"`
}
