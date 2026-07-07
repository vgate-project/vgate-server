// Package transport provides a pluggable stream-transport abstraction for
// the VLESS inbound, modeled after xray-core's transport/internet layer.
//
// A Transport is responsible for turning a raw address (host:port) into a
// stream-oriented net.Listener that yields net.Conn instances. VLESS itself
// only speaks the application-level handshake and does not care whether the
// underlying bytes travel over raw TCP, WebSocket, or any future transport
// (gRPC, mKCP, QUIC, HTTPUpgrade, ...).
//
// Transports register themselves in the global registry via Register() from
// their package init(); users retrieve them by name via Get() or, more
// commonly, use the convenience Listen() function which selects the
// transport based on a StreamConfig.
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// StreamConfig describes which transport and security to use, plus
// their respective settings. It is intentionally opaque so that new
// transports and security types can be added without touching this
// file.
type StreamConfig struct {
	// Network selects the transport implementation ("tcp", "ws", ...). An
	// empty value defaults to "tcp".
	Network string `json:"network" mapstructure:"network" yaml:"network"`

	// Settings is a transport-specific bag of parameters. Each transport is
	// responsible for decoding it into its own typed configuration.
	Settings map[string]interface{} `json:"settings,omitempty" mapstructure:"settings" yaml:"settings"`

	// Security selects the security layer ("none", "tls", "reality").
	// An empty value is treated as "none". Each transport applies this
	// layer to its raw listener inside Listen() via security.Wrap, so the
	// resulting connections are already secured.
	Security string `json:"security" mapstructure:"security" yaml:"security"`

	// SecuritySettings is a security-specific bag of parameters. Each
	// security implementation is responsible for decoding it into its own
	// typed configuration.
	SecuritySettings map[string]interface{} `json:"security_settings,omitempty" mapstructure:"security_settings" yaml:"security_settings"`
}

// Transport is the abstract interface each transport implementation must
// satisfy. Implementations must be safe for concurrent use.
//
// A Transport is responsible for turning a raw address (host:port) plus a
// StreamConfig into a stream-oriented net.Listener that yields net.Conn
// instances. This includes applying the security layer (none/tls/reality):
// each transport calls security.Wrap on its raw listener from inside Listen,
// so transports whose protocol sits above the security layer (HTTP-based
// transports like xhttp and ws) can serve on the secured listener, while
// raw-stream transports (tcp) simply hand back the wrapped listener. This
// mirrors Xray-core's pattern where each transport inlines the security wrap
// at its listener-construction site.
type Transport interface {
	// Name returns the transport's stable identifier used in StreamConfig
	// (e.g. "tcp", "ws").
	Name() string

	// Listen binds on addr, applies cfg.Security to the raw listener, and
	// returns a net.Listener that yields fully established stream
	// connections (post-handshake for framed transports, post-decrypt for
	// tls/reality). The returned listener MUST honor Close() cleanly.
	Listen(ctx context.Context, addr string, cfg StreamConfig) (net.Listener, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Transport{}
)

// Register adds t to the global transport registry. If a transport with the
// same name is already registered it is replaced. This is safe to call from
// package init().
func Register(t Transport) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[t.Name()] = t
}

// Get returns the transport registered under name.
func Get(name string) (Transport, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("transport: unknown network %q (is the transport package imported?)", name)
	}
	return t, nil
}

// Available returns the list of registered transport names. Order is not
// guaranteed and is intended for logging/diagnostics only.
func Available() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}

// Listen resolves the transport referenced by cfg (defaulting to "tcp"),
// starts listening on addr, and returns the resulting net.Listener. The
// selected transport is responsible for applying cfg.Security (none/tls/
// reality) inside its own Listen implementation via security.Wrap, so the
// returned listener already yields secured connections. Security must be
// "none", "tls", or "reality" (an empty value is treated as "none").
func Listen(ctx context.Context, cfg StreamConfig, addr string) (net.Listener, error) {
	name := cfg.Network
	if name == "" {
		name = "tcp"
	}
	t, err := Get(name)
	if err != nil {
		return nil, err
	}
	return t.Listen(ctx, addr, cfg)
}
