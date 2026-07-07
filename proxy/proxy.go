// Package proxy defines the abstract interface for proxy protocol inbound
// servers. Each protocol (VLESS, Trojan, Shadowsocks, ...) implements
// Inbound, and the caller (cmd/root.go) works against this interface
// rather than a concrete type.
package proxy

import "github.com/vgate-project/vgate-server/model"

// Inbound is the abstract interface for a proxy protocol inbound server.
// Each protocol (VLESS, Trojan, Shadowsocks, ...) implements this interface.
// The caller (cmd/root.go) works against this interface, not a concrete type.
type Inbound interface {
	// Start blocks forever, accepting connections. Re-binds when config
	// changes via UpdateConfig.
	Start()

	// UpdateConfig applies a new configuration (hot-reload). If the port
	// or transport changes, the listener is re-bound.
	UpdateConfig(cfg *model.Config)

	// UpdateUsers replaces the user set. Connections of removed users
	// are closed.
	UpdateUsers(users []model.User)

	// GetAndResetTraffic atomically reads and resets per-user traffic
	// counters, returning incremental deltas since the last call.
	GetAndResetTraffic() []model.UserTraffic
}
