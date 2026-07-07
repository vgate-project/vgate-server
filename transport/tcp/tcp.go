// Package tcp implements the "tcp" transport: a plain, unmodified TCP stream.
// It is the default transport used when StreamConfig.Network is empty.
package tcp

import (
	"context"
	"net"

	"github.com/vgate-project/vgate-server/transport"
	"github.com/vgate-project/vgate-server/transport/security"
)

func init() {
	transport.Register(&Transport{})
}

// Transport is the raw TCP implementation. It has no additional settings.
type Transport struct{}

// Name reports the transport name used in configuration.
func (t *Transport) Name() string { return "tcp" }

// Listen binds a plain TCP listener on addr and wraps it with the configured
// security layer (none/tls/reality). Any provided transport settings are
// ignored since raw TCP is parameterless.
func (t *Transport) Listen(_ context.Context, addr string, cfg transport.StreamConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return security.Wrap(ln, cfg.Security, cfg.SecuritySettings)
}
