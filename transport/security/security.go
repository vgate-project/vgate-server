package security

import (
	"fmt"
	"net"
)

// Wrap applies the security layer selected by security to ln and returns the
// wrapped listener. It dispatches to WrapTLS / WrapReality based on the
// security name. An empty string or "none" returns ln unchanged.
//
// This is the single entry point transports call from their Listen(): each
// transport binds its raw listener, calls Wrap to apply the security layer,
// and then serves its own protocol on top of the secured listener — mirroring
// Xray-core's inlined wrap pattern in splithttp/hub.go and grpc/hub.go.
func Wrap(ln net.Listener, security string, settings map[string]interface{}) (net.Listener, error) {
	switch security {
	case "", "none":
		return ln, nil
	case "tls":
		return WrapTLS(ln, settings)
	case "reality":
		return WrapReality(ln, settings)
	default:
		return nil, fmt.Errorf("security: unsupported security %q (must be \"none\", \"tls\", or \"reality\")", security)
	}
}
