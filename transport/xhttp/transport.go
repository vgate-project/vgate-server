// Package xhttp is a thin adapter that delegates to xray-core's
// transport/internet/splithttp leaf package. It replaces the former
// ~1900-line stdlib port with a ~100-line adapter that calls
// splithttp.ListenXH directly.
//
// Unlike tcp/ws transports (which call security.Wrap inside Listen),
// xhttp hands the security config to splithttp via MemoryStreamConfig —
// splithttp applies TLS/Reality internally (hub.go:542-549).
package xhttp

import (
	"context"
	"errors"
	"net"

	"github.com/vgate-project/vgate-server/transport"
	"github.com/vgate-project/vgate-server/transport/xraybridge"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

const protocolName = "xhttp"

type Transport struct{}

func init()                     { transport.Register(&Transport{}) }
func (*Transport) Name() string { return protocolName }

func (*Transport) Listen(ctx context.Context, addr string, cfg transport.StreamConfig) (net.Listener, error) {
	address, port, err := xraybridge.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	var splithttpCfg splithttp.Config
	if err := xraybridge.DecodeSettings(cfg.Settings, &splithttpCfg); err != nil {
		return nil, err
	}

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &splithttpCfg,
	}

	switch cfg.Security {
	case "", "none":
	case "tls":
		tlsCfg, err := xraybridge.BuildXrayTLSConfig(cfg.SecuritySettings)
		if err != nil {
			return nil, err
		}
		streamSettings.SecurityType = "tls"
		streamSettings.SecuritySettings = tlsCfg
	case "reality":
		realityCfg, err := xraybridge.BuildXrayRealityConfig(cfg.SecuritySettings)
		if err != nil {
			return nil, err
		}
		streamSettings.SecurityType = "reality"
		streamSettings.SecuritySettings = realityCfg
	default:
		return nil, errors.New("xhttp: unsupported security " + cfg.Security)
	}

	ln := xraybridge.NewChanListener()
	xrayLn, err := splithttp.ListenXH(ctx, address, port, streamSettings, ln.AddConn)
	if err != nil {
		return nil, err
	}
	ln.Inner = xrayLn
	ln.Addr_ = xrayLn.Addr()
	return ln, nil
}
