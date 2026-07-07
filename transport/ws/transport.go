// Package ws is a thin adapter that delegates to xray-core's
// transport/internet/websocket leaf package. It replaces the former
// ~460-line from-scratch RFC 6455 implementation with a ~90-line
// adapter that calls websocket.ListenWS directly.
//
// Gains over the old port: permessage-deflate, early-data (0-RTT),
// and full protocol parity with real xray clients — via gorilla/websocket
// (already an indirect dep).
//
// Like xhttp, this does NOT call security.Wrap — websocket.ListenWS
// applies TLS/Reality internally via MemoryStreamConfig.SecuritySettings.
package ws

import (
	"context"
	"errors"
	"net"

	"github.com/vgate-project/vgate-server/transport"
	"github.com/vgate-project/vgate-server/transport/xraybridge"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

const protocolName = "ws"

type Transport struct{}

func init()                     { transport.Register(&Transport{}) }
func (*Transport) Name() string { return protocolName }

func (*Transport) Listen(ctx context.Context, addr string, cfg transport.StreamConfig) (net.Listener, error) {
	address, port, err := xraybridge.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	var wsCfg websocket.Config
	if err := xraybridge.DecodeSettings(cfg.Settings, &wsCfg); err != nil {
		return nil, err
	}

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &wsCfg,
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
		return nil, errors.New("ws: unsupported security " + cfg.Security)
	}

	ln := xraybridge.NewChanListener()
	xrayLn, err := websocket.ListenWS(ctx, address, port, streamSettings, ln.AddConn)
	if err != nil {
		return nil, err
	}
	ln.Inner = xrayLn
	ln.Addr_ = xrayLn.Addr()
	return ln, nil
}
