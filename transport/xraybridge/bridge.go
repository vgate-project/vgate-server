// Package xraybridge provides shared helpers for vgate transport adapters
// that delegate to xray-core's transport/internet leaf packages
// (splithttp, websocket, etc.). It bridges vgate's Transport interface
// to xray-core's ListenXH/ListenWS entry points.
package xraybridge

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vgate-project/vgate-server/transport/security"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ChanListener adapts xray-core's callback-based conn delivery to net.Listener.
type ChanListener struct {
	Ch     chan net.Conn
	Closed chan struct{}
	Inner  internet.Listener
	Addr_  net.Addr
	Once   sync.Once
}

func NewChanListener() *ChanListener {
	return &ChanListener{
		Ch:     make(chan net.Conn, 32),
		Closed: make(chan struct{}),
	}
}

// AddConn is the callback to pass as internet.ConnHandler to ListenXH/ListenWS.
func (l *ChanListener) AddConn(c stat.Connection) {
	select {
	case l.Ch <- c:
	case <-l.Closed:
		c.Close()
	}
}

func (l *ChanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.Ch:
		return c, nil
	case <-l.Closed:
		return nil, errors.New("xraybridge: listener closed")
	}
}

func (l *ChanListener) Close() error {
	l.Once.Do(func() {
		close(l.Closed)
		if l.Inner != nil {
			l.Inner.Close()
		}
	})
	return nil
}

func (l *ChanListener) Addr() net.Addr { return l.Addr_ }

// ParseXrayAddress converts a host string to xnet.Address, handling empty
// host (listen on all interfaces) and "localhost" — xray's ListenXH/ListenWS
// require an IPAddress for TCP (address.IP() panics on domains).
func ParseXrayAddress(host string) xnet.Address {
	address := xnet.ParseAddress(host)
	if address.Family() == xnet.AddressFamilyDomain {
		switch host {
		case "localhost":
			address = xnet.LocalHostIP
		default:
			address = xnet.AnyIP
		}
	}
	return address
}

// ParseAddrPort splits "host:port" into xnet.Address + xnet.Port.
func ParseAddrPort(addr string) (xnet.Address, xnet.Port, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	return ParseXrayAddress(host), xnet.Port(port), nil
}

// SnakeToCamel converts snake_case to camelCase (e.g. "x_padding_bytes" →
// "xPaddingBytes"). protojson expects camelCase field names.
func SnakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// DecodeSettings marshals a settings map (snake_case keys) to JSON with
// camelCase keys, then unmarshals into a protobuf message via protojson.
// DiscardUnknown matches vgate's behavior of silently ignoring unknown keys.
func DecodeSettings(settings map[string]any, msg proto.Message) error {
	if len(settings) == 0 {
		return nil
	}
	camel := make(map[string]any, len(settings))
	for k, v := range settings {
		camel[SnakeToCamel(k)] = v
	}
	jsonBytes, err := json.Marshal(camel)
	if err != nil {
		return err
	}
	return (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(jsonBytes, msg)
}

// --- Security config builders ---

var tlsVersionToString = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

// BuildXrayTLSConfig converts vgate's TLS security settings into xray's
// *transport/internet/tls.Config protobuf type.
func BuildXrayTLSConfig(raw map[string]interface{}) (*xraytls.Config, error) {
	vgateCfg, err := security.DecodeTLSConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("xraybridge: decode tls config: %w", err)
	}

	var certPEM, keyPEM []byte
	switch {
	case vgateCfg.CertPEM != "" && vgateCfg.KeyPEM != "":
		certPEM = []byte(vgateCfg.CertPEM)
		keyPEM = []byte(vgateCfg.KeyPEM)
	case vgateCfg.CertFile != "" && vgateCfg.KeyFile != "":
		certPEM, err = os.ReadFile(vgateCfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("xraybridge: read cert file: %w", err)
		}
		keyPEM, err = os.ReadFile(vgateCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("xraybridge: read key file: %w", err)
		}
	default:
		return nil, fmt.Errorf("xraybridge: no certificate/key provided")
	}

	xrayCfg := &xraytls.Config{
		ServerName: vgateCfg.ServerName,
		Certificate: []*xraytls.Certificate{{
			Certificate: certPEM,
			Key:         keyPEM,
		}},
		RejectUnknownSni: vgateCfg.RejectUnknownSNI,
	}

	if len(vgateCfg.ALPN) > 0 {
		xrayCfg.NextProtocol = vgateCfg.ALPN
	} else {
		xrayCfg.NextProtocol = []string{"h2", "http/1.1"}
	}

	if vgateCfg.MinVersion != 0 {
		if s, ok := tlsVersionToString[vgateCfg.MinVersion]; ok {
			xrayCfg.MinVersion = s
		}
	}
	if vgateCfg.MaxVersion != 0 {
		if s, ok := tlsVersionToString[vgateCfg.MaxVersion]; ok {
			xrayCfg.MaxVersion = s
		}
	}

	return xrayCfg, nil
}

// BuildXrayRealityConfig converts vgate's Reality security settings into
// xray's *transport/internet/reality.Config protobuf type.
func BuildXrayRealityConfig(raw map[string]interface{}) (*xrayreality.Config, error) {
	vgateCfg, err := security.DecodeRealityConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("xraybridge: decode reality config: %w", err)
	}

	xrayCfg := &xrayreality.Config{
		Show:         vgateCfg.Show,
		Dest:         vgateCfg.Target,
		Type:         "tcp",
		Xver:         uint64(vgateCfg.Xver),
		PrivateKey:   vgateCfg.PrivateKey,
		MinClientVer: vgateCfg.MinClientVer,
		MaxClientVer: vgateCfg.MaxClientVer,
		MaxTimeDiff:  uint64(vgateCfg.MaxTimeDiff / time.Millisecond),
	}

	for name := range vgateCfg.ServerNames {
		xrayCfg.ServerNames = append(xrayCfg.ServerNames, name)
	}
	if len(xrayCfg.ServerNames) == 0 {
		// This should not happen if DecodeRealityConfig validated it,
		// but we keep it for safety.
	}
	for sid := range vgateCfg.ShortIds {
		xrayCfg.ShortIds = append(xrayCfg.ShortIds, sid[:])
	}

	return xrayCfg, nil
}
