package vless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/vless/encryption"

	"github.com/vgate-project/vgate-server/model"
	"github.com/vgate-project/vgate-server/proxy"
	"github.com/vgate-project/vgate-server/transport"

	log "github.com/sirupsen/logrus"
)

// Compile-time assertion: *Server implements proxy.Inbound.
var _ proxy.Inbound = (*Server)(nil)

// Server handles VLESS inbound connections.
//
// The implementation is split across several files for clarity:
//   - server.go     : core struct, lifecycle (Start) and config hot-reload
//   - user.go       : user set management and per-user connection tracking
//   - traffic.go    : per-user traffic counters and delta reporting
//   - handler.go    : per-connection VLESS handshake and TCP forwarder
//   - udp.go        : UDP-over-TCP relay
//   - bootstrap.go  : anonymous imports registering built-in transports
//
// The listener itself is provided by the `transport` sub-package, which
// abstracts over the concrete network stack (raw TCP, WebSocket, ...).
// This mirrors xray-core's transport/internet layer.
type Server struct {
	mu     sync.RWMutex
	users  map[[16]byte]model.User
	port   int
	stream model.Stream
	vless  model.VLESS
	ln     net.Listener

	// decryption is the VLESS v2 server-side decryption instance. nil means
	// v2 decryption is disabled (the inbound speaks plaintext VLESS v0).
	// When non-nil, handleConnection wraps each accepted conn in a
	// *encryption.CommonConn via Handshake before parsing the VLESS header.
	decryption *encryption.ServerInstance

	// enableMux toggles support for the VLESS CommandMux (Mux.Cool)
	// multiplexing command. Defaults to true; when false, inbound Mux
	// connections are rejected (backward-compatible single-target behavior).
	enableMux bool

	// Connection management: active connections indexed by user UUID.
	userConns map[[16]byte]map[net.Conn]struct{}
	// Traffic statistics: incremental byte counters per user UUID.
	userTraffic map[[16]byte]*trafficStat

	// Speed limiting (token buckets, bytes/sec; nil = unlimited). The global
	// buckets cap the node's aggregate throughput across all users; the
	// per-user buckets cap each user's throughput. Effective per-user rate is
	// min(global, user).
	globalULimiter *rateBucket
	globalDLimiter *rateBucket
	userULimiters  map[[16]byte]*rateBucket
	userDLimiters  map[[16]byte]*rateBucket
}

func NewServer() *Server {
	return &Server{
		users:         make(map[[16]byte]model.User),
		userConns:     make(map[[16]byte]map[net.Conn]struct{}),
		userTraffic:   make(map[[16]byte]*trafficStat),
		userULimiters: make(map[[16]byte]*rateBucket),
		userDLimiters: make(map[[16]byte]*rateBucket),
		enableMux:     true,
	}
}

// UpdateConfig applies a new server configuration (hot-reload). If either
// the listening port OR the stream (transport) settings change, the
// current listener is closed, which causes Start's inner Accept loop to
// break and rebind with the new configuration. If the VLESS decryption
// settings change, the ServerInstance is rebuilt (no listener rebind needed
// — the wrap happens per-connection in handleConnection).
func (s *Server) UpdateConfig(cfg *model.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	if s.port != cfg.Port {
		log.Infof("VLESS server port updated from %d to %d", s.port, cfg.Port)
		s.port = cfg.Port
		changed = true
	}
	if !streamEqual(s.stream, cfg.Stream) {
		log.Infof("VLESS transport updated from %s to %s", transportName(s.stream), transportName(cfg.Stream))
		// Defensive: reality SNI must not be empty.
		if cfg.Stream.Security == "reality" {
			if cfg.Stream.RealityConfig == nil || cfg.Stream.RealityConfig.ServerName == "" {
				log.Errorf("Invalid reality config: ServerName is empty")
			}
		}
		s.stream = cfg.Stream
		changed = true
	}
	if !vlessEqual(s.vless, cfg.VLESS) {
		log.Infof("VLESS decryption updated: %s", cfg.VLESS.Decryption)
		// Defensive: if security is none, flow must be empty.
		if cfg.Stream.Security == "none" {
			cfg.VLESS.Flow = ""
		}
		// Defensive: flow can only be used with tcp network.
		if cfg.VLESS.Flow != "" && cfg.Stream.Network != "" && cfg.Stream.Network != "tcp" {
			log.Errorf("Invalid config: flow %q is not supported on network %q, disabling flow", cfg.VLESS.Flow, cfg.Stream.Network)
			cfg.VLESS.Flow = ""
		}
		s.rebuildDecryptionLocked(cfg.VLESS)
		s.vless = cfg.VLESS
	}

	// Rebuild node-global speed-limit buckets (0 = unlimited → nil bucket).
	s.globalULimiter = newRateBucket(cfg.SpeedLimitUpBps)
	s.globalDLimiter = newRateBucket(cfg.SpeedLimitDownBps)

	if changed && s.ln != nil {
		s.ln.Close() // This will cause Start() to break its Accept loop and re-listen.
	}
}

// rebuildDecryptionLocked tears down the existing ServerInstance (if any) and
// builds a new one from cfg. Caller must hold s.mu. Passes a zero VLESS to
// disable. No listener rebind — the wrap happens per-connection.
func (s *Server) rebuildDecryptionLocked(cfg model.VLESS) {
	if s.decryption != nil {
		s.decryption.Close()
		s.decryption = nil
	}
	if cfg.Decryption == "" || cfg.Decryption == "none" {
		return
	}
	nfsSKeysBytes, err := parseNfsKeys(cfg.Decryption)
	if err != nil {
		log.Errorf("VLESS decryption config invalid, v2 disabled: %v", err)
		return
	}
	inst := &encryption.ServerInstance{}
	if err := inst.Init(nfsSKeysBytes, cfg.XorMode, cfg.SecondsFrom, cfg.SecondsTo, cfg.Padding); err != nil {
		log.Errorf("VLESS decryption init failed, v2 disabled: %v", err)
		return
	}
	s.decryption = inst
}

// parseNfsKeys decodes the "."-separated base64url-encoded NFS server private
// keys from the Decryption config string. Each key is either 32 bytes
// (X25519 private key) or 64 bytes (ML-KEM-768 decapsulation key seed).
func parseNfsKeys(s string) ([][]byte, error) {
	parts := strings.Split(s, ".")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, errors.New("no nfs keys in decryption config")
	}
	return out, nil
}

// vlessEqual reports whether two VLESS configs are semantically equivalent.
func vlessEqual(a, b model.VLESS) bool {
	return a.Decryption == b.Decryption &&
		a.XorMode == b.XorMode &&
		a.SecondsFrom == b.SecondsFrom &&
		a.SecondsTo == b.SecondsTo &&
		a.Padding == b.Padding &&
		a.Flow == b.Flow
}

// Start blocks forever, listening for VLESS connections on the currently
// configured port/transport. It waits for a valid port to be set via
// UpdateConfig and transparently re-binds when the port or transport
// changes.
func (s *Server) Start() {
	for {
		s.mu.RLock()
		port := s.port
		stream := s.stream
		s.mu.RUnlock()

		if port == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		addr := ":" + strconv.Itoa(port)
		ln, err := transport.Listen(context.Background(), transport.StreamConfig{
			Network:          stream.Network,
			Settings:         stream.Settings,
			Security:         stream.Security,
			SecuritySettings: buildSecuritySettings(stream),
		}, addr)
		if err != nil {
			log.Errorf("VLESS failed to listen on %s via %q: %v", addr, transportName(stream), err)
			time.Sleep(5 * time.Second)
			continue
		}

		s.mu.Lock()
		s.ln = ln
		s.mu.Unlock()

		log.Infof("VLESS server listening on %s (transport=%s)", addr, transportName(stream))

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Infof("VLESS listener closed: %v", err)
				break
			}
			go s.handleConnection(conn)
		}
	}
}

// transportName returns the effective transport+security name for logging.
func transportName(s model.Stream) string {
	name := s.Network
	if name == "" {
		name = "tcp"
	}
	return name + "+" + s.Security
}

// streamEqual reports whether two Stream configurations are semantically
// equivalent (same transport, same security, same settings).
func streamEqual(a, b model.Stream) bool {
	if transportName(a) != transportName(b) {
		return false
	}
	if !reflect.DeepEqual(a.Settings, b.Settings) {
		return false
	}
	if !reflect.DeepEqual(a.TLSConfig, b.TLSConfig) {
		return false
	}
	if !reflect.DeepEqual(a.RealityConfig, b.RealityConfig) {
		return false
	}
	return true
}

// buildSecuritySettings converts the model-level security config
// (TLSConfig or RealityConfig) into an opaque map suitable for
// transport.StreamConfig.SecuritySettings.
func buildSecuritySettings(s model.Stream) map[string]any {
	switch s.Security {
	case "tls":
		if s.TLSConfig != nil {
			return structToMap(s.TLSConfig)
		}
	case "reality":
		if s.RealityConfig != nil {
			return structToMap(s.RealityConfig)
		}
	}
	return nil
}

// structToMap converts a typed struct to map[string]interface{} via
// JSON round-trip, preserving field names and values accurately.
func structToMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	m := make(map[string]any)
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}
