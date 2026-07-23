# VGate Server

VLESS inbound proxy node. Go 1.26. Module: `github.com/vgate-project/vgate-server`.

The server is a stateless proxy worker: it registers with the manager, periodically syncs its node config + authorized
user list (hot-reloading on change), serves VLESS traffic (optionally rate-limited per user and node-wide), and reports
per-user traffic back. The manager is the source of truth — the server holds no durable state of its own.

## Tech stack

- [Go 1.26](https://go.dev/)
- [xray-core](https://github.com/XTLS/Xray-core) leaf packages (Vision, VLESS v2 encryption, ws/xhttp transports) —
  imported directly without bootstrapping a
  `core.Instance`
- [xtls/reality](https://github.com/xtls/reality) for Reality security
- [spf13/viper](https://github.com/spf13/viper) — YAML config
- [spf13/cobra](https://github.com/spf13/cobra) — CLI
- [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) — token-bucket rate limiting (per-user / node-wide
  speed caps)

## Prerequisites

- Go **1.26+**
- [xray-core](https://github.com/XTLS/Xray-core) is pulled in as a normal Go module dependency — no local checkout or
  `replace` directive required.

## Build & run

```bash
# from this directory
go build -o vgate .

# run with an explicit config file (defaults to ./config.yml)
./vgate --config config.yml
```

The root command loads the local viper YAML config, creates an `api.Client` pointed at `<AdminAPI>/api/v1/server`,
starts the VLESS inbound server, then runs a ticker loop that calls `sync()` every `SyncInterval` seconds. `sync()`
pulls config + users (short-circuiting with HTTP 304 when unchanged), applies hot-reload, and posts accumulated per-user
traffic back to the manager.

## Local configuration (`config.yml`)

The server's own config file (`config.LoadLocalConfig`, see
[config/config.go](config/config.go)) only carries **how to reach the manager and how often to sync**. It does **not**
contain inbound settings (port / transport / security)
— those are delivered by the manager at runtime (see next section).

| Key             | Type          | Default                 | Description                                                                  |
|-----------------|---------------|-------------------------|------------------------------------------------------------------------------|
| `admin_api`     | string        | `http://localhost:8081` | Base URL of the manager. The node appends `/api/v1/server`.                  |
| `node_id`       | string        | `""`                    | Public node identifier (safe to log).                                        |
| `node_token`    | string        | `default_token`         | Node auth token (issued by the manager).                                     |
| `sync_interval` | int (seconds) | `60`                    | How often to pull config + users and report traffic.                         |
| `log_level`     | string        | `info`                  | logrus + xray-core level: `panic,fatal,error,warn,warning,info,debug,trace`. |

Environment variables override file values (viper `AutomaticEnv`, `.` → `_`, uppercase), e.g. `ADMIN_API`, `NODE_TOKEN`,
`SYNC_INTERVAL`, `LOG_LEVEL`.

Example `config.yml`:

```yaml
admin_api: http://localhost:8081
node_id: node-abc123
node_token: <token issued by the manager>
sync_interval: 60
log_level: info
```

## Node configuration (delivered by the manager)

The actual inbound settings — `port`, `stream` (transport + security), and `vless`
flow options — are **not** in this file. They live in `model.Config` and are pulled from the manager via
`GET /server/config` on every sync tick, then applied with
`server.UpdateConfig` (hot-reload). You configure these **per node in the admin console**
(see [vgate-manager](https://github.com/vgate-project/vgate-manager) and the admin frontend), not in the server's YAML.

The tables and examples below describe the shape of that manager-delivered node config.

### Transports

| network | implementation | security applied by              |
|---------|----------------|----------------------------------|
| `tcp`   | native         | `security.Wrap` (stdlib/reality) |
| `ws`    | xray adapter   | xray `MemoryStreamConfig`        |
| `xhttp` | xray adapter   | xray `MemoryStreamConfig`        |

The `ws` and `xhttp` adapters delegate to xray-core's `websocket.ListenWS` and
`splithttp.ListenXH` respectively. Both use shared helpers from the
`transport/xraybridge` package (`ChanListener`, protojson config decoding, TLS/Reality protobuf builders).

### Security layer

| security  | library                   | supports       |
|-----------|---------------------------|----------------|
| `none`    | —                         | all transports |
| `tls`     | stdlib `crypto/tls`       | all transports |
| `reality` | `github.com/xtls/reality` | tcp, ws, xhttp |

For `tcp`, security is applied via `transport/security.Wrap` after binding the raw listener. For `ws` and `xhttp`, the
security config is handed to xray-core via
`MemoryStreamConfig.SecuritySettings` — xray applies TLS/Reality internally.

Additional optional fields are accepted by each security backend (ignored when absent):
**TLS** — `server_name`, `cert_file` / `key_file` (alternatives to `cert_pem` /
`key_pem`), `alpn`, `max_version`, `reject_unknown_sni`; **Reality** — `show`,
`xver`, `min_client_ver`, `max_client_ver`, `max_time_diff`.

### VLESS flows

| flow               | implementation                           |
|--------------------|------------------------------------------|
| plaintext v0       | vgate-native handler                     |
| v2 AEAD encryption | xray-core `proxy/vless/encryption`       |
| `xtls-rprx-vision` | xray-core `proxy.NewVisionReader/Writer` |

Vision requires the outer connection to be TLS 1.3 or Reality, and is incompatible with v2 encryption. See
`proxy/vless/vision.go` for details.

**Flow restriction:** `flow` (e.g. `xtls-rprx-vision`) is only honored on the `tcp`
transport. The node clears `flow` automatically for `ws` / `xhttp` and when the security layer is `none`.

### VLESS `vless` block

The `vless` object in the manager-delivered node config carries VLESS v2 / obfuscation settings, independent of the
transport. All fields are optional:

| field                         | meaning                                                                                                                                          |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `decryption`                  | `.`-separated list of base64url X25519 (or ML-KEM-768) private keys enabling v2 AEAD decryption; `""` / `none` disables it (plaintext VLESS v0). |
| `xor_mode`                    | `0` off, `1` mask KEM ciphertexts, `2` also wrap the connection in `XorConn`.                                                                    |
| `seconds_from` / `seconds_to` | 0-RTT session-ticket lifetime window in seconds (both `0` = 1-RTT only).                                                                         |
| `padding`                     | `.`-separated `pct-min-max` padding spec; empty = library defaults.                                                                              |
| `flow`                        | VLESS flow control, e.g. `xtls-rprx-vision` (TCP-only, see above).                                                                               |

Example `vless` payload:

```yaml
vless:
  decryption: "BASE64URL_KEY"
  xor_mode: 1
  seconds_from: 0
  seconds_to: 0
  padding: ""
  flow: xtls-rprx-vision
```

### Multiplexing (Mux)

The node enables VLESS `CommandMux` (Mux.Cool) support by default (`enableMux: true`). No config is exposed — it is on
unless disabled in code.

### Speed limiting

A node can cap throughput in both directions. Two values drive it:

- **Node-global** limits (`speed_limit_up_bps` / `speed_limit_down_bps`) cap the node's aggregate upload/download
  throughput (bytes/sec).
- **Per-user** limits (carried on each user in the `GET /server/users` payload) cap that user's throughput.

The effective rate for a user is the **minimum** of the node-global and per-user limits. A value of `0` means unlimited.
Limits are enforced locally with token buckets (`golang.org/x/time/rate`); see `proxy/vless/ratelimit.go` and its test.

### Examples — node config the manager delivers

These are examples of the `port` / `stream` / `vless` payload the manager sends to the node (i.e. what you set in the
admin console for a node), **not** entries for the server's local `config.yml`.

#### raw TCP + TLS

```yaml
port: 10086
stream:
  network: tcp
  security: tls
  tls_settings:
    cert_pem: "..."
    key_pem: "..."
    min_version: "1.3"
```

#### WebSocket + Reality

```yaml
port: 10086
stream:
  network: ws
  security: reality
  settings:
    path: /vless
  reality_settings:
    target: "aws.amazon.com:443"
    server_name: "aws.amazon.com"
    private_key: "<base64url x25519>"
    short_ids: [ "" ]
```

#### XHTTP + TLS

```yaml
port: 10086
stream:
  network: xhttp
  security: tls
  settings:
    path: /xhttp
    x_padding_bytes: { from: 100, to: 1000 }
  tls_settings:
    cert_pem: "..."
    key_pem: "..."
```

## Layout

```
vgate-server/
├── main.go
├── api/                   REST client for manager sync
├── cmd/                   cobra CLI (root only)
├── config/                viper YAML config loader
├── model/                 shared types (User, Config, Stream, VLESS, ...)
├── proxy/
│   └── vless/             VLESS inbound server
│       ├── server.go       lifecycle + hot-reload
│       ├── handler.go      VLESS handshake + TCP/UDP forwarder
│       ├── vision.go       xtls-rprx-vision relay (xray-core leaf)
│       ├── udp.go          UDP-over-TCP relay
│       ├── mux.go          mux (TCP/HTTP/WebSocket) handling
│       ├── protocol.go     VLESS protocol constants/helpers
│       ├── user.go         user set + connection tracking
│       ├── traffic.go      per-user delta traffic counters
│       ├── ratelimit.go    per-user + node-global speed limiting (token buckets)
│       ├── ratelimit_test.go  unit tests for the limiter
│       └── bootstrap.go    anonymous imports registering transports
├── transport/
│   ├── transport.go        Transport interface + registry
│   ├── xraybridge/          shared helpers for xray adapters
│   │                        (ChanListener, DecodeSettings, BuildXrayTLS/Reality)
│   ├── security/            TLS + Reality wrappers (used by tcp)
│   ├── tcp/                 raw TCP transport (native)
│   ├── ws/                  WebSocket transport (xray adapter)
│   └── xhttp/               XHTTP transport (xray adapter)
└── go.mod                  includes github.com/xtls/xray-core as a module dependency
```

> Integration/unit tests (`*_test.go`, `manual_test.go`, `ws/xhttp/vision_*_test.go`)
> live alongside their packages.

## Adding a transport

### Native transport

Implement the `Transport` interface and call `security.Wrap` inside `Listen`:

```go
type Transport struct{}
func (*Transport) Name() string { return "mytransport" }
func (*Transport) Listen(ctx context.Context, addr string, cfg transport.StreamConfig) (net.Listener, error) {
ln, err := net.Listen("tcp", addr)
// ...
return security.Wrap(ln, cfg.Security, cfg.SecuritySettings)
}
func init() { transport.Register(&Transport{}) }
```

Add an anonymous import to `proxy/vless/bootstrap.go`.

### xray-core adapter transport

If xray-core has a `Listen<Proto>` function (same signature as `ListenXH`/`ListenWS`), use the `xraybridge` helpers:

```go
func (*Transport) Listen(ctx context.Context, addr string, cfg transport.StreamConfig) (net.Listener, error) {
address, port, _ := xraybridge.ParseAddrPort(addr)
var protoCfg someproto.Config
xraybridge.DecodeSettings(cfg.Settings, &protoCfg)
streamSettings := &internet.MemoryStreamConfig{ProtocolSettings: &protoCfg}
// security handoff...
ln := xraybridge.NewChanListener()
xrayLn, _ := somepkg.ListenProto(ctx, address, port, streamSettings, ln.AddConn)
ln.Inner = xrayLn
return ln, nil
}
```
