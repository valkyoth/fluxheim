# TCP Stream Proxying

A stream route forwards a TCP connection to another TCP service. Use it for
an opaque application protocol, database connection or TLS passthrough. Fluxheim
does not interpret HTTP requests on this path: vhosts, HTTP routing, cache,
headers, compression, PHP, GeoIP, external authorization and HTTP rate/concurrency
policies do **not** run. Each stream route has its own listeners and limits.

This is separate from [HTTP reverse proxying](reverse-proxy.md) and
[beta UDP](../reference/config-reference.md#udp-beta). It requires the
`stream-proxy` Cargo feature; outbound TLS also requires a TLS backend. Check
your chosen [build profile](../reference/features.md), not just its image name.

## Start With A Local Service

Set `[stream]` `enabled` to `true`; its `routes` array is configured with
one `[[stream.routes]]` table per forwarding policy.

[Complete local example](../../examples/stream/local.toml): Fluxheim listens on
`127.0.0.1:18080` and forwards to your TCP service at `127.0.0.1:19001`.
HTTP listeners and cache are disabled. Start the upstream separately, then run:

```sh
fluxheim --config examples/stream/local.toml --validate-config
fluxheim --config examples/stream/local.toml
```

The example's process files are relative to the configuration directory, which
must be private and writable by the service user. It deliberately accepts only
local IPv4 clients. Replace both addresses and the source policy before a real
deployment. Binding `0.0.0.0` or `[::]` exposes additional interfaces; use a
firewall as well as Fluxheim's source policy. Do not share a listening address
with an HTTP, TLS, metrics, admin or another TCP service.

The essential section is:

```toml
[stream]
enabled = true

[[stream.routes]]
name = "database"
listen = ["127.0.0.1:15432"]
upstream = "10.0.0.11:5432"
connect_timeout_secs = 5
idle_timeout_secs = 300
max_connections = 128
allow_sources = ["127.0.0.1/32"]
```

Every accepted connection gets a new upstream connection. There is no upstream
connection pool, HTTP health-check inheritance or application transaction retry.
TCP half-close is propagated: a client can finish sending and still receive
the upstream's remaining response.

## Multiple Upstreams, Weights And Backups

Replace `upstream` with `upstreams`; never set both:

```toml
upstreams = ["10.0.0.11:5432", "10.0.0.12:5432", "10.0.0.13:5432"]
upstream_weights = [2, 1, 1]
upstream_aliases = ["primary-a", "primary-b", "standby"]
backup_upstreams = ["10.0.0.13:5432"]
drain_upstreams = []
```

Selection is route-local weighted round-robin over non-drained primaries.
Weights occupy consecutive slots, not a smooth least-load schedule. Without
weights each primary has weight one. Backup weights do not determine ordinary
traffic share. Aliases label diagnostics; they are not DNS names or subset keys.

On DNS/connect/TLS failure, Fluxheim tries the remaining primaries in configured
order, then backups in configured order. It does not continuously check health
or remember a failed upstream for later connections. Each candidate gets its
own connect timeout. Once an upstream connects, a PROXY-write or copying failure
ends the connection; Fluxheim does not replay application bytes elsewhere.

For maintenance, add an authority to `drain_upstreams`. The selector excludes
it from new connections; this is not an admin command that migrates existing
sessions. **Stream configuration changes require a process restart**, including
weights, drain lists, ACLs and limits. The reload classifier reports a stream
service change. Coordinate restarts with clients rather than promising a live
drain or zero-disruption session migration.

Hostname upstreams resolve during setup. The DNS guard rejects private/reserved
answers by default for plain TCP **and** TLS. Numeric IP upstreams are explicit
and bypass that guard. For trusted internal DNS only:

```toml
upstream = "database.internal.example:5432"
upstream_dns_allow_private_addresses = true
```

Only the first permitted resolved address is connected; failure does not try
later addresses of that hostname. Another configured upstream can still be tried.
This extends **Current limitation:**, not a new independent finding.

## Admission, Time And Byte Budgets

```toml
connect_timeout_secs = 5
proxy_header_timeout_secs = 10
idle_timeout_secs = 60
max_connection_secs = 3600
max_connection_bytes = 1073741824
max_connections = 128
```

`max_connections` is shared by all listeners of one route. A slot is held before
reading a PROXY header, through setup and copying, and returned when processing
ends. Excess connections are closed; there is no HTTP error response or waiting
queue. Other routes have separate budgets. Zero explicitly disables this cap.

`connect_timeout_secs` covers DNS, TCP and outbound TLS **per candidate**.
`proxy_header_timeout_secs` is an absolute downstream preamble deadline; sending
one byte at a time does not refresh it. `idle_timeout_secs` starts at copying
and refreshes on successful writes in either direction, including partial writes.
Reading buffered data without forwarding it does not count as progress.

**Current limitation:** `max_connection_secs` currently bounds only the
copy phase, not lifetime from accept. Downstream PROXY receive, each candidate's
setup and outbound PROXY writing occur before that timer. A one-second cap still
allows a preamble delayed longer than one second, followed by successful data.
Keep the separate setup/header timeouts finite; do not advertise this option as
an end-to-end deadline until corrected.

`max_connection_bytes` is a separate cap in each direction, not the combined
total. A read chunk that would cross the cap is rejected before forwarding that
chunk, so it may close before delivering exactly the remaining allowance.
PROXY framing is not charged as copied application bytes. Each direction has a
16 KiB buffer; forwarded ranges and buffers on drop are wiped. This is not a
whole-process memory or per-route aggregate traffic cap.

## Client Identity And PROXY Protocol

With PROXY receive off, source rules inspect the TCP peer, not HTTP forwarding
headers. To receive a trusted load balancer's PROXY v1 preamble:

```toml
downstream_proxy_protocol = "v1"
trusted_proxies = ["10.0.0.10/32"]
allow_sources = ["198.51.100.0/24"]
deny_sources = ["198.51.100.99"]
proxy_header_timeout_secs = 5
```

The direct peer must be in this route's `trusted_proxies`; only then is its
claimed client address evaluated. `deny_sources` wins; a nonempty allow list
requires a known matching source. Use `"v2"` for binary framing and `"off"`
for none. Do not expose a PROXY-enabled port to untrusted senders or list an
entire client network as trusted proxies. Ordinary clients without a preamble
cannot use that port. Global HTTP `server.proxy_protocol` and
`server.trusted_proxies` do not configure it.

**Current limitation:** PROXY v1 `UNKNOWN` and v2 `LOCAL` can produce no
client address. With an empty allow list, even a nonempty deny list admits that
connection. This requires a trusted direct peer; it is not an unauthenticated
Internet bypass. Use a positive allow list when client identity is mandatory;
coordinate the trusted sender to supply a client address. Do not rely on a
deny-only policy for fail-closed handling of missing identity.

**Current limitation:** stream address matching preserves address
families. A mapped IPv6 client such as `::ffff:192.0.2.1` does not match the IPv4
deny `192.0.2.0/24`. The live test reproduces this through a trusted PROXY sender.
Use explicit family policies/positive allow lists and firewall restrictions
until the shared mapped-address correction is qualified.
Use unpadded IP/CIDR strings: validation trims surrounding whitespace but the
stream parser does not. A padded rule can pass validation and then fail startup;
parser agreement is included in the local follow-up's shared validation correction.

For an upstream that explicitly expects PROXY framing:

```toml
upstream_proxy_protocol = "v2"
upstream_tls = false
```

This is independent of receiving PROXY downstream. Source is the accepted peer
or trusted reported client; destination is Fluxheim's local listener address,
not the inbound preamble's original destination. Unknown identity produces the
protocol's unspecified form. Do not enable it against an ordinary database
port. Combining outbound PROXY with outbound TLS is rejected, not silently
ignored. See also [HTTP PROXY protocol](proxy-protocol.md) for that separate path.

## TLS Passthrough And Outbound TLS

**Passthrough:** keep `upstream_tls = false`. Client TLS bytes are opaque;
the backend terminates TLS. Fluxheim does not select stream upstreams by SNI,
present a downstream certificate, run ACME on that listener or enforce HTTP
client-certificate pins. Application authentication remains the backend's job.

**Outbound TLS:** Fluxheim wraps the upstream connection in TLS. This does not
encrypt a plaintext client's connection to Fluxheim. It also does not implement
protocol-specific STARTTLS/PostgreSQL SSL negotiation. Use only a backend
expecting TLS immediately:

```toml
upstream = "10.0.0.11:9443"
upstream_tls = true
upstream_sni = "backend.example.test"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "/etc/fluxheim/upstreams/backend-ca.pem"
# For a backend requiring client authentication, set both:
# upstream_client_cert_path = "/etc/fluxheim/upstreams/client-chain.pem"
# upstream_client_key_path = "/etc/fluxheim/upstreams/client-key.pem"
```

Without a custom CA bundle, native trust roots are loaded. A custom bundle
replaces them for this route. Material is loaded at connector construction;
restart to refresh it, rather than using downstream certificate reload.
Paths resolve relative to the config and must pass filesystem trust checks;
keep keys private. The shared upstream-reader limitations in
[upstream TLS](upstream-tls.md#files-reloads-and-current-limits) remain relevant.

Hostname upstreams derive SNI from the authority unless explicitly overridden.
Numeric upstreams with verification enabled require explicit `upstream_sni`.
TLS 1.2/1.3 are supported; there is no per-stream HTTP ALPN or TLS-policy table.
Disabling hostname verification weakens identity checking. Disabling certificate
verification also requires `upstream_verify_hostname = false`; this is not a
solution for a missing CA or wrong name. Rustls still needs a nonempty root
store to construct its connector in that mode.

**Current limitation:** `upstream_alternative_cn` is accepted but ignored
by the rustls stream connector. OpenSSL uses it to replace the verification
name while retaining SNI. Rustls instead still verifies SNI: a matching SNI with
a deliberately wrong alternative succeeds, and wrong SNI with a correct
alternative fails. Do not depend on this option for portable stream identity
policy. Keep SNI equal to the certificate's expected name until parity is fixed.

## Complete Option Checklist

Options below belong to `[[stream.routes]]` unless noted. Omitted optional
numbers are unset; zero is not a substitute for unset unless specified.

| Option | Default | Contract |
| --- | --- | --- |
| `[stream].enabled` | `false` | Enabling requires routes and the compiled feature |
| `[stream].routes` | Empty | At most 128; nonempty routes with disabled stream are rejected; fragment lists replace rather than append |
| `name` | Required | Nonempty, at most 128 bytes; unique ignoring ASCII case |
| `listen` | Empty | Required numeric socket addresses; at most 64 per route; duplicate strings across stream routes rejected |
| `upstream` | Absent | One host:port; mutually exclusive with plural form |
| `upstreams` | Empty | 1..64 unique authorities, compared ignoring ASCII case |
| `upstream_weights` | Empty | Plural only, one per upstream, 1..1000 each, total at most 65535 |
| `upstream_aliases` | Empty | Plural only, one per upstream, unique ignoring ASCII case; 1..64 ASCII letters/digits/dot/dash/underscore |
| `backup_upstreams` | Empty | Exact authority subset, plural list of at least two; disjoint from drain; one active primary required |
| `drain_upstreams` | Empty | Same subset rules; excludes new selections, not a live control |
| `connect_timeout_secs` | `5` | 1..86400, per candidate setup |
| `idle_timeout_secs` | `300` | 1..86400, successful-copy progress |
| `proxy_header_timeout_secs` | `10` | 1..60, complete receive preamble |
| `max_connection_secs` | Absent | 1..86400 when set; currently copy-phase only |
| `max_connection_bytes` | Absent | Positive u64, per direction |
| `max_connections` | `1024` | At most 1000000; zero means unlimited |
| `downstream_proxy_protocol` | `off` | `off`, `v1`, `v2`; enabling requires route-local trusted proxies |
| `trusted_proxies` | Empty | Direct-peer IP/CIDR trust; unspecified addresses rejected, IPv4 prefixes at least /8, IPv6 at least /29; prefer exact peers |
| `allow_sources` | Empty | Client IP/CIDR list, at most 256; duplicates rejected ignoring ASCII case; nonempty requires known source |
| `deny_sources` | Empty | Same size/duplicate rules; deny wins for matching known addresses |
| `upstream_proxy_protocol` | `off` | `off`, `v1`, `v2`; incompatible with upstream TLS |
| `upstream_tls` | `false` | Immediate outbound TLS, not client-facing termination |
| `upstream_dns_allow_private_addresses` | `false` | Allow trusted DNS to select internal addresses |
| `upstream_sni` | Absent | Derived from hostname; explicit name required for verified numeric origins |
| `upstream_verify_cert` | `true` | Certificate trust verification |
| `upstream_verify_hostname` | `true` | Expected-name verification; requires verify-cert |
| `upstream_alternative_cn` | Absent | Non-wildcard verification override; OpenSSL only in current stream runtime |
| `upstream_ca_path` | Absent | PEM root bundle; requires TLS and verify-cert |
| `upstream_client_cert_path` | Absent | PEM client chain; requires TLS and paired key |
| `upstream_client_key_path` | Absent | PEM client key; requires TLS and paired chain |

## Observe And Troubleshoot

With metrics compiled and enabled, connection results feed
`fluxheim_stream_connections_total{route,outcome}`. Copied bytes feed
`fluxheim_stream_bytes_total{route,direction}` **only on successful completion**;
bytes already transferred before timeout/error are not included. These counters
are not a live active-session gauge, exhaustive traffic accounting or HTTP APM.

| Symptom | Check |
| --- | --- |
| Listener never starts | Compiled feature, duplicate/busy port, process paths and startup diagnostics |
| Immediate close, no backend connection | Route connection cap, source policy, trusted peer and preamble format |
| Internal DNS origin fails | DNS guard; explicit trusted-private-DNS opt-in rather than disabling TLS checks |
| Backup never used | Primary TCP/TLS succeeds; application failure is not connect failover |
| Data stops after a fixed interval | Copy lifetime versus idle limit; each has a different clock |
| TLS fails despite a configured alternative name | Current rustls limitation; use matching SNI and trusted CA |
| Editing drain or CA file has no effect | Stream service/connector restart required |

## Evidence And Open Work

```sh
cargo build --locked --bin fluxheim --no-default-features --features stream-proxy,tls-rustls
python3 scripts/smoke_stream_examples.py
sh scripts/smoke_stream_proxy.sh
```

To exercise the alternate TLS backend separately, rebuild with
`--no-default-features --features stream-proxy,tls-openssl` and run
`python3 scripts/smoke_stream_examples.py --backend openssl`. The switch selects
the expected identity contract; it does not change the already-built binary.

The first smoke executes the actual loopback TCP server and temporary TLS
origin, including explicit characterizations of open findings. Those assertions
must change when corrective commits land; passing them is not remediation.
The older smoke also checks an absolute slow-preamble timeout. See the
[coverage ledger](../reference/documentation-coverage.md) and
[correction plan](../roadmap/observability-commit-plan.md) for qualification scope
and required Windows/macOS follow-up.
