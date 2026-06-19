# Config Reference

Fluxheim config is TOML. Unknown fields are rejected, so misspelled settings
fail during `--check-config` instead of being ignored.

Inspect a config before running it:

```bash
fluxheim --check-config --config path/to/fluxheim.toml
```

For deployment preflight, use `--validate-config`. This performs the same
static validation and also builds the runtime proxy state, so missing static
web roots and other startup-blocking filesystem issues fail before systemd
starts the service:

```bash
fluxheim --validate-config --config /etc/fluxheim/fluxheim.toml
```

When debugging a container or mounted config from outside the runtime
environment, use the release-asset tester. `--no-runtime-paths` skips only
`server.process` runtime path inspection, which is useful when `/run/fluxheim`
is not mounted locally, while other config semantics and profile checks still
run:

```bash
fluxheim-config-tester --config /etc/fluxheim/fluxheim.toml --profile web-php --no-runtime-paths
```

For split config directories, Fluxheim reads `*.toml` files in sorted order:

```bash
fluxheim --check-config --config examples/conf.d
```

When the config path is a file, Fluxheim loads only that file unless the file
sets `include_conf_d = true`. With that opt-in, visible `*.toml` files from a
sibling `conf.d/` directory load after the main file. When the config path is a
directory, Fluxheim loads visible `*.toml` files in that directory first and
then visible `*.toml` files in its `conf.d/` child. Files are loaded in lexical
order within each directory.
When multiple fragments set `server.trusted_proxies`, Fluxheim extends the
trusted-proxy list and deduplicates exact entries instead of replacing the
earlier list. This keeps a later fragment from silently discarding the main
config's client-IP trust boundary.
When multiple fragments set `[proxy]`, Fluxheim applies field-level merge
semantics. A later proxy fragment that sets a timeout or buffer setting does
not replace the earlier upstream, TLS verification, authentication, mirror, or
load-balancer policy.
The same field-level merge model applies to `[admin]`, `[compression]`,
`[cache]`, `[cache_purger]`, `[web]`, and `[stream]`. Later fragments can
override fields they explicitly set without clearing previously configured
admin authentication, resource limits, cache encryption, static-file safety
policy, or stream routes.

Relative filesystem paths are resolved from the config file directory.
Config sources must be real TOML files or real directories. Fluxheim rejects a
symlink used as the top-level config source, rejects config sources below a
symlinked directory, and ignores symlinked TOML entries inside split config
directories, so a reload cannot be redirected through an unexpected filesystem
pointer. Each TOML file is size-limited to 1 MiB; large deployments should use
a split config directory instead of one huge file. Split config directories are
limited to 256 visible TOML files. Configured filesystem paths are also rejected
when any existing path component is a symlink; missing final directories may
still be created by the owning runtime module, but never through a symlinked
prefix.

## Server

`[server]` controls listeners, default vhost selection, trusted proxies, and
global request limits.

```toml
[server]
listen = ["127.0.0.1:8080"]
tls_listen = []
default_vhost = "example.test"
trusted_proxies = ["127.0.0.1"]
proxy_protocol = "off"
regex_enabled = false

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "16MiB"

[server.process]
daemon = false
error_log = "/run/fluxheim/error.log"
pid_file = "/run/fluxheim/fluxheim.pid"
upgrade_sock = "/run/fluxheim/fluxheim-upgrade.sock"
certificate_reload_sock = "/run/fluxheim/fluxheim-cert-reload.sock"
threads = 1
listener_tasks_per_fd = 1
work_stealing = true
upstream_keepalive_pool_size = 128
max_retries = 16
grace_period_seconds = 10
graceful_shutdown_timeout_seconds = 30

[server.https_redirect]
enabled = false
status = 308
# target_port = 8443

[server.host_routing]
strict = false
```

Notes:

- `listen` and `tls_listen` cannot both be empty unless `[stream].enabled =
  true` supplies dedicated TCP stream listeners.
- `server.process.upstream_keepalive_pool_size` is a per-native-upstream idle
  socket cap. Size it against the process file-descriptor budget; total idle
  upstream sockets can be the sum of this cap across native proxy entries.
  Values above 16384 are rejected.
- TLS listeners are explicit through `tls_listen`; Fluxheim does not infer TLS
  from port numbers.
- `listen` and `tls_listen` are each capped at 64 entries.
- `default_vhost`, when set, must match a configured `[[vhosts]].name`.
- `[server.host_routing].strict = false` preserves compatibility by falling
  back to `default_vhost` for missing, invalid, or unknown host names. Set it
  to `true` in hardened multi-tenant deployments to reject missing or invalid
  host identity with `400` and unknown hosts with `421`.
- Host names are normalized to lowercase and reject percent signs, empty labels
  such as consecutive dots, leading/trailing label hyphens, overlong labels,
  and numeric-only final labels. Single-label internal names such as
  `localhost` remain valid.
- If vhosts live in a sibling `conf.d` directory and `--config` points at the
  main file, set top-level `include_conf_d = true`; alternatively point
  `--config` at the config directory so visible `.toml` files are loaded in
  sorted order.
- `trusted_proxies` should contain only peers you operate, such as a container
  gateway, Cloudflare, or a trusted edge proxy. When the direct peer is trusted,
  Fluxheim walks `X-Forwarded-For` from right to left and restores the last
  non-trusted hop for generated client-IP headers, equivalent to nginx
  `real_ip_recursive on`. The list is capped at 512 entries. Entries must be
  concrete IP addresses or bounded CIDR ranges; catch-all and near-global trust
  scopes such as `0.0.0.0/0`, IPv4 prefixes broader than `/8`, `::/0`, IPv6
  prefixes broader than `/29`, and unspecified addresses are rejected.
- `proxy_protocol` defaults to `off`. Set it to `v1` or `v2` only on listeners reached
  exclusively through trusted load balancers or edge proxies that send HAProxy
  PROXY protocol before TLS/HTTP/stream bytes. Fluxheim requires
  `server.trusted_proxies` when this is enabled, rejects direct peers outside
  that trust list before parsing the header, and restores the PROXY source
  address before TLS, HTTP, and stream handling. The v2 parser supports TCP4/TCP6 and
  LOCAL/UNSPEC frames, skips bounded TLV payloads, and rejects unsupported
  address families or oversized v2 payloads.
- `[server.process]` maps safe process settings into Pingora's `ServerConf`.
  Changes to these values require a process upgrade, not a live snapshot
  reload. Keep `threads` conservative in containers because Pingora allocates
  worker threads per service.
- `pid_file`, `upgrade_sock`, `certificate_reload_sock`, and optional
  `error_log` must not contain parent traversal, must not be below symlinked
  existing parent directories, and on Unix must not use a group- or
  world-writable existing parent such as `/tmp`. Use a dedicated runtime
  directory such as `/run/fluxheim`.
- `certificate_reload_sock` is a local Unix-domain control socket used by
  `fluxheim-acme` to request certificate-handle reloads after external ACME
  renewal. It is not a general admin API.
- `[server.https_redirect]` is disabled by default. When enabled, cleartext
  requests receive a direct HTTPS redirect before static serving or proxying.
  It requires at least one `tls_listen` address. `status` may be `301`, `302`,
  `307`, or `308`; `308` is the default. `target_port` is optional and should
  be used only when clients must be redirected to a non-default HTTPS port.
  Redirects require a syntactically safe `Host` header, otherwise Fluxheim
  returns `400` instead of constructing a risky `Location`.

## TCP Stream Proxy

`[stream]` is disabled by default and requires a build with the
`stream-proxy` feature. Stream routes are raw L4 TCP services. They do not run
HTTP routing, headers, cache, compression, auth subrequests, PHP, or web
serving logic. The current stream datapath and listener loop are
Fluxheim-owned in the `1.5.6` line, including the internal async IO boundary
used by accepted TCP connections and selected upstream connections. Stream
upstream TLS also uses Fluxheim-owned `tokio-rustls` / `tokio-openssl`
connectors in `1.5.6`; it no longer depends on Pingora's stream wrapper or TLS
connector adapter.

```toml
[stream]
enabled = true

[[stream.routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstreams = ["10.0.0.11:5432", "10.0.0.12:5432"]
# upstream_weights = [1, 2]
# upstream_aliases = ["pg-a", "pg-b"]
# backup_upstreams = []
# drain_upstreams = []
connect_timeout_secs = 5
idle_timeout_secs = 300
# max_connection_secs = 3600
max_connection_bytes = 1073741824
max_connections = 1024
downstream_proxy_protocol = "off" # "off", "v1", or "v2"
trusted_proxies = []
allow_sources = []
deny_sources = []
upstream_proxy_protocol = "off" # "off", "v1", or "v2"
upstream_tls = false
upstream_dns_allow_private_addresses = false
# upstream_sni = "db.internal.example"
# upstream_verify_cert = true
# upstream_verify_hostname = true
# upstream_alternative_cn = "db-alt.internal.example"
# upstream_ca_path = "/etc/fluxheim/upstreams/db-ca.pem"
# upstream_client_cert_path = "/etc/fluxheim/upstreams/client-chain.pem"
# upstream_client_key_path = "/etc/fluxheim/upstreams/client-key.pem"
```

- `listen` entries are `ip:port` TCP listeners. Each listener may appear on
  only one stream route.
- Configure either `upstream = "host:port"` or `upstreams = ["host:port", ...]`.
  Multiple upstreams use stream-local round-robin selection by default.
- `upstream_weights` optionally enables weighted stream selection and must have
  one positive value for each `upstreams` entry. `upstream_aliases` optionally
  assigns safe low-cardinality names for stream logs and future metrics.
- `backup_upstreams` and `drain_upstreams` are optional subsets of
  `upstreams`. Drained stream upstreams do not receive new connections. Backup
  stream upstreams are not selected while a primary is available, but are tried
  as connect-fallback candidates before the downstream stream starts copying.
- `connect_timeout_secs` bounds DNS/connect setup and defaults to `5`.
- `idle_timeout_secs` is a true stream idle timer and defaults to `300`. The
  timer resets whenever either direction transfers bytes.
- `max_connection_secs` is optional and bounds total accepted stream lifetime
  when set. Leave it unset for no wall-clock lifetime cap.
- `max_connection_bytes` is optional and caps copied bytes per direction for a
  single stream connection.
- `max_connections` caps concurrent accepted connections before connecting
  upstream and defaults to `1024`. Setting `max_connections = 0` is an explicit
  unlimited override for private or otherwise externally protected stream
  routes; public listeners should keep a non-zero cap sized to the backend.
- `downstream_proxy_protocol` enables PROXY protocol receive for this stream
  route only. It defaults to `off` and requires route-local `trusted_proxies`.
  The HTTP `server.proxy_protocol` setting does not apply to stream listeners.
- `allow_sources` and `deny_sources` are route-local stream source policies.
  Entries are IP addresses or CIDR ranges. `deny_sources` wins over
  `allow_sources`. When `allow_sources` is non-empty, clients without a source
  address or outside the allow list are rejected before Fluxheim connects
  upstream. With downstream PROXY receive enabled, the policy evaluates the
  trusted PROXY client address; otherwise it evaluates the direct TCP peer.
  HTTP access, auth subrequest, rate-limit, and geo policies do not apply to
  raw TCP stream routes.
- `upstream_proxy_protocol` writes a HAProxy PROXY protocol header to the
  selected upstream before forwarding stream bytes. Use it only when the
  upstream explicitly expects PROXY protocol. It cannot be combined with
  `upstream_tls`; stream TLS handshakes need a dedicated pre-TLS PROXY
  connector before that combination can be enabled safely.
- `upstream_tls = true` sends TLS to the selected stream upstream.
  Hostname upstreams are resolved on connection setup. By default, Fluxheim
  rejects hostname DNS answers that resolve only to private, loopback,
  link-local, multicast, broadcast, documentation, or unspecified addresses to
  reduce DNS-rebinding pivots. Set
  `upstream_dns_allow_private_addresses = true` only for routes whose hostname
  upstreams are intentionally resolved by trusted internal DNS. IP-literal
  upstreams remain explicit and are not blocked by this DNS guard.
  `upstream_sni` is optional for hostname upstreams; when unset Fluxheim derives
  SNI from the selected upstream host. IP-literal upstreams with
  `upstream_tls = true` and certificate verification enabled require explicit
  `upstream_sni`, because an IP address does not provide a DNS hostname for
  certificate verification. `upstream_verify_cert` and
  `upstream_verify_hostname` default to `true`; disabling certificate
  verification also requires hostname verification to be disabled so the policy
  cannot imply a hostname check that is not happening.
- `upstream_alternative_cn` replaces the SNI-derived verification hostname with
  one explicit non-wildcard hostname. It is not an additional hostname checked
  alongside SNI. `upstream_ca_path` loads a route-local PEM CA bundle.
  `upstream_client_cert_path` and `upstream_client_key_path` configure upstream
  mTLS client material and must be set together. Custom trust roots and
  upstream client certificates are supported for rustls and OpenSSL builds.
  Fluxheim zeroizes the PEM input buffers after parsing; in rustls builds the
  parsed private-key DER is then owned by rustls 0.23, which does not yet
  provide zeroing of private-key DER bytes on drop. This is a known upstream
  limitation. BoringSSL and s2n are not supported Fluxheim TLS backends.

When `metrics` is compiled and enabled,
`fluxheim_stream_connections_total{route,outcome}` records bounded connection
outcomes and `fluxheim_stream_bytes_total{route,direction}` records copied
bytes in each direction.

## UDP Beta

`[udp]` is disabled by default. In `1.5.21` it is a beta UDP/GSLB exploration
runtime, not a production UDP platform. Normal release profiles do not enable
the `udp-proxy` feature, and `udp.enabled = true` fails clearly unless
Fluxheim is built with that beta feature.

The namespace is intentionally separate from `[stream]`; TCP stream routes
remain TCP-only and do not accept UDP listeners.

```toml
[udp]
enabled = false

[[udp.routes]]
name = "dns-edge"
mode = "dns-load-balance" # active: dns-load-balance, syslog-forward; reserved: quic-pass-through, game-proxy
listen = ["127.0.0.1:5353"]
upstreams = ["192.0.2.10:53", "192.0.2.11:53"]
# upstream_weights = [1, 1]
# upstream_aliases = ["dns-a", "dns-b"]
idle_timeout_secs = 30
response_timeout_secs = 3
max_datagram_bytes = 1232
max_sessions = 4096
max_sessions_per_source = 64
max_responses_per_source_per_second = 256
passive_health_enabled = true
passive_health_failures = 3
passive_health_ejection_secs = 10
```

- `mode` is an explicit runtime target, not a generic protocol parser.
  `dns-load-balance` performs one bounded upstream request/response exchange
  per downstream datagram. `syslog-forward` forwards one datagram upstream and
  does not wait for a response. `quic-pass-through` and `game-proxy` are
  reserved until route-local UDP session affinity is implemented.
- `listen` entries are `ip:port` UDP listeners. Each listener may appear on
  only one UDP route.
- Configure either `upstream = "host:port"` or `upstreams = ["host:port", ...]`.
  `upstream_weights` and `upstream_aliases` are valid only with `upstreams` and
  must match its length.
- `idle_timeout_secs` is required and non-zero. `response_timeout_secs`
  defaults to `3` and must be less than or equal to `idle_timeout_secs`.
  `dns-load-balance` uses it for upstream connect and response waits so
  unanswered datagrams do not hold route slots for the full idle window.
- `max_datagram_bytes` must be between 1 and 65507. Route examples should use
  smaller protocol-aware values where possible, such as 1232 bytes for DNS over
  UDP deployments that want conservative fragmentation behavior.
- `max_sessions` defaults to `4096`. `max_sessions = 0` means unlimited for
  that UDP route. Non-zero values are capped at 1000000.
- `max_sessions_per_source` defaults to `64`. It limits concurrent in-flight
  datagram sessions per source IP and is released when the datagram finishes.
  `0` disables the per-source cap. Non-zero values are capped at 1000000.
- `max_responses_per_source_per_second` defaults to `256` for response modes.
  It limits downstream responses per source IP per one-second window, and `0`
  disables the response-rate cap. Fluxheim prunes old windows and bounds the
  tracked source table by the larger of the route/session caps and an internal
  4096-source floor.
- `passive_health_enabled` defaults to `true`. In request/response modes,
  consecutive upstream send/receive failures eject a member from selection for
  `passive_health_ejection_secs` seconds once `passive_health_failures` is
  reached. A successful exchange clears the member failure count and ejection
  state. Local downstream drops, including per-source response-rate limiting
  and oversized upstream responses rejected by Fluxheim's datagram cap, do not
  count as upstream passive-health failures. If all members are ejected,
  Fluxheim falls back to trying the selected member so a full pool outage does
  not become a permanent local dead end.
- `dns-load-balance` is beta and can act as a UDP reflector if exposed to
  untrusted networks. Bind beta listeners to loopback or internal interfaces
  unless the deployment has upstream ingress filtering such as BCP38. Fluxheim
  logs a security warning when a `dns-load-balance` route listens on a
  non-loopback address, but this is still an operator decision during beta.
- In rootless container deployments, prefer binding UDP beta routes to an
  explicit host/container IP and publish only the required UDP port. Avoid
  broad `0.0.0.0:port` or `[::]:port` bindings until the route has ingress
  filtering, source pressure limits, and operational metrics monitored.
- UDP routes expose Prometheus metrics when the `metrics` feature is compiled:
  `fluxheim_udp_datagrams_total`, `fluxheim_udp_drops_total`, and
  `fluxheim_udp_active_sessions`. The admin API exposes configured UDP route
  status at `GET /_fluxheim/udp/status` when both admin and `udp-proxy` are
  compiled in.
- `1.5.21` does not add QUIC pass-through, game-server UDP proxying, generic
  UDP proxying, an authoritative DNS server, WAF, VPN/firewall appliance
  behavior, HTTP/3 ingress, or Wasm/iRules/Lua scripting.

## Admin

`[admin]` is disabled by default. When enabled, it must be authenticated and
loopback-only unless the operator explicitly relaxes that.

```toml
[admin]
enabled = false
listen = "127.0.0.1:9090"
require_loopback = true
token_env = "FLUXHEIM_ADMIN_TOKEN"
token_file = "/run/secrets/fluxheim-admin-token"
snapshot_store = "/var/lib/fluxheim/snapshots"

[admin.transport]
mode = "local_only"

[admin.ops_socket]
enabled = false
path = "/run/fluxheim/fluxheim-ops.sock"
mode = "0600"
require_bearer_token = false

[admin.health]
unauthenticated = false
response = "status"

[admin.auth_throttle]
enabled = true
window_secs = 60
per_source_failures = 10
global_failures = 100
base_lockout_secs = 30
max_lockout_secs = 900
max_sources = 4096

[admin.client_certificate]
required = false
sha256_header = "x-client-cert-sha256"
allow_sha256 = []
deny_sha256 = []

[admin.self_healing]
enabled = false
validation_window_secs = 30
health_path = "/_fluxheim/health"
min_successful_checks = 1
max_error_rate_per_mille = 100
```

If `admin.enabled = true`, configure `token_env` or `token_file`. Snapshot and
rollback endpoints also require `snapshot_store`. `token_file` and
`snapshot_store` must not contain parent traversal, must not sit below a
symlinked parent directory, and on Unix must not use a group- or world-writable
existing parent such as `/tmp`. The snapshot store runtime applies the same rule when it
is used directly by CLI/admin paths.

Remote admin exposure fails closed. Keep `admin.listen` loopback whenever
possible. If `admin.require_loopback = false` and `admin.listen` is non-loopback,
Fluxheim requires `[admin.transport] mode = "trusted_tls_terminator"` to make
the operator explicitly declare that a trusted local sidecar, reverse proxy, or
load balancer terminates TLS/mTLS before traffic reaches the plain admin
listener. Direct first-class admin TLS/mTLS remains planned; do not expose the
admin listener over cleartext networks.

`[admin.ops_socket]` enables a separate Unix-domain HTTP socket for local,
read-only operational checks. It exposes only `GET /_fluxheim/status`,
`GET /_fluxheim/cache/status`, `GET /_fluxheim/snapshots`, and the configured
admin health path; mutating admin endpoints such as reload, rollback, and cache
purge are not routed on this socket. The socket requires `admin.enabled = true`,
is Unix-only, and validates its path with the same parent traversal, symlink, and
unsafe-writable-parent checks used for process sockets. `mode` must grant owner
read/write access, may grant group read/write access, and must not grant world
access; use `0600` for service-owner-only status or `0660` for a dedicated
operator group. By default, the Unix socket's filesystem permissions are the
trust boundary. Set `require_bearer_token = true` to require the same
`Authorization: Bearer ...` token as the TCP admin listener for read-only ops
socket status requests. `GET /_fluxheim/snapshots` always requires the bearer
token on the ops socket because snapshot IDs and messages expose deployment
change history.

When compiled with `load-balancer`, `GET /_fluxheim/status` includes a
`load_balancer` object for configured vhost and route pools. The status is
read-only and reports backend readiness, aliases, weights, backup/drain/disabled
state, ready and policy-available backend counts, primary/backup availability
counts, drain/disabled/forced-down/ejected/saturated summary counts, runtime
override counts, circuit-open counts, selection policy, max-iteration and
all-down settings, discovery mode (`static`, `file`, `http`, or `dns`),
discovery refresh status, update frequency, success/failure counters, last
success/failure timestamps, bounded last discovery error, health-check
protocol, frequency and parallel mode, retry policy, passive-health
thresholds, slow-start duration, persistence policy and table size, queue policy
and current waiting count, priority group, locality, tags, max in-flight cap,
current in-flight count, passive failure count, passive ejection, passive
ejection remaining seconds, circuit state, slow-start allowance, persistence
entries currently pinned to each backend, and least-time latency state where
available. In the current load-balancer implementation, `circuit_state = "open"`
is the runtime status view for a backend currently ejected by passive health;
`"closed"` means the backend is not passively ejected. Per-backend rows include
`runtime_state_override` when an
authenticated runtime member operation is active and
`runtime_state_changed_at_unix_secs` when that override currently has a recorded
manual transition time. In `privacy-mode`, backend addresses are omitted from
this status object.

Background discovery refresh loops also emit
`fluxheim_load_balancer_events_total` with `event = "discovery_success"` or
`event = "discovery_failure"` and the same vhost/route pool labels used by
selection, retry, queue, and runtime mutation events.

When compiled with `load-balancer`, authenticated admins can update the
in-memory state of an existing configured pool member without reloading:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-state?vhost=app&member=app-a&state=drain"
```

Use `vhost` for the vhost name, optional `route` for a route-local pool,
`member` for the configured upstream address or `upstream_aliases` value, and
`state` as `normal`, `drain`, `disable`, `forced_down`, or `manual_resume`.
`forced_down` removes the member from selection like `disable` but remains
distinct in admin status so operators can separate forced health actions from
maintenance disables. `manual_resume` clears any runtime override, clears the
member's passive-health failure/ejection state, and restarts slow-start ramp
when slow-start is configured. `normal` clears only runtime overrides; static
`drain_upstreams` and `disabled_upstreams` remain enforced until the config
changes. Runtime member state is in-memory unless
`proxy.load_balance.runtime_state_file` is configured for that pool. Mutation
responses include `"persistent": true` when the pool has a local runtime state
file and `"persistent": false` otherwise. The response also includes
`scope = "vhost"` or `"route"` so operators can audit which pool was changed.
In `privacy-mode`, member mutation responses and structured mutation logs omit
backend addresses just like status output. Member fields use configured aliases
when present and `redacted` otherwise. Successful and rejected mutation metrics
keep member attribution in normal builds and use configured aliases only in
privacy-mode.
For dynamic DNS/file/HTTP-discovery pools, Fluxheim may reclaim stale runtime
`drain` overrides after a member disappears from the live discovery set.
Runtime `disable` and `forced_down` overrides are retained across discovery
churn and are cleared only by explicit `normal` or `manual_resume` admin action.
The retained runtime override table is bounded; if the table is full, new
runtime state or weight overrides fail with a bounded admin error instead of
growing memory without limit.
Successful and rejected member-state operations are logged under the
`fluxheim::load_balancer` target and, when metrics are compiled, counted by
`fluxheim_load_balancer_events_total` with bounded events `member_state`,
`member_state_invalid`, and `member_state_not_found`.

Authenticated admins can also mutate the runtime backend set for static
upstream pools:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-add?vhost=app&member=127.0.0.1:3002&weight=2"

curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-update?vhost=app&member=127.0.0.1:3002&weight=5"

curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-remove?vhost=app&member=127.0.0.1:3002"
```

`member-add` takes a socket-address `member` and optional numeric `weight`
between `1` and `1000` (default `1`). `member-update` takes the existing
`member`, optional `weight`, and optional replacement address via `address`,
`new_member`, `X-Fluxheim-Lb-Address`, or `X-Fluxheim-Lb-New-Member`.
Address retargeting is rejected for aliased members because aliases are part of
the static config identity; change those through config reload. `member-remove`
removes an existing configured address or alias. The backend set and health map
are published as one atomic runtime snapshot, so status and selection do not
observe a half-updated pool. Remove and address-update operations reject members
with active in-flight connections; drain the member first, wait for it to reach
zero in-flight requests, then remove or retarget it. The in-flight check is a
best-effort ordering gate at mutation time; a very narrow race can still allow
one already-selected request to complete against the old member after removal
or retarget, and Fluxheim emits a load-balancer warning if that is observed.
Runtime backend sets are capped at 256 members in this release; remove a member
before adding another when the cap is reached.

Runtime backend-set mutation is available only for static upstream pools in
this release. It is rejected for DNS/file/HTTP-discovery pools because
discovery refresh would overwrite local admin changes. It is also rejected for
Maglev selectors because Maglev requires a rebuilt lookup table; use a
non-Maglev selector for runtime backend-set changes. Runtime-added or retargeted members
carry only address and configured weight; aliases, tags, backup membership,
priority groups, locality metadata, and per-upstream caps still come from the
static config and require reload. Backend-set additions, removals, and
configured-weight updates are in-memory control-plane actions and are reported
with `"persistent": false`; `proxy.load_balance.runtime_state_file` currently
persists runtime member-state overrides, runtime weight overrides, and local
persistence tables, not the mutated backend set itself.

Authenticated admins can adjust the runtime weight of an already configured
member without reloading when the pool uses `round-robin`, `least-connections`,
`least-sessions`, or `least-time` selection:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-weight?vhost=app&member=app-a&weight=25"
```

Use `weight = "default"`, `reset`, `clear`, or `configured` to remove the
runtime override and return to the configured `upstream_weights` value. Runtime
weights are bounded to `1..=1000`, are local/in-memory like runtime member
state, and are returned in backend status as `effective_weight`,
`runtime_weight_override`, and `runtime_weight_changed_at_unix_secs`.
For dynamic DNS/file/HTTP-discovery pools, runtime weight overrides are retained
while the same backend is explicitly `disable`d or `forced_down`, and are
otherwise reclaimed after the backend leaves the live discovery set.
Successful and rejected weight operations are counted as `member_weight`,
`member_weight_invalid`, and `member_weight_not_found`.

Authenticated admins can fetch only load-balancer runtime state without parsing
the full `/_fluxheim/status` payload:

```bash
curl -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/status"
```

The response is `{"status":"ok","load_balancer":...}` and uses the same
runtime pool schema embedded in `/_fluxheim/status`: vhost pools, route pools,
backend health, runtime member-state overrides, queue depth, persistence table
size, circuit/passive-health state, slow-start state, locality, tags, aliases,
and in-flight counts. When `admin.ops_socket.enabled = true`, the same read-only
endpoint is available over the local Unix ops socket. It follows
`admin.ops_socket.require_bearer_token`; unlike status endpoints,
`/_fluxheim/snapshots` always requires bearer authentication.

Authenticated admins can clear the local persistence table for one configured
vhost or route pool without reloading:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/persistence/clear?vhost=app"
```

Use the optional `route` query parameter or `X-Fluxheim-Lb-Route` header to
target a route-local pool. The response includes `cleared_entries`,
`scope = "vhost"` or `"route"`, and a `persistent` boolean. The operation is
local to the current runtime unless `proxy.load_balance.runtime_state_file` is
configured for that pool, in which case the cleared table is written back to
the local runtime state file; it does not alter config or durable snapshots.
When metrics are compiled, successful clears are counted as
`persistence_clear` in `fluxheim_load_balancer_events_total`; rejected clear
requests are counted separately as `persistence_clear_invalid` or
`persistence_clear_not_found`.

`admin.client_certificate` is an extra hardening gate for that trusted
terminator pattern. The admin listener still receives plain HTTP from the
trusted local sidecar, but Fluxheim can require a validated downstream client
certificate fingerprint that the sidecar injects into `sha256_header`.
`required = true` rejects requests without a single valid 64-character SHA-256
hex value, `deny_sha256` rejects matching fingerprints, and `allow_sha256`
restricts admin access to the listed fingerprints when it is non-empty. The
trusted terminator must strip any incoming copy of this header before adding its
own value; do not rely on this option for directly exposed cleartext admin
listeners.
When this option is enabled on a loopback admin listener, Fluxheim emits a
security warning because local processes can inject the configured header unless
a trusted local terminator strips and rewrites it.

Admin endpoint paths are capped at 2048 bytes and query strings are capped at
16 KiB before endpoint-specific parsing. Prefer headers for long cache purge
values.

`admin.auth_throttle` is enabled by default and protects all authenticated
`/_fluxheim/*` endpoints, including the built-in health check unless it is
explicitly configured for loopback-only unauthenticated probes. Repeated failed
bearer-token attempts are tracked per direct socket source and globally over
`window_secs`; once either limit is reached, Fluxheim returns `429` until the
progressive lockout expires. `max_sources` bounds the in-memory per-source
failure table. With metrics enabled,
`fluxheim_admin_auth_events_total{event,scope}` records failed and throttled
admin authentication events, and security logs are emitted without reflecting
the attempted token.

The protected cache purge endpoints accept the optional `vhost` and `route`
query parameters, or `x-fluxheim-cache-vhost` and
`x-fluxheim-cache-route` headers, to target either a vhost cache policy or a
named route-scoped cache policy. Route names are resolved within the selected
vhost. Purge responses include the selected vhost/route, the normalized
`host`, `method`, `path`, optional query, cache key, and per-tier purge result
so bulk purge output can be audited without decoding cache keys.
Indexed scope, prefix, tag, and wildcard purge endpoints accept `soft=true` or
`x-fluxheim-cache-soft: true` to mark matched objects stale without deleting
their cached bodies. Hard purge remains the default.

`admin.self_healing.health_path` must be an absolute path no longer than 2048
bytes and cannot contain whitespace, control characters, backslashes, `?`, or
`#`. Custom health paths must not use the protected `/_fluxheim/` admin prefix.
The built-in `/_fluxheim/health` endpoint requires bearer-token authentication
by default. Set `[admin.health] unauthenticated = true` only for loopback-bound
local probes; validation rejects unauthenticated health on non-loopback admin
listeners. `admin.health.response = "minimal"` returns an empty `204` instead
of the default JSON status body to reduce fingerprinting.

Snapshot messages submitted through the admin API are trimmed and capped at
4096 bytes of non-control text before they are persisted.

On Linux, `token_file` is opened without following symlinks, must resolve to a
regular file handle, must not sit below a symlinked or group- or world-writable parent
directory, and is capped at 8 KiB both before and during the read. Prefer
rootless container secrets or a local file readable only by the Fluxheim user.

## Metrics

`[metrics]` is disabled by default and should remain loopback-only unless it is
fronted by a trusted local monitoring agent.

```toml
[metrics]
enabled = false
listen = "127.0.0.1:9091"
require_loopback = true

[metrics.otlp]
enabled = false
endpoint = "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
service_name = "fluxheim"
interval_secs = 15
timeout_secs = 2
# Optional PEM CA bundle for private-PKI HTTPS collectors.
# tls_ca_cert_path = "/etc/fluxheim/otlp-ca.pem"
```

The `metrics` compile-time feature is not part of `profile-privacy`.
`metrics.otlp.enabled = true` requires the `metrics-otlp` feature. The exporter
sends OTLP/HTTP JSON to `http://` or `https://` endpoints. Prefer local
loopback HTTP for same-host collectors and HTTPS for remote collectors.
`metrics.otlp.tls_ca_cert_path` can point at a PEM CA bundle for private PKI
collectors; when omitted, the bundled WebPKI roots are used. Plaintext HTTP to
non-loopback collectors logs a warning. When enabled,
`fluxheim_metrics_otlp_exports_total{outcome}` records bounded exporter success
and failure attempts through the local Prometheus metrics surface.

## Tracing

`[tracing]` is disabled by default and requires a build with the
`otel-tracing` feature, or a profile that includes it such as
`profile-observability`.

```toml
[tracing]
enabled = false
mode = "propagate_only"
traceparent = true
log_trace_id = true

[tracing.otlp]
enabled = false
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "fluxheim"
queue_size = 8192
timeout_secs = 2
# Optional PEM CA bundle for private-PKI HTTPS collectors.
# tls_ca_cert_path = "/etc/fluxheim/otlp-ca.pem"
```

Implemented values:

- `mode = "propagate_only"` validates W3C `traceparent`, generates a trace
  context when needed, and forwards a normalized `traceparent` to upstreams.
- `traceparent = true` enables inbound/outbound W3C Trace Context propagation.
- `log_trace_id = true` adds `trace_id` to structured access logs when tracing
  is enabled.

`tracing.enabled = true` is rejected when Fluxheim is built without
`otel-tracing`. `tracing.otlp.enabled = true` requires the `otel-otlp` feature.
The exporter supports OTLP/HTTP JSON over `http://` or `https://`.
`tracing.otlp.tls_ca_cert_path` can point at a PEM CA bundle for private PKI
collectors; when omitted, the bundled WebPKI roots are used. Prefer loopback
HTTP for local collectors and HTTPS for remote collectors; plaintext HTTP to a
non-loopback collector logs a warning. When Fluxheim is built with the `cache`
feature, exported request spans include bounded cache attributes for the cache
phase plus cache lookup and request-collapsing wait durations. They do not
include cache keys, paths beyond the normal HTTP span name, query strings,
cookies, or request header values. `otel-tracing` and `otel-otlp` are
incompatible with `privacy-mode`.
Load-balanced spans may include `fluxheim.load_balancer.upstream` from the
configured `proxy.upstream_aliases` value and
`fluxheim.load_balancer.retries`; raw upstream URLs are not exported as trace
attributes.

## Logging

```toml
[logging]
level = "info"
format = "json"
target = "stderr"

[logging.file]
enabled = false
# path = "/var/log/fluxheim/fluxheim.log"
append = true

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true
request_id_header = "x-request-id"
```

`level` values: `error`, `warn`, `info`, `debug`, `trace`.

`format` values: `json`, `text`.

`target` values: `stderr`, `stdout`. File logging overrides this stream target
when `logging.file.enabled = true`.

`logging.file` is disabled by default. When enabled, `path` is required. Relative
paths are resolved from the config file that defines them. Existing symlinked
path prefixes are rejected during config validation, and Linux opens the log file
without following a final symlink. Runtime log-file open also rejects symlinked
path components before creating or appending the file, so restart and rotation
paths apply the same trust boundary as config validation. On Unix, file logs
must use a dedicated log directory and are rejected when the nearest existing
parent is group- or world-writable, such as `/tmp`.

In `privacy-mode` builds, access logging and file logging must stay disabled.
Fluxheim rejects `logging.access.enabled = true` and
`logging.file.enabled = true`.

`logging.access.include_path = false` keeps access logging enabled while
emitting an empty `path` field. This is useful when request paths may contain
tenant IDs, filenames, or other sensitive identifiers.

`logging.access.include_host = false` keeps access logging enabled while
emitting an empty raw `host` field. The configured `vhost` name is still logged
after Fluxheim resolves the request.

`logging.access.include_client_ip = false` emits an empty `client_ip` field.
When enabled, the logged address is the same trusted-proxy-aware client IP used
by access policy and rate limiting.

`logging.access.include_cache_phase = false` emits an empty `cache_phase` field.
When enabled in cache-capable builds, Fluxheim logs the effective request cache
phase, such as `hit`, `miss`, `bypass`, or `disabled`.

Access log events include `compression_encoding` when Fluxheim applies response
compression; the field is empty when the response is served without a Fluxheim
compression encoder.

Access log events include downstream TLS identity fields:
`tls_version`, `tls_cipher`, `tls_client_cert_sha256`,
`tls_client_cert_serial`, and `tls_client_cert_organization`. These fields are
empty when the request is not TLS, when no client certificate was presented, or
when the selected TLS backend does not expose a given certificate attribute.

Access log events also include the resolved route name and selected upstream
address when a request reaches a proxy action; fallback, local static, or
unrouted requests emit empty `route` or `upstream` fields as applicable.
Load-balanced requests also include `upstream_alias` when configured through
`proxy.upstream_aliases`, plus `upstream_retries` for the number of retry
attempts Fluxheim made after the first selected upstream.

`logging.access.include_route = false` emits an empty `route` field.
`logging.access.include_upstream = false` emits empty `upstream` and
`upstream_alias` fields, which is useful when internal backend addresses or
operator-defined backend labels should not appear in logs.

## Headers

Header policies can be global or per-vhost. Vhost policies overlay the global
policy.

```toml
[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false
remove = ["x-powered-by"]

[headers.request.add]
x-proxy-by = "Fluxheim"
x-real-ip = "{remote_addr}"
x-forwarded-host = "{host}"
x-forwarded-proto = "{scheme}"

[headers.request.append]
via = "fluxheim"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
remove = ["x-powered-by"]

[headers.response.add]
cache-control = "public, max-age=60"

[headers.response.append]
vary = ["Accept-Encoding"]

[headers.response.operations]
remove = ["x-origin-banner"]
add = { x-content-source = "fluxheim" }

[[headers.response.rewrite.location]]
from = "http://backend.internal/"
to = "https://www.example.com/"

[[headers.response.rewrite.refresh]]
from = "http://backend.internal/"
to = "https://www.example.com/"

[[headers.response.rewrite.cookie_domain]]
from = "backend.internal"
to = "www.example.com"

[[headers.response.rewrite.cookie_path]]
from = "/app/"
to = "/"
```

`x_forwarded_for` values: `off`, `replace`, `append`. `x_real_ip = true`
emits `X-Real-IP` from the effective client address. If the direct peer matches
`server.trusted_proxies`, Fluxheim recursively restores that address from the
trusted `X-Forwarded-For` chain before writing `X-Real-IP`, `X-Forwarded-For`,
`Forwarded`, or `{remote_addr}` templates. In privacy builds it defaults off and
client-IP forwarding remains stripped. IPv4-mapped IPv6 socket addresses such as
`::ffff:192.0.2.10` are normalized to IPv4 before trusted-proxy, access-policy,
rate-limit, and GeoIP decisions, so IPv4 CIDR rules apply consistently on
dual-stack listeners.

Request header values can use a small safe dynamic template set:

- `{host}`: original request `Host` header.
- `{remote_addr}`: observed client IP address.
- `{scheme}`: `http` or `https` from the downstream listener.
- `{uri}`: current request path and query.
- `{path}`: current request path.
- `{query}`: current request query without `?`, or empty.
- `{request_id}`: Fluxheim request ID when access request IDs are enabled.
- `{tls.cipher}` and `{tls.version}`: downstream TLS cipher and protocol when
  the request arrived over TLS.
- `{tls.client_cert_sha256}`: lowercase SHA-256 fingerprint of the verified
  downstream client certificate when one was presented.
- `{tls.client_cert_serial}` and `{tls.client_cert_organization}`: serial number
  and organization parsed from the verified downstream client certificate when
  the TLS backend exposes them.
- `{http.<header-name>}`: safe request-header forwarding, for example
  `{http.upgrade}`.

Unknown variables fail config validation. Rendered values are still passed
through HTTP header validation before Fluxheim sends them upstream.
Do not put TLS identity templates in `[headers.request.append]` or
`[vhosts.headers.request.append]`; Fluxheim rejects that configuration because
an attacker-supplied inbound header would otherwise remain before the
TLS-derived value. Use `add`/`set` for TLS identity headers so Fluxheim removes
any inbound copy before forwarding the trusted value.

Common proxy migration headers:

```toml
[headers.request.add]
host = "{host}"
x-real-ip = "{remote_addr}"
x-forwarded-for = "{remote_addr}"
x-forwarded-proto = "{scheme}"
x-forwarded-host = "{host}"
x-client-cert-sha256 = "{tls.client_cert_sha256}"
upgrade = "{http.upgrade}"
connection = "upgrade"
```

Prefer the typed `x_forwarded_for`, `x_real_ip`, `x_forwarded_host`, and
`x_forwarded_proto` fields where they fit. Use dynamic values when a backend
expects an exact legacy-style header.

For header mutations, `remove`/`add` are the preferred readable names.
`unset`/`set` remain supported for compatibility. The nested
`[headers.request.operations]`, `[headers.response.operations]`, and
`[vhosts.headers.*.operations]` tables are useful when you want all explicit
header operations grouped together. Do not define the same header in more than
one `set`, `add`, or `operations.add` table in the same policy; Fluxheim rejects
that as ambiguous. Each header mutation policy is bounded: remove/unset, set/add,
and append header-name collections are capped at 128 entries each, and a single
append header may contain at most 32 values. Static header values must be
non-empty after trimming and cannot contain HTTP control bytes, including
horizontal tab, so one config works safely for both HTTP/1.x and HTTP/2
upstreams. Dynamic template variables strip control characters before insertion.

Security headers are easy to enable globally:

```toml
[headers.response]
content_security_policy = "default-src 'self'"
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"

[headers.response.hsts]
enabled = true
max_age_secs = 63072000
include_subdomains = false
preload = false
```

You may still set `headers.response.strict_transport_security` directly as a raw
header value, but do not combine it with `[headers.response.hsts]` in the same
policy. HSTS and CSP are intentionally not enabled blindly in examples because
they are site-specific and can break local HTTP testing or asset policies.

Fluxheim sets `Server: fluxheim` and strips `X-Powered-By` by default. Operators
who do not want a server banner can remove it with `remove = ["server"]`, and
operators who want a different banner can set one through
`[headers.response.add]`.

`[[headers.response.rewrite.location]]` and
`[[headers.response.rewrite.refresh]]` provide bounded prefix rewrites for
upstream redirect headers, similar to NGINX `proxy_redirect` or Apache
`ProxyPassReverse`. `Location` rewrites apply to the whole header value.
`Refresh` rewrites apply only to the URL after `url=` and preserve the refresh
delay. Quoted `Refresh` URLs such as `url="https://backend/"` and
`url='https://backend/'` are matched against the unquoted URL and keep their
quote style after rewriting. `from` and `to` values must be absolute
`http://` / `https://` prefixes or absolute paths, must not contain control
characters, and each header supports up to 32 rules. When `from` is an absolute
URL prefix, Fluxheim only rewrites matches that end at the URL boundary or are
followed by `/`, `?`, or `#`; this prevents authority-continuation values such
as `http://backend.internal@evil.example/` from matching a backend origin
prefix.

`[[headers.response.rewrite.cookie_domain]]` and
`[[headers.response.rewrite.cookie_path]]` rewrite `Set-Cookie` `Domain=` and
`Path=` attributes. Domain rewrites are exact case-insensitive matches against
safe ASCII domain labels. Path rewrites are prefix replacements and must use
absolute paths. Vhost and route response-header policies inherit global rewrite
rules and can append additional rules.

## Proxy

`[proxy]` is the global fallback proxy policy. Vhosts can override it with
`[vhosts.proxy]`.

```toml
[proxy]
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
upstream_weights = [1, 2]
upstream_priority_groups = [100, 50]
upstream_priority_group_min_active = 1
upstream_localities = ["site-a", "site-b"]
preferred_upstream_localities = ["site-a"]
upstream_max_in_flight = [256, 512]
upstream_aliases = ["app-a", "app-b"]
upstream_tags = [["blue", "primary"], ["green"]]
backup_upstreams = ["127.0.0.1:3001"]
drain_upstreams = []
disabled_upstreams = []
upstream_tls = false
upstream_sni = "origin.example.test"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_alternative_cn = "fallback-origin.example.test"
upstream_ca_path = "/etc/fluxheim/upstreams/origin-ca.pem"
upstream_client_cert_path = "/etc/fluxheim/upstreams/client-chain.pem"
upstream_client_key_path = "/etc/fluxheim/upstreams/client-key.pem"
upstream_proxy_protocol = "off"
upstream_http_version = "http1"
websocket = false

[proxy.auth_request]
enabled = false
# url = "http://127.0.0.1:4180/auth"
forward_headers = ["authorization", "cookie"]
allow_response_headers = ["x-auth-request-user", "x-auth-request-email"]
connect_timeout_secs = 2
read_timeout_secs = 5
max_response_bytes = "64KiB"

[proxy.mirror]
enabled = false
# base_url = "http://127.0.0.1:9000/shadow"
sample_per_mille = 1000
methods = ["GET", "HEAD", "OPTIONS"]
forward_headers = ["user-agent"]
timeout_secs = 2
max_response_bytes = "16KiB"
max_in_flight = 64

# upstream_h2_max_streams = 64
# upstream_h2_ping_interval_secs = 30
connect_timeout_secs = 5
upstream_total_connection_timeout_secs = 10
upstream_idle_timeout_secs = 120
upstream_tcp_keepalive_idle_secs = 30
upstream_tcp_keepalive_interval_secs = 10
upstream_tcp_keepalive_count = 3
upstream_tcp_user_timeout_ms = 15000
upstream_tcp_recv_buffer_bytes = "1MiB"
upstream_dscp = 46
upstream_tcp_fast_open = false
read_timeout_secs = 60
send_timeout_secs = 30
downstream_read_timeout_secs = 60
downstream_write_timeout_secs = 30
downstream_total_response_timeout_secs = 300
downstream_min_send_rate_bytes_per_sec = 8192

[proxy.load_balance]
selection = "round-robin"
max_iterations = 256
all_down_status = 502
# Optional local restart-persistent runtime state file for load-balancer member
# overrides and local persistence tables.
# runtime_state_file = "/var/lib/fluxheim/load-balancer/default.json"

[proxy.load_balance.health_check]
enabled = true
protocol = "tcp"
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
parallel = false
method = "GET"
path = "/"
host = "origin.example.test"
expected_statuses = []
expected_status_ranges = []
expected_headers = []
expected_body_contains = []
reuse_connection = false
connect_timeout_secs = 1
read_timeout_secs = 1

[proxy.load_balance.slow_start]
enabled = false
duration_secs = 30

[proxy.load_balance.passive_health]
enabled = false
consecutive_failure = 3
ejection_secs = 30
min_healthy_backends = 1
failure_statuses = []
failure_status_ranges = []
max_latency_ms = 0

[proxy.load_balance.retry]
enabled = false
max_retries = 1
methods = ["GET", "HEAD", "OPTIONS"]
statuses = []
status_ranges = []
budget_per_window = 0
budget_window_secs = 1

[proxy.load_balance.queue]
max_waiting = 0
timeout_ms = 0
retry_interval_ms = 10

[proxy.load_balance.persistence]
enabled = false
mode = "source-ip"
ttl_secs = 300
table_max_entries = 65536

[[proxy.error_pages]]
status = 502
path = "/502.html"

[proxy.error_pages.web]
root = "/srv/fluxheim/errors"
cache_control = "private, no-store"
```

Every `upstreams` entry must be an authority such as
`127.0.0.1:3000` or `origin.example.test:443`. Hostname authorities use the
same normalized DNS-label checks as incoming `Host` headers.
Proxy upstream lists are capped at 64 entries and reject duplicates
case-insensitively. Proxy error-page lists are also capped at 64 entries.
For load-balancer builds, `upstreams_file = "/run/fluxheim/backends/app.txt"`
can be used instead of `upstream` or `upstreams`. The file is read at startup
and refreshed every `upstreams_file_refresh_secs` seconds, with a default of
5 seconds and a bounded range of 1 through 300 seconds. The first file format is
deliberately small: one `host:port` or `ip:port` authority per line, blank lines
and full-line `#` comments ignored, 2 through 64 unique entries required.
Fluxheim reads the file with the same symlink and parent-permission hardening
used for other operator-controlled files. In this release, file-refreshed pools
cannot be combined with `upstream_weights`, `upstream_priority_groups`,
`upstream_localities`, `preferred_upstream_localities`,
`upstream_max_in_flight`, `upstream_aliases`, `upstream_tags`, `backup_upstreams`,
`drain_upstreams`, or `disabled_upstreams`; use static `upstreams` for those
policies.
For DNS-based service names, load-balancer builds can set
`upstream_dns_refresh_secs = 5` together with `upstreams = ["app.service:8080"]`.
Fluxheim resolves those authorities at startup and then refreshes them on the
configured 1 through 300 second interval. This first DNS-refresh slice is
mutually exclusive with `upstream`, `upstreams_file`, `upstream_weights`,
`upstream_priority_groups`, `upstream_localities`,
`preferred_upstream_localities`, `upstream_max_in_flight`, `upstream_aliases`,
`upstream_tags`, `backup_upstreams`, `drain_upstreams`, and
`disabled_upstreams`; use the
static pool form when those richer backend policies are required.
Resolved DNS addresses in private, loopback, link-local, multicast, reserved,
documentation, metadata, or unspecified ranges are rejected by default so a
compromised or attacker-controlled DNS record cannot silently rebind a public
service name to an internal backend. Set
`upstream_dns_allow_private_backends = true` only for trusted service-discovery
DNS zones that intentionally resolve to private service-network addresses.
For pull-based control-plane discovery, load-balancer builds can set
`upstreams_http_url = "https://control-plane.example.test/v1/upstreams"` instead
of `upstream`, `upstreams`, or `upstreams_file`. Fluxheim fetches the endpoint at
startup and refreshes it every `upstreams_http_refresh_secs` seconds, with a
default of 5 seconds and a bounded range of 1 through 300 seconds. The response
body is bounded to 64 KiB and must be JSON in either of these forms:
`["10.0.0.10:8080","10.0.0.11:8080"]` or
`{"upstreams":["10.0.0.10:8080","10.0.0.11:8080"]}`. The parsed upstream list
must contain 2 through 64 unique `host:port` or `ip:port` authorities. The
optional `upstreams_http_bearer_token_file` adds a `Bearer` token to the request;
the token file is validated with the same safe-path and parent-permission checks
used for other operator-controlled secret files, must not be empty, and must not
contain whitespace after trimming surrounding whitespace. Fluxheim sends
`Accept: application/json` and `Cache-Control: no-store`, and rejects non-JSON
`Content-Type` values when the discovery endpoint includes that header; missing
`Content-Type` is accepted so small internal sidecars can stay simple.
Returned IP-literal backends in private, loopback, link-local, multicast,
reserved, documentation, metadata, IPv4-mapped IPv6, IPv4-compatible IPv6,
6to4, or Teredo-embedded private ranges are rejected by default. Set
`upstreams_http_allow_private_backends = true` only when the configured
discovery endpoint is trusted to return private service-network members and the
route is intended to reach those networks.
Discovery endpoints must use HTTPS unless they are numeric loopback
`http://127.0.0.1` or `http://[::1]` control-plane sidecars. HTTP discovery is
intentionally pull-only in this
release: it does not watch Kubernetes, Consul, or xDS streams directly, and it
cannot be combined with per-member static policy lists such as weights,
localities, aliases, tags, backup, drain, disabled, or max-in-flight.
`examples/load-balancer-http-discovery.toml` contains a complete minimal
control-plane-backed load-balancer pool, including health checks, passive
health, retries, and queue policy.
Changing a load-balanced pool's discovery source, discovery refresh interval,
HTTP bearer-token file, or route/vhost pool membership is classified as a
process-upgrade change rather than a live snapshot reload because the refresh
loop is registered with the process service set at startup.
When `upstream_tls = true`, Fluxheim sends TLS to the origin. `upstream_sni`
overrides the SNI name; if it is omitted, Fluxheim derives SNI from the primary
upstream host. `upstream_verify_cert` and `upstream_verify_hostname` default to
`true`. Disabling certificate verification is an explicit insecure policy and
also requires `upstream_verify_hostname = false` so the config cannot imply
hostname validation while certificate validation is off. IP-addressed upstreams
with `upstream_tls = true` and certificate verification enabled require explicit
`upstream_sni`; otherwise the upstream TLS connector cannot perform normal
certificate verification. `upstream_alternative_cn` adds one additional hostname
that may match the upstream certificate when the configured SNI does not.
Wildcards are rejected for this field.
`upstream_ca_path` points at a PEM CA bundle used instead of the platform trust
store for this proxy policy. `upstream_client_cert_path` and
`upstream_client_key_path` configure an upstream client certificate and private
key for origin mTLS and must be set together. These file paths are resolved
relative to the containing config file, reject parent-directory traversal,
reject symlinked existing path components, and reject group/world-writable
existing parents. Rustls and OpenSSL builds support custom upstream trust roots
and upstream client certificates. BoringSSL and s2n are not supported Fluxheim
TLS backends.
`upstream_proxy_protocol` defaults to `off`. Set it to `v1` or `v2` to send a
HAProxy PROXY protocol header to the origin immediately after the upstream TCP/Unix
connection is established and before any upstream TLS handshake. The source
address is trusted-proxy-aware: if the direct peer is trusted and
`X-Forwarded-For` restores a client IP, that restored IP is used with source
port `0`; otherwise the direct downstream socket address is used. If Fluxheim
cannot produce a same-family TCP4/TCP6 source and destination pair, it sends
`PROXY UNKNOWN` for v1 or an empty v2 PROXY/UNSPEC frame for v2.
`upstream_http_version` defaults to `http1`. Set it to `http2` for origins
that require HTTP/2, including gRPC-style upstreams, or to `http1-and-http2`
to allow HTTP/2 with HTTP/1.1 fallback where the selected TLS/backend connector
can negotiate it. For plaintext origins, `http2` means h2c; use it only when
the origin is known to accept cleartext HTTP/2. `upstream_h2_max_streams`
limits concurrent streams per upstream HTTP/2 connection and must be between
1 and 1024. `upstream_h2_ping_interval_secs` enables upstream HTTP/2 keepalive
pings. Both h2 settings require `upstream_http_version` to allow HTTP/2.
For explicit gRPC routes, set route-scoped `[vhosts.routes.grpc] enabled =
true`; Fluxheim then requires the route proxy to allow upstream HTTP/2, rejects
non-`POST` requests, accepts only `application/grpc` or `application/grpc+*`
content types, and leaves gRPC-Web/JSON transcoding out of scope.
`connect_timeout_secs` bounds the low-level socket connect phase.
`upstream_total_connection_timeout_secs` wraps full upstream establishment,
including protocol/TLS setup where the selected connector exposes it.
`upstream_idle_timeout_secs` controls how long reusable idle upstream
connections remain in the native HTTP/1.1 upstream pool or the remaining
Pingora compatibility keepalive pool before they are closed.
`upstream_tcp_keepalive_idle_secs`, `upstream_tcp_keepalive_interval_secs`, and
`upstream_tcp_keepalive_count` configure TCP keepalive probes on upstream
connections and must be set together. `upstream_tcp_user_timeout_ms` maps to
Linux `TCP_USER_TIMEOUT` through the same keepalive setting and is ignored by
non-Linux kernels. `upstream_tcp_recv_buffer_bytes` requests a receive-buffer
size for new upstream sockets, capped at 256MiB. `upstream_dscp` accepts a DSCP
value from 0 through 63. `upstream_tcp_fast_open` enables upstream TCP Fast Open
where the platform and kernel allow it.
`upstream_weights` is optional and, when set, must contain one positive weight
for each `upstreams` entry. It enables weighted selection in `load-balancer`
builds. Each weight must be at most 1000 and the total configured weight must
fit in Pingora's weighted selector.
`upstream_priority_groups` is optional and, when set, must contain one priority
value for each `upstreams` entry. Higher values are preferred first, then lower
values are activated when higher priority groups have fewer than
`upstream_priority_group_min_active` selectable members. The activation
threshold defaults to `1`, matching strict preferred/fallback behavior. Each
priority group must be at most 1000. This is the static F5-style
preferred/fallback group foundation for the `1.5` load-balancer line.
`upstream_localities` is optional and, when set, must contain one safe
low-cardinality locality or failure-domain label for each `upstreams` entry.
`preferred_upstream_localities` is optional and must refer only to labels from
`upstream_localities`. When preferred localities are configured, selection tries
matching backends first and then falls back to all localities if no preferred
backend is selectable. This keeps same-site traffic preferred without turning a
site outage into a route outage. Locality labels are normalized
case-insensitively, capped at 64 bytes, and exposed in load-balancer runtime
status.
`upstream_max_in_flight` is optional and, when set, must contain one positive
concurrency cap for each `upstreams` entry. A capped backend is skipped when it
already has that many in-flight requests, regardless of the selected
load-balancing algorithm. Each cap must be at most 1000000.
`upstream_aliases` is optional and, when set, must contain one safe
low-cardinality alias for each `upstreams` entry. Aliases may contain ASCII
letters, digits, dots, dashes, and underscores, are capped at 64 bytes, and
must be unique case-insensitively. Fluxheim uses them only for operator-facing
metrics and status surfaces; they are not sent upstream and do not affect
selection.
`upstream_tags` is optional and, when set, must contain one tag list for each
`upstreams` entry. Tags use the same safe low-cardinality label syntax as
aliases, are capped at 16 tags per backend, must be unique per backend
case-insensitively, and are exposed only in load-balancer runtime status for
operator grouping and migration metadata. They are not sent upstream and do not
affect selection.
`backup_upstreams`, `drain_upstreams`, and `disabled_upstreams` are optional
subsets of `upstreams`. Backups stay out of normal rotation and are selected
only when no non-backup backend is currently selectable. Drained upstreams
remain configured for health and operator visibility but receive no new
selections. Disabled upstreams are the explicit administrative off state for a
configured member, are reported separately in load-balancer status, and show as
not ready in that status. Backup, drain, and disabled sets must not overlap,
and at least one upstream must remain a normal primary.
`proxy.load_balance.selection` defaults to `round-robin`. It also accepts
`least-connections`, `weighted-least-connections`,
`ratio-least-connections`, `least-sessions`, `least-time`, `power-of-two`,
`source-hash`, `uri-hash`, `header-hash`, `cookie-hash`, `consistent-source-hash`,
`consistent-uri-hash`, `consistent-header-hash`, and
`consistent-cookie-hash`, bounded-load consistent modes
`bounded-load-consistent-source-hash`,
`bounded-load-consistent-uri-hash`,
`bounded-load-consistent-header-hash`, and
`bounded-load-consistent-cookie-hash`, plus static-pool Maglev modes
`maglev` / `maglev-source-hash`, `maglev-uri-hash`,
`maglev-header-hash`, and `maglev-cookie-hash`. Header-hash modes require
`proxy.load_balance.hash_header = "x-session"` or another valid HTTP header
name. Cookie-hash modes require `proxy.load_balance.hash_cookie = "session"` or
another valid cookie name. Hash modes use weighted FNV selection seeded with a
per-boot secret. Consistent modes use Fluxheim-owned weighted rendezvous
hashing, also seeded with a per-boot secret, for low remapping when upstream
membership changes. Upgrading from the pre-1.5.7 Pingora ring-backed
consistent selector can remap existing affinity keys once. Bounded-load
consistent modes use the same rendezvous candidate ordering and skip a hash
target whose weighted in-flight pressure is above the configured soft bound
when another eligible candidate is available inside `max_iterations`; they
fall back to normal consistent selection if no bounded candidate is found.
`bounded_load_factor_per_mille` defaults to `1250`, meaning roughly 125% of
current weighted average load, and is valid only with bounded-load consistent
selectors. Maglev modes use a fixed 65,537-slot bounded lookup table for static
`proxy.upstreams` pools only; file-refreshed and DNS-refreshed pools reject
Maglev until dynamic table rebuild semantics are promoted later.
`max_iterations` bounds how many ready candidates Pingora or Fluxheim may
inspect while applying health, drain, slow-start, backup, priority, and
in-flight policies. `all_down_status` defaults to `502` and may be set to
another HTTP 5xx status, commonly `503`, for requests where a configured
load-balanced pool has no selectable backend. `least-connections`,
`weighted-least-connections`, and
`ratio-least-connections` all use the same Fluxheim-held in-flight request
permits, `upstream_weights`, and Pingora's current backend health state, so a
backend with weight `4` can carry roughly four times the in-flight request
share of a backend with weight `1`. `least-sessions` requires
`proxy.load_balance.persistence.enabled = true` and selects by the lowest
bounded persistence-entry share per backend, weighted by `upstream_weights`.
`least-time` uses the same request permits plus an EWMA of observed upstream
latency from completed requests, weighted by `upstream_weights`; unsampled
healthy backends are allowed to receive traffic so new or recovered pool
members can establish a latency baseline. Runtime weight overrides through the
admin API are honored by `round-robin`, `least-connections`, `least-sessions`,
and `least-time` in the current release. Hash, consistent hash, bounded-load
consistent hash, Maglev, and power-of-two selections reject runtime weight
changes until ring/table rebuild and sampling semantics are specified.
`power-of-two`
also accepts `power-of-two-choices`, `two-choice`, `weighted-two-choice`, and
`weighted-random-two-choice`; all names sample two healthy backends through
Pingora's random weighted selector and choose the lower weighted in-flight
pressure using `upstream_weights`.
With metrics enabled, load-balanced selections, unavailable pools, retries,
queue wait/full/timeout outcomes, and success/failure/ejection outcomes are counted by
`fluxheim_load_balancer_events_total` with bounded configured vhost/route
labels. The metric does not label raw upstream addresses; it uses
`upstream_aliases` when present and otherwise leaves the upstream label empty.
`fluxheim_load_balancer_pools` reports configured pool counts by bounded scope
(`vhost` or `route`) and bounded selection algorithm so dashboards can see which
load-balancing modes are active without labeling raw upstreams or route names.
Queued requests that actually wait also record
`fluxheim_load_balancer_queue_wait_seconds` by configured vhost/route and
bounded outcome (`waited` or `timeout`).
When persistence is enabled, the same counter records bounded
`persistence_hit`, `persistence_miss`, and `persistence_fallback` events.
`examples/load-balancer-enterprise.toml` is the validated 1.5 migration
fixture for a richer HAProxy/F5-style pool: weighted members, aliases, priority
groups, backup/drain policy, active and passive health, slow start,
source-IP persistence, retry budgets, metrics, and explicit all-down behavior.
`examples/load-balancer-exec-health.toml` shows the local exec health-check
shape for operators that need a bounded command monitor instead of a network
probe.
`examples/load-balancer-redis-health.toml` shows a Redis `PING` health-check
shape for Redis pools that expose no HTTP/gRPC health endpoint.
`examples/load-balancer-mysql-health.toml` shows a MySQL/MariaDB handshake
health-check shape for database pools where a TCP connect is too weak but
authentication or SQL execution is not acceptable.
`examples/load-balancer-postgres-health.toml` shows a PostgreSQL pre-auth
SSLRequest health-check shape for pools where a TCP connect is too weak but
authentication or SQL execution is not acceptable.
`proxy.load_balance.health_check.protocol` defaults to `tcp`, which verifies
TCP reachability and, when `upstream_tls = true`, a TLS handshake. Set
`protocol = "http"` to send `method` to `path`; `method` defaults to `GET` and
must be an uppercase HTTP token. By default only `200` passes, or
`expected_statuses = [200, 204]` can define an explicit allow-list.
`expected_status_ranges = [{ start = 200, end = 399 }]` accepts inclusive
HTTP status ranges and can be combined with exact statuses.
HTTP-family health checks may include bounded custom request headers for
authenticated or tenant-scoped health endpoints:

```toml
[[proxy.load_balance.health_check.request_headers]]
name = "Authorization"
value = "Bearer health-check-token"
```

Request headers are valid only for HTTP and gRPC health checks, are capped at
16 entries and 1024 bytes per value, reject duplicate names
case-insensitively, and reserve hop-by-hop headers plus `Host`. Use
`host = "app.internal"` for the HTTP Host header. Header values are not exposed
in metrics labels or runtime status, and are redacted from serialized config
views.
Set `protocol = "grpc"` to run the standard gRPC Health Checking Protocol over
HTTP/2. Fluxheim sends `POST /grpc.health.v1.Health/Check` with a bounded
hand-encoded request body and expects HTTP `200`, `content-type:
application/grpc`, and a `SERVING` response message. `grpc_service =
"package.Service"` optionally checks a specific gRPC service name. gRPC health
checks may use `host`, `request_headers`, timeout fields, and `port_override`;
HTTP status/header/body matchers are rejected because the standard gRPC health
response has its own fixed semantics.
Set `protocol = "redis"` to run a bounded Redis health check. Fluxheim opens a
TCP connection to the selected backend, sends one fixed RESP `PING` frame, and
requires a simple-string `+PONG` response. Redis checks use
`connect_timeout_secs` and `read_timeout_secs`, but reject request headers,
HTTP/gRPC response matchers, `host`, `port_override`, connection reuse, and
`parallel = true`. Redis health checks are probes only: they do not
authenticate, inspect keys, execute arbitrary Redis commands, or make Fluxheim
a Redis proxy. Redis TLS and authenticated Redis checks remain future work.
For local proof against a real Redis-compatible server, run
`scripts/smoke_redis_health_check.sh`; it starts Valkey in Podman, verifies
Valkey observes Fluxheim's `PING`, then stops Valkey and checks that Fluxheim
marks the Redis backend unhealthy.
Set `protocol = "mysql"` to run a bounded MySQL/MariaDB handshake health
check. Fluxheim opens a TCP connection to the selected backend, reads one
bounded MySQL server greeting packet, and requires a protocol-10 handshake with
a terminated server-version field. MySQL checks use `connect_timeout_secs` and
`read_timeout_secs`, but reject request headers, HTTP/gRPC response matchers,
`host`, `port_override`, connection reuse, and `parallel = true`. MySQL checks
are probes only: they do not authenticate, send a login packet, execute SQL,
inspect schemas, or make Fluxheim a MySQL proxy. MySQL TLS and authenticated
readiness checks remain future work. Because the probe intentionally disconnects
before authentication, non-loopback MySQL/MariaDB servers can count repeated
idle health probes against their host-cache error budget (`max_connect_errors`)
and eventually block all connections from the Fluxheim host until `FLUSH HOSTS`
or equivalent host-cache cleanup. For MySQL pools with low real traffic, set a
larger `max_connect_errors`, use conservative health-check intervals and
failure thresholds, or use an authenticated `exec` health check such as
`mysqladmin ping` when credentialed readiness is required.
For local proof against a real MySQL-compatible server, run
`scripts/smoke_mysql_health_check.sh`; it starts MariaDB in Podman, verifies
Fluxheim increases MariaDB's unauthenticated handshake counter, then stops
MariaDB and checks that Fluxheim marks the backend unhealthy.
Set `protocol = "postgres"` to run a bounded PostgreSQL protocol health check.
Fluxheim opens a TCP connection to the selected backend, sends PostgreSQL's
8-byte SSLRequest pre-auth handshake, and requires the one-byte `S` or `N`
SSLResponse. PostgreSQL checks use `connect_timeout_secs` and
`read_timeout_secs`, but reject request headers, HTTP/gRPC response matchers,
`host`, `port_override`, connection reuse, and `parallel = true`. PostgreSQL
checks are probes only: they do not authenticate, send a StartupMessage,
execute SQL, inspect schemas, or make Fluxheim a PostgreSQL proxy. PostgreSQL
TLS and authenticated readiness checks remain future work.
For local proof against a real PostgreSQL server, run
`scripts/smoke_postgres_health_check.sh`; it starts PostgreSQL in Podman,
verifies PostgreSQL observes Fluxheim's pre-auth connection, then stops
PostgreSQL and checks that Fluxheim marks the backend unhealthy.
Set `protocol = "exec"` to run an opt-in local command health check for
backends that cannot be represented by TCP/TLS, HTTP, gRPC, or JSON response
checks:

```toml
[proxy.load_balance.health_check]
protocol = "exec"
exec_command = "/usr/local/libexec/fluxheim-health"
exec_args = ["--probe"]
exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
exec_timeout_secs = 2
```

Exec health checks require an absolute command path without `.` or `..` path
components, and that exact path must appear in `exec_allowed_commands`.
Fluxheim does not invoke a shell, does not inherit the process environment,
and connects stdin/stdout/stderr to null devices. The command receives only
bounded backend context through
`FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST`, and
`FLUXHEIM_HEALTH_BACKEND_PORT`; host and port are empty for non-inet backend
addresses. `exec_args` are literal argv entries, not shell fragments.
`exec_timeout_secs` follows the normal health-check timeout bounds. Exec
checks are serial per pool in this release; `parallel = true` is rejected for
exec checks to avoid spawning many local processes at once. HTTP/gRPC
request-header and response-matcher fields, `host`, `port_override`,
`connect_timeout_secs`, and `read_timeout_secs` are rejected on exec checks so
this remains a local monitor, not a scripting engine.
Runtime load-balancer status exposes only the health-check protocol name
(`tcp`, `http`, `grpc`, `redis`, `mysql`, `postgres`, or `exec`) for operator
visibility; it does not expose exec command paths or arguments. Exec backend
summaries likewise identify the check as `via exec` without including the
configured command path.
Do not place secrets in `exec_command`, `exec_args`, or
`exec_allowed_commands`: they are normal configuration fields and may appear in
local config files, snapshots, backups, or operator review output. Use a local
root/service-owned helper that reads its own protected credential file if the
probe needs credentials.
`expected_body_json` performs bounded exact scalar matching against JSON health
responses without JSONPath, array indexing, expressions, or regexes:

```toml
expected_body_json = [
  { path = "status", equals = "ok" },
  { path = "database.connected", equals = "true" },
  { path = "queue_depth", equals = "42" },
]
```

Paths are dot-separated object fields capped at 256 bytes; values are compared
as strings after scalar JSON conversion. Object and array values are not
matchable.
HTTP and gRPC health responses may include `X-Health-Weight: N`, where `N` is
an integer from `1` through `100`. Values below `100` reduce the backend's
effective selection weight to that percentage of its configured/admin runtime
weight while the backend remains healthy; `100` or an absent header clears the
health-derived override. `health_weight_min_percent` defaults to `25`, so a
backend cannot self-report below 25% of its base weight unless the operator
explicitly lowers that floor. Invalid values fail the health check. Runtime
status exposes this as `health_weight_percent` separately from configured
weight and admin runtime weight overrides.
`expected_headers` can require exact response header values:
`expected_headers = [{ name = "x-fluxheim-health", value = "ready" }]`.
`expected_body_contains = ["ready"]` requires each configured byte substring
to appear in the HTTP health response body. Fluxheim reads at most 64 KiB of a
health-check body for this validation.
`host` overrides the health-check `Host` header and TLS SNI fallback. It must
not contain CR/LF or userinfo (`@`). `port_override` sends checks to a
different port on the same backend address.
Omit `port_override` to check the backend's normal port. `reuse_connection` is
accepted for configuration compatibility with older releases, but the native
HTTP/gRPC health-check client introduced in 1.6.17 opens a fresh bounded
connection per probe. `connect_timeout_secs` and `read_timeout_secs` are
optional active-check overrides; when omitted, checks inherit the proxy
upstream timeout where applicable and otherwise use Fluxheim's native
health-check defaults.
`proxy.load_balance.passive_health.enabled = true` adds opt-in passive outlier
detection. Fluxheim records selected upstream outcomes, treats 5xx responses as
failures by default, and temporarily ejects a backend after
`consecutive_failure` failures for `ejection_secs`. `min_healthy_backends`
defaults to `1`; when passive ejection would leave fewer than this number of
selectable backends, Fluxheim ignores passive ejection for that selection pass
instead of failing the entire pool. Set it to `0` only when strict fail-closed
behavior is preferred over availability during a full-pool passive ejection.
`failure_statuses` may narrow the failure set to specific 5xx status codes, and
`failure_status_ranges` accepts inclusive 5xx ranges such as
`[{ start = 520, end = 529 }]`. `max_latency_ms = 0` disables latency ejection;
a positive value treats responses at or above that latency as passive failures.
Passive ejection is also exposed in load-balancer runtime status as
`circuit_state = "open"` with a pool-level `circuit_open_backend_count` so
temporary outlier removal is explainable through the admin plane.
Active health checks and passive ejection are combined; if no backend is
currently selectable after the passive-health floor and other policy gates,
Fluxheim returns a proxy error instead of falling back to a configured primary
upstream. Disabled, drained, saturated, or active-health-unready backends are
not revived by the passive-health floor.
`proxy.load_balance.slow_start.enabled = true` warms newly seen and passively
recovered load-balanced backends over `duration_secs` before they receive their
full normal selection share. If all otherwise healthy candidates are still
warming, Fluxheim allows a selection instead of failing the entire pool, so
slow-start is a traffic-shaping guard rather than an availability blocker.
`proxy.load_balance.retry.enabled = true` enables bounded redispatch for
connection failures that happen before the request is sent upstream. It is
limited by `max_retries`, by Pingora's process-wide retry cap, and by
`methods`, which accepts only safe method tokens such as `GET`, `HEAD`,
`OPTIONS`, and `TRACE`. `statuses = [500, 502, 503]` can additionally
redispatch selected HTTP 5xx responses before response streaming starts, and
`status_ranges = [{ start = 520, end = 529 }]` accepts inclusive 5xx ranges.
Empty `statuses` and `status_ranges` keep response-status retries disabled.
`budget_per_window = 0` disables the shared retry budget; set it to a positive value with
`budget_window_secs` to cap total redispatch attempts for this vhost or route
over a moving window. Fluxheim does not retry after response streaming has
started.
`proxy.load_balance.queue` is disabled by default. Set both `max_waiting` and
`timeout_ms` to let a bounded number of requests wait briefly when no backend is
selectable, for example because every member is at its per-upstream
`upstream_max_in_flight` cap. `max_waiting = 0` and `timeout_ms = 0` preserve
the default immediate `all_down_status` behavior. When enabled, `max_waiting`
is capped at 100000, `timeout_ms` at 60000, and `retry_interval_ms` must be 1
through 1000. Waiting requests occupy only the load-balancer queue counter; no
upstream permit is held until a backend becomes selectable.
`proxy.load_balance.persistence.enabled = true` enables a bounded local
persistence table. `mode = "source-ip"` maps a client IP to the selected
backend for `ttl_secs`; `mode = "header"` maps the configured request `header`
value, for example an operator-trusted session header; `mode = "cookie"` maps
the configured request `cookie` value from the client request. `mode =
"managed-cookie"` creates a Fluxheim-owned signed/opaque affinity cookie with
`Set-Cookie` on eligible 2xx/3xx backend responses, verifies that cookie on
later requests, and maps the opaque cookie key to the selected backend in the
same bounded local table. Managed-cookie values do not expose backend
addresses, aliases, or weights. Configure the cookie name through `cookie =
"fluxheim_lb"` and optional attributes through `managed_cookie_domain`,
`managed_cookie_path` (default `/`), `managed_cookie_secure` (default `true`),
`managed_cookie_http_only` (default `true`), `managed_cookie_same_site`
(default `lax`), and `managed_cookie_max_age_secs` (default `ttl_secs`).
`SameSite=None` requires `managed_cookie_secure = true`. Managed-cookie
signing keys are generated locally at process start, rotated daily, and verified
against the current or previous key generation so in-flight cookies survive a
normal rotation window.
Stored backends are reused while they remain ready, not
drained/disabled/forced-down, not passively ejected, and below their in-flight
cap. If the stored backend is no longer selectable, Fluxheim falls back to the
normal load-balancing algorithm and refreshes the table with the new backend.
`table_max_entries` bounds memory use; expired entries are pruned and the oldest
expiry is evicted when the table is full. Without
`proxy.load_balance.runtime_state_file`, persistence is local to one Fluxheim
process and is reset by process restart, runtime rebuild, or the authenticated
persistence-clear admin operation. It is rejected in `privacy-mode` builds
because persistence retains client-derived identifiers.

`proxy.load_balance.runtime_state_file` enables local restart persistence for
runtime member-state overrides, runtime weight overrides, and bounded local
persistence-table entries. The state file is JSON, versioned, size-limited,
written atomically with a private file mode, and read with symlink checks.
Corrupt, oversized, incompatible, or stale state is ignored and rebuilt instead
of poisoning the pool. The file is local to one Fluxheim process and does not
share managed-cookie signing keys across nodes.

When persistence is enabled, the state file includes local affinity table keys.
`source-ip` mode writes client IP bytes, `header` mode writes the configured
header value, and `cookie` mode writes the configured cookie value.
`managed-cookie` mode writes opaque affinity keys generated by Fluxheim. Use
`managed-cookie` for session affinity when possible, or place the state file on
an encrypted, access-restricted volume when raw header or cookie identifiers are
used.

The current load-balancer implementation does not apply runtime weights to
hash/ring selectors, share managed-cookie signing keys across nodes, or
synchronize load-balancer state across active-active Fluxheim nodes.
Managed-cookie HA mirroring is tracked separately from the local managed-cookie
table shipped in `1.5.3`; see
[Load Balancer HA Design Notes](load-balancer-ha.md).

`upstreams` is the preferred static proxy target form for both one and many origins.
The older single `upstream = "host:port"` field remains supported for simple
configs, but do not set both fields in the same proxy block. Fluxheim rejects
that as ambiguous. `upstreams_file` is also mutually exclusive with both static
forms. A single `upstreams = ["host:port"]` entry behaves like a
normal single proxy target in all builds and is resolved when requests are
proxied, so a missing backend does not prevent the gateway from starting. Two
or more entries activate the Fluxheim load-balancer path in builds compiled
with `load-balancer`; those entries may be resolved by load-balancer setup and
health checking. File-refreshed and DNS-refreshed pools also use the
load-balancer path and keep serving the previous healthy set when a later
refresh is invalid. The same `proxy.load_balance` policy applies inside
`[[vhosts.routes.proxy]]` route proxy blocks; route-level pools get their own
selection, passive-health, retry, and health-check state.
`connect_timeout_secs`, `read_timeout_secs`, and `send_timeout_secs` are
optional. They map to the upstream connection timeout, upstream response/read
timeout, and upstream request-body/write timeout. Optional and required
second-based proxy/PHP/load-balancer health-check timeout fields reject `0` and
values above `86400` seconds so a malformed config cannot pin connections or
workers indefinitely.
`websocket = true` enables HTTP/1.1 upgrade forwarding for websocket-style or
other token-based upgrade requests on that proxy block. Fluxheim validates this
with `upstream_http_version = "http1"` because HTTP/2 origins do not use the
same hop-by-hop upgrade mechanism.
`downstream_read_timeout_secs`,
`downstream_write_timeout_secs`,
`downstream_total_response_timeout_secs`, and
`downstream_min_send_rate_bytes_per_sec` protect the client-facing side of
proxied requests and responses. The read timeout caps each stalled downstream
request-body read and defaults to 60 seconds; this applies to HTTP/1 and to
HTTP/2 DATA-frame waits in Fluxheim's vendored Pingora core. The write timeout
caps each stalled downstream write and defaults to 30 seconds. The total
response timeout is an absolute HTTP/2 response-write lifetime bound and
defaults to 300 seconds; it is not reset by partial writes or client
`WINDOW_UPDATE` frames. The minimum send rate asks Pingora to derive a timeout
from each response chunk size and is mainly useful
against slow HTTP/1 clients. These fields are optional and can be set globally,
per vhost, or on a route-level proxy block.

Fluxheim also installs hardened downstream HTTP/2 handshake defaults whenever
HTTP/2 is enabled: decoded request header lists are capped at 64 KiB per stream
and remotely initiated concurrent streams are capped at 32 per connection.
HTTP/2 DATA frame size is kept at 16 KiB, the advertised receive window is
fixed at 64 KiB, per-stream send buffering is capped at 256 KiB, and
pending-accept reset streams are capped at 8 so slow-reading HTTP/2 clients
cannot use the h2 crate's larger defaults to accumulate unbounded response
buffers.
Fluxheim also enforces `server.limits.max_request_headers` after HTTP/2 header
decoding; duplicate header values such as split `Cookie` crumbs count toward
that limit. These service-level caps are applied before vhost routing because
HTTP/2 negotiation happens before a `Host`/`:authority` value can be trusted.

When `websocket = true` and the downstream request contains a valid
`Connection: Upgrade` token plus a valid `Upgrade` token, Fluxheim forwards the
request upstream with `Connection: upgrade` and the downstream upgrade token.
Upgrade requests bypass proxy cache policy and should normally use route-level
read/send timeouts sized for long-lived connections. Leave `websocket = false`
on normal HTTP routes; Fluxheim strips HTTP/1 `Connection` and `Upgrade`
request headers in that mode so normal proxy routes cannot tunnel upgraded
protocols accidentally.

`[proxy.auth_request]` is Fluxheim's NGINX-style external authorization hook for
proxy actions. When enabled, Fluxheim sends a bounded `GET` subrequest to `url`
before forwarding the real request. Only headers listed in `forward_headers`
are forwarded to the auth endpoint. For common request-context headers,
Fluxheim does not copy client-supplied values: `X-Original-URI`,
`X-Forwarded-URI`, `X-Auth-Request-Redirect`, `X-Forwarded-For`, `X-Real-IP`,
`X-Forwarded-Host`, and `X-Forwarded-Proto` are synthesized from the trusted
request context when those names are allow-listed. Repeated `Cookie` fields are
joined with `; ` before the auth subrequest, matching the origin request path.
Any 2xx auth response allows the request and headers listed in
`allow_response_headers` are copied into the upstream request; 4xx/5xx auth
responses stop the request and return the auth status with a bounded text body.
Other auth statuses are treated as a gateway-side auth failure. The hook can be
configured globally, per vhost proxy, or per route proxy block. In
FIPS/ISO-required mode, auth subrequests are limited to numeric local
`http://127.0.0.1/...` or `http://[::1]/...` sidecars until outbound TLS client
evidence is routed through the selected validated provider. With metrics
enabled, auth subrequest decisions are counted by
`fluxheim_edge_policy_events_total` with bounded `auth_request` policy labels
and `allow`, `deny`, or `error` outcomes.

`[[proxy.error_pages]]` entries are internal static fallback pages for proxy
failures. The `path` is an internal request path resolved below the entry's
`web.root`; it is not exposed as a public route unless you also configure a
route for that root.

`[proxy.mirror]` is an opt-in traffic shadowing hook available in binaries
built with the `traffic-mirror` feature. The first implementation mirrors only
safe, bodyless requests (`GET`, `HEAD`, `OPTIONS`, or `TRACE`) to `base_url`
and appends the original path and query. Mirror requests are fire-and-forget:
timeouts, response statuses, and failures never affect the primary response.
Only headers listed in `forward_headers` are copied; credentials and cookies are
not mirrored unless explicitly allow-listed. `sample_per_mille` deterministically
selects 1 through 1000 requests per 1000 for a stable method/host/path key.
`max_response_bytes` bounds how much of the mirror response Fluxheim drains
before discarding it. `max_in_flight` caps outstanding mirror worker tasks per
vhost/route mirror key; requests above the cap skip mirroring and continue on
the primary path. Mirroring is rejected in `privacy-mode`; in FIPS/ISO required
mode it is limited to numeric local `http://127.0.0.1/...` or
`http://[::1]/...` sidecars until outbound TLS client evidence is routed
through the selected validated provider.

## Compression

`[compression]` is a global opt-in response compression policy. It is available
only in binaries built with one or more codec features: `compression-gzip`,
`compression-zstd`, or `compression-brotli`. The 1.4 production profile aliases
used for official full/cache/proxy/PHP artifacts compile all three codecs so
operators can enable compression by vhost or route without rebuilding; default
developer builds still omit compression code. `privacy-mode` builds reject
compression at compile time.

```toml
[compression]
enabled = true
gzip = true
zstd = false
brotli = false
min_bytes = "1KiB"
max_input_bytes = "1MiB"
max_output_bytes = "2MiB"
gzip_level = 4
zstd_level = 3
brotli_quality = 4
```

Each vhost inherits the global compression policy unless it declares
`[vhosts.compression]`. Each route inherits the vhost compression policy unless
it declares `[vhosts.routes.compression]`. This lets one site enable
compression while another site continues to serve identity responses, or lets a
specific path prefix opt in or out:

```toml
[[vhosts]]
name = "docs"
hosts = ["docs.example.com"]

[vhosts.compression]
enabled = true
gzip = true
zstd = true
brotli = false
min_bytes = "1KiB"
max_input_bytes = "2MiB"
max_output_bytes = "4MiB"

[[vhosts.routes]]
name = "uploads"
path_prefix = "/wp-content/uploads/"

[vhosts.routes.proxy]
upstream = "127.0.0.1:8080"

[vhosts.routes.compression]
enabled = true
gzip = true
zstd = true
min_bytes = "1KiB"
max_input_bytes = "2MiB"
max_output_bytes = "4MiB"
```

The compression path compresses only eligible `GET` responses with known
`Content-Length`, status `200`, a matching client `Accept-Encoding`, no
existing `Content-Encoding`, no `Set-Cookie`, no request `Cookie` or
`Authorization`, no `Content-Range`, no `Cache-Control: no-transform`, and a
conservative text, JavaScript, JSON, XML, or SVG media type. Fluxheim prefers
`br`, then `zstd`, then `gzip` when those codecs are enabled and accepted by
the client. Fluxheim removes `Content-Length` and `ETag` from compressed
responses and adds `Vary: Accept-Encoding`. `Accept-Encoding` q-values are
parsed as finite RFC-style values from `0` through `1` with at most three
decimal digits; malformed values such as `NaN` or `Infinity` do not enable an
encoding token.

`min_bytes` and `max_input_bytes` bound the original response size.
`max_output_bytes` bounds the encoded response size. The configured input
maximum cannot exceed 64 MiB and the output maximum cannot exceed 128 MiB.
`gzip_level` must be between `0` and `9`, `zstd_level` between `1` and `19`,
and `brotli_quality` between `0` and `11`.

## Web

```toml
[web]
root = "/srv/sites/example"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
expires = "Wed, 21 Oct 2030 07:28:00 GMT"

[web.directory_listing]
enabled = false
exact_size = false
local_time = false
```

Static serving requires `web.root` to be a real directory, not a symlink and
not below a symlinked parent directory. Request paths are symlink-free,
including intermediate directories. Static serving also rejects traversal,
dotfiles by default, and unknown nested index file names. `index_files` is
capped at 32 entries. Static body reads
re-check the opened file handle and full-body reads are length-exact, failing
if the file changes while it is being read. The current static response path is
buffered and refuses response bodies larger than 64 MiB; larger-file streaming
is planned before this limit is relaxed. Static responses support MIME
detection, `GET`/`HEAD`, `ETag`, `If-Match`, `If-Unmodified-Since`,
`If-None-Match`, `If-Modified-Since`, and single byte ranges.

`web.directory_listing` is disabled by default. When enabled, Fluxheim only
generates a listing after no index file matches. Listings inherit dotfile
protection, skip symlink entries, cap entry count, and use `private, no-store`
so repository indexes are not accidentally cached by shared intermediaries.
`local_time = true` renders listing modification times with the server's local
UTC offset; otherwise listings use GMT HTTP-date timestamps.

`cache_control` is emitted on static responses and defaults to
`public, max-age=60`. Use response header policy when you need to append or
unset CDN-specific headers such as `Vary`, `Surrogate-Control`, or
provider-specific cache controls. `expires` is optional and must be an HTTP
header-safe value when set. Per-vhost static settings use `[vhosts.web]`.

## Cache

`[cache]` is disabled by default at runtime even when the `cache` feature is
compiled.

```toml
[cache]
preset = "none"
enabled = false
local_static = false
status_header = "X-Cache-Status"
status_reason_header = "X-Cache-Reason"
hide_response_headers = ["set-cookie"]
tag_headers = ["surrogate-key", "cache-tag", "x-cache-tags"]
no_store_response_headers = ["x-app-no-store"]
no_store_response_header_values = { x-app-cache = "private" }
bypass_path_prefixes = ["/wp-admin/"]
bypass_path_exact = ["/wp-login.php", "/xmlrpc.php"]
bypass_request_headers = ["cookie", "authorization"]
bypass_request_header_values = { x-preview-mode = "1" }
bypass_cookie_names = ["sessionid", "wordpress_logged_in"]
bypass_cookie_name_prefixes = ["wordpress_logged_in_", "wordpress_sec_"]
bypass_cookie_values = { preview = "1" }
bypass_query_params = ["preview", "token"]
bypass_query_values = { mode = "private" }
bypass_query = false
allow_client_cache_refresh = false
vary_request_headers = ["accept-encoding"]
ignore_origin_cache_headers = false
key_namespace = "repoheim-assets-v1"
key_parts = ["method", "host", "path", "query"]
min_uses = 2
pass_uncacheable_after = 3
status_ttls = { "200" = 3600, "404" = 60 }
default_status_ttl_secs = 15
stale_while_revalidate_secs = 30
stale_if_error_secs = 120
stale_if_error_on = ["connect", "timeout", "http-status"]
stale_if_error_statuses = [500, 502, 503, 504]
include_query = true
content_types = ["image/*", "text/css", "application/javascript", "font/*"]
extensions = ["avif", "css", "gif", "ico", "jpg", "js", "png", "svg", "webp", "woff2"]
methods = ["GET", "HEAD"]
max_object_bytes = "32MiB"

[cache.range]
enabled = false
max_bytes = "8MiB"

[cache.memory]
enabled = false
max_size_bytes = "1GiB"

[cache.disk]
enabled = false
backend = "filesystem"
path = "/var/cache/fluxheim"
max_size_bytes = "10GiB"

[cache.disk.storage_bin]
bin_size_bytes = "256MiB"
preallocate = false
max_open_bins = 16

[cache.disk.encryption]
enabled = false
provider = "local"
algorithm = "aes-256-gcm"
# key_id = "cache-v1"
# key_file = "/run/secrets/fluxheim-cache-key"
# key_credential = "fluxheim-cache-key"

# Optional OpenBao Transit provider for external key custody:
# provider = "openbao-transit"
#
# [cache.disk.encryption.openbao]
# address = "https://openbao.internal.example"
# mount = "transit"
# key_name = "fluxheim-cache"
# token_credential = "openbao-token"

[cache.lock]
enabled = true
age_timeout_secs = 30
wait_timeout_secs = 30

[cache.predictor]
enabled = false
capacity = 65536
```

If `cache.enabled = true`, at least one storage tier must be enabled.
Each enabled tier must be at least as large as `max_object_bytes`.
Disk cache requires `cache.disk.path`. The disk cache root must be a real
directory and must not sit below a symlinked parent directory. On Unix,
Fluxheim also rejects disk cache roots whose nearest existing parent is
group- or world-writable, such as creating a cache root directly below `/tmp`; use a
dedicated cache directory such as `/var/cache/fluxheim` or a pre-created private
runtime directory.

`[cache.range]` is disabled by default. When enabled, Fluxheim can cache safe
bounded single `Range: bytes=start-end` proxy responses under a range-specific
cache key. This is intended for large object workloads such as package mirrors,
media files, and resumable downloads where clients repeatedly request the same
byte window. Fluxheim only admits matching upstream `206 Partial Content`
responses whose `Content-Range` and `Content-Length` match the requested range;
unkeyed upstream `206` responses are rejected from the normal full-object cache
to avoid poisoning complete-object entries. Without slice caching,
`range.max_bytes` must be greater than zero and no larger than
`cache.max_object_bytes`.

`[cache.range.slice]` enables the `1.2.6` fixed-slice range cache. Fluxheim
normalizes client ranges into fixed-size slices, stores each slice under a
slice-specific key, and can compose fresh compatible slices into single-range,
open-ended, suffix, or `multipart/byteranges` responses. Missing slices can be
filled from origin with bounded single-slice `Range` requests when
`fill_missing = true`; concurrent fills for the same slice key are collapsed.
Slice fill rejects responses unless `206`, `Content-Range`, `Content-Length`,
content type, object length, and validators are compatible. `If-Range` requests
are served from slices only when the cached `ETag` or `Last-Modified` matches;
otherwise Fluxheim falls back to the normal proxy path. Exact admin purges also
remove indexed slices for the same request path.

```toml
[cache.range]
enabled = true
max_bytes = "128MiB"

[cache.range.slice]
enabled = true
size_bytes = "1MiB"
max_slices = 128
fill_missing = true
```

When `range.slice.enabled = true`, `range.max_bytes` may be larger than
`cache.max_object_bytes`, but `range.slice.size_bytes` must not exceed
`cache.max_object_bytes`, and `range.max_bytes` must not exceed
`range.slice.size_bytes * range.slice.max_slices`.

`cache.disk.backend` defaults to `filesystem`, the stable complete-object disk
backend used by `1.2.0` and `1.2.1`. `storage-bin` selects the focused `1.2.2`
slab/bin disk backend, which stores objects inside bounded `.fhbin` data files
with a durable object index and free-range reuse. The `[cache.disk.storage_bin]`
table defines the allocator shape:
`bin_size_bytes` must be at least `cache.max_object_bytes` and no larger than
`cache.disk.max_size_bytes`, `preallocate` controls whether Fluxheim should
reserve full bin files ahead of object writes, and `max_open_bins` bounds the
number of concurrently opened bin files.

`[cache.disk.encryption]` is disabled by default. When `enabled = true` with
`provider = "local"`, Fluxheim encrypts disk cache objects with AES-256-GCM
before they are written to the filesystem or storage-bin backend. The local key
must be a 64-character hex-encoded 256-bit key loaded from exactly one of
`key_file` or `key_credential`; credential names are resolved through
`$CREDENTIALS_DIRECTORY` when present or `/run/secrets` otherwise. `key_id`
is stored with the encrypted object and is included with the combined cache key
as authenticated data, so objects cannot be silently swapped between cache
keys. Local cache encryption is intended for cache-at-rest protection; it does
not encrypt memory cache contents.
Filesystem disk-cache fills with the local provider encrypt streamed objects in
bounded AEAD chunks, so enabling local encryption does not require Fluxheim to
copy a complete streamed origin response back into heap before committing it to
disk.

`provider = "openbao-transit"` uses OpenBao Transit for regulated deployments
that need centralized key custody and rotation. Fluxheim calls the Transit
`encrypt` and `decrypt` endpoints for disk cache objects and stores only the
returned `vault:v...` ciphertext in the filesystem or storage-bin backend. The
OpenBao endpoint must be HTTPS unless it is loopback HTTP, and the token must
come from exactly one safe `token_file` or `token_credential` source. The
configured key id plus combined cache key are passed as associated data, so a
stored ciphertext is bound to the cache object identity. The default local-key
provider does not require OpenBao. Transit calls do not follow HTTP redirects,
and Transit JSON responses are read with an explicit size limit before parsing.
OpenBao Transit accepts a single plaintext value per `encrypt` request, so
Fluxheim bounds concurrent OpenBao encrypted commit heap usage and may refuse a
cache fill instead of buffering too many large plaintext objects at once.

In FIPS/ISO-required mode, OpenBao Transit is further restricted to local
numeric loopback HTTP (`http://127.0.0.1` or `http://[::1]`). Remote OpenBao
and HTTPS OpenBao endpoints require outbound TLS evidence that Fluxheim does
not provide yet.

For local validation, `examples/podman-compose-openbao.yml` starts an OpenBao
development server and `scripts/smoke_openbao_cache_encryption.sh` runs an
end-to-end proxy-cache test against OpenBao Transit. The smoke test enables the
Transit engine, creates a cache key, serves a cacheable object through
Fluxheim, verifies `MISS` then `HIT`, and checks that the stored cache object
contains OpenBao `vault:v...` ciphertext rather than the plaintext response
body. It is intentionally optional because normal CI should not depend on a
local Podman/OpenBao runtime.
`examples/cache-encryption-local.toml` and
`examples/cache-encryption-openbao.toml` provide full example policies using
the storage-bin backend with local-key and OpenBao Transit encryption. See
`docs/cache-encryption.md` for key setup and rotation guidance.

`local_static` is disabled by default. When set to `true`, the same cache
policy may also store local `[web]`, `[vhosts.web]`, and route-scoped
`[vhosts.routes.web]` file responses. Local static caching is opt-in because it
changes an otherwise direct file-read path into a shared in-process cache path.
Fluxheim keys local static cache objects by the request cache key plus canonical
file identity metadata, so a changed local file creates a new cache key instead
of serving the old body. Memory storage is preferred when both memory and disk
tiers are configured, avoiding a second disk copy of files that already exist
under the static site root. Disk-only cache policies are still accepted for
operators who explicitly want disk-backed local static caching.

`status_header` is optional. When set, Fluxheim emits a cache debug header such
as `X-Cache-Status: HIT`, `MISS`, `STALE`, `BYPASS`, `EXPIRED`, or
`REVALIDATED` for requests that participate in the proxy cache or opt-in local
static cache.
`status_reason_header` is optional. When set, Fluxheim emits a bounded reason
header such as `OriginNotCache`, `ResponseTooLarge`, or `cache-min-uses` when
the cache phase has an explicit no-cache reason. Leave it unset unless you are
actively debugging cache policy.

`[cache.predictor]`, `[vhosts.cache.predictor]`, and
`[vhosts.routes.cache.predictor]` are opt-in Pingora cacheability predictors.
When enabled, Fluxheim can remember recent origin-level uncacheable outcomes
such as `private`/`no-store` cache responses or oversized responses and bypass
future cache lookup and cache locking for the same primary key until the
bounded predictor entry ages out of its LRU table. Fluxheim-specific custom
policy reasons are intentionally skipped so settings such as `min_uses`,
configured request bypasses, and explicit response-header refusal policies stay
controlled by Fluxheim's own policy counters.

`[cache.origin_protection]`, `[vhosts.cache.origin_protection]`, and
route-scoped `origin_protection` configure a cache-aware origin-fill budget for
Fluxheim-owned cache fill paths. It is disabled by default and requires the
owning cache policy to be enabled. The first protected path is range slice
fill: when a requested slice is missing locally and Fluxheim would fetch it
from origin, the request must acquire a per-vhost or per-route fill permit.

```toml
[cache.origin_protection]
enabled = true
max_concurrent_fills = 32
```

`max_concurrent_fills` is bounded to 1-1024. When the budget is saturated,
Fluxheim refuses the protected slice fill with `503` instead of falling through
to the normal origin path. This is intentionally fail-closed for origin
protection: operators should enable it only on cache policies where protecting
origin capacity is preferable to serving an uncached slice during brownout.
Existing cache locks still coalesce same-key fills; origin protection is a
route/vhost-level budget across distinct cache keys. Metrics builds expose
`fluxheim_cache_origin_protection_enabled_policies` and
`fluxheim_cache_origin_protection_max_concurrent_fills`, and policy activity
records `origin_protected` when the budget rejects a fill.

`[cache.peer_fill]`, `[vhosts.cache.peer_fill]`, and route-scoped
`peer_fill` configure the distributed-cache peer-fill contract used by the
`1.2.4` line. Peer fill is disabled by default and currently requires the
owning cache policy to be enabled. The configuration is intentionally strict so
runtime peer retrieval can stay bounded:

```toml
[cache.peer_fill]
enabled = true
connect_timeout_secs = 2
read_timeout_secs = 10
max_object_bytes = "32MiB"
max_concurrent_requests = 64
allow_insecure_http = false
fail_open = true

[[cache.peer_fill.peers]]
name = "edge-a"
base_url = "https://edge-a.internal.example:8443"

[[cache.peer_fill.peers]]
name = "edge-b"
base_url = "https://edge-b.internal.example:8443"
```

`peers` must contain between 1 and 32 entries when peer fill is enabled.
Peer names are short ASCII identifiers. Peer `base_url` values must be
HTTP(S) origins with an explicit `host:port`, no userinfo, no query or
fragment, and no path beyond `/`. Plain HTTP is accepted only for loopback
peers unless `allow_insecure_http = true`, which is intended for private test
networks or trusted in-cluster transport. `max_concurrent_requests` is bounded
to 1-1024 and `fail_open = true` means peer-fill failure should fall back to the
normal origin path rather than failing the user request. `max_concurrent_requests`
is enforced per vhost or route cache policy for active outbound peer-fill
fetches. If that limit is saturated, Fluxheim follows `fail_open`: fallback to
origin when allowed, or a bounded `504` miss response otherwise. The first
runtime primitive is available now:
proxy-cache requests with `Cache-Control: only-if-cached` are answered only from
a fresh local cache object and otherwise return `504` without contacting origin.
Outbound peer fill uses the same safe request mode on local proxy-cache misses,
stores valid peer hits locally, and falls back to origin only when `fail_open`
is true. Peer-fill requests do not forward the client `Host` header; peers
receive the authority from their configured `base_url` plus safe negotiation
headers such as `Accept`, `Accept-Encoding`, and `Accept-Language`.
Credentials such as `Authorization` and `Cookie` are not forwarded. Outbound
peer-fill requests carry `X-Fluxheim-Peer-Fill: 1`; inbound requests with that
marker are not allowed to launch another peer-fill fetch, which prevents
recursive peer-fill loops in cyclic peer topologies.
`examples/cache-peer-fill.toml` shows the focused validated fixture. Metrics
builds expose aggregate origin-protection and peer-fill configuration through
`fluxheim_cache_origin_protection_enabled_policies`,
`fluxheim_cache_origin_protection_max_concurrent_fills`,
`fluxheim_cache_peer_fill_enabled_policies`,
`fluxheim_cache_peer_fill_peers`, and
`fluxheim_cache_peer_fill_max_concurrent_requests`.

For offline debugging, `fluxheim cache-key --host example.com --path
/assets/app.js` previews the vhost/route cache policy and generated cache key
without contacting the upstream. `cache-key` can fail closed with
`--expect-eligible`, `--expect-ineligible`, `--expect-reason`,
`--expect-cache-lock-enabled`, `--expect-cache-lock-wait-timeout-secs`,
`--expect-cache-predictor-enabled`,
`--expect-origin-protection-enabled`,
`--expect-origin-protection-max-concurrent-fills`,
`--expect-peer-fill-enabled`, `--expect-peer-fill-peers`,
`--expect-peer-fill-max-concurrent-requests`,
`--expect-memory-tier-enabled`, `--expect-disk-tier-enabled`, and
`--expect-storage-tiers` when a deploy requires a specific cache policy layout.
Use `--expect-scope vhost|route`, `--expect-vhost NAME`, and
`--expect-route NAME` when a deploy must prove that a specific vhost or route
policy was selected. Use `--expect-namespace NAME` for the internal cache
namespace and `--expect-key-namespace NAME` / `--expect-user-tag TAG` when
cache namespace migrations or purge-scope automation must fail closed on the
exact selected key space.
`fluxheim cache-lookup --host example.com --path /assets/app.js` also checks
configured cache tiers and prints safe object
metadata without dumping bodies or header values, including a compact
fresh/stale/expired state and stale-serving eligibility booleans. Both commands
accept repeated `--header "Name: value"` options for safe negotiated variant
inspection, such as `Accept-Language` or `Accept-Encoding`; use `--host` for
the Host header. `cache-lookup` can fail closed for deploy scripts with
`--require-object`, `--expect-tier memory|disk`, `--expect-status`,
`--expect-body-bytes`, `--expect-fresh-ttl-secs`, `--expect-cache-tag`,
`--expect-header-name`, `--expect-header "Name: value"`, `--expect-objects`,
`--expect-cache-lock-enabled`,
`--expect-cache-lock-wait-timeout-secs`, `--expect-cache-predictor-enabled`,
`--expect-origin-protection-enabled`,
`--expect-origin-protection-max-concurrent-fills`,
`--expect-peer-fill-enabled`, `--expect-peer-fill-peers`,
`--expect-peer-fill-max-concurrent-requests`, `--expect-memory-tier-enabled`,
`--expect-disk-tier-enabled`,
`--expect-storage-tiers`, `--expect-scope`, `--expect-vhost`,
`--expect-route`, `--expect-namespace`, `--expect-key-namespace`,
`--expect-user-tag`,
`--expect-ineligible`, `--expect-reason`,
`--expect-serve-stale-if-error`,
`--expect-serve-stale-while-revalidate`, `--expect-purge-indexed`, and
`--expect-freshness-state fresh|stale|expired`.
`fluxheim cache-warm --header "Name: value"` warms negotiated variants with
the same safe request-header syntax, and `fluxheim cache-warm --dry-run`
validates bounded warm target input files, repeat counts, cache-status
expectations, request headers, and listener selection without sending requests,
which is useful
before release deploy jobs.
Proxy cache storage currently bypasses `HEAD` requests with
`X-Cache-Reason: method-head` to avoid unsafe body handling; this keeps HEAD
probes from corrupting `GET` cache entries. Full HEAD-to-GET cache parity is a
future compatibility feature, not the `1.2` stable behavior.
`hide_response_headers` removes selected upstream response headers before cache
admission and downstream delivery. Use it only on tightly matched cache routes,
for example to strip `Set-Cookie` from known static asset responses.
`tag_headers` controls which origin response headers are trusted as cache-tag
sources for indexed tag purge. The default is `surrogate-key`, `cache-tag`, and
`x-cache-tags`. Set it to a smaller list for application-specific tag headers,
or to `[]` to disable cache-tag indexing while keeping scope, prefix, stale,
and wildcard purge available.
`no_store_response_headers` rejects shared cache admission when any listed
origin response header is present, while still delivering the response to the
client. Use it for application-specific no-store signals that are not expressed
through standard `Cache-Control` directives.
`no_store_response_header_values` rejects shared cache admission only when a
listed origin response header has the exact configured value. Use it for
bounded app signals such as `x-app-cache = "private"` when header presence
alone is too broad.
`preset = "wordpress"` expands common WordPress shared-cache bypasses for
admin/login paths, app/mail/register/index and sitemap endpoints,
auth-related cookies, any non-empty query string, and authorization headers.
Explicit fields still work normally and are not removed by the preset.
Cache bypass, header, status, vary, content-type, extension, and method lists
are capped to bounded sizes to keep validation and per-request matching work
predictable.
`bypass_path_prefixes` and `bypass_path_exact` disable both cache lookup and
storage for matching request paths. Prefixes are useful for app admin areas;
exact paths are useful for login, XML-RPC, cron, sitemap, or legacy WordPress endpoints.
`bypass_request_headers` disables both cache lookup and cache storage when any
listed request header is present. Use it on routes where a header such as
`Cookie` or `Authorization` changes the upstream response but should not become
part of the shared cache identity. The default is empty so explicit static
asset routes can still cache browser requests that carry unrelated cookies.
`bypass_request_header_values` disables lookup and storage only when a listed
request header has the exact configured value. Use it for bounded flags such as
`x-preview-mode = "1"` when header presence alone is too broad.
`bypass_cookie_names` disables both cache lookup and cache storage when a
listed cookie name appears in any `Cookie` request header. Only exact names are
matched; values are ignored. `bypass_cookie_name_prefixes` applies the same
behavior to cookie-name prefixes such as WordPress hashed login cookies.
This is narrower than bypassing on every `Cookie` header and is useful for
static routes where only session or preview cookies make the response unsafe to
share.
`bypass_cookie_values` disables both cache lookup and cache storage when a
listed cookie name appears with the exact configured value. Use it for bounded
flags such as `preview = "1"` when the cookie name alone is too broad.
`bypass_query = true` disables both cache lookup and cache storage for any
non-empty query string. This matches common WordPress FastCGI cache examples
where query-string requests are treated as dynamic.
`bypass_query_params` disables both cache lookup and cache storage when the
request query string contains any listed parameter name. Matching is exact on
the raw key before `=` and on its percent-decoded form, so `preview=true` and
`pr%65view=true` both match `preview`, while `previewed=true` does not. Use it
for preview, token, or other app-specific query switches that make a response
unsafe to share.
`bypass_query_values` disables both cache lookup and cache storage when a query
parameter has the exact configured value. Matching checks raw and
percent-decoded parameter names and values, so `mode=private` and
`mode=priv%61te` both match `{ mode = "private" }`.
`allow_client_cache_refresh` is disabled by default. When disabled, client
headers such as `Cache-Control: no-cache`, `Cache-Control: max-age=0`, and
`Pragma: no-cache` do not force upstream revalidation, which keeps unauthenticated
clients from neutralizing the shared cache. Enable it only on routes where
browser-style refresh semantics are explicitly desired. `Cache-Control:
no-store` still bypasses lookup and storage because the client explicitly
forbids storing the response.
`vary_request_headers` adds safe request headers to the cache variance key even
when the origin does not emit a matching `Vary` header. Use this for negotiated
static assets, for example `Accept-Encoding`. Sensitive request-specific
headers such as `Cookie`, `Authorization`, and `Proxy-Authorization` are
rejected here; use `bypass_request_headers` for those. Fluxheim accepts at most
16 configured vary request headers, matching the runtime Vary field cap.
`key_namespace` is optional. When set, Fluxheim adds the string to the primary
cache key, which gives operators a simple cache-versioning knob. Bump it, for
example from `repoheim-assets-v1` to `repoheim-assets-v2`, to isolate new
objects from an older route cache without changing URLs.
`key_parts` controls which safe request fields are included in the primary
cache key. Valid values are `method`, `host`, `path`, and `query`; the list is
capped at 4 entries, `path` is required, and duplicates are rejected. This gives
operators the useful part of cache-key templates without allowing arbitrary
interpolation. `query` is still ignored when `include_query = false`.
`min_uses` delays cache admission until the same cache key has produced a
cacheable origin response at least that many times within a short bounded
window. The default is `1`, which stores the first cacheable response. Increase
it on routes where one-off URLs should pass through without occupying shared
cache space.
`pass_uncacheable_after` is disabled by default with `0`. When set, Fluxheim
counts repeated uncacheable origin responses for the same cache key in a bounded
short-lived in-memory table. After the configured threshold, matching requests
temporarily bypass cache lookup and storage instead of repeatedly entering the
shared cache path. A later cacheable response clears the pass decision.
When `status_header` and `status_reason_header` are configured, this policy is
reported as `BYPASS` with reason `cache-pass`.
`ignore_origin_cache_headers` removes upstream `Cache-Control` and `Expires`
before cache admission and downstream delivery. Keep the default `false` unless
the matched route is known static content and Fluxheim policy is responsible for
freshness.
`status_ttls` is optional. Each key is an HTTP status code and each value is a
positive TTL in seconds. When a cache-participating origin response matches, the
cache policy replaces response freshness headers with
`Cache-Control: max-age=<ttl>` before cache admission. Origin
`private`, `no-store`, `no-cache`, `Set-Cookie`, and other shared-cache
rejections are preserved and still prevent storage unless
`ignore_origin_cache_headers` is explicitly enabled for a trusted static route.
Non-200 origin responses are admitted only when their status appears in
`status_ttls`, or when `default_status_ttl_secs` is set as a fallback for any
status. Use `default_status_ttl_secs` carefully: it can make unusual or error
statuses cacheable on the matched route unless another admission rule rejects
the response. `stale_while_revalidate_secs` and `stale_if_error_secs` are
optional and must be greater than zero when set.
`stale_while_revalidate_secs` permits serving an already-stored stale object
while Fluxheim revalidates it in the background, and `stale_if_error_secs`
permits serving stale during upstream errors. Both windows are counted after
normal freshness expires. If `stale_if_error_secs` is unset, Fluxheim will not
serve stale solely because the upstream failed. `stale_if_error_on` optionally
narrows which upstream error classes may use that stale-on-error window. Valid
values are `connect`, `timeout`, `read`, `write`, `connection-closed`,
`http-status`, `protocol`, `tls`, and `other`. The default includes all
classes. `stale_if_error_statuses` optionally narrows HTTP-status stale serving
to selected 5xx origin statuses; when it is empty, any upstream 5xx status that
Pingora reports as stale-if-error eligible is allowed. `content_types` is the
allow-list for `200 OK` origin
response media types. Entries may be exact media types such as `text/css` or
subtype wildcards such as `image/*`. `extensions` is the user-facing alias for
the request-path extension allow-list; the older `image_extensions` key remains
accepted for compatibility. A request must match the extension policy and a
`200 OK` response must match `content_types` before it can enter the shared
proxy cache. `include_query` controls whether the query string is part of the
cache key. It defaults to `true`; set it to `false` only on tightly matched
static-asset routes where query parameters are not part of the response
identity.
`[cache.lock]` controls request collapsing for concurrent misses on the same
cache key. Keep it enabled for expensive static misses and stampede protection:
one request fetches the origin object while matching readers wait for the cache
fill instead of all hitting the backend together. `age_timeout_secs` controls
how long an active writer lock is considered valid, while `wait_timeout_secs`
controls how long readers wait for the writer before falling back to their own
origin fetch.

Per-vhost cache settings use `[vhosts.cache]`, `[vhosts.cache.memory]`, and
`[vhosts.cache.disk]`. Route cache settings use `[vhosts.routes.cache]` and
the same nested `memory`, `disk`, and `lock` subtables.

`[cache_purger]` is a process-wide stale disk cleanup loop. It is disabled by
default and requires the `cache` feature.

```toml
[cache_purger]
enabled = false
interval_secs = 300
limit = 512
batches = 1
```

When enabled, Fluxheim periodically scans indexed disk-cache entries for each
vhost and route cache, removes entries whose stored freshness window has
expired, and stops after the configured bounded `limit` and `batches` per
target. It does not walk arbitrary cache directories. Truncated non-dry-run
stale purges rotate scanned fresh entries to the back of the bounded index, so
later batches can reach expired entries that are behind a fresh front page.
Keep `limit` and `batches` modest on large production caches; the admin
`/_fluxheim/cache/purge-stale` endpoint remains available for explicit dry-runs
or larger operator-controlled cleanup windows. With metrics enabled,
`fluxheim_cache_purger_runs_total{outcome}` and
`fluxheim_cache_purger_entries_total{result}` show whether the background
purger is cleanly keeping up or returning `truncated` runs.
`fluxheim_cache_purger_duration_seconds{outcome}` reports per-tick cleanup
duration with bounded outcome labels and without cache paths or keys.
Aggregate storage-pressure gauges such as `fluxheim_cache_memory_entries`,
`fluxheim_cache_memory_weighted_size_bytes`, `fluxheim_cache_memory_max_size_bytes`,
`fluxheim_cache_disk_entries`, `fluxheim_cache_disk_size_bytes`, and
`fluxheim_cache_disk_max_size_bytes` are updated while metrics are enabled.
Use the protected admin cache-status endpoint when you need vhost or route
breakdowns.

## TLS

```toml
[tls]
enabled = false
backend = "rustls"
profile = "intermediate"
min_protocol = "tls1.2"
alpn = "http1-and-http2"
curve_preferences = ["X25519", "CurveP256", "CurveP384"]
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]

[tls.fips]
required = false
require_disk_cache_encryption = false

[tls.iso19790]
required = false
require_disk_cache_encryption = false

[[tls.certificates]]
cert_path = "tls/fullchain.pem"
key_path = "tls/key.pem"

[tls.client_auth]
mode = "off"
# ca_path = "tls/client-ca.pem"
```

TLS backend values: `rustls`, `openssl`. `boringssl` and `s2n` are rejected
config values.

Exactly one matching TLS compile-time feature should be selected:
`tls-rustls` or `tls-openssl`, with `tls-rustls-fips` and `tls-openssl-fips`
for compliance builds. The default build uses `tls-rustls`.

TLS policy values:

- `profile = "modern"`: Mozilla-style modern baseline. It requires TLS 1.3 and
  allows only TLS 1.3 cipher suites.
- `profile = "intermediate"`: the default production compatibility baseline. It
  requires TLS 1.2 or newer and uses the common AEAD ECDHE TLS 1.2 suites plus
  TLS 1.3 suites.
- `profile = "compat"`: keeps the TLS 1.2-or-newer baseline explicit for sites
  that prioritize client compatibility. It currently maps to the same safe
  baseline as `intermediate`; older protocol support is not planned for normal
  listeners.

See [examples/tls-modern.toml](../examples/tls-modern.toml) and
[examples/tls-intermediate.toml](../examples/tls-intermediate.toml) for
complete checked examples.

`min_protocol` may be set to `tls1.2` or `tls1.3`; `VersionTLS12` and
`VersionTLS13` are accepted as compatibility aliases for operators migrating
from router-style TLS option files. `modern` rejects `min_protocol = "tls1.2"`
so the named modern policy cannot be weakened by accident. `alpn` may be
`http1`, `http2`, or `http1-and-http2`. The default is `http1-and-http2`,
matching the 1.0 listener behavior.

The rustls and OpenSSL backends enforce the configured minimum protocol, ALPN
policy, curve preferences, and cipher suite allow-list. BoringSSL and s2n are
not part of the supported TLS matrix because their Fluxheim integrations did
not provide the same complete policy, SNI, upstream TLS, and client-auth
coverage.
Explicit `curve_preferences` are capped at 16 entries, and explicit
`cipher_suites` are capped at 32 entries.

Supported curve names are `X25519`, `CurveP256`, and `CurveP384`.
`X25519MLKEM768` is accepted by the config schema for future post-quantum
hybrid key exchange support, but the default rustls/ring backend rejects it
until Fluxheim offers a rustls crypto provider with post-quantum groups. OpenSSL
passes configured group names to the TLS library; runtime startup fails if the
installed library does not support a configured group.

The first global `[[tls.certificates]]` entry is the default downstream
certificate. Vhosts may provide their own static certificate for SNI selection:

```toml
[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "tls/example-fullchain.pem"
key_path = "tls/example-key.pem"
```

Fluxheim selects vhost certificates by SNI using the vhost `hosts` list,
including one-label wildcards such as `*.api.example.test`. The default rustls
build supports this through a rustls certificate resolver. Callback-capable TLS
backends use their native certificate callback APIs. TLS backends without SNI
certificate selection support reject vhost-specific certificates at startup
instead of silently serving the default certificate.
The global `[[tls.certificates]]` table is capped at 1024 certificate pairs.

Downstream client certificate authentication is configured globally for TLS
listeners:

```toml
[tls.client_auth]
mode = "required" # "off", "optional", or "required"
ca_path = "/etc/fluxheim/tls/client-ca.pem"
```

`mode = "required"` rejects TLS handshakes that do not present a certificate
chain trusted by `ca_path`. `mode = "optional"` asks for a client certificate
and verifies it when present, but still accepts clients without one. The CA
bundle path uses the same safe-path validation as other TLS files: no
parent-directory traversal, no symlinked path components, and no group- or
world-writable existing parent directory. The supported TLS matrix wires rustls
and OpenSSL listeners only.
Verified client-certificate identity can be forwarded explicitly with
request header templates such as `{tls.client_cert_sha256}`. Route decisions
based on certificate identity remain future work; do not rely on client-cert
attributes for routing or authorization unless a later release documents that
exact policy surface.

Release validation must still scan every release candidate with a TLS scanner
before publishing a stable release.

### FIPS / ISO-Capable TLS Guard

`[tls.fips] required = true` is accepted by the config schema as a fail-closed
guard for FIPS/ISO-capable TLS builds. `[tls.iso19790] required = true` is an
ISO/IEC 19790 terminology alias for the same validated-provider enforcement
path. Neither setting is a blanket FIPS or ISO/IEC 19790 compliance claim. When
enabled, Fluxheim rejects non-NIST or unproven groups such as `X25519` and
`X25519MLKEM768`, rejects non-approved cipher choices such as ChaCha20 suites,
and requires a backend-specific proof path.

Default builds fail closed because they do not contain a FIPS/ISO-capable proof
path. Builds compiled with `tls-openssl-fips` or the
`tls-openssl-iso19790` alias may use `backend = "openssl"`: runtime validation
then checks that the OpenSSL FIPS provider can be loaded and that an approved
cipher can be fetched with the `fips=yes` property query, enables OpenSSL
default FIPS properties for the process-default library context, verifies those
default properties, and checks that the default fetch path rejects a non-FIPS
cipher.
Builds compiled with `tls-rustls-fips` may use `backend = "rustls"`: runtime
validation checks the rustls AWS-LC FIPS provider, TLS setup uses
`rustls::crypto::default_fips_provider()`, and listener startup rejects a
FIPS/ISO-required config unless `ServerConfig::fips()` reports true.
Operators still need the selected module's CMVP certificate, Security Policy,
provider/build configuration, platform evidence, and deployment records.
Fluxheim does not hardcode an OpenSSL provider path; OpenSSL provider discovery
follows the platform OpenSSL configuration and environment visible to the
process. The rustls/AWS-LC FIPS path follows rustls and aws-lc-fips-sys build
requirements, including CMake, Go, and a C compiler.

Use `fluxheim crypto` or `fluxheim-config-tester --crypto` to print compiled
TLS backend diagnostics. Use [FIPS-Capable Deployments](fips.md) for the full
compliance boundary and roadmap. Do not treat a Cargo feature or this config
block alone as a FIPS compliance claim.

FIPS/ISO-required mode also applies internal-crypto guards outside the TLS
listener. Config validation rejects managed ACME (`[tls.acme] enabled = true`)
because ACME account key generation, JWS account signing, EAB handling,
outbound ACME HTTPS transport, and TLS-ALPN certificate generation are not yet
routed through the selected validated module. It allows
`admin.enabled = true` only in `tls-openssl-fips` or `tls-rustls-fips` builds,
where bearer-token HMAC is routed through OpenSSL FIPS or AWS-LC FIPS. It
rejects local disk-cache encryption because that path uses ring AES-GCM.
`provider = "openbao-transit"` cache encryption is allowed only through local
numeric loopback HTTP as an external evidence boundary, and OTLP metrics/traces
export is allowed only to numeric local `http://` loopback collectors
(`127.0.0.1` or `[::1]`) until outbound TLS can be provider-aligned. Disk cache
without encryption is still allowed, but Fluxheim logs a compliance warning
because cached response bodies are written at rest without a Fluxheim-managed
encryption boundary. Set `tls.fips.require_disk_cache_encryption = true` or
`tls.iso19790.require_disk_cache_encryption = true` to promote that warning to
a hard config error.
Request IDs and temporary object names are treated as non-secret operational
identifiers, not SSPs.

Check certificate storage permissions separately:

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

On Unix, private keys should be owner-only and ACME storage directories should
be owner-only. The storage checker rejects symlinked certificate files, private
key files, ACME EAB secret files, ACME storage directories, and paths below
symlinked or group- or world-writable directories; mount or configure the real paths
directly. If Fluxheim cannot inspect any TLS path prefix for symlinks,
validation fails closed and reports the path as unreadable. Config validation
also rejects static certificate paths, ACME storage paths, and ACME EAB secret
files when their nearest existing parent directory is group- or world-writable. EAB secret
files are checked with the same owner-only permission rule as private keys.

## ACME

ACME config parsing, renewal planning, managed certificate storage paths, local
HTTP-01 challenge serving, and the local renewal execution contract exist.
Builds with `acme-client` can load or create issuer accounts and complete
HTTP-01 or rustls TLS-ALPN-01 orders through `instant-acme`. By default, the
runtime registers a background renewal service for configured ACME vhosts when
`acme-client` is compiled in. Set `tls.acme.automation = "external"` when a
systemd timer, container scheduler, or another supervisor runs `acme-renew`.
The background service observes managed certificate expiry and renews missing or
due certificates on the configured check interval. After successful renewal,
Fluxheim reloads downstream SNI certificate objects so new handshakes can use
the renewed files without a restart when the selected TLS backend exposes a
reloadable resolver or callback.

For reloadable SNI TLS backends, including the default rustls backend, missing
Fluxheim-managed ACME certificate files are a pending issuance state rather than
a startup failure. This lets operators add a new `[vhosts.tls.acme]` vhost while
keeping port `80` online for HTTP-01. Static certificates are different: if a
vhost points at operator-owned `cert_path`/`key_path` files, those files must
exist and pass storage checks before the listener starts.

You can also invoke renewal explicitly. Production packages include
`fluxheim-acme`, which can renew and then request live certificate activation
from the running gateway:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
fluxheim --config /etc/fluxheim/fluxheim.toml acme-renew
```

By default the command renews missing or due certificates only. `--force-renew`
attempts every configured ACME vhost even when certificates are still valid;
use it sparingly because repeated forced renewals can hit issuer rate limits.
`--all` is accepted as a backward-compatible alias, but it prints a deprecation
warning and should not be used in new automation.

```toml
[tls.acme]
enabled = false
storage = "/var/lib/fluxheim/acme"
contact_email = "admin@example.test"
default_issuer = "letsencrypt"
challenge = "http-01"
automation = "background" # or "external" for fluxheim-acme.timer/container cron

[tls.acme.renewal]
enabled = true
renew_before_secs = 2592000
renew_after = 2026-06-01T00:00:00Z
check_interval_secs = 3600
retry_initial_secs = 300
retry_max_secs = 86400
reload_after_renewal = true
zero_downtime_reload = true
```

Managed ACME supports `http-01` and, with the default rustls backend,
`tls-alpn-01`. HTTP-01 is easiest to operate when port 80 is reachable.
TLS-ALPN-01 is useful when port 443 is reachable and Fluxheim owns the TLS
listener; it requires `server.tls_listen`, `tls.backend = "rustls"`, and an
ACME-managed or static fallback certificate for the listener. DNS-01 remains
future work because provider integrations need explicit secret handling and
record-cleanup behavior.
See [examples/acme-http-01.toml](../examples/acme-http-01.toml) for a minimal
HTTP-01 managed-certificate config. It can be used for first issuance with a
public HTTP listener only, or with a rustls SNI HTTPS listener whose managed
certificate is still pending. See
[examples/acme-actalis.toml](../examples/acme-actalis.toml) for the same flow
with file-backed External Account Binding secrets.

Built-in issuer names include `letsencrypt`, `letsencrypt-staging`,
`actalis`, `google-trust-services`, and `google-trust-services-staging`.
The custom `[[tls.acme.issuers]]` list is capped at 128 entries.
Actalis and Google Trust Services require External Account Binding. Their EAB
secret sources are configured through environment variables, files, or
credential names. Credential names are preferred for production because the same
config works with systemd credentials, Docker/Podman secrets, and Kubernetes
secret volumes without exposing values in process environments or container
metadata.

Example with systemd credentials:

```toml
[[tls.acme.issuers]]
name = "actalis"
directory_url = "https://acme-api.actalis.com/acme/directory"

[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Example with container secrets:

```toml
[[tls.acme.issuers]]
name = "actalis"
directory_url = "https://acme-api.actalis.com/acme/directory"

[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Google Trust Services production uses
`https://dv.acme-v02.api.pki.goog/directory`; staging uses
`https://dv.acme-v02.test-api.pki.goog/directory`. Fluxheim provides separate
built-in issuer names and default environment variables because Google EAB
secrets are single-use and environment-specific:

```toml
[tls.acme]
default_issuer = "google-trust-services"

# Production defaults:
# FLUXHEIM_GTS_EAB_KID
# FLUXHEIM_GTS_EAB_HMAC_KEY
#
# Staging defaults:
# FLUXHEIM_GTS_STAGING_EAB_KID
# FLUXHEIM_GTS_STAGING_EAB_HMAC_KEY
```

EAB secret files are validated as sensitive files by
`fluxheim --check-tls-storage`: they must be regular files, must not be
symlinks, must not sit below symlinked or group- or world-writable parent directories, and
should be readable only by the Fluxheim process owner.

When `[vhosts.tls.acme]` is enabled, Fluxheim derives managed certificate files
below `tls.acme.storage` using a sanitized and hashed vhost directory:

```text
<storage>/certificates/<safe-vhost-segment>/fullchain.pem
<storage>/certificates/<safe-vhost-segment>/privkey.pem
```

The exact directory segment is intentionally generated by Fluxheim rather than
accepted from config, so vhost names cannot create path traversal or hidden
filesystem locations.
Explicit `vhosts.tls.acme.domains` lists are capped at 64 domains. If
`domains` is omitted, Fluxheim derives the ACME names from the vhost `hosts`
list after excluding wildcard hosts.

ACME account credentials are stored under the same storage root with a sanitized
and hashed issuer directory:

```text
<storage>/accounts/<safe-issuer-segment>/credentials.json
```

These files contain account private key material. Fluxheim writes them with
owner-only permissions on Unix, bounds their size, parses them as JSON, and
rejects symlinked credential files.

When `tls.acme.challenge = "http-01"` and `[vhosts.tls.acme]` is enabled,
Fluxheim automatically serves `/.well-known/acme-challenge/<token>` for that
vhost from:

```text
<storage>/http-01/<safe-vhost-segment>/<token>
```

Challenge tokens are restricted to one URL-safe path segment, challenge files
must be regular files, and oversized or control-character-containing responses
are rejected. If `[vhosts.acme_challenge]` is enabled, the explicit forwarding
helper takes precedence instead of the local managed challenge store.

When `tls.acme.challenge = "tls-alpn-01"` and `[vhosts.tls.acme]` is enabled,
Fluxheim generates temporary ACME challenge certificates below:

```text
<storage>/tls-alpn-01/<safe-domain-segment>/fullchain.pem
<storage>/tls-alpn-01/<safe-domain-segment>/privkey.pem
```

These certificates are served only for TLS handshakes that offer the
`acme-tls/1` ALPN protocol. Normal browser and proxy traffic continues to use
the configured static or ACME-managed vhost certificate selected by SNI.

## Vhosts

Vhosts bind hostnames to per-site web, proxy, PHP-FPM, TLS, cache, and header settings.
TOML uses `[[vhosts]]` to start a new vhost. Every `[vhosts.*]` table that
follows belongs to that current vhost until the next `[[vhosts]]`.
Vhost names and route names are capped at 128 bytes. These names are operator
labels used in logs, admin responses, and metrics; use DNS-style or short
service names rather than long descriptive strings.

```toml
# First vhost. The tables below belong to example.test.
[[vhosts]]
name = "example.test"
hosts = ["example.test", "www.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.web]
root = "/srv/sites/example"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.proxy]
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
upstream_tls = false

[vhosts.headers.response.add]
access-control-allow-origin = "https://example.test"

[vhosts.access]
allow = ["198.51.100.0/24", "2001:db8:100::/48"]
deny = ["198.51.100.66"]
require_client_cert = false
allow_client_cert_sha256 = []
deny_client_cert_sha256 = []

[vhosts.rate_limit]
enabled = true
requests_per_second = 50
burst = 100
mode = "nodelay"
status = 429
reject_indeterminate = false

[vhosts.concurrency]
enabled = true
max_in_flight = 256
max_queue = 1024
queue_timeout_ms = 0
status = 503

# Second vhost. The tables below belong to api.example.test.
[[vhosts]]
name = "api.example.test"
hosts = ["api.example.test", "*.api.example.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:4000", "127.0.0.1:4001"]
upstream_tls = false
```

Hostnames are normalized to lower case. Duplicate hosts are rejected. A single
left-most wildcard label is supported, for example `*.api.example.test`.
The config is capped at 1024 vhosts; each vhost may define up to 64 host
aliases and 256 routes.
`max_request_body_bytes` is optional on a vhost and overrides the global
`server.limits.max_request_body_bytes` for that host. Route-level
`max_request_body_bytes` still wins when a matching route sets its own limit.

`[vhosts.access]` and `[vhosts.routes.access]` provide the first `1.4` ACL
surface. IP rules accept exact IP addresses or CIDR ranges. `deny` entries win
first. When `allow` is non-empty, the effective client IP must match at least
one allow entry. The effective client IP is the direct peer address unless the
direct peer matches `server.trusted_proxies`; only then does Fluxheim inspect
`X-Forwarded-For` recursively. Client-certificate rules use the verified
downstream certificate SHA-256 fingerprint exposed by the TLS backend.
`require_client_cert = true` rejects requests without a verified client
certificate, `deny_client_cert_sha256` rejects matching fingerprints, and
`allow_client_cert_sha256` restricts access to the listed fingerprints when it
is non-empty. Fingerprints are 64-character hex SHA-256 values and are matched
case-insensitively. A vhost policy is evaluated before any matching route
policy, so route ACLs can further restrict traffic but cannot bypass a
vhost-level denial. With metrics enabled, ACL denials are counted by
`fluxheim_edge_policy_events_total` with bounded labels.

When Fluxheim is built with the optional `geoip` feature, `[geoip]` enables
local MMDB Geo-Context lookup for access policy:

```toml
[geoip]
enabled = true
fallback_enabled = true

[[geoip.databases]]
provider = "maxmind"
path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"

[[geoip.databases]]
provider = "circl-geo-open"
path = "/var/lib/fluxheim/geo/circl-country.mmdb"
```

`provider = "maxmind"` covers MaxMind GeoIP2/GeoLite2 MMDB files.
`provider = "circl-geo-open"` covers European CIRCL Geo Open datasets when
supplied in MMDB-compatible form. Databases are ordered local fallbacks when
`fallback_enabled = true`; Fluxheim fills missing country or ASN fields from
later databases when possible.
Fluxheim does not download GeoIP databases in-process. Each MMDB file is capped
at 512 MiB at read time and each loaded GeoIP runtime is capped at 1 GiB total.
GeoIP update jobs should write and verify a replacement file, then atomically
rename it into place before reloading Fluxheim.

Vhost and route access policies can then use:

```toml
[vhosts.access]
allow_countries = ["SE", "NO", "DK", "FI"]
deny_countries = ["RU"]
allow_asns = [12552]
deny_asns = [64512]
```

Country values must be uppercase ISO alpha-2 codes. ASN values are numeric and
must be greater than zero. Geo allow lists fail closed when no Geo-Context is
available; Geo deny lists deny only on a resolved match. See
[`docs/geoip.md`](geoip.md) for the feature boundary and operational update
pattern.

`[vhosts.rate_limit]` and `[vhosts.routes.rate_limit]` enable local token-bucket
request limiting. The first implementation keys by the same trusted-proxy-aware
client IP used for ACLs. `requests_per_second` sets the refill rate, `burst`
sets the bucket capacity, and `status` controls the rejection status. `mode =
"nodelay"` consumes burst capacity immediately and rejects once the bucket is
empty. `mode = "delay"` reserves future tokens and sleeps the request up to
`max_delay_ms`; if the backlog would exceed that bounded delay budget, Fluxheim
rejects instead of queueing indefinitely. If `burst` is omitted or zero,
Fluxheim uses `requests_per_second` as the burst. State is bounded by
`table_max_entries` and stale entries are pruned after `entry_ttl_secs`. Vhost
limits are checked before route limits. If Fluxheim cannot determine an
effective client IP, the request uses one shared anonymous bucket for that
vhost or route; do not rely on anonymous-IP rate limiting as the only
protection for sensitive internal paths. Set `reject_indeterminate = true` to
reject those requests instead of placing them in the shared bucket.
With metrics enabled, delayed and rejected rate-limit decisions are counted by
`fluxheim_edge_policy_events_total` with bounded labels.

`[vhosts.concurrency]` and `[vhosts.routes.concurrency]` cap active in-flight
requests. They are local process limits, not distributed cluster limits.
`max_in_flight` sets the active request budget and `status` controls the
rejection status when the budget is exhausted. `queue_timeout_ms = 0` rejects
immediately. A positive `queue_timeout_ms` lets Fluxheim wait briefly for a
permit before rejecting. `max_queue` caps waiting requests; `0` derives a
bounded default from `max_in_flight`. Vhost permits are acquired before route
permits and are released automatically when the request finishes.
With metrics enabled, concurrency-limit rejections are counted by
`fluxheim_edge_policy_events_total` with bounded labels.

Vhosts can also contain ordered route tables. Routes may optionally set
`methods = ["GET", "HEAD"]`; when present, the route only matches those
uppercase HTTP methods. Exact matches win first, then the longest prefix match,
then the first configured regex route, then one optional fallback route. Regex
routes require explicit global opt-in with
`server.regex_enabled = true`; configs that use `path_regex` without that flag
are rejected. Regex patterns use Rust's bounded `regex` engine and are checked
at config load time. Regex routes expose bounded request-header template
variables for migration patterns: `{route.regex.0}` is the full match,
`{route.regex.1}` through `{route.regex.15}` are numbered captures, and
`{route.regex.name}` reads a named capture such as `(?P<name>...)`. Capture
values are capped before template rendering and are not used as metric labels.
A route must define exactly one matcher: `path_exact`, `path_prefix`,
`path_regex`, or `fallback = true`, and one action: `redirect`, `proxy`, `web`,
or `php`. Regex routes may also set `rewrite_template` to build a new upstream
path from bounded regex captures. `rewrite_template` is path-only, preserves the
original query string, rejects unsafe rendered paths, and cannot be combined
with `strip_prefix` or `rewrite_prefix`.

```toml
[[vhosts.routes]]
name = "chat"
path_prefix = "/chat/"
methods = ["GET", "HEAD"]
strip_prefix = "/chat/"
rewrite_prefix = "/backend/chat/"
max_request_body_bytes = "64MiB"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:6012"]
connect_timeout_secs = 5
read_timeout_secs = 600
send_timeout_secs = 600

[vhosts.routes.grpc]
enabled = false
require_content_type = true

[[vhosts.routes]]
name = "versioned-api"
path_regex = "^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$"
rewrite_template = "/internal/v{route.regex.version}/{route.regex.rest}"

[vhosts.routes.headers.request.add]
x-api-version = "{route.regex.version}"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:6013"]

[vhosts.routes.cache]
enabled = true
status_header = "X-Cache-Status"
hide_response_headers = ["set-cookie"]
no_store_response_header_values = { x-app-cache = "private" }
bypass_request_header_values = { x-preview-mode = "1" }
bypass_cookie_values = { preview = "1" }
bypass_query_values = { mode = "private" }
bypass_query = false
status_ttls = { "200" = 3600, "302" = 3600, "404" = 60 }
stale_while_revalidate_secs = 30
stale_if_error_secs = 120
stale_if_error_on = ["connect", "timeout", "http-status"]
stale_if_error_statuses = [500, 502, 503, 504]
methods = ["GET", "HEAD"]
max_object_bytes = "32MiB"

[vhosts.routes.cache.memory]
enabled = true
max_size_bytes = "256MiB"

[[vhosts.routes.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.routes.proxy.error_pages.web]
root = "/srv/fluxheim/errors"

[[vhosts.routes]]
name = "repo"
path_prefix = "/repo"
strip_prefix = "/repo"

[vhosts.routes.web]
root = "/srv/infra/repository/public"
index_files = ["repo.html", "index.html"]

[vhosts.routes.web.directory_listing]
enabled = true
exact_size = false

[[vhosts.routes]]
name = "php-app"
path_prefix = "/app/"
strip_prefix = "/app"
max_request_body_bytes = "64MiB"

[vhosts.routes.php]
preset = "wordpress"
enabled = true
runtime = "php-fpm"
root = "/srv/sites/php.example.test/public"
# Default false. When true, only the final php.root component may be a symlink;
# Fluxheim resolves it once at startup and still rejects symlinked parents.
resolve_root_symlink = false
# Optional: path visible inside a separate php-fpm container.
# When omitted, Fluxheim sends php.root as DOCUMENT_ROOT/SCRIPT_FILENAME.
fpm_root = "/app/public"
index = "index.php"
allowed_extensions = ["php"]
deny_path_prefixes = ["/wp-content/uploads/"]
# `wordpress` and `front-controller` fall back to index.php for missing paths.
# `strict` only executes explicit PHP scripts or directory PHP indexes.
try_files = "wordpress"
# Advanced migration switches; both default to true.
pass_request_headers = true
pass_request_body = true
# Optional override for CGI SERVER_PORT; otherwise Host port or scheme default is used.
server_port = 8443
request_timeout_secs = 30
max_in_flight = 8
max_request_body_bytes = "64MiB"
# Optional: spill larger PHP request bodies to disk before FastCGI dispatch.
request_body_spool_threshold_bytes = "4MiB"
request_body_spool_dir = "/var/lib/fluxheim/php-spool/example.test"
max_response_bytes = "64MiB"
max_response_header_bytes = "64KiB"
stderr_log = true
stderr_log_level = "warn"
stderr_max_bytes = "2KiB"
stderr_failure_patterns = ["PHP Fatal error:"]
hide_response_headers = ["x-powered-by"]
ignore_origin_cache_headers = false
intercept_error_statuses = []
# Use "split" only when the application expects PATH_INFO after script.php.
path_info = "disabled"

[[vhosts.routes.php.error_pages]]
status = 502
path = "/502.html"

[vhosts.routes.php.error_pages.web]
root = "/srv/errors"
index_files = ["index.html"]

[vhosts.routes.php.params]
APP_ENV = "production"
APP_MEMORY_LIMIT = "256M"

[vhosts.routes.php.fpm]
# Default mode. Fluxheim connects to an operator-managed php-fpm pool.
mode = "external"
tcp = "php-fpm:9000"
# Required when TCP endpoints use loopback, private, or link-local IP literals.
# allow_private_tcp_upstreams = true
# Or use a private Unix socket:
# socket = "/run/php/php-fpm.sock"
# Or list multiple TCP endpoints for simple safe-method failover:
# tcp_upstreams = ["php-fpm-a:9000", "php-fpm-b:9000"]
connect_timeout_secs = 5
read_timeout_secs = 30
write_timeout_secs = 30
keepalive = true
pool_max_idle = 8
idle_timeout_secs = 60
# Conservative retry policy for connection failures before php-fpm returns data.
max_retries = 1
retry_timeout_secs = 5
retry_methods = ["GET", "HEAD", "OPTIONS"]
retry_invalid_response = false
retry_statuses = [500, 502, 503, 504]

# Managed mode keeps the same FastCGI/php-fpm protocol but lets Fluxheim start
# and supervise a private php-fpm master process. Do not set socket, tcp, or
# tcp_upstreams in managed mode; Fluxheim creates the socket itself.
# mode = "managed"
# php_fpm_binary = "/usr/sbin/php-fpm"
# socket_dir = "/run/fluxheim/php"
# workers = 4
# max_requests_per_worker = 1000
# process_manager = "static" # "static", "dynamic", or "ondemand"
# listen_backlog = 128
# Optional socket ownership controls for managed pools that drop privileges.
# Defaults to a private 0600 socket.
# listen_owner = "fluxheim"
# listen_group = "php"
# listen_mode = "0660" # "0600" or "0660"
#
# Dynamic pool sizing, only when process_manager = "dynamic":
# start_servers = 2
# min_spare_servers = 1
# max_spare_servers = 4
# max_spawn_rate = 8
#
# Ondemand pool sizing, only when process_manager = "ondemand":
# process_idle_timeout_secs = 10
#
# Request lifecycle and diagnostics:
# request_terminate_timeout_secs = 30
# request_terminate_timeout_track_finished = false
# request_slowlog_timeout_secs = 5
# request_slowlog_trace_depth = 20
# clear_env = true
# catch_workers_output = true
# decorate_workers_output = true
# session_save_path = "/run/fluxheim/php/session"
# upload_tmp_dir = "/run/fluxheim/php/upload"
#
# Optional, configure both together when php-fpm starts as root and should drop
# worker privileges. Pair with listen_owner/listen_group/listen_mode when
# Fluxheim itself is not running as the same user.
# user = "fluxheim"
# group = "fluxheim"
# Generated socket/config/pid/log files live under socket_dir. Forced process
# termination can leave stale files; remove them only while Fluxheim is stopped.

[vhosts.acme_challenge]
enabled = true
upstreams = ["host.containers.internal:8080"]
upstream_tls = false
connect_timeout_secs = 5
read_timeout_secs = 30
send_timeout_secs = 30

[vhosts.redirect]
enabled = true
to = "https://example.test{uri}"
status = 308
```

`strip_prefix` is useful when a backend or alias root should receive `/room`
instead of `/chat/room`. Add `rewrite_prefix` when the stripped suffix should
be attached to an upstream path prefix, for example `/chat/room?id=7` to
`/backend/chat/room?id=7`; it must be paired with `strip_prefix` and must be an
absolute safe path. Redirect targets must be absolute `http://` or
`https://` templates and may use `{uri}`, `{path}`, and `{query}`. `{query}` is
allowed only after the URL authority, for example in the path or query string,
because placing untrusted query text inside the authority can create open
redirects. Use
`max_request_body_bytes` on a route to narrow or expand the vhost or global
body limit for uploads handled by that route. Proxy actions accept
`connect_timeout_secs`, `read_timeout_secs`, and `send_timeout_secs`; route
proxy timeout values override the vhost/global proxy timeout values because the
route owns its own proxy action.

`[vhosts.routes.grpc]` is disabled by default and is valid only on proxy
routes. When enabled, the route proxy must set `upstream_http_version = "http2"`
or `"http1-and-http2"`, cache must remain disabled for that route, and
`require_content_type` must stay `true`. This is a pass-through compatibility
policy: Fluxheim preserves HTTP/2 proxying behavior and rejects obvious
non-gRPC requests before forwarding, but it does not transcode gRPC-Web or JSON
to gRPC.

Managed PHP-FPM validates `php_fpm_binary` at config load and again immediately
before each supervised spawn. The binary path must be absolute, must not contain
parent traversal, must not be or be below a symlink, must point directly to a
regular file, and must not be below a group/world-writable parent directory.

For PHP actions, `max_request_body_bytes` bounds the request sent to php-fpm
and `max_response_bytes` bounds the FastCGI STDOUT/STDERR bytes accepted from
php-fpm before Fluxheim rejects the response. `max_in_flight` caps concurrent
PHP-FPM requests for that vhost or route before request body buffering and
FastCGI dispatch; it defaults to `8` to bound the number of fully buffered PHP
responses held at once. Set `php.request_body_spool_threshold_bytes` with
`php.request_body_spool_dir` to spill larger request bodies to an owner-safe
temporary file before php-fpm dispatch. This keeps `CONTENT_LENGTH` exact for
FastCGI and lets retries replay the same upload without cloning a large memory
buffer; both spool settings must be configured together, and the spool file is
removed when the request completes. When `php.max_request_body_bytes` is set on
the same PHP action, the spool threshold must be lower than that body limit.
Existing spool paths must be directories, and existing directories must not be
group/world writable. Fluxheim rechecks those permissions after creating a
missing spool directory and before writing upload bodies.
`php.fpm_root` optionally rewrites `DOCUMENT_ROOT`,
`SCRIPT_FILENAME`, and `PATH_TRANSLATED` for separate php-fpm container
filesystem roots while Fluxheim still checks scripts under `php.root`.
`php.resolve_root_symlink = true` allows Caddy-style/current-release deploy
layouts where the final `php.root` path is a symlink. The default is false.
When enabled, Fluxheim resolves that final symlink at startup and still rejects
parent-directory traversal, symlinked parent directories, and unsafe writable
parents; script resolution and static offload continue to run under the
canonical target root.
`php.max_response_header_bytes` caps the CGI-style response header block before
body parsing and defaults to `64KiB`.
`php.deny_path_prefixes` rejects PHP script execution for configured absolute
URI path prefixes before php-fpm is contacted. Use it for WordPress-style media
directories such as `/wp-content/uploads/` where uploaded PHP files must never
execute. This is defense in depth on top of filesystem permissions; it blocks
Fluxheim's PHP execution path for matching URI prefixes even if a writable
upload directory accidentally contains a `.php` file. The list is capped at 128
prefixes.
`php.allowed_extensions` is capped at 16 plain extension names and rejects
case-insensitive duplicates.
`php.preset = "wordpress"` applies PHP-side WordPress migration defaults: it
uses the WordPress front-controller mode when `try_files` is otherwise unset and
adds deny prefixes for common upload/file directories such as
`/wp-content/uploads/` and `/files/`.
`php.try_files` is a typed replacement for common `try_files` recipes:
`front-controller` keeps the default `/index.php` fallback, `wordpress` is an
explicit alias for WordPress-style front-controller sites, and `strict` behaves
like `try_files $uri =404` for PHP execution while still allowing static files
to be served by `[vhosts.web]`.
`php.path_info` defaults to `disabled`; set it to `split` only for applications
that expect safe trailing `PATH_INFO` after an explicit PHP script such as
`/index.php/user/1`. The older `strict` spelling is accepted as an alias for
`split`.
`php.fpm.connect_timeout_secs` caps connecting to php-fpm and is also bounded
by `php.request_timeout_secs`. `read_timeout_secs` and `write_timeout_secs`
currently act as stricter caps on the buffered FastCGI request phase; the
shortest of `php.request_timeout_secs`, `php.fpm.read_timeout_secs`, and
`php.fpm.write_timeout_secs` is used until the future streaming FastCGI path
can enforce separate per-direction timeouts.
`php.pass_request_headers` controls whether safe inbound request headers are
translated to CGI `HTTP_*` params. `php.server_port` can override CGI
`SERVER_PORT`; when omitted, Fluxheim uses an explicit port from the request
`Host` authority and otherwise falls back to `443` for TLS or `80` for
cleartext. `php.pass_request_body` controls whether the
HTTP request body is sent to php-fpm; when disabled, Fluxheim still drains and
limits the downstream body but sends `CONTENT_LENGTH=0` and an empty FastCGI
stdin.
`php.stderr_log` controls whether FastCGI STDERR is written to Fluxheim logs.
`php.stderr_log_level` controls the emitted log level and accepts `error`,
`warn`, `info`, or `debug`; the default is `warn`.
`php.stderr_max_bytes` bounds each logged STDERR message and defaults to `2KiB`;
larger output is sanitized and marked as truncated.
`php.stderr_failure_patterns` is a default-empty list of literal ASCII-safe
substrings. If any configured pattern appears in FastCGI STDERR, Fluxheim treats
the PHP response as invalid. With `php.fpm.retry_invalid_response = true`, this
can fail over safe methods to another php-fpm upstream for fatal PHP runtime
failures such as `PHP Fatal error:`. Matching STDERR is still sanitized,
bounded by `php.stderr_max_bytes`, and logged when `php.stderr_log` is enabled
before Fluxheim rejects the response. Up to 32 patterns are allowed, each 1 to
512 bytes without ASCII control characters.
`php.hide_response_headers` removes selected headers emitted by php-fpm before
Fluxheim applies the normal response header policy. This is useful for
NGINX-style migrations that hide `X-Powered-By` or other backend-only headers.
The list is case-insensitively deduplicated and capped at 64 header names.
`php.ignore_origin_cache_headers` removes PHP-generated `Cache-Control`,
`Expires`, and `Pragma` response headers after Fluxheim has consumed internal PHP
control headers. It defaults to `false`; use response header policy to set
replacement cache directives when needed.
Fluxheim consumes PHP `X-Accel-Redirect` and `X-Sendfile` headers for
PHP-assisted static offload instead of forwarding them to clients.
`X-Accel-Redirect` targets are internal URI paths resolved under `php.root`;
`X-Sendfile` targets are absolute filesystem paths resolved under `php.root`,
and are mapped from `php.fpm_root` for split-container layouts. Fluxheim refuses
to offload files with configured PHP script extensions.
Fluxheim also consumes PHP `X-Accel-Expires` control headers instead of
forwarding them to clients. Positive TTLs become normal `Cache-Control` and
`Expires` headers; responses with `Set-Cookie` use `private` cache directives,
and zero or past expiries become `no-store, private`. When the PHP response
already carries restrictive origin cache policy such as `Cache-Control:
private`, `no-store`, `no-cache`, or `Pragma: no-cache`, Fluxheim strips only
the internal `X-Accel-Expires` header and preserves the origin cache policy
instead of promoting the response to shared-cache eligibility.
Fluxheim always strips hop-by-hop php-fpm response headers such as
`Connection`, `Transfer-Encoding`, and headers named by `Connection` before it
frames the client response.
`php.intercept_error_statuses` is an explicit `fastcgi_intercept_errors`-style
status list. When PHP returns one of those 4xx/5xx statuses, Fluxheim discards
the PHP response body and sends a Fluxheim-generated error response instead.
It defaults to an empty list so PHP applications keep their normal error pages
unless the operator opts in. The status list is capped at the valid 400-599
error-status range and cannot contain duplicates.
`[[vhosts.php.error_pages]]` and `[[vhosts.routes.php.error_pages]]` are
internal static fallback pages for selected PHP statuses. A configured error
page also intercepts that status; if the static page cannot be served, Fluxheim
falls back to its generated error response. Use this for NGINX-style
`fastcgi_intercept_errors` migrations where PHP 502/503/504 responses should
never expose backend details. PHP error-page lists are capped at 64 entries and
cannot contain duplicate statuses.
When a slashless request resolves to a directory PHP index, Fluxheim returns a
canonical `308` redirect before executing the script, for example `/blog` to
`/blog/` when `/blog/index.php` exists.
`max_response_bytes` defaults to `64MiB`; set a smaller value on
memory-constrained or high-assurance edge nodes. Because PHP responses are
currently buffered, the configured value is capped at `64MiB`. Use
`X-Accel-Redirect` or `X-Sendfile` for large files so Fluxheim can serve the
static asset path instead of buffering PHP output.
`php.fpm.keepalive` enables
FastCGI keep-connection reuse with an idle pool capped by
`php.fpm.pool_max_idle`; it is off by default for conservative compatibility.
Use either `php.fpm.socket`, `php.fpm.tcp`, or `php.fpm.tcp_upstreams`; the
endpoint modes are mutually exclusive. `tcp_upstreams` enables round-robin TCP
selection and conservative failover across configured php-fpm backends. The
`tcp_upstreams` list is capped at 64 entries and rejects duplicate authorities.
Unsafe TCP IP literals such as unspecified or multicast addresses are rejected.
Loopback, private, or link-local IP literals require
`php.fpm.allow_private_tcp_upstreams = true`; this keeps numeric local and
private-network FastCGI connectivity an explicit operator trust boundary. Use a
Unix socket for same-host php-fpm when possible. Hostname endpoints are
validated as authorities, but DNS resolution remains an operational boundary
for the php-fpm network.
When enabled, stale idle entries older than `php.fpm.idle_timeout_secs` are
discarded before reuse. `pool_max_idle` must be between 1 and 1024 when
keepalive is enabled. `php.fpm.max_retries` defaults to `0`; when set,
Fluxheim retries only connection failures and connect timeouts for configured
`php.fpm.retry_methods` before php-fpm has returned a response.
`php.fpm.retry_timeout_secs` optionally caps the total retry window for one PHP
request. With
`tcp_upstreams`, Fluxheim tries enough endpoints to cover the configured list
for safe methods even when `max_retries = 0`. Request timeouts are not retried
to avoid duplicating side effects. `php.fpm.retry_invalid_response` and
`php.fpm.retry_statuses` extend the same safe-method retry policy to malformed
FastCGI responses and selected PHP 5xx responses. They default to disabled;
configure them only for idempotent request methods where replaying the PHP
request is acceptable. `php.fpm.retry_methods` is capped at 16 uppercase safe-method
tokens and only accepts `GET`, `HEAD`, `OPTIONS`, and `TRACE`; `php.fpm.retry_statuses` is capped at the valid 500-599 server-error
status range.
`[vhosts.php.params]` or `[vhosts.routes.php.params]`
adds administrator-controlled FastCGI parameters such as `APP_ENV` or
`APP_MEMORY_LIMIT`; Fluxheim rejects unsafe names, control-character values, and
core CGI parameters that it owns, including `SCRIPT_FILENAME`,
`CONTENT_LENGTH`, `HTTPS`, `PHP_VALUE`, `PHP_ADMIN_VALUE`, and all `HTTP_*`
request-header parameters. Custom parameter tables are capped at 128 entries;
each parameter name is capped at 128 bytes and each value at 16KiB.

`[vhosts.routes.cache]` is optional. When present, it replaces the vhost cache
policy for that matched route only. Routes without a cache block continue to use
the vhost cache policy, so selective caches can cover paths such as `/assets/`,
`/avatars/`, or repository image content without caching every backend response.

When global `[server.https_redirect]` is enabled, non-redirect routes are
redirected on cleartext requests by default. `[vhosts.acme_challenge]` creates
the standard HTTP-01 `/.well-known/acme-challenge/` proxy route and exempts only
that path. Advanced route configs can still use `https_redirect_exempt = true`
for deliberate non-ACME cleartext exceptions.
Use either `upstream = "host:port"` or `upstreams = ["host:port"]`; do not set
both. The helper accepts the same `upstream_tls` and upstream timeout fields as
normal proxy actions. ACME challenge upstream lists are capped at 64 entries
and reject duplicates case-insensitively.

`[vhosts.redirect]` creates a fallback redirect route for the whole vhost. It is
intended for canonical-host vhosts such as `www` to apex redirects. Do not
combine it with an explicit fallback route on the same vhost.

Static route actions support directory listing for repository-style file roots.
Listings are disabled by default, index files still win when present, dotfiles
remain denied when `deny_dotfiles = true`, symlink entries are skipped, and the
generated HTML is sent with `cache-control: private, no-store`. Keep
`exact_size = false` for large directories when approximate display is enough.
`local_time = true` renders listing modification times with the server's local
UTC offset; otherwise listings use GMT HTTP-date timestamps.

For production readability, prefer one vhost per file in a split config
directory. See [Vhost Config Guide](vhost-config.md) and
[Gateway Recipes](gateway-recipes.md).

## Privacy Profile

Build:

```bash
cargo build --no-default-features --features profile-privacy
```

Use `examples/privacy.toml` as the baseline config. It disables access logging,
request IDs, metrics, cache, and client-IP forwarding headers.

Invalid privacy combinations are rejected by release checks:

- `privacy-mode` with `cache`
- `privacy-mode` with `metrics`

## Feature Preflight

Before packaging a custom feature set, validate it:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

This catches unsupported combinations before Cargo starts compiling Pingora.
See [Feature Matrix](features.md) for the complete feature/profile list.
