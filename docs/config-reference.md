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

- `listen` must not be empty.
- TLS listeners are explicit through `tls_listen`; Fluxheim does not infer TLS
  from port numbers.
- `listen` and `tls_listen` are each capped at 64 entries.
- `default_vhost`, when set, must match a configured `[[vhosts]].name`.
- `[server.host_routing].strict = false` preserves compatibility by falling
  back to `default_vhost` for missing, invalid, or unknown host names. Set it
  to `true` in hardened multi-tenant deployments to reject missing or invalid
  host identity with `400` and unknown hosts with `421`.
- If vhosts live in a sibling `conf.d` directory and `--config` points at the
  main file, set top-level `include_conf_d = true`; alternatively point
  `--config` at the config directory so visible `.toml` files are loaded in
  sorted order.
- `trusted_proxies` should contain only peers you operate, such as a container
  gateway, Cloudflare, or a trusted edge proxy. When the direct peer is trusted,
  Fluxheim walks `X-Forwarded-For` from right to left and restores the last
  non-trusted hop for generated client-IP headers, equivalent to nginx
  `real_ip_recursive on`. The list is capped at 512 entries.
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
without following a final symlink. On Unix, file logs must use a dedicated log
directory and are rejected when the nearest existing parent is group- or world-writable,
such as `/tmp`.

In `privacy-mode` builds, access logging and file logging must stay disabled.
Fluxheim rejects `logging.access.enabled = true` and
`logging.file.enabled = true`.

`logging.access.include_path = false` keeps access logging enabled while
emitting an empty `path` field. This is useful when request paths may contain
tenant IDs, filenames, or other sensitive identifiers.

`logging.access.include_host = false` keeps access logging enabled while
emitting an empty raw `host` field. The configured `vhost` name is still logged
after Fluxheim resolves the request.

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
```

`x_forwarded_for` values: `off`, `replace`, `append`. `x_real_ip = true`
emits `X-Real-IP` from the effective client address. If the direct peer matches
`server.trusted_proxies`, Fluxheim recursively restores that address from the
trusted `X-Forwarded-For` chain before writing `X-Real-IP`, `X-Forwarded-For`,
`Forwarded`, or `{remote_addr}` templates. In privacy builds it defaults off and
client-IP forwarding remains stripped.

Request header values can use a small safe dynamic template set:

- `{host}`: original request `Host` header.
- `{remote_addr}`: observed client IP address.
- `{scheme}`: `http` or `https` from the downstream listener.
- `{uri}`: current request path and query.
- `{path}`: current request path.
- `{query}`: current request query without `?`, or empty.
- `{request_id}`: Fluxheim request ID when access request IDs are enabled.
- `{http.<header-name>}`: safe request-header forwarding, for example
  `{http.upgrade}`.

Unknown variables fail config validation. Rendered values are still passed
through HTTP header validation before Fluxheim sends them upstream.

Common proxy migration headers:

```toml
[headers.request.add]
host = "{host}"
x-real-ip = "{remote_addr}"
x-forwarded-for = "{remote_addr}"
x-forwarded-proto = "{scheme}"
x-forwarded-host = "{host}"
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
append header may contain at most 32 values.

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

## Proxy

`[proxy]` is the global fallback proxy policy. Vhosts can override it with
`[vhosts.proxy]`.

```toml
[proxy]
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
upstream_tls = false
upstream_sni = "origin.example.test"
connect_timeout_secs = 5
read_timeout_secs = 60
send_timeout_secs = 30
downstream_write_timeout_secs = 30
downstream_min_send_rate_bytes_per_sec = 8192

[proxy.load_balance]
max_iterations = 256

[proxy.load_balance.health_check]
enabled = true
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
parallel = false

[[proxy.error_pages]]
status = 502
path = "/502.html"

[proxy.error_pages.web]
root = "/srv/fluxheim/errors"
cache_control = "private, no-store"
```

Every `upstreams` entry must be an authority such as
`127.0.0.1:3000` or `origin.example.test:443`.
Proxy upstream lists are capped at 64 entries and reject duplicates
case-insensitively. Proxy error-page lists are also capped at 64 entries.

`upstreams` is the preferred proxy target form for both one and many origins.
The older single `upstream = "host:port"` field remains supported for simple
configs, but do not set both fields in the same proxy block. Fluxheim rejects
that as ambiguous. A single `upstreams = ["host:port"]` entry behaves like a
normal single proxy target in all builds and is resolved when requests are
proxied, so a missing backend does not prevent the gateway from starting. Two
or more entries activate the Pingora load-balancer path in builds compiled with
`load-balancer`; those entries may be resolved by load-balancer setup and health
checking.
`connect_timeout_secs`, `read_timeout_secs`, and `send_timeout_secs` are
optional. They map to the upstream connection timeout, upstream response/read
timeout, and upstream request-body/write timeout.
`downstream_write_timeout_secs` and
`downstream_min_send_rate_bytes_per_sec` protect the client-facing side of
proxied responses. The write timeout caps stalled downstream writes; the minimum
send rate asks Pingora to derive a timeout from each response chunk size and is
mainly useful against slow HTTP/1 clients. These fields are optional and can be
set globally, per vhost, or on a route-level proxy block.

For websocket-style upgrades, Fluxheim keeps the downstream `Connection:
Upgrade` and `Upgrade` headers unless your header policy removes or replaces
them. Route-level proxy blocks can use longer read/send timeouts for these
long-lived paths without changing the whole vhost.

`[[proxy.error_pages]]` entries are internal static fallback pages for proxy
failures. The `path` is an internal request path resolved below the entry's
`web.root`; it is not exposed as a public route unless you also configure a
route for that root.

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

`provider = "openbao-transit"` uses OpenBao Transit for regulated deployments
that need centralized key custody and rotation. Fluxheim calls the Transit
`encrypt` and `decrypt` endpoints for disk cache objects and stores only the
returned `vault:v...` ciphertext in the filesystem or storage-bin backend. The
OpenBao endpoint must be HTTPS unless it is loopback HTTP, and the token must
come from exactly one safe `token_file` or `token_credential` source. The
configured key id plus combined cache key are passed as associated data, so a
stored ciphertext is bound to the cache object identity. The default local-key
provider does not require OpenBao.

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
is true. Peer requests include the original host plus safe negotiation headers
such as `Accept`, `Accept-Encoding`, and `Accept-Language`; credentials such as
`Authorization` and `Cookie` are not forwarded.
`examples/cache-peer-fill.toml` shows the focused validated fixture. Metrics
builds expose aggregate peer-fill configuration through
`fluxheim_cache_peer_fill_enabled_policies`,
`fluxheim_cache_peer_fill_peers`, and
`fluxheim_cache_peer_fill_max_concurrent_requests`.

For offline debugging, `fluxheim cache-key --host example.com --path
/assets/app.js` previews the vhost/route cache policy and generated cache key
without contacting the upstream. `cache-key` can fail closed with
`--expect-eligible`, `--expect-ineligible`, `--expect-reason`,
`--expect-cache-lock-enabled`, `--expect-cache-lock-wait-timeout-secs`,
`--expect-cache-predictor-enabled`, `--expect-peer-fill-enabled`,
`--expect-peer-fill-peers`, `--expect-peer-fill-max-concurrent-requests`,
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
`bypass_query_params` disables both cache lookup and cache storage when the raw
request query string contains any listed parameter name. Matching is exact on
the raw key before `=`, so `preview=true` matches `preview`, while
`previewed=true` does not. Use it for preview, token, or other app-specific
query switches that make a response unsafe to share.
`bypass_query_values` disables both cache lookup and cache storage when a raw
query parameter has the exact configured value. Matching is performed before
URL decoding, so keep values simple and encode spaces or separators at the
application edge.
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
rejected here; use `bypass_request_headers` for those.
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
`Cache-Control: public, max-age=<ttl>` before cache admission. Non-200 origin
responses are admitted only when their status appears in `status_ttls`, or when
`default_status_ttl_secs` is set as a fallback for any status. Use
`default_status_ttl_secs` carefully: it can make unusual or error statuses
cacheable on the matched route unless another admission rule rejects the
response. `stale_while_revalidate_secs` and `stale_if_error_secs` are optional
and must be greater than zero when set.
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

[[tls.certificates]]
cert_path = "tls/fullchain.pem"
key_path = "tls/key.pem"
```

TLS backend values: `rustls`, `openssl`, `boringssl`, `s2n`.

Exactly one matching TLS compile-time feature should be selected:
`tls-rustls`, `tls-openssl`, `tls-boringssl`, or `tls-s2n`. The default build
uses `tls-rustls`.

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
policy, curve preferences, and cipher suite allow-list. BoringSSL enforces
minimum protocol, ALPN, curve preferences, and TLS 1.2 cipher allow-lists; its
Rust API does not currently expose TLS 1.3 cipher-suite allow-lists, so explicit
TLS 1.3 `cipher_suites` are rejected for that backend. The s2n backend
currently accepts only Fluxheim's default TLS 1.2+ / HTTP/1.1+HTTP/2 listener
policy because the project does not yet expose the needed s2n listener controls.
Explicit `curve_preferences` are capped at 16 entries, and explicit
`cipher_suites` are capped at 32 entries.

Supported curve names are `X25519`, `CurveP256`, and `CurveP384`.
`X25519MLKEM768` is accepted by the config schema for future post-quantum
hybrid key exchange support, but the default rustls/ring backend rejects it
until Fluxheim offers a rustls crypto provider with post-quantum groups. OpenSSL
and BoringSSL pass configured group names to the TLS library; runtime startup
fails if the installed library does not support a configured group.

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

Release validation must still scan every release candidate with a TLS scanner
before publishing a stable release.

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

Vhosts can also contain ordered route tables. Exact matches win first, then the
longest prefix match, then one optional fallback route. A route must define one
action: `redirect`, `proxy`, `web`, or `php`.

```toml
[[vhosts.routes]]
name = "chat"
path_prefix = "/chat/"
strip_prefix = "/chat/"
max_request_body_bytes = "64MiB"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:6012"]
connect_timeout_secs = 5
read_timeout_secs = 600
send_timeout_secs = 600

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
PHP_VALUE = "memory_limit=256M"

[vhosts.routes.php.fpm]
tcp = "php-fpm:9000"
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
instead of `/chat/room`. Redirect targets must be absolute `http://` or
`https://` templates and may use `{uri}`, `{path}`, and `{query}`. Use
`max_request_body_bytes` on a route to narrow or expand the vhost or global
body limit for uploads handled by that route. Proxy actions accept
`connect_timeout_secs`, `read_timeout_secs`, and `send_timeout_secs`; route
proxy timeout values override the vhost/global proxy timeout values because the
route owns its own proxy action.

For PHP actions, `max_request_body_bytes` bounds the request sent to php-fpm
and `max_response_bytes` bounds the FastCGI STDOUT/STDERR bytes accepted from
php-fpm before Fluxheim rejects the response. Set `php.request_body_spool_threshold_bytes` with
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
and zero or past expiries become `no-store, private`.
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
`PHP_VALUE`; Fluxheim rejects unsafe names, control-character values, and core
CGI parameters that it owns, including `SCRIPT_FILENAME`, `CONTENT_LENGTH`,
`HTTPS`, and all `HTTP_*` request-header parameters. Custom parameter tables are capped at 128 entries;
each parameter name is capped at 128 bytes and each value at 16KiB. `PHP_VALUE`
and `PHP_ADMIN_VALUE` are powerful php-fpm controls; Fluxheim logs high-risk
warnings when they mention directives such as `open_basedir`,
`disable_functions`, `allow_url_include`, or `allow_url_fopen`, and logs an
error-level warning if `PHP_ADMIN_VALUE` overrides `disable_functions`.

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
