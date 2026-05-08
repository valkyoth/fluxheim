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
```

Notes:

- `listen` must not be empty.
- TLS listeners are explicit through `tls_listen`; Fluxheim does not infer TLS
  from port numbers.
- `default_vhost`, when set, must match a configured `[[vhosts]].name`.
- `trusted_proxies` should contain only direct peers whose forwarded client-IP
  headers are allowed to influence routing/log context.
- In `1.0`, trusted proxy support is intentionally explicit and CIDR-based.
  Later trusted-client identity work should keep the direct socket peer,
  restored client IP, and forwarding chain as separate request-context values
  rather than replacing one with the other.
- `[server.process]` maps safe process settings into Pingora's `ServerConf`.
  Changes to these values require a process upgrade, not a live snapshot
  reload. Keep `threads` conservative in containers because Pingora allocates
  worker threads per service.
- `pid_file`, `upgrade_sock`, and optional `error_log` must not contain parent
  traversal, must not be below symlinked existing parent directories, and on
  Unix must not use a world-writable existing parent such as `/tmp`. Use a
  dedicated runtime directory such as `/run/fluxheim`.
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
symlinked parent directory, and on Unix must not use a world-writable existing
parent such as `/tmp`. The snapshot store runtime applies the same rule when it
is used directly by CLI/admin paths.

Admin endpoint paths are capped at 2048 bytes and query strings are capped at
16 KiB before endpoint-specific parsing. Prefer headers for long cache purge
values.

`admin.self_healing.health_path` must be an absolute path no longer than 2048
bytes and cannot contain whitespace, control characters, backslashes, `?`, or
`#`. Custom health paths must not use the protected `/_fluxheim/` admin prefix;
the built-in `/_fluxheim/health` endpoint is the only unauthenticated path in
that namespace.

Snapshot messages submitted through the admin API are trimmed and capped at
4096 bytes of non-control text before they are persisted.

On Linux, `token_file` is opened without following symlinks, must resolve to a
regular file handle, must not sit below a symlinked or world-writable parent
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
```

The `metrics` compile-time feature is not part of `profile-privacy`.

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
directory and are rejected when the nearest existing parent is world-writable,
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
emits `X-Real-IP` from the observed client address. In privacy builds it
defaults off and client-IP forwarding remains stripped.

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
that as ambiguous.

Security headers are easy to enable globally:

```toml
[headers.response]
strict_transport_security = "max-age=31536000; includeSubDomains"
content_security_policy = "default-src 'self'"
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
```

HSTS and CSP are intentionally not enabled blindly in examples because they are
site-specific and can break local HTTP testing or asset policies.

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

`upstreams` is the preferred proxy target form for both one and many origins.
The older single `upstream = "host:port"` field remains supported for simple
configs, but do not set both fields in the same proxy block. Fluxheim rejects
that as ambiguous. When `upstreams` is present, Fluxheim uses the first entry
as the primary upstream in builds without `load-balancer`, and uses the full
list for the Pingora load-balancer path when compiled with `load-balancer`.
`connect_timeout_secs`, `read_timeout_secs`, and `send_timeout_secs` are
optional. They map to the upstream connection timeout, upstream response/read
timeout, and upstream request-body/write timeout.

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
dotfiles by default, and unknown nested index file names. Static body reads
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
enabled = false
image_extensions = ["avif", "gif", "jpeg", "jpg", "png", "svg", "webp"]
methods = ["GET", "HEAD"]
max_object_bytes = "32MiB"

[cache.memory]
enabled = false
max_size_bytes = "1GiB"

[cache.disk]
enabled = false
path = "/var/cache/fluxheim"
max_size_bytes = "10GiB"
```

If `cache.enabled = true`, at least one storage tier must be enabled.
Each enabled tier must be at least as large as `max_object_bytes`.
Disk cache requires `cache.disk.path`. The disk cache root must be a real
directory and must not sit below a symlinked parent directory. On Unix,
Fluxheim also rejects disk cache roots whose nearest existing parent is
world-writable, such as creating a cache root directly below `/tmp`; use a
dedicated cache directory such as `/var/cache/fluxheim` or a pre-created private
runtime directory.

Per-vhost cache settings use `[vhosts.cache]`, `[vhosts.cache.memory]`, and
`[vhosts.cache.disk]`.

## TLS

```toml
[tls]
enabled = false
backend = "rustls"

[[tls.certificates]]
cert_path = "tls/fullchain.pem"
key_path = "tls/key.pem"
```

TLS backend values: `rustls`, `openssl`, `boringssl`, `s2n`.

Exactly one matching TLS compile-time feature should be selected:
`tls-rustls`, `tls-openssl`, `tls-boringssl`, or `tls-s2n`. The default build
uses `tls-rustls`.

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

Fluxheim does not expose user-configurable TLS cipher-suite or protocol-version
settings yet. Downstream TLS listeners currently use the selected Pingora TLS
backend defaults. Release validation must scan those defaults with a TLS scanner
before publishing a stable release. Explicit named TLS policy profiles and
optional cipher allow-lists are planned for a later stable release.

Check certificate storage permissions separately:

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

On Unix, private keys should be owner-only and ACME storage directories should
be owner-only. The storage checker rejects symlinked certificate files, private
key files, ACME EAB secret files, ACME storage directories, and paths below
symlinked or world-writable directories; mount or configure the real paths
directly. If Fluxheim cannot inspect any TLS path prefix for symlinks,
validation fails closed and reports the path as unreadable. Config validation
also rejects static certificate paths, ACME storage paths, and ACME EAB secret
files when their nearest existing parent directory is world-writable. EAB secret
files are checked with the same owner-only permission rule as private keys.

## ACME

ACME config parsing and renewal planning exist, but automated issuance/runtime
challenge handling is not considered release-ready yet.

```toml
[tls.acme]
enabled = false
storage = "/var/lib/fluxheim/acme"
contact_email = "admin@example.test"
default_issuer = "letsencrypt"
challenge = "tls-alpn-01"

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

Built-in issuer names include `letsencrypt`, `letsencrypt-staging`, and
`actalis`. Actalis EAB secret sources are configured through environment
variables or files.

## Vhosts

Vhosts bind hostnames to per-site web, proxy, TLS, cache, and header settings.
TOML uses `[[vhosts]]` to start a new vhost. Every `[vhosts.*]` table that
follows belongs to that current vhost until the next `[[vhosts]]`.

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
`max_request_body_bytes` is optional on a vhost and overrides the global
`server.limits.max_request_body_bytes` for that host. Route-level
`max_request_body_bytes` still wins when a matching route sets its own limit.

Vhosts can also contain ordered route tables. Exact matches win first, then the
longest prefix match, then one optional fallback route. A route must define one
action: `redirect`, `proxy`, or `web`.

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

When global `[server.https_redirect]` is enabled, non-redirect routes are
redirected on cleartext requests by default. `[vhosts.acme_challenge]` creates
the standard HTTP-01 `/.well-known/acme-challenge/` proxy route and exempts only
that path. Advanced route configs can still use `https_redirect_exempt = true`
for deliberate non-ACME cleartext exceptions.
Use either `upstream = "host:port"` or `upstreams = ["host:port"]`; do not set
both. The helper accepts the same `upstream_tls` and upstream timeout fields as
normal proxy actions.

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
