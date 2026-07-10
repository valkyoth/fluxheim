# PHP Runtime Support

Fluxheim `1.3.1` adds the first production-compatible PHP path through
`php-fpm`. PHP is not part of the default binary. Each PHP runtime changes the
security model from serving files and proxying HTTP to executing user code, so
every PHP path is opt-in at compile time and opt-in per vhost or route.

## Current Recommendation

Use this implementation model:

1. `php-fpm`: stable backwards-compatible path for PHP applications. This is
   implemented in `1.3.1`.
2. Managed `php-fpm`: zero-admin deployment mode inside the existing `php-fpm`
   feature. Fluxheim generates a minimal private php-fpm pool, spawns and
   supervises php-fpm, and connects to its private socket while still using the
   same FastCGI request path as external php-fpm.

As of the current review, `fastcgi-client 0.11.1` is available for the php-fpm
path under Apache-2.0. Pure-Rust PHP/phprs support is no longer planned for the
1.3 line because managed php-fpm covers the useful zero-admin deployment goal
without adopting an immature interpreter. `ripht-php-sapi 0.1.0-rc.7` remains an
embedding reference only. Turbine is not a Fluxheim runtime target; it is better
treated as an external PHP application server that Fluxheim can reverse-proxy to
if an operator chooses it.

## Compile-Time Features

Implemented feature flags:

```toml
php = ["proxy", "web"]
php-fpm = ["php", "dep:fastcgi-client", "dep:tokio", "fastcgi-client/runtime-tokio"]
```

`php-fpm` is the only PHP runtime feature in the 1.3 line. Managed php-fpm is a
runtime configuration mode under the same feature because it changes process
lifecycle, not the request protocol.

The default feature set must not include `php`.

Release order:

- `1.3.0`: shared ingress/TLS feature-graph split and focused image/profile
  cleanup.
- `1.3.1`: `php-fpm` FastCGI bridge, WordPress-style front-controller support,
  strict script resolution, bounded request/response buffering, split-cookie
  normalization, and browser-validated WordPress login/admin flows.
- `1.3.3`: focused php-fpm hardening and compatibility fixes found during
  production tests.
- `1.3.7`: managed php-fpm mode as a config option under the existing
  `php-fpm` feature, not as a separate Cargo runtime. The goal is a
  single-binary operator experience while retaining normal php-fpm request
  isolation and compatibility.
- Pure-Rust PHP/phprs is intentionally out of scope for the 1.3 line. Revisit
  only if an upstream interpreter has mature compatibility, maintenance, and
  security evidence.

## Config Shape

Minimal vhost TOML:

```toml
[[vhosts]]
name = "php.example.test"
hosts = ["php.example.test"]

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/sites/php.example.test/public"
index = "index.php"
allowed_extensions = ["php"]
deny_path_prefixes = ["/wp-content/uploads/"]
request_timeout_secs = 30
max_request_body_bytes = "16MiB"
max_response_bytes = "64MiB"
max_response_header_bytes = "64KiB"
pass_request_headers = true
pass_request_body = true
stderr_log = true
stderr_max_bytes = "2KiB"
hide_response_headers = ["x-powered-by"]
ignore_origin_cache_headers = false
intercept_error_statuses = []
# Use "split" only when the application expects PATH_INFO after script.php.
path_info = "disabled"

[[vhosts.php.error_pages]]
status = 502
path = "/502.html"

[vhosts.php.error_pages.web]
root = "/srv/errors"
index_files = ["index.html"]

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
allow_private_tcp_upstreams = true
# socket = "/run/php/php-fpm.sock"
```

Managed php-fpm mode keeps the runtime selection in
`[vhosts.php.fpm]` instead of adding a new compile-time PHP runtime:

```toml
[vhosts.php.fpm]
mode = "managed" # "external" remains the default
php_fpm_binary = "/usr/sbin/php-fpm"
workers = 4
max_requests_per_worker = 1000
socket_dir = "/run/fluxheim/php"
process_manager = "static" # "static", "dynamic", or "ondemand"
# listen_backlog = 128
# Optional socket ownership controls when php-fpm changes socket ownership
# after dropping privileges. Defaults to a private 0600 socket.
# listen_owner = "fluxheim"
# listen_group = "php"
# listen_mode = "0660"
# request_terminate_timeout_secs = 30
# request_slowlog_timeout_secs = 5
# clear_env = true
# catch_workers_output = true
# decorate_workers_output = true
# Optional, configure both together when php-fpm starts as root and should drop
# worker privileges. Pair with listen_owner/listen_group/listen_mode when
# Fluxheim itself is not running as the same user.
user = "fluxheim"
group = "fluxheim"
```

Managed mode generates a minimal private php-fpm config, creates a
Fluxheim-owned Unix socket, supervises the php-fpm master process, and shuts it
down cleanly on reload or gateway shutdown. It is not implemented as a
persistent `php-cli` stdin/stdout worker pool for production apps, because
normal WordPress, Laravel, Symfony, forum, and wiki applications expect
per-request PHP isolation.

The generated socket, config, pid, and php-fpm log files live under
`socket_dir`. Normal reload/drop cleanup removes the generated control files,
but forced process termination can leave stale files behind because destructors
do not run. They are safe to remove when Fluxheim is stopped.

Managed pools support the php-fpm process manager modes operators usually tune
in `www.conf`:

- `process_manager = "static"` starts exactly `workers` children.
- `process_manager = "dynamic"` uses `workers` as `pm.max_children` and
  requires `min_spare_servers` and `max_spare_servers`; `start_servers` and
  `max_spawn_rate` are optional.
- `process_manager = "ondemand"` uses `workers` as `pm.max_children` and can
  set `process_idle_timeout_secs`.

Fluxheim also writes bounded php-fpm directives for `listen_backlog`,
`listen_owner`, `listen_group`, `listen_mode`,
`request_terminate_timeout_secs`,
`request_terminate_timeout_track_finished`, `request_slowlog_timeout_secs`,
`request_slowlog_trace_depth`, `clear_env`, `catch_workers_output`,
`decorate_workers_output`, `session_save_path`, and `upload_tmp_dir`.
`session_save_path` and `upload_tmp_dir` are created with owner-only
permissions when missing; if the managed pool drops to another `user`/`group`,
make those directories writable by that PHP worker identity before starting
Fluxheim.

The PHP handler runs before static fallback. Existing non-PHP files under the
PHP root are declined so the normal static server can serve assets. Missing
paths use the configured front controller, normally `/index.php`. Explicit
`.php` requests are executed through php-fpm. Static serving must never return
PHP source when PHP execution fails.

Fluxheim normalizes multiple inbound `Cookie` header lines into one CGI
`HTTP_COOKIE` value before calling php-fpm. This matters for WordPress and other
PHP applications behind HTTP/2 or intermediaries that split cookies across
multiple header fields.

For application-specific examples, including WordPress, WordPress Multisite,
Laravel, Symfony, Flarum, MediaWiki, phpBB, XenForo, MyBB, and
Discourse-as-proxy, see
[`PHP-FPM Application Recipes`](php-fpm-app-recipes.md).

## FastCGI Protocol Scope

Fluxheim's php-fpm integration intentionally implements the normal web-serving
FastCGI subset: one `FCGI_RESPONDER` request at a time per selected backend
connection, `BEGIN_REQUEST`, bounded `PARAMS`, optional `STDIN`, collected
`STDOUT`, bounded and sanitized `STDERR`, and `END_REQUEST`. Opt-in keepalive
may reuse an idle backend connection after a request completes, but Fluxheim does
not multiplex concurrent FastCGI request IDs on one connection.

`FCGI_AUTHORIZER`, `FCGI_FILTER`, FastCGI management records, and application
protocols that require multiplexed request state are unsupported in `1.3.x`.
They are not required for standard PHP-FPM WordPress, Laravel, Symfony, or
legacy PHP web serving. Operators that need those roles should keep them behind
a dedicated FastCGI-aware component until Fluxheim has an explicit design and
test suite for them.

## Security Requirements

The PHP layer must implement these checks before any runtime is production
eligible:

- Canonicalize the vhost PHP root and target script path.
- Reject traversal, symlink escapes, empty script names, and non-file script
  targets.
- Never build `SCRIPT_FILENAME` through string concatenation alone.
- Deny dotfiles and hidden path segments by default.
- Deny configured PHP execution path prefixes before contacting php-fpm.
- Never pass arbitrary process environment to PHP.
- Use a small allow-list for CGI/FastCGI params.
- Reject decoded control characters in path-derived FastCGI params and avoid
  protocol-relative directory-slash redirects.
- Set `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `REQUEST_METHOD`,
  `QUERY_STRING`, `REQUEST_URI`, `SERVER_NAME`, `SERVER_PORT`, and
  `SERVER_PROTOCOL` explicitly.
- Translate safe inbound HTTP headers to CGI `HTTP_*` params, including
  `HTTP_HOST`, while dropping `Proxy` to avoid HTTPoxy exposure.
- Set TLS-related CGI context (`HTTPS` and `REQUEST_SCHEME`) from the
  downstream connection state.
- Set `REDIRECT_STATUS=200` for php-fpm compatibility with common PHP
  hardening defaults.
- Treat `PATH_INFO` as disabled by default; enable `path_info = "split"` only
  when the application expects safe trailing segments after `script.php`.
- Allow administrator-controlled custom FastCGI params only after validating
  names and values, and never let them override Fluxheim-managed CGI params
  such as `SCRIPT_FILENAME`, `CONTENT_LENGTH`, `HTTPS`, or `HTTP_PROXY`.
- Enforce global and PHP-specific request body limits for both declared and
  streaming bodies.
- Support explicit `pass_request_headers` and `pass_request_body` switches.
  Body pass-through disabled still drains and limits the downstream body before
  sending empty FastCGI stdin.
- Apply runtime request timeouts and connection timeouts.
- Log php-fpm STDERR only when `stderr_log` is enabled, sanitize controls, and
  cap each log message with `stderr_max_bytes`.
- Remove selected php-fpm response headers with `hide_response_headers` before
  the response reaches clients.
- Optionally ignore PHP-generated `Cache-Control`, `Expires`, and `Pragma`
  headers with `ignore_origin_cache_headers` before response policy is applied.
- Cap response header bytes returned by PHP.
  Implemented as `php.max_response_header_bytes`, defaulting to `64KiB`.
- Parse PHP-generated headers strictly; reject malformed status lines and
  header injection.
- Strip hop-by-hop php-fpm response headers, including `Connection`-named
  headers and `Transfer-Encoding`, before Fluxheim frames the client response.
- Optionally intercept selected PHP 4xx/5xx responses with
  `intercept_error_statuses` and replace them with Fluxheim-generated error
  responses.
- Serve configured static PHP error pages with `[[vhosts.php.error_pages]]` or
  `[[vhosts.routes.php.error_pages]]`; an error-page entry also intercepts that
  status and falls back to Fluxheim's generated error if the static page cannot
  be served.
- Log PHP STDERR only through size-limited sanitized logs.
- Keep php-fpm sockets private and validate Unix socket path permissions where
  possible.
- Prefer php-fpm process isolation for production until embedded runtimes prove
  safe concurrency and reload behavior.

## Runtime Plans

### `php-fpm`

This is the compatibility-first path. Fluxheim acts as a FastCGI client:

1. Match an eligible PHP request from vhost config.
2. Resolve and canonicalize the target script under the configured root.
3. Build FastCGI params from a strict allow-list.
4. Bounded-buffer the request body to php-fpm.
5. Bounded-buffer and parse FastCGI STDOUT into HTTP headers and body.
6. Send PHP STDERR to sanitized logs and metrics.

`max_response_bytes` defaults to `64MiB` and is capped at `64MiB`. Hardened edge
deployments can lower it per vhost or route to reduce per-request memory
exposure for PHP responses. Large generated files should use `X-Accel-Redirect`
or `X-Sendfile` so Fluxheim serves the file path directly instead of buffering
the PHP output in memory.

Prefer Unix sockets first for local/rootless deployments. TCP support is useful
for separate php-fpm containers, but must require explicit config.

Current tests cover config validation, traversal rejection, disabled `PATH_INFO`
behavior, safe CGI header translation with HTTPoxy mitigation, custom FastCGI
param validation, malformed FastCGI response headers, php-fpm timeout
classification, spooled request-body replay and cleanup, and bounded STDERR
handling. Local WordPress php-fpm and proxied WordPress TLS smoke tests live in
`scripts/smoke_wordpress_php_fpm.sh` and
`scripts/smoke_wordpress_proxy_tls.sh`; keep running them as release evidence
when PHP behavior changes. The local WordPress smoke accepts `external`,
`managed-static`, `managed-dynamic`, `managed-ondemand`, `managed-all`, or
`managed-respawn`, or `both` so the same install/login/admin flow can verify an
operator-managed php-fpm container, every Fluxheim-managed php-fpm process
manager mode, and the managed php-fpm post-start crash respawn watchdog.
`scripts/smoke_fluxheim_php_wolfi.sh` verifies the self-contained Wolfi PHP
image path with bundled `php-8.5-fpm` and managed php-fpm enabled.

Managed php-fpm starts the php-fpm master with a cleared environment and a
minimal `PATH`, so Fluxheim process secrets such as admin tokens are not
inherited by the child process. On reload/shutdown, Fluxheim asks the managed
php-fpm master to terminate gracefully before escalating to a forced kill after
a short deadline. A per-pool watchdog monitors the php-fpm master after startup
and respawns it with bounded backoff if it crashes, so managed PHP service can
recover without a Fluxheim config reload.

Adding or removing a managed pool, or changing its executable, socket
directory, identity, environment isolation, process-manager, worker, or
supervision settings requires supervised Fluxheim process replacement. Routing,
request limits, FastCGI transport timeouts, and response policy remain eligible
for snapshot reload because they do not mutate the already-running php-fpm
master.

When a managed php-fpm pool drops workers to a different `user`/`group`,
configure `listen_owner` and `listen_group` when the php-fpm master should chown
the private socket for Fluxheim, and use `listen_mode = "0660"` only when a
shared service group is intentional. The default remains `listen_mode = "0600"`
for single-user/rootless deployments.

`1.3.3` php-fpm hardening status:

- Connection pooling to php-fpm with idle pruning. Implemented as opt-in
  `php.fpm.keepalive`.
- Safe FastCGI keep-connection reuse where the client/runtime supports it.
  Implemented for the `fastcgi-client` keep-alive path.
- True streaming request and response bodies. Request-body disk replay is in
  place for large PHP bodies; direct downstream-to-FastCGI and FastCGI-to-client
  streaming remain future work.
- Chunked upload disk-spooling before php-fpm dispatch. Implemented with
  `php.request_body_spool_threshold_bytes` and `php.request_body_spool_dir` so
  large uploads keep exact FastCGI `CONTENT_LENGTH` without retaining the whole
  request body in memory. Both settings must be configured together, and the
  threshold must be lower than `php.max_request_body_bytes` when both are set
  on the same PHP action. Existing spool directories must not be group/world
  writable, and runtime spool creation rechecks permissions before writing
  upload bodies.
- Custom FastCGI params in config. Implemented as `[vhosts.php.params]` and
  `[vhosts.routes.php.params]` with protected core CGI params.
- Path mapping for separate Fluxheim/php-fpm container filesystem roots.
  Implemented as `php.fpm_root` for FastCGI `DOCUMENT_ROOT`,
  `SCRIPT_FILENAME`, and `PATH_TRANSLATED` mapping. Existing local
  `php.fpm_root` paths are rejected when they include symlink components; missing
  absolute values are allowed for split-container paths that exist only inside
  the php-fpm environment.
- PHP root override for split container filesystem layouts. Implemented with
  `php.fpm_root` for the path sent to php-fpm and
  `php.resolve_root_symlink` for opt-in final `php.root` symlink resolution in
  current-release deploy layouts.
- Typed `try_files`/front-controller presets for WordPress, Laravel/Symfony,
  and strict `=404` PHP locations.
  Implemented as `php.try_files = "front-controller"`, `"wordpress"`, or
  `"strict"`.
- WordPress PHP-side migration preset. Implemented as `php.preset =
  "wordpress"` to combine WordPress front-controller behavior with deny prefixes
  for common upload/file execution paths.
- Configurable safe `PATH_INFO` splitting.
  Implemented as `php.path_info = "disabled"` or `"split"`; the legacy
  `"strict"` spelling remains accepted as an alias for `"split"`.
- Canonical directory slash redirects for directory index PHP apps.
  Implemented as a `308` redirect before executing directory `index.php`
  scripts.
- Explicit request header/body pass-through switches for advanced migrations.
  Implemented as `php.pass_request_headers` and `php.pass_request_body`, both
  defaulting to `true`.
- PHP-specific in-flight request cap. Implemented as `php.max_in_flight`,
  defaulting to `8`, so buffered PHP-FPM responses cannot multiply without a
  route-local or vhost-local bound.
- `X-Accel-Redirect` / `X-Sendfile` support. Implemented for PHP-assisted
  static offload under `php.root`; `X-Sendfile` paths are mapped from
  `php.fpm_root` for split containers, and configured PHP script extensions
  are refused as offload targets.
- `X-Accel-Expires` response control handling. Implemented for PHP responses:
  Fluxheim strips the internal header, maps valid TTLs to `Cache-Control` and
  `Expires`, treats zero or past expiries as `no-store`, and uses `private`
  directives for responses that set cookies. If the origin response already has
  restrictive cache policy such as `Cache-Control: private`, `no-store`,
  `no-cache`, or `Pragma: no-cache`, Fluxheim preserves that policy and does not
  promote the response to shared-cache eligibility.
- `fastcgi_intercept_errors`-style integration with Fluxheim error pages.
  Initial generic interception implemented as `php.intercept_error_statuses`.
- Response header hide/pass/ignore controls for PHP backends.
  Initial hide controls implemented as `php.hide_response_headers`;
  `php.ignore_origin_cache_headers` removes PHP-generated `Cache-Control`,
  `Expires`, and `Pragma`; hop-by-hop PHP response headers are stripped by
  default.
- STDERR capture/truncation/severity controls and fatal-error matching.
  Initial controls implemented as `php.stderr_log`, `php.stderr_log_level`,
  `php.stderr_max_bytes`, and `php.stderr_failure_patterns` for marking
  matching STDERR output as an invalid php-fpm response eligible for opt-in
  safe-method retry/failover.
- Initial php-fpm TCP upstream list and failover. Implemented as
  `php.fpm.tcp_upstreams` with round-robin endpoint selection and safe-method
  failover on connection failures and connect timeouts. Upstream lists are
  capped at 64 entries and reject duplicate authorities.
- Retry policy for connection failures and connect timeouts on configured safe
  methods. Implemented as `php.fpm.max_retries` and
  `php.fpm.retry_methods`, with `php.fpm.retry_timeout_secs` as an optional
  per-request retry window; php-fpm connect timeouts are bounded by
  `php.request_timeout_secs`, and request timeouts are not retried to avoid
  duplicating PHP side effects. With `tcp_upstreams`, Fluxheim tries enough
  endpoints to cover the configured list for safe methods even when
  `max_retries = 0`. Broader status/invalid-header retry policy is available
  as opt-in `php.fpm.retry_invalid_response` and `php.fpm.retry_statuses`.
- PHP-specific Prometheus metrics for bounded request totals, durations, STDERR,
  retries, and keepalive pool state. Multi-upstream keepalive pools use stable
  indexed pool labels for Prometheus gauges. Implemented as
  `fluxheim_php_requests_total`, `fluxheim_php_request_duration_seconds`,
  `fluxheim_php_stderr_events_total`, `fluxheim_php_fpm_retries_total`,
  `fluxheim_php_fpm_pool_idle_connections`, and
  `fluxheim_php_fpm_pool_events_total`; OpenTelemetry metrics export follows the
  existing metrics exporter path when enabled. OTLP request spans include
  low-cardinality `fluxheim.php.runtime` and `fluxheim.php.outcome` attributes
  for PHP-handled requests when `otel-otlp` is enabled.
- FastCGI cache-specific convenience config.
  Initial convenience preset implemented as `cache.preset = "wordpress"`,
  expanding common admin/login/legacy endpoint, cookie-prefix, query, and
  authorization bypasses. The underlying cache predicate lists are bounded to
  prevent unbounded per-request matching.
- FastCGI cache compatibility presets: cache keys, status TTLs, bypass/no-cache
  predicates, cache lock, stale-on-error/timeout, background refresh, and purge.
  The WordPress cache preset now also supports the common NGINX rule that any
  non-empty query string bypasses shared cache lookup and storage.
- WordPress cache-plugin migration presets for logged-in/commenter cookie
  bypass, admin/login exclusions, and denial of PHP execution under
  uploads/files directories. The first cache safety preset is
  `cache.preset = "wordpress"`.
  Initial execution denial implemented as `php.deny_path_prefixes`; this is
  defense in depth above local filesystem permissions and stops Fluxheim from
  sending matching PHP scripts to php-fpm.
- Super Cache/W3TC-style static-file fallbacks remain future work. They need a
  typed static-file probing design so Fluxheim can avoid broad rewrite-string
  interpolation while still matching common WordPress plugin cache layouts.
- FastCGI multiplexing, authorizer, and filter-role review. Documented as
  unsupported for `1.3.x`; Fluxheim supports the normal one-request-at-a-time
  `FCGI_RESPONDER` PHP-FPM web-serving subset.

### Turbine-Style PHP App Servers

Turbine-style PHP runtimes are outside Fluxheim's embedded PHP runtime plan.
They are app servers with their own listener, worker, TLS, lifecycle, and
metrics model. Operators can run one behind Fluxheim like any other HTTP
upstream:

```toml
[[vhosts]]
name = "turbine-app"
hosts = ["turbine.example.test"]

[vhosts.proxy]
upstreams = ["turbine-app:8080"]
upstream_tls = false
```

Fluxheim should not duplicate that model as an embedded PHP runtime unless a
future project exposes a small auditable library API with a clearly safer
security boundary than reverse proxying.

### Pure-Rust PHP

Pure-Rust PHP/phprs is not a Fluxheim runtime target for the 1.3 line. Managed
php-fpm provides the useful single-binary operational model while preserving the
normal php-fpm compatibility and isolation boundary. Revisit only if a future
interpreter has mature PHP/framework compatibility, security testing,
performance evidence, and a clear maintenance signal.

Fluxheim 1.3.6 also completed the adjacent admin API JSON cleanup. This is not
part of the PHP runtime, but it landed in the same hardening window: dynamic
admin responses now serialize through `serde_json::to_vec` while preserving the
existing admin API schemas and regression coverage.

## Reload And Operations

PHP runtime selection and PHP runtime process settings should be classified as
process-upgrade changes until a runtime proves safe snapshot-only reload
semantics.

Per-vhost PHP routing policy may later become snapshot-safe, but only after
path resolution, runtime handles, and request isolation are immutable per
runtime snapshot.

Operational metrics include bounded Prometheus request totals, durations,
STDERR event counts, php-fpm retry-attempt counts, and keepalive pool idle and
event metrics for the PHP handler.
