# PHP Runtime Support

Fluxheim `1.3.1` adds the first production-compatible PHP path through
`php-fpm`. PHP is not part of the default binary. Each PHP runtime changes the
security model from serving files and proxying HTTP to executing user code, so
every PHP path is opt-in at compile time and opt-in per vhost or route.

## Current Recommendation

Use this order for implementation and evaluation:

1. `php-fpm`: stable backwards-compatible path for real PHP applications today.
   This is implemented in `1.3.1`.
2. `php-turbine`: embedded Rust/library or managed-sidecar direction if
   Turbine has an auditable API, compatible licensing, active maintenance, and
   a security model that works inside Fluxheim. This belongs in a later `1.3.x`
   release after `php-fpm`.
3. `php-phprs`: experimental pure-Rust interpreter path. Useful for research,
   tests, and long-term optionality, not for production PHP hosting yet.

As of the current review, `fastcgi-client 0.11.1` is available for the php-fpm
path under Apache-2.0. `phprs 0.1.9` exists under Apache-2.0 but is still young.
`ripht-php-sapi 0.1.0-rc.7` exists under MIT as an embedding reference. Turbine
appears to be available as an external PHP app server/container, but it needs a
source, license, crate/library API, and security review before Fluxheim treats
it as an embeddable recommended module.

## Compile-Time Features

Implemented feature flags:

```toml
php = ["proxy", "web"]
php-fpm = ["php", "dep:fastcgi-client", "dep:tokio", "fastcgi-client/runtime-tokio"]
php-turbine = ["php"]
php-phprs = ["php"]
```

Only one PHP runtime feature may be selected in one binary. Fluxheim enforces
this at compile time and in `scripts/validate-features.sh`.

The default feature set must not include `php`.

Release order:

- `1.3.0`: shared ingress/TLS feature-graph split and focused image/profile
  cleanup.
- `1.3.1`: `php-fpm` FastCGI bridge, WordPress-style front-controller support,
  strict script resolution, bounded request/response buffering, split-cookie
  normalization, and browser-validated WordPress login/admin flows.
- `1.3.3`: focused php-fpm hardening and compatibility fixes found during
  production tests.
- `1.3.3`: `php-turbine` review and first integration if the library/sidecar
  model is safe enough.
- `1.3.4`: `php-phprs` pure-Rust interpreter experiment, test-only or beta
  unless compatibility and maintenance are proven.

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
request_timeout_secs = 30
max_request_body_bytes = "16MiB"
max_response_bytes = "64MiB"
pass_request_headers = true
pass_request_body = true
stderr_log = true
stderr_max_bytes = "2KiB"
# Use "split" only when the application expects PATH_INFO after script.php.
path_info = "disabled"

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
# socket = "/run/php/php-fpm.sock"
```

The PHP handler runs before static fallback. Existing non-PHP files under the
PHP root are declined so the normal static server can serve assets. Missing
paths use the configured front controller, normally `/index.php`. Explicit
`.php` requests are executed through php-fpm. Static serving must never return
PHP source when PHP execution fails.

Fluxheim normalizes multiple inbound `Cookie` header lines into one CGI
`HTTP_COOKIE` value before calling php-fpm. This matters for WordPress and other
PHP applications behind HTTP/2 or intermediaries that split cookies across
multiple header fields.

## Security Requirements

The PHP layer must implement these checks before any runtime is production
eligible:

- Canonicalize the vhost PHP root and target script path.
- Reject traversal, symlink escapes, empty script names, and non-file script
  targets.
- Never build `SCRIPT_FILENAME` through string concatenation alone.
- Deny dotfiles and hidden path segments by default.
- Never pass arbitrary process environment to PHP.
- Use a small allow-list for CGI/FastCGI params.
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
- Cap response header bytes returned by PHP.
- Parse PHP-generated headers strictly; reject malformed status lines and
  header injection.
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

`max_response_bytes` defaults to `64MiB`. Hardened edge deployments can lower
it per vhost or route to reduce per-request memory exposure for PHP responses.

Prefer Unix sockets first for local/rootless deployments. TCP support is useful
for separate php-fpm containers, but must require explicit config.

Current tests cover config validation, traversal rejection, disabled `PATH_INFO`
behavior, safe CGI header translation with HTTPoxy mitigation, custom FastCGI
param validation, and malformed FastCGI response headers. Rootless php-fpm
container smoke tests, timeout tests, and oversized body tests remain part of
the `1.3.3` hardening pass.

Planned `1.3.3` php-fpm hardening:

- Connection pooling to php-fpm with idle pruning. Implemented as opt-in
  `php.fpm.keepalive`.
- Safe FastCGI keep-connection reuse where the client/runtime supports it.
  Implemented for the `fastcgi-client` keep-alive path.
- True streaming request and response bodies.
- Chunked upload disk-spooling before php-fpm dispatch.
- Custom FastCGI params in config. Implemented as `[vhosts.php.params]` and
  `[vhosts.routes.php.params]` with protected core CGI params.
- Path mapping for separate Fluxheim/php-fpm container filesystem roots.
  Implemented as `php.fpm_root` for FastCGI `DOCUMENT_ROOT`,
  `SCRIPT_FILENAME`, and `PATH_TRANSLATED` mapping.
- PHP root override for split container filesystem layouts.
- Typed `try_files`/front-controller presets for WordPress, Laravel/Symfony,
  and strict `=404` PHP locations.
  Implemented as `php.try_files = "front-controller"`, `"wordpress"`, or
  `"strict"`.
- Configurable safe `PATH_INFO` splitting.
  Implemented as `php.path_info = "disabled"` or `"split"`; the legacy
  `"strict"` spelling remains accepted as an alias for `"split"`.
- Canonical directory slash redirects for directory index PHP apps.
  Implemented as a `308` redirect before executing directory `index.php`
  scripts.
- Explicit request header/body pass-through switches for advanced migrations.
  Implemented as `php.pass_request_headers` and `php.pass_request_body`, both
  defaulting to `true`.
- `X-Accel-Redirect` / `X-Sendfile` support.
- `X-Accel-Expires` mapping into Fluxheim cache metadata where safe.
- `fastcgi_intercept_errors`-style integration with Fluxheim error pages.
- Response header hide/pass/ignore controls for PHP backends.
- STDERR capture/truncation/severity controls and fatal-error matching.
  Initial controls implemented as `php.stderr_log` and
  `php.stderr_max_bytes`.
- php-fpm upstream load balancing and failover.
- Retry policy for connect error, timeout, invalid header, selected statuses,
  max tries, total retry timeout, and retry-safe methods.
- PHP-specific Prometheus/OpenTelemetry metrics.
- FastCGI cache-specific convenience config.
- FastCGI cache compatibility presets: cache keys, status TTLs, bypass/no-cache
  predicates, cache lock, stale-on-error/timeout, background refresh, and purge.
- WordPress cache-plugin migration presets for Super Cache/W3TC-style static
  fallbacks, logged-in/commenter cookie bypass, admin/login exclusions, and
  denial of PHP execution under uploads/files directories.
- FastCGI multiplexing, authorizer, and filter-role review. These are not
  needed for normal PHP-FPM web serving, but should be explicitly unsupported
  or implemented if enterprise users need them.

### `php-turbine`

Treat Turbine as the preferred direction only after review. The first evaluation
must answer:

- Is Turbine available as a Rust crate/library, or only as a standalone server?
- Is the license compatible with Fluxheim's EUPL-1.2 project policy?
- Does it embed PHP through unsafe FFI/SAPI code, and how is request isolation
  handled?
- Does it support rootless containers and local development without privileged
  host setup?
- Can Fluxheim safely reload config without corrupting embedded PHP state?

If Turbine is standalone-only, Fluxheim should integrate it as an HTTP upstream
or managed sidecar rather than embedding it. If Turbine is embeddable, the
module must remain feature-gated and should have separate build docs because PHP
embed/ZTS requirements can be hardware and distribution specific.

### `php-phprs`

`phprs` is interesting because it points toward a pure-Rust PHP runtime, but it
should stay experimental. Before it is considered production-capable, Fluxheim
needs language compatibility tests, framework compatibility tests, extension
behavior analysis, security tests, performance benchmarks, and a clear upstream
maintenance signal.

## Reload And Operations

PHP runtime selection and PHP runtime process settings should be classified as
process-upgrade changes until a runtime proves safe snapshot-only reload
semantics.

Per-vhost PHP routing policy may later become snapshot-safe, but only after
path resolution, runtime handles, and request isolation are immutable per
runtime snapshot.

Operational metrics should include request totals by runtime, PHP status codes,
runtime errors, timeouts, STDERR counts, and php-fpm connection failures.
