# Zero-Retention Privacy Mode

Zero-retention privacy mode is a future compile-time build profile for users
who want Fluxheim to serve static files and reverse-proxy requests without
persisting request logs, client IPs, request metadata, or per-client telemetry.

This is the better name for the requested "dark mode": the goal is not visual
appearance, but no application-level retention.

## Honest Boundary

Fluxheim cannot be literally zero-knowledge at the network layer. A TCP/TLS
server necessarily sees the peer address transiently while accepting and routing
a connection. The operating system, container runtime, firewall, CDN, and
upstream applications may also log traffic.

The privacy-mode guarantee should be scoped to Fluxheim itself:

- no Fluxheim access logs;
- no Fluxheim request audit logs;
- no Fluxheim request metrics;
- no persisted client IPs;
- no persisted request paths, user agents, cookies, request IDs, or real-IP
  headers;
- no Fluxheim disk cache of proxied responses;
- no client-IP forwarding to upstreams by default.

Operators still need to configure the OS, Podman/systemd, firewall, CDN, and
upstream services consistently if they want a whole deployment to be
zero-retention.

## Goals

- Compile a small static-web plus reverse-proxy binary.
- Exclude logging and metrics exporters from the binary.
- Strip inbound client-identifying forwarding headers.
- Avoid adding new client-identifying forwarding headers.
- Keep request data transient and memory-only.
- Keep startup/config diagnostics possible without request metadata.

## Non-Goals

- No WAF audit logs.
- No Cloudflare real-IP restoration.
- No per-client metrics.
- No disk response cache.
- No PHP/CGI dynamic runtime execution.
- No legacy protocol compatibility mode.
- No claim that upstream applications will avoid logging.

## Feature Flags

Target build:

```bash
cargo build --no-default-features --features proxy,web,tls-rustls,privacy-mode
```

Implemented feature:

```toml
privacy-mode = ["proxy", "web"]
```

`privacy-mode` must not be part of `default`.

Initial implemented behavior: privacy builds strip inbound client-IP forwarding
headers before proxying and do not synthesize `X-Forwarded-For` or RFC
`Forwarded`, even when config requests those headers.

Access logging is disabled by default in `privacy-mode`, the Pingora access-log
emission hook is not compiled into privacy builds, and config validation rejects
`logging.access.enabled = true` and `logging.file.enabled = true`.
Privacy builds also do not generate Fluxheim request IDs for access-log
correlation.

Implemented compile-time incompatible features:

- `metrics`
- `cache`

Because `cache` is part of the normal default build, privacy builds must use
`--no-default-features` or the `profile-privacy` alias:

```bash
cargo build --no-default-features --features profile-privacy
```

Use `examples/privacy.toml` as the baseline runtime config for this profile.
It disables Fluxheim access logging, request ID generation, metrics, cache, and
client-IP forwarding headers.

## Future Privacy Cache

Normal `cache` remains incompatible with `privacy-mode` because shared HTTP
cache can persist response bodies, paths, query strings, `Vary` dimensions,
cookies, and upstream privacy mistakes. A future `privacy-cache` design is
planned as a separate, restricted public-asset cache rather than normal cache in
privacy builds. The intended boundary is: no client-IP cache keys, no
`Cookie`/`Authorization` admission, no per-user variants, no
`private`/`no-store`/`Set-Cookie` storage, strict query-string defaults, and
memory or encrypted short-TTL disk storage as the preferred shape.

Implemented incompatible features:

- `metrics`
- `metrics-otlp`
- `otel-tracing`
- `otel-otlp`

Planned incompatible features:

- `metrics-advanced`
- `metrics-push`
- `logging-remote`
- `logging-spool`
- `waf`
- `waf-native`
- `waf-hyperscan`
- `waf-proxy-wasm`
- `cloudflare`
- `cloudflare-api`
- `cloudflare-origin-ca`
- `cloudflare-aop`
- PHP runtime features
- Perl CGI features
- legacy HTTP features
- disk cache features

Where possible, enforce this with `compile_error!` guards so invalid builds fail
early.

## Runtime Behavior

Allowed:

- static file serving;
- reverse proxying;
- TLS termination with configured certificates;
- memory-only routing/config state;
- startup/config diagnostics without request metadata.

Disabled or forbidden:

- access logs;
- request IDs persisted outside the request;
- remote logging;
- file logging;
- request metrics;
- admin endpoints that expose request activity;
- cache activity endpoints;
- disk cache;
- WAF audit events;
- Cloudflare real-IP restoration;
- self-healing systems that persist request/error samples.

## Header Policy

Privacy mode should strip inbound headers that may carry client identity before
proxying unless a future non-privacy build explicitly allows them:

- `X-Forwarded-For`
- `Forwarded`
- `X-Real-IP`
- `CF-Connecting-IP`
- `True-Client-IP`
- `X-Client-IP`
- `Client-IP`

Privacy mode must not synthesize:

- `X-Forwarded-For`
- `Forwarded`
- `X-Real-IP`

It may still forward normal HTTP headers needed for the application, such as
`Host`, `Accept`, `Content-Type`, and authentication headers, because removing
those would break normal proxy behavior. Operators should understand that
upstreams can still log whatever headers they receive.

## Static File Serving

Static serving is compatible with privacy mode if it:

- uses canonical path resolution;
- does not create per-client records;
- does not write request activity to disk;
- allows operators to set conservative static response cache headers;
- avoids directory listings unless explicitly enabled outside privacy mode.

The privacy example uses `cache_control = "no-store"` to avoid encouraging
client-side or intermediary retention. That is a deployment policy choice:
Fluxheim's zero-retention guarantee covers Fluxheim itself, not browsers,
intermediate networks, or upstream applications.

OS-level filesystem access times may still change depending on mount options.
Operators who care about that should use `noatime`/`relatime` choices
appropriate to their deployment.

## Reverse Proxying

Reverse proxying is compatible with privacy mode if Fluxheim:

- does not log upstream choices per request;
- does not emit per-request metrics;
- does not persist failed request samples;
- strips client-IP forwarding headers;
- avoids disk cache;
- keeps only transient in-memory request state.

Upstream applications must be configured separately to avoid logging IPs or
request metadata.

## Config Shape

Initial target:

```toml
[privacy]
enabled = true
deny_request_logging = true
deny_metrics = true
deny_disk_cache = true
strip_forwarded_client_ip_headers = true
forbid_client_ip_forwarding = true

[server]
listen = ["0.0.0.0:80"]
tls_listen = ["0.0.0.0:443"]

[[vhosts]]
name = "private-site"
hosts = ["private.example.test"]

[vhosts.web]
root = "/srv/sites/private"

[vhosts.proxy]
upstreams = ["127.0.0.1:3000"]
```

The config validator should reject privacy mode if request logging, metrics,
disk cache, WAF, Cloudflare real-IP restoration, PHP/CGI, or legacy HTTP modules
are enabled.

## Logging Policy

Privacy builds should use a no-op request logger.

Allowed operational messages:

- process start/stop;
- config validation failure without request data;
- certificate load failure without peer data;
- fatal internal errors without request data.

Forbidden operational messages:

- client IP;
- restored real IP;
- request path;
- query string;
- user-agent;
- cookies;
- authorization headers;
- request ID;
- upstream selection tied to a request.

## Metrics Policy

The safest privacy build has no metrics module compiled.

If a future operator asks for privacy-compatible metrics, it should be a
separate feature and limited to process-level counters that cannot identify
clients or requests, for example process uptime and build info. It should not
be part of the first privacy mode.

## Tests

Required tests:

- Default build does not include `privacy-mode`.
- Privacy build excludes metrics and logging exporter features.
- Invalid feature combinations fail at compile time.
- Config validation rejects metrics, disk cache, WAF, Cloudflare real-IP
  restoration, PHP/CGI, and legacy HTTP when privacy mode is enabled.
- Proxy requests strip `X-Forwarded-For`, `Forwarded`, `X-Real-IP`,
  `CF-Connecting-IP`, and `True-Client-IP`.
- Proxy requests do not synthesize new real-IP forwarding headers.
- Access logging hook emits no request event.
- No request path, IP, user-agent, cookie, or request ID is written by
  Fluxheim-controlled sinks.
- Static file serving still works.
- Reverse proxying still works.
- TLS still works with configured certificates.
