# HTTP Hosts, Routes And Rewrites

Routing answers two questions: which site should handle this hostname, and what
should that site do with this path? A route can forward to an application, serve
files, execute PHP or return a redirect. A rewrite changes the path used by the
selected action; it does not ask the browser to navigate elsewhere.

This guide covers the native HTTP routing contract. Start with the
[complete local example](../../examples/routing/local.toml), then use
[upstream TLS](upstream-tls.md), [load balancing](load-balancer.md),
[PHP recipes](php-fpm-app-recipes.md) and [caching](cache.md) for the selected
action's additional policies. TCP/UDP stream proxying is not HTTP routing.

## Run The Example

The example listens only on `127.0.0.1:8080`. It expects an HTTP application at
`127.0.0.1:9001` and a `site/hello.txt` file beside the configuration. The static
directory is resolved relative to the configuration base. Its tiny four-byte
upload limit is deliberately for demonstration, not a production recommendation.

Validate and run with a binary containing the proxy and web features:

```bash
fluxheim --config /path/to/local.toml --validate-config
fluxheim --config /path/to/local.toml
```

Supply the configured hostname when testing a numeric listener address:

```bash
curl -i -H 'Host: gateway.example.test' http://127.0.0.1:8080/api/status
curl -i -H 'Host: gateway.example.test' 'http://127.0.0.1:8080/api/users?active=1'
curl -i -H 'Host: gateway.example.test' http://127.0.0.1:8080/assets/hello.txt
```

For a self-contained developer test, the repository harness creates the file,
starts an echo origin and runs Fluxheim on temporary loopback ports:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/smoke_routing_examples.py
```

It checks actual HTTP responses and the path received by the origin, not just
TOML parsing. It runs the trusted local `target/debug/fluxheim` binary. Public
DNS, TLS certificates, authentication and firewall exposure are not set up by
this demo. Never use its permissive fallback as an access-control policy.

## Select A Site By Hostname

`[[vhosts]]` begins a site; every following `[vhosts.*]` table belongs to it
until the next `[[vhosts]]`. Similarly, `[[vhosts.routes]]` starts a route within
that site. See [vhost configuration](vhost-config.md) for split-file layouts.

```toml
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "gateway"

[server.host_routing]
strict = true

[[vhosts]]
name = "gateway"
hosts = ["gateway.example.test", "www.gateway.example.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:9001"]
```

The HTTP router normalizes the host identity, tries exact hostnames first, then
the matching wildcard with the longest suffix. `*.gateway.example.test` matches
both `one.gateway.example.test` and `deep.one.gateway.example.test`, but not the
apex `gateway.example.test`. List the apex separately when needed.

**HTTP host wildcards and TLS certificate wildcards are different.** The HTTP
router's multi-label match does not make a one-label wildcard certificate valid
for a deeper hostname. Configure certificates and SNI policy separately using
the [HTTPS guide](tls.md); HTTP routing does not issue certificates.

With strict routing, unknown hosts return 421; missing or invalid identities
are rejected with 400. With strict routing disabled, an otherwise admissible
unknown host uses `server.default_vhost`, identified by the vhost's `name`.
Without an explicit default, the first vhost is selected. This does not disable
HTTP parser checks for malformed requests. A root-only configuration without
vhosts uses its root handler rather than this named-host allowlist.

## Understand Route Priority

Fluxheim first removes routes that do not match the request method. Among the
remaining routes, selection is:

1. An exact path match.
2. The longest matching path prefix.
3. The first matching regex in configuration order.
4. The optional fallback route.

For equal-priority exact matches or equal-length prefixes, the first eligible
route wins. Keep configurations unambiguous instead of relying on ties. A
matching prefix wins over a regex even when the regex appears earlier in the
file. A broad prefix `/` therefore shadows every regex for the same methods.

| Request in the local example | Selected route | Origin path or result |
| --- | --- | --- |
| `/api/status?check=1` | `api-status` exact | `/api/status?check=1` |
| `/api/private/users` | `api-private` longest prefix | `/api/private/users` |
| `/api/users?x=1&x=2` | `api` prefix, ahead of regex | `/internal/users?x=1&x=2` |
| `/api` or `/api/` | `api` | `/internal/` |
| `/apix` | `fallback` | `/apix` |
| `/products/Ab_7?x=1` | First matching product regex | `/items/Ab_7?x=1` |
| `/assets/missing.txt` | Static `assets` route | 404, not a retry through fallback |

Paths are case-sensitive and matching excludes the query string. A prefix is
segment-aware: `/api` matches `/api`, `/api/` and `/api/item`, not `/apix`.
The trailing slash matters: `/api/` does not match `/api`. Unsafe traversal and
separator forms are rejected; do not depend on an origin normalizing them.
Forwarding selection uses the incoming path spelling, while native ACL checks
also enforce decoded-path policy. Following the **Current limitation:** correction,
Wasm access hooks cover both routes and any Wasm-selected route, with shared
attachments executed once in configured priority order. A denial or fail-closed
error on one route cannot be replaced by another route's allow. Older binaries
do not have this correction. See the [Wasm policy guide](wasm-extensibility.md) and
[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections).

## Limit Methods And Uploads

```toml
[[vhosts.routes]]
name = "upload"
path_exact = "/upload"
methods = ["POST"]
max_request_body_bytes = "16MiB"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
```

This is a fragment to place under an existing vhost. An omitted or empty
`methods` list matches any method. Configuration requires uppercase HTTP tokens,
at most 16 entries, each at most 32 bytes, with no duplicates. List both `GET`
and `HEAD` if both should select the route; `GET` alone does not imply `HEAD`.

A method mismatch **skips the route**, rather than automatically returning
405. Another route or the vhost fallback may handle the request. In the local
example, `GET /write` reaches fallback while `POST /write` selects `write`.
Enforce allowed methods at the application/policy boundary when required.
gRPC has a separate POST/content-type contract; see below.

The selected route's body limit overrides the vhost and server limits. Crossing
the limit returns 413. It is not an application timeout or a file-storage quota.
CORS-enabled route selection can use `Access-Control-Request-Method` for a
preflight; the ordinary `OPTIONS` method alone does not describe that workflow.

## Strip Or Replace A Prefix

```toml
[[vhosts.routes]]
name = "api"
path_prefix = "/api"
strip_prefix = "/api"
rewrite_prefix = "/internal/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
```

`/api/users?active=1` becomes `/internal/users?active=1`. Without
`rewrite_prefix`, it becomes `/users?active=1`. Stripping the entire path
produces `/`; joining a replacement prefix avoids a duplicate boundary slash.

`strip_prefix` is only available on prefix routes. Use the same prefix for
matching and stripping: a different strip prefix can fail at request time even
when validation accepts the relationship. `rewrite_prefix` requires
`strip_prefix`, starts with `/` and must be a safe path. These operations preserve
the query unchanged. They do not change the Host header or switch to another
route after rewriting.

For a static alias, use the same match/strip fields with `[vhosts.routes.web]`
and a `root` instead of the proxy action. In the example, `/assets/hello.txt`
reads `site/hello.txt`. A selected static route's missing file is a 404; a
fallback route is not an error handler for actions that already matched.

## Use A Bounded Regex Rewrite

Regex requires explicit `server.regex_enabled = true` in the existing server
table. Patterns are compiled at configuration load using Rust's regex engine;
pattern text is capped at 4096 bytes and compiled program budgets at 1 MiB.
Anchors make the intended whole-path match clear.

```toml
[[vhosts.routes]]
name = "product"
path_regex = '^/products/(?P<id>[A-Za-z0-9_-]{1,64})$'
rewrite_template = "/items/{route.regex.id}"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]

[vhosts.routes.headers.request.add]
x-product-id = "{route.regex.id}"
```

The pattern captures one required, bounded identifier. `/products/Ab_7?x=1`
is sent as `/items/Ab_7?x=1` with `x-product-id: Ab_7`. That header is diagnostic
application data, not an authenticated identity.

`rewrite_template` is path-only and accepts route-regex capture variables, not
general header-template variables. It cannot be combined with prefix rewrites.
Capture bytes outside the unreserved URL set are percent-encoded, then the
result is checked for path safety. Capturing an arbitrary slash-containing
suffix with `.*` is not equivalent to a prefix rewrite: encoded separators can
be rejected. Prefer prefix stripping for multi-segment suffixes.

### Current Capture Limitation

**Current limitation:** Rewrite lookup permits indices
0 through 15 (`0` is the whole match) and named groups within those positions,
with a 256-byte value cap. However, unavailable values are currently omitted
silently, including a misspelled name, an unmatched optional group or an
oversized capture. `/internal/{route.regex.id}` can become `/internal/` and
reach a different backend resource instead of failing closed. Configuration
checks variable syntax, not whether the referenced group exists.

Header capture collection is inconsistent: it omits the whole-match `.0` and
does not apply the rewrite collector's 16-position/256-byte limits before
copying groups. Overall request and regex limits still exist, but do not assume
the documented rewrite cap is also a per-header-capture bound.

Until corrected, use required, explicitly bounded ASCII groups within the
first 15 group positions, verify names and test the actual origin path. Avoid
optional or arbitrary-size captures for resource/authorization selection. The
example follows these restrictions; they are not a substitute for fixing the
implementation. [Contract tests](../../crates/fluxheim-server/src/native_http1_route_proxy_tests/regex_contract.rs)
record current behavior so the correction can replace these assertions.

## Return A Redirect

```toml
[[vhosts.routes]]
name = "move"
path_prefix = "/old"

[vhosts.routes.redirect]
to = "https://new.example.test{uri}"
status = 308
```

`to` must be an absolute HTTP or HTTPS destination. Supported `status` values
are 301, 302, 307 and 308; default is 308. Use 307/308 when preserving the method
and body matters; 301/302 clients may change POST to GET.

| Variable | Value |
| --- | --- |
| `{uri}` | Path plus its query string, including `?` when present |
| `{path}` | Path only, starting with `/` |
| `{query}` | Query only, without the leading `?` |

For example, `https://new.example.test{uri}` preserves `/old?id=7`.
Do not add another slash before `{uri}` or `{path}`. Do not use request input
to choose the destination authority. When a route also strips/rewrites its
prefix, the redirect uses that rewritten target; routing is not repeated.

For an entire site's remaining paths, `[vhosts.redirect]` offers `enabled`,
`to` and `status`. Enabling it generates a fallback redirect; do not combine it
with another fallback route. More-specific routes still win.

Global HTTP-to-HTTPS redirection also applies to ordinary selected routes.
`https_redirect_exempt = true` allows a deliberate plaintext exception; explicit
redirect actions supply their own destination instead. Exemption does not bypass
access policy or provide TLS. Prefer the documented [ACME challenge helper](acme.md)
for HTTP-01 rather than exempting a broad application prefix.

## Route Option Map

Each route requires one matcher and one action. Optional nested policies are
not additional actions. There may be at most 256 explicit routes per vhost and
one fallback. Names must be nonempty and no more than 128 bytes.

| Field | Meaning / configuration |
| --- | --- |
| `name` | Required route identifier; use stable operator-chosen names |
| `path_exact`, `path_prefix`, `path_regex`, `fallback` | Exactly one matcher; `fallback` defaults to false |
| `methods` | Optional method filter; empty matches any method |
| `https_redirect_exempt` | Default false; narrowly scoped plaintext redirect exception |
| `strip_prefix`, `rewrite_prefix`, `rewrite_template` | Optional selected-action path changes described above |
| `max_request_body_bytes` | Optional route body-limit override, byte count or size string |
| `redirect` | Local redirect response; `to` required, `status` defaults to 308 |
| `proxy` | Forward to explicitly configured origin(s); [proxy reference](../reference/config-reference.md#proxy) and [TLS](upstream-tls.md) |
| `web` | Local static action; [web options](../reference/config-reference.md#web) |
| `php` | PHP action; [FastCGI and application recipes](php-fpm-app-recipes.md) |
| `access` | Route admission rules; [IP/certificate policy and scope](access-control.md) and [GeoIP examples](geoip.md) |
| `rate_limit`, `concurrency` | Request-rate and in-flight budgets; [configuration](../reference/config-reference.md#vhosts) |
| `grpc` | Opt-in proxy POST/content-type policy described below |
| `cache` | Optional route cache policy; [cache examples](cache.md) |
| `compression` | Optional route compression policy; [compression](compression.md) |
| `headers` | Request/response policies; [header operations](../reference/config-reference.md#headers) |

For gRPC, `[vhosts.routes.grpc]` has `enabled = false` and
`require_content_type = true` by default. Enabling it requires a proxy action
with `upstream_http_version = "http2"` or `"http1-and-http2"`, requires
content-type checking and rejects enabled response caching. Prefer explicit
`"http2"` when the origin must use H2. Once selected, the gRPC route admits POST
with a gRPC content type, rejects other methods with 405 and wrong media types
with 415. This is not HTTP/JSON-to-gRPC
transcoding. See [gateway recipes](gateway-recipes.md) for a complete service
configuration and transport requirements.

## Troubleshoot A Route

| Symptom | Check |
| --- | --- |
| 421 from a numeric URL | Send the configured Host or use curl `--resolve`; check strict routing |
| Regex never used | Look for an eligible prefix first, especially `/`; check global regex opt-in |
| Wrong application for GET/HEAD | Check each route's method filter and fallback, not just its path |
| 400 after rewriting | Inspect strip-prefix relationship and safe capture contents; avoid encoded separators |
| 404 for an asset | Check the rewritten filename and static root; matched actions do not fall through |
| 413 on one endpoint | Check the selected route body override before raising the global limit |
| 502 from proxy | Investigate origin reachability, TLS identity and application behavior, not route order alone |
| Unexpected shortened origin path | Check the documented limitation; missing captures are not currently rejected |

The live harness qualifies plaintext HTTP/1.1 routing on Linux. Native
macOS/Windows, HTTP/2, CORS, PHP and security-policy integration have their own
tests; this example does not claim to requalify all of them.
