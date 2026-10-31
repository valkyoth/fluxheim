# Vhost Config Guide

For file selection, `conf.d`, ordering, permissions and cross-file merge rules,
start with [loading configuration](configuration.md). Keep each vhost together:
another `[[vhosts]]` with the same name does not patch its earlier declaration.

Fluxheim uses TOML array-of-tables syntax for virtual hosts:

```toml
[[vhosts]]
name = "example.test"
hosts = ["example.test", "www.example.test"]

[vhosts.web]
root = "/srv/sites/example.test/public"

[vhosts.proxy]
upstreams = ["127.0.0.1:3000"]

[[vhosts]]
name = "api.example.test"
hosts = ["api.example.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:4000"]
```

The important rule is:

- `[[vhosts]]` starts a new vhost.
- Every `[vhosts.*]` table after it belongs to that current vhost.
- The next `[[vhosts]]` starts the next vhost.

So in the example above, `[vhosts.web]` and the first `[vhosts.proxy]` belong to
`example.test`. The second `[vhosts.proxy]` belongs to `api.example.test`
because it appears after the second `[[vhosts]]`.

## Recommended Layout

For readable production configs, prefer split config directories and keep one
vhost per file:

```text
/etc/fluxheim/
  00-server.toml
  10-example-site.toml
  20-api-site.toml
```

`00-server.toml`:

```toml
[server]
listen = ["0.0.0.0:8080"]
default_vhost = "example.test"
```

`10-example-site.toml`:

```toml
[[vhosts]]
name = "example.test"
hosts = ["example.test", "www.example.test"]

[vhosts.web]
root = "/srv/sites/example.test/public"

[vhosts.proxy]
upstreams = ["127.0.0.1:3000"]
```

`20-api-site.toml`:

```toml
[[vhosts]]
name = "api.example.test"
hosts = ["api.example.test", "*.api.example.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:4000"]
```

This avoids long files where it is hard to see which `[vhosts.*]` table belongs
to which host.

## Common Mistakes

Do not write `[vhosts.proxy]` before the first `[[vhosts]]`. There is no current
vhost yet.

Do not repeat `[vhosts.proxy]` for the same vhost in the same file. TOML table
headers are definitions, not append operations.

Do not use `[[vhosts.proxy]]`. `proxy`, `web`, `cache`, `tls`, and `headers` are
normal nested tables inside one vhost, not arrays.

Do not use `[[vhosts.tls.certificates]]` for a vhost certificate. A vhost has
one direct certificate pair under `[vhosts.tls.certificate]`:

```toml
[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "/etc/fluxheim/tls/example/fullchain.pem"
key_path = "/etc/fluxheim/tls/example/privkey.pem"
```

Do not treat global `[[tls.certificates]]` as an independent extra certificate
store when vhosts are configured. Follow the [SNI and certificate selection
guide](tls.md) for effective certificate sources and fallback behavior. Use
`[vhosts.tls.acme]` when Fluxheim should manage the vhost certificate.

Proxy error pages are arrays because one proxy can define multiple fallback
statuses. Define the array entry first, then its nested web root:

```toml
[[vhosts.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.proxy.error_pages.web]
root = "/srv/fluxheim/errors"
```

The same rule applies inside route proxy blocks:

```toml
[[vhosts.routes.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.routes.proxy.error_pages.web]
root = "/srv/fluxheim/errors"
```

When a vhost has both static files and a proxy, Fluxheim can use both policies:
static files are served from `[vhosts.web]` when they match, and other requests
can continue through `[vhosts.proxy]`.

## Routes Inside A Vhost

For gateway-style configs, add `[[vhosts.routes]]` under the current vhost.
Routes first filter by method, then match in this order:

- exact path;
- longest path prefix;
- first configured matching regex (requires `server.regex_enabled = true`);
- one optional fallback route.

Each route must define exactly one action by adding one nested table:
`[vhosts.routes.redirect]`, `[vhosts.routes.proxy]`, `[vhosts.routes.web]`, or
`[vhosts.routes.php]`.
Do not add an `action = "proxy"` field.

The [routing guide](routing.md) explains segment boundaries, method mismatches,
regex capture limitations and redirects with a runnable loopback example. A
matched action's failure does not cause the router to try the fallback route.

Do not write route tables such as `[vhosts.routes.proxy]`,
`[vhosts.routes.web]`, or `[vhosts.routes.cache]` before a
`[[vhosts.routes]]` block. There is no current route yet. Also do not use
array syntax such as `[[vhosts.routes.proxy]]` or `[[vhosts.routes.web]]`;
route `proxy`, `web`, `cache`, and `headers` are normal nested tables inside
one route, not arrays.

```toml
[[vhosts]]
name = "dev.example.test"
hosts = ["dev.example.test"]
max_request_body_bytes = "64MiB"

[[vhosts.routes]]
name = "chat"
path_prefix = "/chat/"
strip_prefix = "/chat/"
rewrite_prefix = "/backend/chat/"
max_request_body_bytes = "64MiB"

[vhosts.routes.proxy]
upstreams = ["host.containers.internal:6012"]
connect_timeout_secs = 5
read_timeout_secs = 600
send_timeout_secs = 600

[[vhosts.routes.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.routes.proxy.error_pages.web]
root = "/srv/fluxheim/errors"
cache_control = "private, no-store"

[[vhosts.routes]]
name = "static-repo"
path_prefix = "/repo"
strip_prefix = "/repo"

[vhosts.routes.web]
root = "/srv/infra/repository/public"
index_files = ["repo.html", "index.html"]

[vhosts.routes.web.directory_listing]
enabled = true
exact_size = false

[[vhosts.routes]]
name = "fallback"
fallback = true

[vhosts.routes.redirect]
to = "https://dev.example.test{uri}"
status = 308
```

`strip_prefix` rewrites the path for the selected route only. For example,
`/chat/room?id=7` becomes `/room?id=7` before it is sent to the route backend.
When `rewrite_prefix` is also set, the stripped suffix is attached to that
upstream prefix instead, so `/chat/room?id=7` becomes
`/backend/chat/room?id=7`. `rewrite_prefix` must be paired with
`strip_prefix` and must be an absolute safe path.
`max_request_body_bytes` can be set on a vhost for a host-wide upload limit, or
on a route to override both the vhost and global request body limit for the
selected route. Route proxy actions can also set `connect_timeout_secs`,
`read_timeout_secs`, and `send_timeout_secs` for long-lived uploads or websocket
paths without changing every backend on the vhost.

WebSocket upgrade forwarding requires `websocket = true` on the proxy action
and an HTTP/1 origin policy. Ordinary proxy actions strip upgrade headers when
that flag is false. Prefix matching and optional rewriting still apply. The
current tunnel uses the upstream read timeout as an absolute lifetime, not an
idle timeout. Do not enable upgrades on the assumption that external auth will
protect them: [the documented limitation](external-authorization.md#important-current-limits)
is an open authorization bypass in the takeover path.

When global HTTP-to-HTTPS redirect is enabled, proxy and static routes are also
redirected by default on cleartext requests. Use the vhost ACME challenge helper
for normal HTTP-01 challenge forwarding:

```toml
[vhosts.acme_challenge]
enabled = true
upstreams = ["host.containers.internal:8080"]
upstream_tls = false
```

That helper creates the standard `/.well-known/acme-challenge/` route and marks
only that route as cleartext-exempt. Advanced configs can still set
`https_redirect_exempt = true` on an explicit route for other rare exceptions.

Static route actions can serve repository-style aliases with optional directory
listing. Directory listing is disabled by default, index files are preferred
when present, dotfiles remain hidden when `deny_dotfiles = true`, and symlink
entries are skipped.

Route-specific header policy is nested under the route:

```toml
[vhosts.routes.headers.request.add]
x-route = "chat"
x-public-host = "{host}"

[vhosts.routes.headers.response]
remove = ["server"]
```

Route request headers use the same renderer as global request headers. See the
[request-header guide](request-headers.md) for supported values, privacy and
trusted-client limits. Generic `{http.<header-name>}` values currently render
empty except `{http.upgrade}`; TLS cipher/organization are also unresolved.
Unknown variables fail validation, but successful validation does not prove
runtime support.

Leave Host untouched when preserving it: `host = "{host}"` currently removes its
input before rendering. URL templates see the rewritten target,
and request IDs are diagnostic only. Do not use forwarded client IPs for origin
authorization behind trusted proxies until the documented limitation is corrected.
Use [WebSocket route configuration](websocket.md), not a manual Upgrade field,
to select tunnel behavior.

Use the normal user-friendly header operations when possible:

```toml
[vhosts.routes.headers.response.operations]
remove = ["server", "x-powered-by"]
add = { cache-control = "private, no-store" }
```
