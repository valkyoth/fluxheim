# Vhost Config Guide

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

When a vhost has both static files and a proxy, Fluxheim can use both policies:
static files are served from `[vhosts.web]` when they match, and other requests
can continue through `[vhosts.proxy]`.

## Routes Inside A Vhost

For gateway-style configs, add `[[vhosts.routes]]` under the current vhost.
Routes are matched in this order:

- exact path;
- longest path prefix;
- one optional fallback route.

Each route must define one action: `redirect`, `proxy`, or `web`.

```toml
[[vhosts]]
name = "dev.example.test"
hosts = ["dev.example.test"]
max_request_body_bytes = "64MiB"

[[vhosts.routes]]
name = "chat"
path_prefix = "/chat/"
strip_prefix = "/chat/"
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
`max_request_body_bytes` can be set on a vhost for a host-wide upload limit, or
on a route to override both the vhost and global request body limit for the
selected route. Route proxy actions can also set `connect_timeout_secs`,
`read_timeout_secs`, and `send_timeout_secs` for long-lived uploads or websocket
paths without changing every backend on the vhost.

Fluxheim preserves downstream `Connection: Upgrade` and `Upgrade` request
headers by default, so websocket-style upgrade routes usually only need prefix
matching, optional `strip_prefix`, and longer read/send timeouts. Header policy
can still remove or replace those headers when an operator intentionally wants
to disable upgrade tunneling for a route.

Static route actions can serve repository-style aliases with optional directory
listing. Directory listing is disabled by default, index files are preferred
when present, dotfiles remain hidden when `deny_dotfiles = true`, and symlink
entries are skipped.

Route-specific header policy is nested under the route:

```toml
[vhosts.routes.headers.request.add]
x-route = "chat"
host = "{host}"
upgrade = "{http.upgrade}"

[vhosts.routes.headers.response]
remove = ["server"]
```

Route request headers support the same safe dynamic values as global request
headers, including `{host}`, `{remote_addr}`, `{scheme}`, `{uri}`, `{path}`,
`{query}`, `{request_id}`, and `{http.<header-name>}`. Unknown variables are
config errors.

Use the normal user-friendly header operations when possible:

```toml
[vhosts.routes.headers.response.operations]
remove = ["server", "x-powered-by"]
add = { cache-control = "private, no-store" }
```
