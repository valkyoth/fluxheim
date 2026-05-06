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
