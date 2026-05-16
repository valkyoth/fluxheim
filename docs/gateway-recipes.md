# Gateway Recipes

This page shows practical `1.0` gateway-style patterns for moving common static
and proxy vhosts into Fluxheim. The examples use one split config file per
site; keep shared listeners, TLS defaults, logging, and global header policy in
`00-server.toml`.

## Shared Server Baseline

```toml
[server]
listen = ["0.0.0.0:8080"]
tls_listen = ["0.0.0.0:8443"]
default_vhost = "example"
trusted_proxies = []

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "16MiB"

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true

[headers.request.set]
x-forwarded-host = "{host}"
x-original-uri = "{uri}"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
```

Use `trusted_proxies` only for proxies you actually control. When it is empty,
Fluxheim uses the direct peer address for generated client-IP headers. When the
direct peer is trusted, Fluxheim treats `X-Forwarded-For` like nginx
`real_ip_recursive on`: trusted hops are skipped from the right and generated
`X-Real-IP`, `X-Forwarded-For`, `Forwarded`, and `{remote_addr}` values use the
restored client address.

## Cleartext Challenge Exception And HTTPS Redirect

If a cleartext challenge helper must stay reachable while everything else moves
to HTTPS, enable the global redirect and the vhost challenge helper:

```toml
[server.https_redirect]
enabled = true
status = 308
target_port = 443

[[vhosts]]
name = "site-cleartext"
hosts = ["example.test", "www.example.test"]

[vhosts.acme_challenge]
enabled = true
upstreams = ["host.containers.internal:8080"]
upstream_tls = false
```

This internally creates the standard HTTP-01 challenge route at
`/.well-known/acme-challenge/` and exempts only that path from the global
redirect. Normal proxy and static routes still redirect on cleartext requests.

## Canonical Host Redirect

Create a small vhost for the secondary host and redirect it to the canonical
name:

```toml
[[vhosts]]
name = "www-example"
hosts = ["www.example.test"]

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "/etc/fluxheim/tls/example-fullchain.pem"
key_path = "/etc/fluxheim/tls/example-key.pem"

[vhosts.redirect]
enabled = true
to = "https://example.test{uri}"
status = 308
```

## App Proxy With Upload Limit

Set `max_request_body_bytes` on the vhost when the whole site shares one upload
budget. Set it on a route only when a specific path needs a different limit.

```toml
[[vhosts]]
name = "app"
hosts = ["app.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "/etc/fluxheim/tls/app-fullchain.pem"
key_path = "/etc/fluxheim/tls/app-key.pem"

[vhosts.proxy]
upstreams = ["host.containers.internal:6010"]
connect_timeout_secs = 5
read_timeout_secs = 60
send_timeout_secs = 60
```

For common upstream identity headers, prefer the typed request-header fields in
the shared baseline:

```toml
[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "append"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true

[headers.request.add]
host = "{host}"
```

Use dynamic header templates only when a backend needs an exact value that is
not covered by a typed field. The supported variables are intentionally small:
`{host}`, `{remote_addr}`, `{scheme}`, `{uri}`, `{path}`, `{query}`,
`{request_id}`, and `{http.<header-name>}`. Unknown variables fail config
validation, and rendered values still pass HTTP header validation before they
are sent upstream.

### Browser Login Probe For WordPress

Some proxy bugs only show up in a real browser. One important example is
HTTP/2 clients sending multiple `Cookie` header fields; an HTTP/2-to-HTTP/1.x
gateway must forward those to classic backends as one semicolon-delimited
`Cookie` header, not as a comma-delimited list.

Use the browser probe when a WordPress login works with `curl` but loops in
Chrome or another browser:

```sh
FLUXHEIM_BROWSER_BASE_URL=https://example.test \
FLUXHEIM_BROWSER_USER=admin \
FLUXHEIM_BROWSER_PASSWORD='change-me' \
scripts/browser_wordpress_login_probe.mjs
```

The script launches local Chrome or Chromium through the DevTools protocol,
submits the login form, checks for the admin dashboard, and writes artifacts to
`/tmp/fluxheim-browser-wordpress-*`. Password values are redacted from request
logs, but the captured HTML and cookie names are still operational debugging
artifacts; keep them local and delete them after analysis.

Set `FLUXHEIM_BROWSER_CHROME=chromium` or another supported browser name when
more than one standard Chrome/Chromium binary is installed. The accepted names
are `google-chrome`, `google-chrome-stable`, `chromium`, and
`chromium-browser`; arbitrary executable paths are intentionally rejected. The
probe is intentionally not part of the normal release gate because it targets
live sites and needs credentials.

## Websocket Or Long-Lived Route

Fluxheim preserves `Connection: Upgrade` and `Upgrade` request headers by
default. Use a prefix route with longer upstream timeouts and optional prefix
stripping:

```toml
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
```

If the backend requires explicit legacy-style upgrade forwarding on that route,
set it route-locally:

```toml
[vhosts.routes.headers.request.add]
upgrade = "{http.upgrade}"
connection = "upgrade"
```

## Static Alias With Directory Listing

Use a route-local static action when only one path should expose a different
filesystem root:

```toml
[[vhosts.routes]]
name = "repo"
path_prefix = "/repo"
strip_prefix = "/repo"

[vhosts.routes.web]
root = "/srv/infra/repository/public"
index_files = ["repo.html", "index.html"]
deny_dotfiles = true

[vhosts.routes.web.directory_listing]
enabled = true
exact_size = false
local_time = true
```

Directory listings are off by default. When enabled, index files still win,
dotfiles remain hidden when `deny_dotfiles = true`, and symlink entries are
skipped. Set `local_time = true` when you want listing modification times shown
with the server's local UTC offset instead of GMT HTTP-date timestamps.

## Custom Upstream Error Page

Attach static fallback pages to a proxy policy:

```toml
[[vhosts.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.proxy.error_pages.web]
root = "/srv/fluxheim/errors"
cache_control = "private, no-store"
```

The configured error page is internal to the proxy fallback. It is not exposed
as a public route unless another `web` route serves that same path.

## Current 1.0 Boundaries

- Active DNS refresh and resolver TTL controls are not stable yet. Use stable
  container/service names or IPs, and rely on your container runtime or host
  resolver behavior for now.
- Per-route proxy, static, redirect, upload limit, timeout, header policy,
  prefix stripping, and internal error-page fallback are the supported gateway
  building blocks.
- Advanced auth, rewrite engines, compression, WAF, image/video filters, and
  WASM policy hooks are planned as optional post-`1.0` modules.
