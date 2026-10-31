# Static Files And Directory Listings

Fluxheim can serve a directory of HTML, CSS, images and other public files
without an application server. Static serving reads files; it does not execute
PHP, render templates or automatically provide a single-page-app fallback.
Never put secrets, application source or private backups in a public root.
Use the [PHP guide](php-runtime-support.md) for executable PHP applications.

This guide covers the native runtime's `web` feature. Check your package's
[feature profile](../reference/features.md) before enabling it. HTTPS is
configured separately through [TLS](tls.md). Known directory URL, conditional
request and file-publication gaps are listed below; documentation is not a fix.

## Start A Local Site

The complete [static recipe](../../examples/web/static.toml) listens only on
loopback. From the repository root, create a small public site:

```sh
mkdir -p examples/web/site/docs
printf '<!doctype html><title>My site</title><h1>Hello</h1>\n' > examples/web/site/index.html
printf 'download example\n' > examples/web/site/hello.txt
fluxheim --config examples/web/static.toml --validate-config
fluxheim --config examples/web/static.toml
```

In another terminal:

```sh
curl -i -H 'Host: app.example.test' http://127.0.0.1:8080/
curl -I -H 'Host: app.example.test' http://127.0.0.1:8080/hello.txt
curl -i -H 'Host: app.example.test' -H 'Range: bytes=0-7' http://127.0.0.1:8080/hello.txt
```

`root = "site"` is relative to the configuration file, not the terminal's
working directory. For a deployed service, use an absolute root such as
`/srv/sites/example/public` or a TOML literal Windows path
`root = 'C:\sites\example\public'`. Create it before starting the server.
The service account needs directory traversal and file-read permission.
Use real directories, not symlink-based `current` deployment paths.

The recipe has a default vhost so local testing is convenient. For a production
host allowlist, use [strict host routing](routing.md#select-a-site-by-hostname) and review
the default-vhost behavior. Do not assume a `hosts` list alone rejects every
unmatched host.

## Where Static Settings Apply

Use `[web]` for the root/default handler, `[vhosts.web]` for a selected site,
or `[vhosts.routes.web]` for one route. There is no `web.enabled` option:
providing a root enables the handler. These are handler settings, not a promise
of automatic inheritance between all three scopes.

For a site that must return 404 when a file is missing, prefer an explicit
static-only vhost like the recipe. Root-level static lookup can fall through
to the default proxy handler on a miss. A vhost with both static and proxy
behavior can also fall through; see [routing](routing.md) before combining them.
Only GET and HEAD are served as static files. Other methods are not uploads;
the static-only vhost recipe returns 404 for POST because routing finds no
eligible action. The lower-level static handler's standalone rejection is 405.

To expose a directory under a URL prefix, add this route to a vhost:

```toml
[[vhosts.routes]]
name = "assets"
path_prefix = "/assets"
strip_prefix = "/assets"

[vhosts.routes.web]
root = "/srv/sites/example/assets"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=3600"

[vhosts.routes.web.directory_listing]
enabled = false
```

`/assets/logo.png` reads `/srv/sites/example/assets/logo.png`. Without stripping,
the request path still includes `/assets`. Keep listings disabled for stripped
or rewritten routes until the documented limitation is corrected: generated listing links
currently omit the public route prefix.

## Every Web Option

All options below are available in the three `web` scopes above. Listing
settings belong in the corresponding `directory_listing` table.

| Field | Default | Meaning / example |
| --- | --- | --- |
| `root` | Absent | Directory containing public files. `root = "/srv/sites/example/public"`; a real existing directory is required at runtime |
| `index_files` | `["index.html"]` | Ordered directory-index candidates. `index_files = ["index.html", "default.html"]`; first existing regular file wins. Nonempty list, at most 32 names; no nested paths, empty names, `.` or `..` |
| `deny_dotfiles` | `true` | Reject requested path components beginning with `.` and hide dotfiles from listings. Set `false` only for a deliberately public tree; it is not a substitute for access control |
| `cache_control` | `"public, max-age=60"` | Literal response header for files. Use `"no-store"` for content that must not be retained by clients/intermediaries; this does not grant authentication |
| `expires` | Absent | Optional literal header value, not a duration. For example `expires = "Thu, 01 Jan 1970 00:00:00 GMT"`; no automatic date calculation or date-format validation, only header-safety validation |
| `enabled` (listing) | `false` | Generate an HTML directory listing only when no configured index file is found |
| `exact_size` | `false` | With `true`, show file byte counts. With `false`, show `-`, **not** a rounded/human-readable size. Directories show `-` |
| `local_time` | `false` | With `true`, show the server's local time with UTC offset; otherwise GMT HTTP-date. This is not the browser's timezone |

Configured index filenames are operator-selected: `deny_dotfiles` does not
filter that candidate list. Do not name a private `.secret` file as an index.
Likewise, `index_files = ["index.php"]` in a static-only handler serves source,
not executed PHP. Leave private material outside the root regardless of names.

## Directories And Listings

The [listing recipe](../../examples/web/listing.toml) enables a public download
index on `files.example.test`. Run it instead of the static recipe on port 8080:

```sh
mkdir -p examples/web/site/downloads
printf 'public download\n' > examples/web/site/downloads/readme.txt
fluxheim --config examples/web/listing.toml --validate-config
fluxheim --config examples/web/listing.toml
curl -i -H 'Host: files.example.test' http://127.0.0.1:8080/downloads/
```

Listing responses use `Cache-Control: private, no-store` even if file responses
are cacheable. Names are HTML-escaped, leaf link names are percent-encoded,
directories sort before files, and names sort within each group. Symlinks,
special files, non-UTF-8 names and (by default) dotfiles are omitted.

Current limits:

- `/docs` can return an index directly without redirecting to `/docs/`.
  Relative links in that HTML then resolve against the wrong browser base.
  Publish slash-terminated directory links; this is only a workaround, not a
  canonical redirect implementation.
- Listing parent paths are not fully URL-encoded. A Unix directory containing
  `?` can generate links interpreted as queries; stripped route prefixes are
  also lost. Use simple directory names and unrewritten roots
  for listings for now.
- Enumeration inspects at most 4,097 entries and retains at most 4,096.
  A fully visible overflowing directory errors, but filtered entries can cause
  a partial 200 listing without an overflow notice.
  There is no pagination. Do not use it as a complete large-directory inventory.

## Validators And Byte Ranges

Ordinary file responses include MIME type, cache policy, `Accept-Ranges: bytes`,
an `ETag`, and `Last-Modified` when filesystem modification time is available.
The ETag is weak and based on file length and timestamp, not a content hash.
HEAD reports the response headers without reading/sending the file body.

| Request | Current behavior |
| --- | --- |
| GET / HEAD with no conditions | 200; HEAD has no body |
| Matching `If-None-Match` | 304 without body, unless a refresh directive below suppresses it |
| `If-Modified-Since` at/after mtime | 304 when `If-None-Match` is absent and refresh is not forced |
| `If-Match: *` for an existing file | Allows serving; a missing file remains a routing miss |
| `If-Match` with the weak ETag returned by Fluxheim | 412; weak validators do not satisfy a strong match |
| `If-Unmodified-Since` before mtime | 412 when `If-Match` is absent |
| `Range: bytes=2-4`, `bytes=8-`, `bytes=-3` | Single inclusive, open-ended or suffix range; 206 with Content-Range |
| Unsatisfiable byte range | 416 with `Content-Range: bytes */length` |
| Multiple comma-separated ranges | Ignored; full 200, no multipart response |
| `If-Range` with returned weak ETag | Full response; cannot establish a strong validator match |
| `If-Range` with a sufficiently recent valid HTTP date | Allows range evaluation |

the documented limitation records three inconsistencies for correction: `Cache-Control:
no-cache` / `no-store` or `Pragma: no-cache` force a full response despite a
matching conditional validator; a Range on HEAD changes status/length to 206;
an unknown range unit such as `items=0-1` returns 416 rather than being ignored.
These are observed behavior, not recommended client contracts. Repeated
condition fields currently use only the first value; the correction must also
define consistent handling of repeated/combinable fields.

## Memory, File Publication And Caching

File response bodies are buffered. The maximum selected response body is
64 MiB; a larger full GET returns 413. HEAD can describe a larger file, and a
small single range of that file can succeed. Concurrent buffering is also
subject to the server's shared retained-byte admission policy; increasing a
request-body limit does not remove this static-response limit.

Paths are decoded once; traversal, backslashes, NUL and residual percent escapes
are rejected. Symlinked roots, intermediate directories and leaf files are not
supported. Unix file opens traverse with no-follow directory handles; Windows
uses its handle-relative security helper. Files must be regular files.

However, size-exact reads alone do not detect all concurrent changes.
the documented limitation reproduces a same-size atomic replacement after resolution:
new bytes are served with the old metadata-derived ETag. The reader does not
bind response planning to the subsequently opened file's identity. This is a
publication-consistency gap, not evidence of a root escape. Prefer immutable,
versioned asset names and avoid mutating files being served; even atomic rename
does not currently guarantee coherent validators for an in-flight request.

Client caching and Fluxheim's own cache are different. `cache_control` and
`expires` govern response headers. Local static-memory caching is a separate
opt-in, with no native static disk-cache support:

```toml
[cache]
enabled = true
local_static = true

[cache.memory]
enabled = true

[cache.disk]
enabled = false
```

Use a cache-capable build and review the [static-cache recipe and policy](cache.md#local-static-files).
Do not treat cache TTLs as a fix for concurrent file publication or validators.

## MIME Types And Additional Headers

The built-in extension map is case-insensitive:

| Extensions | Content-Type |
| --- | --- |
| html, htm | `text/html; charset=utf-8` |
| css | `text/css; charset=utf-8` |
| js | `application/javascript; charset=utf-8` |
| txt | `text/plain; charset=utf-8` |
| json | `application/json` |
| gif / png / webp / svg | `image/gif` / `image/png` / `image/webp` / `image/svg+xml` |
| jpg, jpeg / ico | `image/jpeg` / `image/x-icon` |
| wasm | `application/wasm` |
| Anything else, or no extension | `application/octet-stream` |

There is no `web.mime_types` table, extension allowlist or automatic precompressed
sidecar selection in this module. For a narrowly matched route, set an explicit
MIME type through response headers, for example for PDF downloads:

```toml
[[vhosts.routes]]
name = "manual"
path_exact = "/manual.pdf"
[vhosts.routes.web]
root = "/srv/sites/example/public"
[vhosts.routes.headers.response.add]
content-type = "application/pdf"
x-content-type-options = "nosniff"
```

Do not override every asset with one MIME type. [Compression](compression.md),
CORS, browser controls and response-header transformations are separate policies.
Gateway error pages also use static files but have their own status/condition
handling; see [reverse proxy error pages](reverse-proxy.md).

## Troubleshooting And Verification

| Symptom | Check |
| --- | --- |
| Startup rejects root | Existing real directory, no symlinked ancestors, service-account access and config-relative base; Windows trusted ACL policy |
| 404 for directory | Index filenames/order; listing disabled; route strip/rewrite; Host selection |
| 502 for a missing file | Root/static-plus-proxy fallback may be trying an origin; use an explicit static-only vhost if that is not intended |
| 403 for a file | Dotfile/path policy or access policy; do not disable path checks to expose private files |
| 413 for download | Selected body exceeds 64 MiB; not the request upload setting |
| Broken relative links | Missing directory slash, stripped listing prefix or special parent names; the documented limitation |
| Download instead of browser rendering | Extension falls back to octet-stream; use a narrow response-header override |
| Unexpected conditional status | Weak validator semantics and the documented limitation; inspect request headers |

Repository qualification (from the repository root):

```sh
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_static_examples.py
python3 scripts/smoke_static_examples.py
```

The smoke starts the actual local binary on private loopback ports, validates
the complete recipes and probes files, listings, range/condition handling and
known gaps. The deterministic Rust test covers file replacement after metadata
resolution. [Coverage and correction status](../reference/documentation-coverage.md)
distinguish passing behavior from failing-contract characterizations. Native
Windows/macOS, HTTP/2 and container requalification are still required for the
corrections; a passing characterization does not mean the defect is fixed.
