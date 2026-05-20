# PHP-FPM Application Recipes

This page maps common PHP application web-server requirements to Fluxheim's
php-fpm/FastCGI primitives. It is intentionally documentation-first: add an
application preset only after repeated production testing proves that a stable,
security-sensitive pattern is common enough to encode in Fluxheim itself.

References checked for this page:

- WordPress NGINX handbook, including single-site, multisite, upload PHP-deny,
  and cache examples:
  <https://developer.wordpress.org/advanced-administration/server/web-server/nginx/>
- Laravel deployment docs:
  <https://laravel.com/docs/12.x/deployment>
- Symfony web-server configuration:
  <https://symfony.com/doc/current/setup/web_server_configuration.html>
- Flarum install and URL rewriting docs:
  <https://docs.flarum.org/install/>
- XenForo friendly URL docs:
  <https://docs.xenforo.com/manual/configuration/friendly-urls>
- MediaWiki short URL NGINX docs:
  <https://www.mediawiki.org/wiki/Manual:Short_URL/Nginx>
- MyBB SEF URL, install, and security docs:
  <https://docs.mybb.com/1.8/administration/configuring-search-engine-friendly-URLs/>
  <https://docs.mybb.com/1.8/install/>
  <https://docs.mybb.com/1.8/administration/security/protection/>
- phpBB on NGINX Unit, used as a compact PHP routing reference:
  <https://docs.nginx.com/nginx-unit/howto/apps/phpbb/>
- Discourse install docs:
  <https://github.com/discourse/discourse/blob/main/docs/INSTALL-cloud.md>

## Supported PHP-FPM Functionality

Fluxheim has the PHP-FPM primitives needed by the reviewed PHP applications.
The authoritative field-by-field reference is
[Config Reference](config-reference.md#vhosts-and-routes); this section is the
operational checklist.

FastCGI and backend connectivity:

- `php.runtime = "php-fpm"` uses the one-request-at-a-time FastCGI
  `FCGI_RESPONDER` web-serving subset.
- `php.fpm.socket`, `php.fpm.tcp`, and `php.fpm.tcp_upstreams` cover Unix
  sockets, a single TCP endpoint, or multiple TCP php-fpm backends.
- `php.fpm.keepalive`, `pool_max_idle`, and `idle_timeout_secs` enable
  optional FastCGI keep-connection pooling.
- `php.fpm.connect_timeout_secs`, `read_timeout_secs`,
  `write_timeout_secs`, `max_retries`, `retry_timeout_secs`,
  `retry_methods`, `retry_invalid_response`, and `retry_statuses` provide
  conservative safe-method retry/failover before php-fpm has side effects, or
  after explicitly configured malformed/5xx responses.

CGI/FastCGI request construction:

- Fluxheim generates `SCRIPT_FILENAME`, `SCRIPT_NAME`, `DOCUMENT_ROOT`,
  `DOCUMENT_URI`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_METHOD`,
  `CONTENT_TYPE`, `CONTENT_LENGTH`, `SERVER_NAME`, `SERVER_PORT`, `HTTPS`,
  `REQUEST_SCHEME`, `REMOTE_ADDR`, `REMOTE_PORT`, and related CGI variables.
- `php.pass_request_headers` safely translates inbound HTTP headers to
  `HTTP_*`, including `HTTP_HOST` and `HTTP_AUTHORIZATION`, while dropping
  `Proxy` for HTTPoxy mitigation.
- `php.pass_request_body` controls whether the bounded HTTP body is forwarded
  to FastCGI STDIN.
- `php.server_port` can pin CGI `SERVER_PORT` when a deployment needs an
  application-visible port different from the listener port.
- `[vhosts.php.params]` and `[vhosts.routes.php.params]` add validated custom
  FastCGI params without allowing overrides of Fluxheim-owned CGI fields.
  Treat `PHP_VALUE` and `PHP_ADMIN_VALUE` as privileged php-fpm controls:
  Fluxheim logs high-risk warnings for sensitive PHP directives, but the
  operator remains responsible for not weakening production PHP policy.

Path mapping and application routing:

- `php.root` is the local root Fluxheim validates before any PHP execution.
- `php.fpm_root` maps that validated root to a different path visible inside a
  separate php-fpm container or chroot.
- `php.resolve_root_symlink` allows only a trusted final root symlink for
  current-release deploy layouts.
- `php.index` chooses the front-controller or directory index script.
- `php.allowed_extensions` limits executable script extensions.
- `php.deny_path_prefixes` blocks PHP execution under upload/private
  directories even if a matching script file exists.
- `php.try_files = "front-controller"`, `"wordpress"`, or `"strict"` covers
  missing-path front controllers and strict `try_files $uri =404` execution.
- `php.path_info = "split"` enables safe `PATH_INFO` for apps that route
  through `/index.php/foo`.
- `php.preset = "wordpress"` combines WordPress front-controller behavior with
  upload/file PHP execution denies.

Request and response controls:

- `php.max_request_body_bytes` bounds request bodies sent to php-fpm.
- `php.request_body_spool_threshold_bytes` and
  `php.request_body_spool_dir` spill larger request bodies to a safe temporary
  file before php-fpm dispatch so retries can replay them without cloning a
  large buffer.
- `php.max_response_bytes` bounds combined FastCGI STDOUT/STDERR buffering.
- `php.max_response_header_bytes` bounds the CGI response header block.
- `php.hide_response_headers` removes selected php-fpm response headers before
  Fluxheim response policy runs.
- `php.ignore_origin_cache_headers` discards PHP `Cache-Control`, `Expires`,
  and `Pragma` response headers when Fluxheim should own cache directives.
- Fluxheim consumes PHP `X-Accel-Redirect`, `X-Sendfile`, and
  `X-Accel-Expires` for internal static offload and cache-control behavior
  instead of forwarding those headers to clients.
- Hop-by-hop php-fpm response headers such as `Connection` and
  `Transfer-Encoding` are stripped automatically.
- `php.intercept_error_statuses` and `[[vhosts.php.error_pages]]` implement
  `fastcgi_intercept_errors`-style generated or static fallback error pages.

Logging and observability:

- `php.stderr_log`, `stderr_log_level`, and `stderr_max_bytes` control
  sanitized FastCGI STDERR logging.
- `php.stderr_failure_patterns` can mark a response invalid when STDERR
  contains configured fatal patterns, which can trigger safe-method failover
  when `retry_invalid_response` is enabled.
- Metrics builds expose PHP request/error/retry and php-fpm pool metrics.

The common application-level gap is not a FastCGI protocol gap. Some flat-root
applications, especially classic forum/wiki packages, expect the web server to
deny arbitrary private directories while still serving selected static
directories. Fluxheim currently has dotfile denial and PHP execution
`deny_path_prefixes`, but it does not yet have a first-class static
`deny_path_prefixes` or static allow-list policy. For flat-root applications,
prefer public-directory installs where available, or expose only explicit
static routes until a generic static deny/allow policy exists.

## WordPress

WordPress single-site installs need the normal PHP-FPM front-controller shape:
serve existing static files, route missing paths to `index.php`, and execute
real `.php` scripts only through php-fpm. The official NGINX guidance also
denies PHP execution under upload/file directories. Fluxheim's
`php.preset = "wordpress"` encodes that PHP-side behavior.

```toml
[[vhosts]]
name = "wordpress.example.test"
hosts = ["wordpress.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.php]
preset = "wordpress"
enabled = true
runtime = "php-fpm"
root = "/srv/sites/wordpress.example.test/public"
index = "index.php"
allowed_extensions = ["php"]
request_timeout_secs = 30
max_request_body_bytes = "64MiB"
max_response_bytes = "64MiB"
max_response_header_bytes = "64KiB"
hide_response_headers = ["x-powered-by"]
stderr_log = true

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
connect_timeout_secs = 5
read_timeout_secs = 30
write_timeout_secs = 30

[vhosts.web]
root = "/srv/sites/wordpress.example.test/public"
index_files = ["index.html", "index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
```

If php-fpm runs in a separate container with a different filesystem root, keep
`root` as the path Fluxheim validates and add the path php-fpm sees:

```toml
[vhosts.php]
root = "/srv/sites/wordpress.example.test/public"
fpm_root = "/app/public"
```

For a shared edge cache in front of WordPress, use Fluxheim's WordPress cache
preset only when you want shared cache behavior. It bypasses common admin,
login, XML-RPC, cron, sitemap, query-string, authorization, and logged-in cookie
paths. It does not implement WP Super Cache or W3 Total Cache static file
probing.

```toml
[vhosts.cache]
preset = "wordpress"
enabled = true
status_ttls = { "200" = 300, "301" = 300, "302" = 300, "404" = 60 }
stale_if_error_secs = 60

[vhosts.cache.memory]
enabled = true
max_size_bytes = "256MiB"
```

## WordPress Multisite

Modern WordPress Multisite uses the same PHP-FPM primitives as single-site
WordPress. WordPress handles subdirectory blog paths through `index.php`, and
subdomain networks need the same front-controller behavior for every mapped
host. Keep the Multisite constants and domain mapping in `wp-config.php`; the
Fluxheim part is host matching, TLS coverage, static serving, and PHP-FPM
dispatch.

Subdirectory Multisite:

```toml
[[vhosts]]
name = "wordpress-ms.example.test"
hosts = ["wordpress-ms.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.php]
preset = "wordpress"
enabled = true
runtime = "php-fpm"
root = "/srv/sites/wordpress-ms.example.test/public"
index = "index.php"
allowed_extensions = ["php"]
max_request_body_bytes = "64MiB"
max_response_bytes = "64MiB"
stderr_log = true

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"

[vhosts.web]
root = "/srv/sites/wordpress-ms.example.test/public"
index_files = ["index.html", "index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
```

Subdomain Multisite:

```toml
[[vhosts]]
name = "wordpress-ms-subdomains"
hosts = ["example.test", "*.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.tls]
enabled = true

# Wildcards require a certificate that already covers the wildcard name.
# HTTP-01 ACME cannot issue wildcard certificates.
[vhosts.tls.certificate]
cert_path = "/etc/fluxheim/tls/example.test/fullchain.pem"
key_path = "/etc/fluxheim/tls/example.test/privkey.pem"

[vhosts.php]
preset = "wordpress"
enabled = true
runtime = "php-fpm"
root = "/srv/sites/example.test/public"
index = "index.php"
allowed_extensions = ["php"]
max_request_body_bytes = "64MiB"
max_response_bytes = "64MiB"
stderr_log = true

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"

[vhosts.web]
root = "/srv/sites/example.test/public"
index_files = ["index.html", "index.php"]
deny_dotfiles = true
```

For named domain-mapped sites instead of a wildcard, list the concrete host
names in `hosts` and cover each name through the vhost certificate or ACME
target. Older WordPress Multisite deployments that still use legacy `/files/`
and `blogs.dir` rewrite/offload rules may need app-specific static aliases or
an upstream NGINX/Apache helper until Fluxheim has typed static fallback and
internal-route rules. The PHP-FPM part is still covered by the WordPress preset.

## Generic Front-Controller Apps

This shape fits Laravel, Symfony, and Flarum public-directory installs. It also
fits many modern PHP applications that serve static assets from a public root
and route missing paths to `index.php`.

```toml
[[vhosts]]
name = "app.example.test"
hosts = ["app.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/apps/app.example.test/public"
index = "index.php"
try_files = "front-controller"
path_info = "disabled"
allowed_extensions = ["php"]
request_timeout_secs = 30
max_request_body_bytes = "64MiB"
max_response_bytes = "64MiB"
max_response_header_bytes = "64KiB"
hide_response_headers = ["x-powered-by"]
stderr_log = true

[vhosts.php.params]
APP_ENV = "production"

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
connect_timeout_secs = 5
read_timeout_secs = 30
write_timeout_secs = 30

[vhosts.web]
root = "/srv/apps/app.example.test/public"
index_files = ["index.html", "index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
```

Application notes:

- Laravel requires the public directory to be the web root and routes all
  requests to `public/index.php` when no static file matches. The example above
  matches that model. Keep writable `storage/` and `bootstrap/cache/` outside
  the public root.
- Symfony's public directory and front-controller model also matches this
  config. Use `php.resolve_root_symlink = true` only when your deployment uses
  a final `current` symlink and php-fpm sees the same resolved path, or set
  `php.fpm_root` when php-fpm runs in a different container root.
- Flarum should use the normal `public` directory install with this shape. The
  Flarum no-public-dir layout relies on extra protection rules for sensitive
  resources; keep that behind a web server with explicit deny rules until
  Fluxheim has static deny/allow path policy.

## Symfony With Final Root Symlink

Symfony and Caddy-style deployments often point the web root at a `current`
symlink. Fluxheim rejects symlinked parents by default. If only the final root
component is a trusted release symlink, opt in explicitly:

```toml
[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/apps/example/current/public"
resolve_root_symlink = true
index = "index.php"
try_files = "front-controller"
hide_response_headers = ["x-powered-by"]

[vhosts.web]
root = "/srv/apps/example/current/public"
index_files = ["index.html", "index.php"]
deny_dotfiles = true
```

If php-fpm sees the same release under a different path, add:

```toml
[vhosts.php]
fpm_root = "/app/public"
```

## MediaWiki

MediaWiki is not a pure single-front-controller app. Official NGINX examples
use selected PHP entry points under `/w/`, optional REST `PATH_INFO`, static
asset paths, image handling rules, and a `/wiki/` short-URL rewrite to
`/w/index.php`.

Fluxheim can cover the PHP-FPM pieces:

- explicit PHP entry points with `try_files = "strict"`;
- short URL route to `index.php`;
- REST paths with `php.path_info = "split"`;
- `php.index = "index.php"` for article routes.

Keep image/private-path rules conservative. The official NGINX example denies
`/w/images/deleted` and treats uploaded HTML-like files specially. Fluxheim does
not yet provide equivalent static deny/type-override rules, so avoid exposing
private upload paths directly.

Example split-route sketch:

```toml
[[vhosts]]
name = "wiki.example.test"
hosts = ["wiki.example.test"]

[[vhosts.routes]]
name = "wiki-short-urls"
path_prefix = "/wiki/"

[vhosts.routes.php]
enabled = true
runtime = "php-fpm"
root = "/srv/mediawiki/w"
index = "index.php"
try_files = "front-controller"
path_info = "disabled"

[vhosts.routes.php.fpm]
tcp = "127.0.0.1:9000"

[[vhosts.routes]]
name = "wiki-entry-points"
path_prefix = "/w/"
strip_prefix = "/w"

[vhosts.routes.php]
enabled = true
runtime = "php-fpm"
root = "/srv/mediawiki/w"
index = "index.php"
try_files = "strict"
path_info = "split"
deny_path_prefixes = ["/mw-config/"]

[vhosts.routes.php.fpm]
tcp = "127.0.0.1:9000"
```

MediaWiki still needs matching `LocalSettings.php` values such as
`$wgScriptPath`, `$wgArticlePath`, and `$wgUsePathInfo`.

## phpBB

phpBB needs both direct PHP entry scripts and a fallback front controller
(`app.php` in the NGINX Unit reference). Fluxheim supports that at the PHP-FPM
level by setting `php.index = "app.php"` and using front-controller routing.

The security-sensitive part is private path exposure. The NGINX Unit reference
denies paths such as cache, config, files, store, and uploaded avatars before
serving static files. Fluxheim can block PHP execution for those paths, but it
does not yet block arbitrary static access by prefix. Prefer an upstream with
explicit deny rules, or expose only selected static directories with route-level
`[vhosts.routes.web]`.

```toml
[[vhosts]]
name = "phpbb.example.test"
hosts = ["phpbb.example.test"]

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/phpbb"
index = "app.php"
try_files = "front-controller"
path_info = "split"
deny_path_prefixes = [
  "/cache/",
  "/config/",
  "/files/",
  "/store/",
  "/images/avatars/upload/",
  "/config.php",
  "/common.php",
]
stderr_log = true

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
```

Do not add a broad `[vhosts.web] root = "/srv/phpbb"` unless you have audited
the static paths that become public.

## XenForo

XenForo friendly URLs need a front-controller fallback to `index.php`, strict
execution for real PHP scripts, and private directory protection for paths such
as `internal_data`, `src`, `install/data`, and legacy `library`.

Fluxheim covers the PHP-FPM part. The same flat-root static caution applies:
do not expose the whole XenForo root as static content unless you have explicit
private-path protection outside Fluxheim or a future static deny policy.

```toml
[[vhosts]]
name = "xenforo.example.test"
hosts = ["xenforo.example.test"]

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/xenforo"
index = "index.php"
try_files = "front-controller"
path_info = "disabled"
deny_path_prefixes = [
  "/install/data/",
  "/install/templates/",
  "/internal_data/",
  "/library/",
  "/src/",
]

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"

[[vhosts.routes]]
name = "xenforo-styles"
path_prefix = "/styles/"

[vhosts.routes.web]
root = "/srv/xenforo"
index_files = ["index.html"]
deny_dotfiles = true
```

Add explicit static routes for the public asset directories your XenForo
installation requires.

## MyBB

MyBB's PHP-FPM requirements are simple: execute real PHP scripts and optionally
translate search-engine-friendly URL patterns to legacy PHP endpoints such as
`forumdisplay.php`, `showthread.php`, and `member.php`.

Fluxheim does not currently have a generic regex rewrite engine for MyBB's
classic SEF URL rules. Use MyBB's non-SEF URLs, place NGINX/Apache in front for
those specific rewrites, or wait for typed rewrite support. This is not a
FastCGI protocol gap.

MyBB also documents writable directories such as `cache/`, `uploads/`,
`uploads/avatars/`, and optional `admin/backups/`. Avoid serving writable
directories as PHP and avoid exposing backup/config files as static content.

```toml
[[vhosts]]
name = "mybb.example.test"
hosts = ["mybb.example.test"]

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "/srv/mybb"
index = "index.php"
try_files = "strict"
path_info = "disabled"
deny_path_prefixes = [
  "/cache/",
  "/uploads/",
  "/uploads/avatars/",
  "/admin/backups/",
  "/inc/config.php",
  "/inc/settings.php",
]

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
```

Serve only audited static directories until Fluxheim has first-class static
deny/allow path controls.

## Discourse

Discourse is not a PHP-FPM application. The official install path is a Docker
application stack with its own Rails/Unicorn/PostgreSQL/Redis deployment model.
In Fluxheim, treat Discourse as a reverse-proxy upstream, not as `[vhosts.php]`.

```toml
[[vhosts]]
name = "discourse.example.test"
hosts = ["discourse.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.proxy]
upstreams = ["discourse_app:80"]
upstream_tls = false
connect_timeout_secs = 5
read_timeout_secs = 90
send_timeout_secs = 90
```

Keep Discourse's own documented container lifecycle and upgrade path intact.

## When To Add A Fluxheim Feature

Prefer documentation unless the missing behavior is generic and safety-critical.
Good future candidates are:

- Static `deny_path_prefixes` / allow-list policy for flat-root PHP apps.
- Typed rewrite mappings for legacy forum SEF URLs without arbitrary regex
  replacement strings.
- A typed internal redirect action for app-specific private/offload paths.

Avoid app-named presets unless the behavior is stable across versions and hard
to express safely with generic Fluxheim primitives.
