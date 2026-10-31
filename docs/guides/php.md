# PHP And FastCGI

Fluxheim accepts HTTP requests; PHP-FPM executes the PHP code. They communicate
using FastCGI, not HTTP. PHP remains a separate installation and process. A PHP
script is not executed merely because a static web root contains a `.php` file.

This guide covers deployment, script selection and static assets. See
[advanced PHP runtime settings](php-runtime-support.md) for transport, process
supervision and response controls, and [application recipes](php-fpm-app-recipes.md)
for framework layouts. Those advanced sections are still undergoing the
[documentation audit](../reference/documentation-coverage.md); do not infer
support from a migration checklist alone.

## Choose A Deployment

| Deployment | Configure | Who starts PHP? |
| --- | --- | --- |
| External local Unix socket | `mode = "external"`, `socket` | Your service manager |
| External TCP, including a separate container | `mode = "external"`, `tcp` or `tcp_upstreams` | Your service manager/container |
| Managed local PHP-FPM on Unix | `mode = "managed"`, `php_fpm_binary`, `socket_dir` | Fluxheim |
| Windows | External TCP FastCGI | You; managed mode is rejected |

Use a PHP-capable binary (`php-fpm` feature). A full Fluxheim binary does not
install PHP or its extensions. The focused `php` container images include PHP;
ordinary full/proxy/cache images do not thereby include a PHP interpreter.
See [features](../reference/features.md) and [container runtime refresh](container-runtime-refresh.md).

FastCGI endpoints must remain private. Fluxheim does not add TLS or application
authentication to FastCGI. Do not publish port 9000 to the Internet. For numeric
loopback/private/link-local addresses, set `allow_private_tcp_upstreams = true`.
This is an explicit address-policy opt-in, not encryption. Hostnames are not a
network isolation boundary; control DNS, routing and firewall access yourself.

## Run An External PHP Pool

Start with [external.toml](../../examples/php/external.toml). It listens only on
`127.0.0.1:8080`, expects PHP-FPM at `127.0.0.1:9000`, and uses a `public`
directory beside the configuration. Relative filesystem paths resolve against
the configuration directory, not the shell's current working directory.

Create this minimal `public/index.php`:

```php
<?php
header('Content-Type: text/plain');
echo "PHP is running\n";
```

Create `public/style.css` containing `body { color: black; }`. Configure your
external PHP-FPM pool to listen on the private address, then run:

```sh
fluxheim --config /srv/fluxheim-demo/external.toml --validate-config
fluxheim --config /srv/fluxheim-demo/external.toml
curl --noproxy '*' -H 'Host: php.example.test' http://127.0.0.1:8080/index.php
curl --noproxy '*' -H 'Host: php.example.test' http://127.0.0.1:8080/style.css
```

Use an owner-controlled configuration directory and run as the intended service
user. Validation checks path trust; startup also needs the real document root.
Neither a successful parse nor a listening FastCGI socket proves that PHP has
the required application extensions or database access.

To use a Unix socket, **replace**, rather than supplement, the FPM block:

```toml
[vhosts.php.fpm]
mode = "external"
socket = "/run/php/site.sock"
```

External mode accepts exactly one of `socket`, `tcp`, or a nonempty
`tcp_upstreams`. It rejects managed-only settings. Keep socket ownership and
directory access appropriate for both service identities; do not fix permission
errors by making sockets or their parents world-writable.

## Let Fluxheim Start PHP-FPM

[managed.toml](../../examples/php/managed.toml) has the same site and static
asset setup, with this Unix-only pool:

```toml
[vhosts.php.fpm]
mode = "managed"
php_fpm_binary = "/usr/sbin/php-fpm"
socket_dir = "/run/fluxheim/php"
workers = 4
process_manager = "dynamic"
start_servers = 2
min_spare_servers = 1
max_spare_servers = 4
```

Install PHP-FPM first. Set `php_fpm_binary` to the actual trusted executable on
your distribution, not a guessed path or symlink wrapper. Fluxheim validates the
binary and its ancestors and uses a retained executable handle on Unix. The
`socket_dir` must be private and usable by the service user. Keep it short:
Unix-domain sockets have platform-specific pathname limits. Fluxheim creates
its own socket; do not also configure `socket`, `tcp` or `tcp_upstreams`.

`workers` means the maximum PHP child count (1 through 256), not Fluxheim's HTTP
thread count. The choices are:

- `static`: fixed `workers` children. Remove all dynamic/ondemand sizing fields.
- `dynamic`: grow/shrink between spare-worker limits, up to `workers`.
  `min_spare_servers` and `max_spare_servers` are required. If omitted,
  `start_servers` is the midpoint of the spare limits, clamped to those limits.
- `ondemand`: create children as needed, up to `workers`. Remove dynamic fields;
  optionally set `process_idle_timeout_secs`.

For example, replace the dynamic settings with:

```toml
process_manager = "ondemand"
workers = 4
process_idle_timeout_secs = 10
```

Default process-manager mode is `static`, default workers is 4, and default
`max_requests_per_worker` is 1000. The latter recycles a worker after that many
requests; zero disables that recycling. PHP remains responsible for its own
interpreter limits, extensions, upload limits and database credentials.

Managed configuration uses a minimal child environment, not the complete
Fluxheim environment. Do not assume exported shell secrets reach PHP workers.
When intentionally starting PHP as root and dropping workers to another
identity, configure `user` and `group` together, and separately arrange socket,
session and upload-directory access. Do not run Fluxheim as root merely to avoid
planning permissions. See the advanced guide for those settings and supervision.

## Understand Request Routing

`[vhosts.php]` is the fallback PHP handler for a vhost. Explicit routes win
first. For a request reaching vhost fallback, PHP script selection runs before
the ordinary static fallback. A found non-PHP file is declined by PHP so that
`[vhosts.web]` can serve it. Missing application paths can execute the front
controller. A denied PHP script does not fall through into static source output.

Use **both** `php.root` and `web.root` for the common mixed application:

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
index = "index.php"
try_files = "front-controller"
allowed_extensions = ["php"]
path_info = "disabled"

[vhosts.php.fpm]
tcp = "127.0.0.1:9000"
allow_private_tcp_upstreams = true

[vhosts.web]
root = "/srv/site/public"
index_files = ["index.html"]
deny_dotfiles = true
```

This is a vhost fragment, not a complete standalone configuration. Keep roots
identical unless you have deliberately reviewed the two separate trees. Static
file serving does not itself execute PHP. Avoid static-only routes over source,
configuration or backup directories; see [static files](static-files.md).

| Request | Current behavior with the mixed front-controller setup |
| --- | --- |
| `/index.php?x=1` | Execute the existing script, pass the query separately |
| `/missing.php` | 404; never pretend the missing explicit script exists |
| `/news/article` with no matching file | Execute `/index.php` |
| `/style.css` when it exists | Serve through `web.root` |
| `/index.php/user` with default `path_info` | Reject, rather than split implicitly |
| A denied upload `.php` script | 403, not PHP source |
| `/blog` with `blog/index.php` | 308 to `/blog/`; query-loss caveat below |

`try_files` defaults to `front-controller`. `wordpress` has the same native
selection behavior; `strict` disables missing-path front-controller fallback,
while still permitting existing scripts and directory indexes. For a strict
script endpoint change the PHP block to:

```toml
try_files = "strict"
path_info = "split"
```

Then `/missing/page` is 404 and `/index.php/user/1` executes the existing
`index.php` with `PATH_INFO=/user/1`. The older spelling `path_info = "strict"`
means **split**, not strict file existence. Use the unambiguous `split` spelling.

`[vhosts.routes.php]` is an explicit PHP **action**, not a mixed static/PHP
fallback. Give it its own root and FPM settings. An existing `.css` file matched
by that PHP action returns 404; it does not retry another action. Use separate
static routes or the mixed vhost setup. Read [routing](routing.md) before adding
prefix stripping or rewrites; they change the URI seen by the action.

## Protect Uploaded And Private Files

`preset = "wordpress"` adds these PHP execution denies without removing your
own `deny_path_prefixes`: `/wp-content/uploads/`, `/wp-content/blogs.dir/`,
`/blogs.dir/`, `/uploads/` and `/files/`. It selects WordPress front-controller
mode when `try_files` is the default; an explicit `strict` mode stays strict.
Setting `try_files = "wordpress"` alone does **not** add the deny list.

```toml
[vhosts.php]
enabled = true
preset = "wordpress"
root = "/srv/site/public"
deny_path_prefixes = ["/private/", "/config.php"]
```

These are script-name execution rules, not general HTTP path ACLs. A non-PHP
file in `/private/` can still be served by a broad static root. Keep secrets
outside public roots and expose only reviewed asset directories for flat-root
applications. Directory listing is off by default; keep it off for applications.
Application authentication and database security remain the application's job.

## Map A Separate Container Root

Fluxheim must see local script files to validate them even when PHP is remote.
Mount the same deployed code in both environments:

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
fpm_root = "/app/public"

[vhosts.php.fpm]
tcp = "php-fpm:9000"
allow_private_tcp_upstreams = true
```

For a validated local `/srv/site/public/index.php`, PHP receives
`SCRIPT_FILENAME=/app/public/index.php`. `fpm_root` does not copy files or check
the remote deployment. PHP must see that file and have permission to read it.
In a separate container, `127.0.0.1` refers to that container, not the database or
PHP container next to it. Connect containers on a private network and use their
service names. A WordPress database is still configured in `wp-config.php`.

`resolve_root_symlink = true` allows only the **last component of php.root** to
be a trusted symlink, resolved at startup. If `current` is the symlink, use
`root = "/srv/app/current"` with `current` pointing directly at the public
directory. `/srv/app/current/public` has a symlinked parent and is rejected.
This option does not relax `web.root`; use its real trusted directory separately.
Changing the symlink does not hot-switch the running PHP root.

## Limits And Troubleshooting

The examples set both `server.limits.max_request_body_bytes` and
`vhosts.php.max_request_body_bytes` to `"1MiB"`. Set the outer HTTP and
PHP limits intentionally; a higher PHP limit cannot override an earlier HTTP
rejection. Also configure PHP's own `post_max_size` and `upload_max_filesize`.
`max_in_flight` defaults to 8 (valid 1 through 4096) per PHP handler and returns
503 with `Retry-After: 1` when busy. It is not an application-wide database pool
limit. `request_timeout_secs` defaults to 30. Retry and phase semantics require
the advanced transport settings, not an assumption of streaming end to end.

| Symptom | Check |
| --- | --- |
| PHP module not compiled | Use a PHP-capable build/image; a configuration option cannot add a compiled feature |
| Missing/unsafe PHP binary | Correct managed executable path, owner and ancestor permissions; external mode does not start that executable |
| 502 `php-fpm failed` | Pool running, correct private socket/address, matching deployed files, bounded response, PHP error logs |
| PHP works, assets 404 | Configure `web.root`; do not route all assets through an explicit PHP action |
| Missing MySQL extension | Inspect the actual FPM runtime's modules, not a different host CLI installation |
| Database connection error | Check the application's DB credentials and container network; localhost is not another container |
| 413 | Check HTTP and PHP body limits; PHP's own upload settings are separate |
| 503 | PHP in-flight cap reached; inspect worker capacity before increasing it |

## Open Native-Runtime Gaps

These are **pending corrections**, not supported alternatives:

- **Current limitation:** explicit PHP actions accept GET/HEAD/POST only,
  but pre-resolved vhost fallback currently forwards methods such as PUT. Do not
  use this inconsistency as authorization. Applications must enforce their own
  permitted operations; moving an API between route types can change behavior.
- **Current limitation:** a directory-slash redirect drops the query, and
  `/blog/` can execute `blog/index.php` while sending `SCRIPT_NAME=/index.php`.
  Use explicit script URLs where CGI script identity matters until corrected.
- **Current limitation:** the native adapter strips `X-Accel-Redirect`,
  `X-Sendfile` and `X-Accel-Expires`, but neither serves the offload target nor
  translates the expiry. Keep downloads within the bounded PHP response or use
  a separately secured file-serving design. Do not expose private files as a
  workaround or rely on these headers to make a response cache-safe.
- **Current limitation:** the documented PHP-only WordPress cache policy
  is rejected by native runtime validation. Adding local static caching can make
  configuration admissible but still does not cache PHP responses. The
  [WordPress cache preset](cache.md) is not proof of FastCGI cache integration.

## Verification Scope

`scripts/smoke_php_examples.py` starts the actual debug Fluxheim binary and real
installed PHP-FPM over private loopback, then tests managed static/dynamic/
ondemand pools. It covers PHP execution, POST body/query, static assets,
front-controller/strict/PATH_INFO routing, upload execution denial, hidden paths,
HEAD, declared oversized uploads and the four open findings. It is deliberately
a Linux/Unix test, not a replacement for native Windows/macOS qualification or a
fresh WordPress/database/container test. The existing WordPress and PHP-image
smokes remain separate application/release gates.
