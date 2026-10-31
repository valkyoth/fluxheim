# PHP Application Deployment Recipes

Start with [PHP deployment and routing](php.md), then use the
[option reference](../reference/php-options.md) and
[transport/operations guide](php-runtime-support.md) for individual settings.
This page explains deployment layouts, not automatic support for every version,
plugin, rewrite file or application security rule.

**What was actually tested:** the repository's external-FPM WordPress smoke
installed WordPress against MariaDB, logged in and loaded the authenticated
dashboard. A separate real-FPM fixture verified front-controller routing,
explicit public assets and private-path behavior. Neither proves complete
WordPress Multisite, Laravel, Symfony, Flarum, MediaWiki or forum compatibility.

## Choose The Filesystem Layout First

There are three separate responsibilities:

1. Fluxheim must inspect scripts under its local PHP root.
2. PHP-FPM must see the same scripts, possibly under a different backend root.
3. Only intended public files may be exposed by static actions.

Prefer an application-owned public directory. Keep source libraries, database
backups, logs, environment files and credentials outside it. Dotfile denial is
not protection for names such as config.bak or backup.sql. Do not copy another
server's configuration into TOML expecting equivalent interpretation; Fluxheim
does not read.htaccess or NGINX rewrite files.

| Layout | Starting point | Important boundary |
| --- | --- | --- |
| Dedicated public directory with index.php | [External example](../../examples/php/external.toml), remove the WordPress preset for a generic application | Only deliberately public files belong in the web root. |
| WordPress mixed PHP/assets | Same example with the WordPress preset | Preset denies execution in common upload directories; it is not a static-file filter or FastCGI cache. |
| Flat-root application with private source beside assets | [Explicit-asset example](../../examples/php/flat-root.toml) | No vhost-wide static root; publish only reviewed asset paths. |
| PHP-FPM in another container | Same routing, plus fpm_root when paths differ | Code must be available to both processes; the FastCGI connection does not transfer script files. |
| An application serving HTTP itself | [Reverse proxy](reverse-proxy.md) | An HTTP port is not a FastCGI port. |

## WordPress Single Site

Use the complete external or managed recipe from the PHP deployment guide.
For an existing server configuration, this is the site fragment:

```toml
[[vhosts]]
name = "blog"
hosts = ["blog.example.test"]
max_request_body_bytes = "64MiB"

[vhosts.php]
enabled = true
preset = "wordpress"
root = "/srv/wordpress"
index = "index.php"
allowed_extensions = ["php"]
max_request_body_bytes = "64MiB"
hide_response_headers = ["x-powered-by"]

[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:9000"
allow_private_tcp_upstreams = true

[vhosts.web]
root = "/srv/wordpress"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
```

Also set the outer server body limit appropriately. Fluxheim's limit does not
override PHP upload_max_filesize/post_max_size, application limits or proxy
limits in front of Fluxheim. Add [TLS](tls.md) and the desired hostnames before
public exposure. A site name is a configuration identity; hosts selects requests.

PHP handles index.php; it does not belong in the static index list. The
WordPress preset supplies front-controller and PHP upload-execution denials,
not a general ban on serving every file in uploads. Review plugins that create
backups or private exports there. An explicit static route can override the
vhost PHP fallback, as demonstrated below.

WordPress's [NGINX guidance](https://developer.wordpress.org/advanced-administration/server/web-server/nginx/)
contains additional restrictions, multisite rewrites and cache-plugin rules.
Those are not automatically translated by a Fluxheim preset. In particular,
native PHP response caching and X-Accel/X-Sendfile offload remain open gaps
the documented limitation. Do not enable a cache preset expecting WordPress pages to be
cached, or assume WP Super Cache/W3TC file probing exists.

### Database And Container Networking

PHP-FPM makes the database connection, not Fluxheim's HTTP listener. When PHP
and MariaDB are in different containers, 127.0.0.1 inside the PHP container is
not the database container. Use the database service name on a shared private
network, for example this wp-config.php fragment:

```php
define('DB_HOST', 'db:3306');
define('DB_NAME', 'wordpress');
define('DB_USER', 'wordpress');
// Supply DB_PASSWORD and salts through your protected deployment configuration.
```

Do not publish MariaDB to the Internet. Attach only the services that need it
to the database network. If Fluxheim supervises FPM inside its own container,
that container needs the database network too. A separate external FPM container
needs it instead. Reuse a site's real database only after backup and migration
planning; the smoke commands below use disposable data.

The [PHP image module baseline](../../packaging/container/php-required-modules.txt)
includes database modules. Inspect the actual FPM binary's startup output if
WordPress reports missing mysqli; a module file or configure flag is not proof
it loaded. Missing mysqlnd or incorrect ini order can make mysqli fail to load.
See [PHP images](php-runtime-support.md#php-images-and-application-checks).

### Volumes, Paths And Permissions

Mount the site into Fluxheim as well as external FPM. A missing asset mount
often explains a 404 even when PHP itself executes. If Fluxheim sees
/srv/wordpress and the backend sees /var/www/html, change the PHP table:

```toml
[vhosts.php]
enabled = true
root = "/srv/wordpress"
fpm_root = "/var/www/html"
```

This translates CGI paths, not file ownership, mounts or URLs. Keep identical
application content on both sides. Give workers write access only where the
application needs it; keep code, configuration and backups outside public
writable directories whenever possible. Do not solve a permission error with
world-writable roots or disable Fluxheim's path checks.

For Podman, choose SELinux labels for the intended sharing model::z is shared,
:Z is private. A private label intended for one container is not a promise that
two independently relabelled mounts can share files. Check host/container
ownership and security labels independently; PHP's Unix account may differ from
Fluxheim's. See [Podman's volume documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

### Multisite Is A Separate Qualification

A single-site login smoke does not establish Multisite compatibility.
Subdirectory sites can require path adjustments for shared admin and core
resources, not merely index.php fallback. Subdomain sites also need hostname
mapping and certificates for every accepted name.

For a subdomain layout the host list can be:

```toml
[[vhosts]]
name = "network"
hosts = ["example.test", "*.example.test"]
```

Retain the rest of your site configuration and provision suitable certificates.
HTTP wildcard host matching is broader than a single-label TLS wildcard;
see [host routing](routing.md). HTTP-01 cannot issue wildcard certificates.
Legacy files/blogs.dir mappings and plugin-generated static-cache rules need
explicit migration. Test admin URLs, login cookies, assets, upload isolation and
every mapped hostname before replacing the old web server.

## Public-Directory Frameworks

The public-directory pattern suits a framework that sends unknown URLs to
index.php and keeps internal source outside that directory. Replace only the
PHP/web roots in the single-site example with /srv/app/public, remove
preset="wordpress", and set:

```toml
[vhosts.php]
enabled = true
root = "/srv/app/public"
index = "index.php"
try_files = "front-controller"
path_info = "disabled"
hide_response_headers = ["x-powered-by"]

[vhosts.php.params]
APP_ENV = "production"
```

Retain an FPM endpoint and a web table rooted at the same public directory.
APP_ENV is an administrator-controlled CGI parameter, not a general replacement
for application secret provisioning or a guarantee that a framework reads it.

- [Laravel deployment](https://laravel.com/docs/12.x/deployment) places its entry
  point in public and requires writable application storage/cache directories.
  Do not expose the project root as static content.
- [Symfony web-server configuration](https://symfony.com/doc/current/setup/web_server_configuration.html)
  likewise uses public as the document root. Its deployment-specific environment
  and cache tasks remain application responsibilities.
- [Flarum installation](https://docs.flarum.org/install/) documents its required
  interpreter/extensions and web-server setup. Verify the version you deploy;
  this generic recipe is not a tested replacement for all vendor-specific rules.

Test GET, POST and any PUT/PATCH/DELETE API routes explicitly. The current native
direct-PHP versus vhost-fallback method difference is the documented limitation; changing a
working fallback into an explicit PHP route can change method admission.

### Release Symlinks And Mounted Prefixes

Only a trusted final PHP-root symlink can be opted in. For example:

```toml
[vhosts.php]
enabled = true
root = "/srv/app/current-public"
resolve_root_symlink = true
index = "index.php"

[vhosts.web]
root = "/srv/app/releases/release-a/public"
index_files = ["index.html"]
```

Here current-public points directly to release-a/public. A current/public path
with current as a symlinked parent is rejected. The static root has no matching
opt-in. Coordinate both roots and FPM's visible root during deployment/reload.

Route rewrites change the URI passed to PHP. Do not add strip_prefix merely to
make a filesystem path resolve: the application also sees changed URI/CGI data.
Directory SCRIPT_NAME consistency and lost redirect queries are the documented limitation.
Subpath applications need their generated links, cookies and redirects tested,
not only a successful script response.

## Flat-Root Forums And Wikis

Some applications keep public scripts/assets next to private libraries or data.
Use the [complete flat-root fixture](../../examples/php/flat-root.toml) as a
layout pattern, not an application certification. It executes PHP from app/
without a catch-all static root and publishes just /assets/style.css from
public-static/assets/style.css:

```toml
[[vhosts.routes]]
name = "public-stylesheet"
path_exact = "/assets/style.css"

[vhosts.routes.web]
root = "/srv/site/public-static"
index_files = ["index.html"]
deny_dotfiles = true
```

The exact route retains the whole URI, so the assets subdirectory must exist
under that root. Prefix stripping requires a prefix matcher, not path_exact.
Add reviewed asset entries or generate them from your deployment manifest.
Unknown paths may reach the application front controller, but they must not
publish arbitrary files from the static tree.

A prefix static route is reasonable only for an entirely public, controlled
asset tree. Never assume PHP execution-denial rules make that tree safe:

**Current limitation:** a selected static action serves files as data and
does not inherit php.deny_path_prefixes or allowed_extensions. The real-FPM
layout smoke first gets 403 for /uploads/payload.php through PHP policy, then
200 containing the literal source when a broad static route selects that file.
This is a missing cross-action publication policy, not proof that static serving
escaped its configured root. Do not put secrets or executable uploads in a
broadly published tree.

An existing route ACL can deliberately deny an entire selected subtree:

```toml
[[vhosts.routes]]
name = "private-files"
path_prefix = "/private"

[vhosts.routes.access]
deny = ["0.0.0.0/0", "::/0"]

[vhosts.routes.web]
root = "/srv/site"
```

Omit methods so all methods selecting this route receive the policy. More-specific
routes do not inherit it: repeat the restriction or avoid overlapping routes.
See [access control](access-control.md). This can protect known paths, but it is
not a filesystem-level or extension-aware policy shared by every static action.

### Application-Specific Migration Checklist

| Application | Verify before exposure |
| --- | --- |
| MediaWiki | Actual script entry points, /w versus /wiki mapping, REST PATH_INFO, private/deleted images, MIME handling and LocalSettings.php URL settings. The old two-route sketch was not a qualified full configuration. |
| phpBB | Its selected front controller (often app.php), direct entry scripts, private config/cache/store data and public asset inventory. Do not treat PHP deny prefixes as static protection. |
| XenForo | Friendly URL behavior and the exact private/public directory rules shipped with the installed version; review vendor configuration rather than assuming a fixed directory list is exhaustive. |
| MyBB | Direct script URLs first; port any optional SEF rewrites separately and protect configuration/backups/uploads. |

[MediaWiki's short-URL example](https://www.mediawiki.org/wiki/Manual:Short_URL/Nginx)
includes application URL settings and specific server rules.
[MyBB's SEF instructions](https://docs.mybb.com/1.8/administration/configuring-search-engine-friendly-URLs/)
include capture-to-query rewrites. Fluxheim has bounded path regex rewrites,
but rewrite_template is path-only: it does not synthesize query arguments such
as fid from a regex capture. Preserve the application's ordinary URLs or retain
a separately maintained compatible routing layer. Do not describe this as
absence of all regex support.

For phpBB consult the [NGINX Unit migration example](https://docs.nginx.com/nginx-unit/howto/apps/phpbb/);
for XenForo consult its [friendly URL documentation](https://docs.xenforo.com/manual/configuration/friendly-urls/).
Those sources help identify requirements; they are not evidence those
applications have been installed and tested on this Fluxheim candidate.

## Validate In Layers

1. Validate configuration as the real service identity.
2. Execute a small PHP request and serve a known asset.
3. Probe private files, backup extensions, encoded paths and uploaded scripts.
4. Verify application install/login/logout, authenticated pages, uploads,
   generated URLs and required HTTP methods.
5. Check TLS/proxy identity, worker permissions, modules, database connectivity,
   failure recovery and logs using the actual deployment.

Developer layout smoke, using local installed PHP-FPM:

```sh
cargo build --locked --bin fluxheim --features php-fpm
python3 scripts/smoke_php_app_layouts.py
```

Real WordPress and MariaDB container smoke:

```sh
FLUXHEIM_BIN="$PWD/target/debug/fluxheim" \
  sh scripts/smoke_wordpress_php_fpm.sh external
```

The WordPress script requires rootless Podman, curl and tar, downloads WordPress,
and uses disposable containers with test-only database credentials. Published
FPM/HTTP ports are loopback-only; do not transplant the credentials into a real
site. Its current image/download inputs are not a reproducible release artifact
or certification of Fluxheim's four PHP images. Managed modes additionally need
a suitable local interpreter and extensions; managed-respawn exercises recovery.

The [coverage ledger](../reference/documentation-coverage.md) records exactly
which checks ran. Native Windows/macOS, complete framework integrations,
Multisite and four-image PHP qualification remain separate gates.
