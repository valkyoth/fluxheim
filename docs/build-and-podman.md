# Build And Rootless Podman

Fluxheim pins Rust 1.96.0 in `rust-toolchain.toml` and `Cargo.toml`. The local
toolchain and the container builder should stay on the same stable release.

## Local Builds

Native builds are the best option when the binary should be optimized for the
current CPU:

```bash
cargo build --release
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Use `target-cpu=native` only for binaries that will run on the same CPU family
they were built on. For portable release artifacts, omit the flag.

Feature-reduced builds keep the binary small and reduce dependency surface:

```bash
cargo build --release --no-default-features --features proxy
cargo build --release --no-default-features --features proxy,load-balancer
cargo build --release --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --release --no-default-features --features profile-cache-edge,acme-client
cargo build --release --no-default-features --features profile-proxy-edge,acme-client
cargo build --release --no-default-features --features profile-web-server,php-fpm,acme-client
```

The default build enables `proxy`, `web`, `cache`, `tls-rustls`, and
`security`. Cargo does not have a separate `--group` flag, so Fluxheim exposes
grouped build profiles as normal feature aliases such as `profile-core`,
`profile-static-site`, `profile-reverse-proxy`, `profile-cache-server`,
`profile-load-balancer`, `profile-observability`, and `profile-privacy`.
Fluxheim 1.3 also adds focused profile aliases: `profile-full`,
`profile-web-server`, `profile-cache-edge`, `profile-proxy-edge`,
`profile-load-balancer-edge`, `profile-fips-openssl`, and
`profile-iso19790-openssl`. The `1.3.5` release line introduced
`profile-fips-rustls` and `profile-iso19790-rustls` for the rustls/AWS-LC FIPS
candidate path, and `1.3.6` adds fail-closed internal-crypto gates and
compliance evidence templates around those FIPS/ISO profiles.
`profile-development` is a broad development profile with all compatible
production modules enabled: full proxy/web/cache and load-balancer support,
PHP-FPM, ACME, Prometheus, OTLP metrics, and OTel tracing.

TLS backends are mutually exclusive. Select exactly one of `tls-rustls`,
`tls-rustls-fips`, or `tls-openssl`; `tls-rustls` is the default and
recommended non-FIPS backend.

For FIPS/ISO-capable OpenSSL testing, build with `tls-openssl-fips` or the
`tls-openssl-iso19790` alias instead of the default rustls backend and
configure `[tls] backend = "openssl"` plus `[tls.fips] required = true` or
`[tls.iso19790] required = true`. The build must link to an OpenSSL 3
installation with a validated provider installed and configured by the
operator:

```bash
cargo build --release --no-default-features --features profile-fips-openssl
cargo build --release --no-default-features --features profile-iso19790-openssl
fluxheim crypto
```

For rustls/AWS-LC FIPS candidate testing, build with `tls-rustls-fips` or a
matching profile and configure `[tls] backend = "rustls"` plus `[tls.fips]
required = true` or `[tls.iso19790] required = true`. This path builds
`aws-lc-fips-sys`, so the build host needs CMake, Go, and a C compiler:

```bash
cargo build --release --no-default-features --features profile-fips-rustls
cargo build --release --no-default-features --features profile-iso19790-rustls
scripts/validate-fips-rustls.sh check
```

Use an AWS-LC-supported FIPS builder for
`scripts/validate-fips-rustls.sh release`. Rolling distribution compilers can be
ahead of AWS-LC FIPS support; newer GCC/Clang families may fail inside
`aws-lc-fips-sys` before Fluxheim code is compiled. The helper fails early for
known newer compiler families and documents the investigation-only override in
[FIPS-Capable Deployments](fips.md).

The FIPS/ISO profile aliases are narrow proof profiles, not a limitation of the
FIPS features. For custom cache or PHP-FPM builds, select raw modules so that
the binary has exactly one TLS backend:

```bash
# FIPS/ISO-capable cache edge
cargo build --release --no-default-features \
  --features proxy,cache,security,tls-openssl-fips

# FIPS/ISO-capable PHP-FPM web build
cargo build --release --no-default-features \
  --features php-fpm,security,tls-openssl-fips
```

For the rustls/AWS-LC candidate, replace `tls-openssl-fips` with
`tls-rustls-fips` in those raw feature examples.

These examples intentionally omit `acme-client`. For stricter FIPS/ISO
deployment boundaries, prefer local/static certificate files generated and
renewed by an approved external process. If you add `acme-client`, treat ACME
account key generation, JWS account signing, EAB handling, ACME HTTPS client
behavior, challenge certificate generation, and CA policy as a separate
evidence area outside the TLS provider proof. In FIPS/ISO-required configs,
Fluxheim rejects `[tls.acme] enabled = true`; compile-time availability of
`acme-client` does not make managed ACME part of the approved boundary.

The OpenSSL feature makes Fluxheim fail closed, loads the OpenSSL FIPS
provider, enables default FIPS properties for the process, and exposes
provider/default property diagnostics. The rustls/AWS-LC candidate installs or
passes the rustls FIPS provider and checks rustls' FIPS indicators for required
configs. Either deployment still needs the selected module's CMVP certificate,
Security Policy, provider/build configuration, and platform evidence. See
[FIPS-Capable Deployments](fips.md).

`1.3.6` also closes other non-TLS crypto paths in FIPS/ISO-required mode:
provider-backed admin auth is allowed in OpenSSL FIPS or rustls/AWS-LC FIPS
builds, while local cache encryption, managed ACME, and remote/HTTPS OTLP
export are rejected unless the path is non-secret, numeric-local-loopback-only,
or externally evidenced as documented in the FIPS guide.

PHP support starts with `php-fpm` in `1.3.1`. It is never compiled by default;
build it explicitly with `profile-web-server,php-fpm` when Fluxheim should
serve PHP applications through php-fpm.

See [Feature Matrix](features.md) for the complete feature/profile list.

Fluxheim's production RPM intentionally compiles
`profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp` for the
current production line. That keeps the normal packaged binary broad while the
container and tarball release assets also provide focused cache/proxy builds.
Custom source builds can still omit `acme-client`, load-balancer, cache, web,
or observability features when they are not needed.

For package scripts or custom CI that accept user-provided feature strings, run
the feature preflight before invoking Cargo:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

## System Build Dependencies

Fluxheim builds with Rust 1.96.0. Starting in `1.6.34`, the default feature set
uses the Fluxheim-owned native runtime with rustls, cache support, and static
file serving; normal profiles no longer compile Pingora crates. Native builds
need a normal C/C++ toolchain plus a few build helpers for transitive native
code.

Required for the default build:

- Rust 1.96.0, usually through `rustup` or the distro Rust packages when they
  are new enough;
- C and C++ compiler toolchain;
- `make`;
- `cmake`;
- `perl`;
- `pkg-config`/`pkgconf`;
- `ca-certificates`.

Package examples:

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake perl pkg-config ca-certificates

# Alpine / Wolfi
apk add build-base cmake perl pkgconf ca-certificates

# openSUSE / SUSE
sudo zypper install gcc gcc-c++ make cmake perl pkgconf-pkg-config ca-certificates

# RHEL / Fedora-style systems
sudo dnf install gcc gcc-c++ make cmake perl pkgconf-pkg-config ca-certificates
```

Optional backend-specific packages:

- `tls-openssl`: install OpenSSL development headers, such as `libssl-dev`,
  `openssl-devel`, or the distro equivalent.

Container builds install the same requirements in the builder stage. The
runtime images only need CA certificates plus the Fluxheim binary and config.

## Container Variants

Fluxheim ships multiple runtime Containerfiles so operators can choose the base
OS that fits their security and operations model.

| Variant | Containerfile | Runtime base | Notes |
| --- | --- | --- | --- |
| `wolfi` | `containers/Containerfile.wolfi` | `cgr.dev/chainguard/wolfi-base:latest` | Recommended minimal security-focused runtime. |
| `alpine` | `containers/Containerfile.alpine` | `alpine:3.23` | Small musl-based runtime with broad availability. |
| `suse-micro` | `containers/Containerfile.suse-micro` | `registry.suse.com/suse/sl-micro/6.2/base-os-container:latest` | SUSE Micro runtime base aligned with Leap Micro-style deployments. |
| `debian` | `containers/Containerfile.debian` | `debian:trixie-slim` | Conservative glibc runtime for broad compatibility. |

The root `Containerfile` remains the Debian default for simple local builds.
New packaging and publishing work should use the explicit variant files under
`containers/`.

The Alpine, Wolfi, and SUSE Micro variants build with the official Rust
`1.96.0-alpine3.23` image to keep a musl-linked release binary portable across
small runtime bases. The Debian variant builds with the official Rust
`1.96.0-bookworm` image and runs on `debian:trixie-slim`.

The builder installs `cmake` for native TLS/compression transitives that may
compile C code. The runtime runs as UID/GID `65532` and owns only:

- `/etc/fluxheim`
- `/var/lib/fluxheim`
- `/var/cache/fluxheim`
- `/srv/fluxheim`

This default works under both rootless and rootful container engines. Running a
rootful engine does not require running Fluxheim as root inside the container.

Operators who intentionally want a root runtime image can build one by setting
the runtime UID/GID to `0`. This is supported, but not the recommended default:

```bash
podman build \
  --build-arg FLUXHEIM_RUNTIME_UID=0 \
  --build-arg FLUXHEIM_RUNTIME_GID=0 \
  -t fluxheim:wolfi-root \
  -f containers/Containerfile.wolfi .
```

You can also override the user at runtime with the container engine's `--user`
flag. Prefer a non-root runtime unless a deployment explicitly needs root-owned
filesystem writes or low-port binding inside the container.

Build the default Debian image:

```bash
podman build -t fluxheim:dev -f Containerfile .
```

By default, the bundled Containerfiles compile the full production image
profile:

```text
profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
```

That default image includes proxying, static serving, cache, load balancing,
gzip/Zstandard/Brotli compression codecs, rustls TLS, managed ACME, Prometheus
metrics, and OpenTelemetry export support.
Published releases also build smaller focused profiles:

- `cache`: `profile-cache-edge,acme-client`
- `proxy`: `profile-proxy-edge,acme-client`
- `php`: `profile-web-server,php-fpm,acme-client`
- `load-balancer`: `profile-load-balancer-edge,acme-client`

These focused profiles use TLS/ACME as shared ingress capabilities. The
`cache` image is TLS-capable and omits local static web serving. The `proxy`
image is TLS-capable and omits cache and static web serving. The `php` image is
TLS-capable, includes static web serving and PHP-FPM support, and omits cache
and proxy-edge extras. Starting with `1.3.7`, the recommended Wolfi `php` image
also installs `php-8.5-fpm` and uses
[packaging/container/php-managed.toml](../packaging/container/php-managed.toml)
so `mode = "managed"` works out of the box for content mounted under
`/srv/fluxheim`. The non-Wolfi PHP image variants keep the external php-fpm
container config unless their runtime packages are customized. The
`load-balancer` image is TLS-capable and omits cache and static web serving.
Starting with the `1.5` load-balancer line, it is part of the normal focused
release image set. The
focused images still reuse the shared proxy runtime internally until lower-level
serving internals are split further. Override `FLUXHEIM_FEATURES` only when you
intentionally want a custom image.

Release images remain tag-driven. When a development container is useful,
manually trigger the Quay-only development image build:

```bash
scripts/publish_dev_image.py --watch
```

That workflow publishes `quay.io/<namespace>/<repository>:dev-wolfi` plus an
immutable `dev-<short-sha>-wolfi` tag from `main`. The development image is
intentionally not mirrored to GHCR or Docker Hub, and it does not publish from
pull requests, so registry secrets are not exposed to forked PR builds.

Build a specific runtime variant:

```bash
podman build -t fluxheim:wolfi -f containers/Containerfile.wolfi .
podman build -t fluxheim:alpine -f containers/Containerfile.alpine .
podman build -t fluxheim:suse-micro -f containers/Containerfile.suse-micro .
podman build -t fluxheim:debian -f containers/Containerfile.debian .
```

Build the cache-focused profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-cache-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/cache.toml \
  -t fluxheim:cache-wolfi \
  -f containers/Containerfile.wolfi .
```

Build the proxy-focused profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-proxy-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/proxy.toml \
  -t fluxheim:proxy-wolfi \
  -f containers/Containerfile.wolfi .
```

Build a PHP-FPM-enabled web profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
  --build-arg FLUXHEIM_CONFIG=examples/php-fpm.toml \
  -t fluxheim:php-fpm-wolfi \
  -f containers/Containerfile.wolfi .
```

Build the self-contained managed PHP-FPM Wolfi profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/php-managed.toml \
  --build-arg FLUXHEIM_RUNTIME_PACKAGES=php-8.5-fpm \
  -t fluxheim:php-wolfi \
  -f containers/Containerfile.wolfi .
```

The matching smoke test builds that image when needed and verifies `/index.php`
is executed through Fluxheim-managed php-fpm:

```bash
scripts/smoke_fluxheim_php_wolfi.sh
```

Build the development Wolfi profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-development \
  --build-arg FLUXHEIM_CONFIG=packaging/container/fluxheim.toml \
  -t fluxheim:dev-wolfi \
  -f containers/Containerfile.wolfi .
```

Build the load-balancer profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-load-balancer-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/load-balancer.toml \
  -t fluxheim:load-balancer-wolfi \
  -f containers/Containerfile.wolfi .
```

Build a smaller proxy-only binary:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=proxy \
  -t fluxheim:proxy \
  -f containers/Containerfile.wolfi .
```

Build a zero-retention privacy image. The smoke script automatically uses
`examples/privacy.toml` for `profile-privacy`, but explicit builds should pass
the matching config:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-privacy \
  --build-arg FLUXHEIM_CONFIG=examples/privacy.toml \
  -t fluxheim:privacy \
  -f containers/Containerfile.wolfi .
```

Validate the bundled example config:

```bash
podman run --rm fluxheim:dev --check-config --config /etc/fluxheim/fluxheim.toml
```

Run the complete local smoke:

```bash
scripts/podman_smoke.sh
```

The smoke script builds the image, validates the packaged config, and confirms
the runtime user is `65532`.

Run the focused load-balancer image as a real container and verify
round-robin plus header persistence through two local origins:

```bash
scripts/smoke_load_balancer_container.sh
```

This smoke builds the `profile-load-balancer-edge,acme-client` image by
default, starts Fluxheim with host networking, verifies HTTP active health
checks plus round-robin/header persistence, and fails if the
load-balancer-edge dependency tree or the `fluxheim-load-balancer` crate
dependency tree contains any Pingora crate.

Run every runtime variant smoke:

```bash
scripts/podman_smoke_variants.sh
```

Limit the variant smoke while iterating:

```bash
FLUXHEIM_CONTAINER_VARIANTS="wolfi alpine" scripts/podman_smoke_variants.sh
```

Smoke a root-runtime build:

```bash
FLUXHEIM_CONTAINER_VARIANTS=wolfi \
FLUXHEIM_RUNTIME_UID=0 \
FLUXHEIM_RUNTIME_GID=0 \
FLUXHEIM_EXPECTED_UID=0 \
scripts/podman_smoke_variants.sh
```

## FreeBSD

Fluxheim's published OCI images are Linux containers. They are not FreeBSD jail
images and should not be expected to run natively on a FreeBSD kernel without a
Linux VM or compatible Linux-container runtime layer.

FreeBSD support should be treated as a native build target instead:

```bash
cargo build --release
```

Native FreeBSD packaging should be documented separately after it is tested on a
FreeBSD host. The expected path is a normal Fluxheim binary plus an rc.d service
or jail deployment, not the Linux container images above.

Cross-compiling from Linux to FreeBSD may be possible later, but it needs its
own CI job because native TLS/compression dependencies can require
platform-specific toolchains and libraries.

## Publishing Images

The `Container Images` GitHub workflow builds the four variant Containerfiles
and pushes tags to:

- `ghcr.io/<owner>/fluxheim`
- `docker.io/<owner>/fluxheim`, when Docker Hub secrets are configured
- `quay.io/<namespace>/<repository>`, when Quay secrets are configured

Optional Docker Hub repository secrets:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

Optional Quay repository secrets and variables:

- `QUAY_USERNAME`
- `QUAY_TOKEN`
- `QUAY_NAMESPACE`
- `QUAY_REPOSITORY`

The workflow publishes OS-variant tags for the full/default image profile:

- `v1.6.36-wolfi`, `v1.6.36-alpine`, `v1.6.36-suse-micro`, `v1.6.36-debian`
- `sha-<short-sha>-wolfi`, `sha-<short-sha>-alpine`, etc.
- `latest-wolfi`, `latest-alpine`, etc. when run from the default branch

For the recommended Wolfi runtime, the full/default profile also gets short
aliases:

- `v1.6.36`
- `v1.6.36-base`
- `latest`
- `latest-base`

The `-base` aliases are kept for compatibility with earlier release notes and
automation. They point at the full/default image profile.

The focused image profiles publish tags with a profile segment:

- `v1.6.36-cache-wolfi`, `v1.6.36-cache-alpine`,
  `v1.6.36-cache-suse-micro`, `v1.6.36-cache-debian`
- `v1.6.36-proxy-wolfi`, `v1.6.36-proxy-alpine`,
  `v1.6.36-proxy-suse-micro`, `v1.6.36-proxy-debian`
- `v1.6.36-load-balancer-wolfi`, `v1.6.36-load-balancer-alpine`,
  `v1.6.36-load-balancer-suse-micro`, `v1.6.36-load-balancer-debian`
- `v1.6.36-php-wolfi`, `v1.6.36-php-alpine`,
  `v1.6.36-php-suse-micro`, `v1.6.36-php-debian`
- `sha-<short-sha>-cache-wolfi`, `sha-<short-sha>-proxy-wolfi`,
  `sha-<short-sha>-load-balancer-wolfi`, `sha-<short-sha>-php-wolfi`, etc.
- `latest-cache-wolfi`, `latest-proxy-wolfi`,
  `latest-load-balancer-wolfi`, `latest-php-wolfi`, etc. when run from the
  default branch
- Wolfi short aliases: `v1.6.36-cache`, `v1.6.36-proxy`,
  `v1.6.36-load-balancer`, `v1.6.36-php`, `latest-cache`, `latest-proxy`,
  `latest-load-balancer`, and `latest-php`

Starting with `v1.5.0`, the load-balancer image profile is part of normal tag
publishing. For older tags or development branches, it can still be included in
manual workflow runs by setting `include_load_balancer=true`.

The workflow defaults to `linux/amd64`. Use manual dispatch to test additional
platforms, for example `linux/amd64,linux/arm64`, once every selected runtime
base has been verified for those architectures.

Manual workflow inputs also allow `runtime_uid`, `runtime_gid`, and a temporary
feature override. Keep both IDs at `65532` for normal images. Use `0` only for
a deliberate root-runtime image. Leave the feature override empty for normal
release profile builds.

## Config Tester Release Asset

`1.3.2` adds a separate `fluxheim-config-tester` binary target for diagnosing
configs outside the runtime container. It is intended for cases where a Podman
or systemd deployment cannot start and the operator still needs Fluxheim's real
config parser, feature/profile checks, TLS storage checks, ACME target preview,
and upstream DNS checks.

The tester is built as a release asset and is not installed into normal RPMs or
runtime images by default.

Example:

```bash
fluxheim-config-tester \
  --config /etc/fluxheim/fluxheim.toml \
  --profile proxy \
  --check-tls-storage \
  --acme-targets \
  --resolve-upstreams \
  --runtime-cutover \
  --explain
```

Use `--profile full`, `--profile cache`, `--profile proxy`, or
`--profile web-php` to match the release artifact or image profile you plan to
run. Add `--no-runtime-paths` when you only need syntax, semantic, and profile
validation without touching runtime paths. During the `1.6.x` Pingora-exit
line, `--runtime-cutover` prints the active runtime adapter and stable blocker
keys for configs that still require compatibility glue.
validation from outside the gateway container and do not have access to the
service runtime mount such as `/run/fluxheim`. Leave that flag off when you
want the tester to inspect `server.process.pid_file`, upgrade socket, and
certificate reload socket paths as part of a deployment preflight.

Runtime images and RPMs do include `fluxheim-acme`, which is the ACME companion
entry point for service-manager or container-scheduled renewal workflows:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml targets
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
```

For live activation after renewal, the running gateway and companion need the
same writable `/run/fluxheim` mount so `fluxheim-acme` can reach
`server.process.certificate_reload_sock`.

## Volume Mapping

Fluxheim containers use a small set of stable paths. Mount host directories to
these paths instead of writing inside the image layer.

| Container path | Purpose | Mount mode |
| --- | --- | --- |
| `/etc/fluxheim/fluxheim.toml` | Main config file. | `ro,Z` |
| `/etc/fluxheim/conf.d` | Optional config directory. | `ro,Z` |
| `/etc/fluxheim/tls` | Static certificate chains and private keys. | `ro,Z` |
| `/run/fluxheim` | Process runtime files such as PID files, upgrade sockets, and the certificate reload socket. | `Z,U` |
| `/var/lib/fluxheim` | Runtime state: ACME storage and future snapshots. | `Z,U` |
| `/var/cache/fluxheim` | Disk cache root. | `Z,U` |
| `/srv/fluxheim` | Default static content root if you want one shared root. | `ro,Z` |
| `/srv/sites/<site>` | Per-site static roots referenced by vhosts. | `ro,Z` |
| `/var/log/fluxheim` | Optional file logs when `[logging.file]` is enabled. | `Z,U` |

For Podman on SELinux hosts, `:Z` gives the bind mount a private container
label. Add `:U` only for writable paths when you want Podman to adjust ownership
for user namespaces. Read-only paths normally use `:ro,Z`, not `:U`.

The default image user is `65532:65532`, so writable host directories should be
owned or mapped for that user. With rootless Podman, `:U` is often the easiest
safe option for cache/state/log directories.

Example host layout:

```text
/srv/infra/fluxheim/
  config/fluxheim.toml
  config/conf.d/
  tls/
  logs/
  state/
  cache/
/srv/sites/example/public/
/srv/sites/app/public/
```

Matching config paths:

```toml
[server]
listen = ["0.0.0.0:8080"]
tls_listen = ["0.0.0.0:8443"]
default_vhost = "example"

[logging.file]
enabled = true
path = "/var/log/fluxheim/fluxheim.log"

[tls]
enabled = true
backend = "rustls"

[[tls.certificates]]
cert_path = "/etc/fluxheim/tls/fullchain.pem"
key_path = "/etc/fluxheim/tls/key.pem"

[cache.disk]
enabled = true
path = "/var/cache/fluxheim"
max_size_bytes = "10GiB"

[[vhosts]]
name = "example"
hosts = ["example.test"]

[vhosts.web]
root = "/srv/sites/example/public"
```

For multi-site setups, prefer `/etc/fluxheim/conf.d/` with one vhost per file.
`[[vhosts]]` starts a vhost, and each following `[vhosts.*]` table belongs to
that vhost until the next `[[vhosts]]`.
The packaged `/etc/fluxheim/fluxheim.toml` sets `include_conf_d = true`, so it
also loads visible `*.toml` files from `/etc/fluxheim/conf.d/` after the main
file. When Fluxheim starts from `/etc/fluxheim`, it loads top-level TOML files
first and then `/etc/fluxheim/conf.d/*.toml`.

Podman run example:

```bash
podman run --rm \
  --name fluxheim \
  --network gateway_net \
  --stop-signal SIGTERM \
  --stop-timeout 15 \
  -p 80:8080 \
  -p 443:8443 \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/tls:/etc/fluxheim/tls:ro,Z \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/sites/example/public:/srv/sites/example/public:ro,Z \
  ghcr.io/valkyoth/fluxheim:latest-wolfi
```

Compose example:

```yaml
name: gateway

networks:
  gateway_net:
    external: true

services:
  fluxheim:
    image: ghcr.io/valkyoth/fluxheim:latest-wolfi
    container_name: fluxheim_gateway
    restart: always
    stop_signal: SIGTERM
    stop_grace_period: 15s
    ports:
      - "80:8080"
      - "443:8443"
    volumes:
      - /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z
      - /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z
      - /srv/infra/fluxheim/tls:/etc/fluxheim/tls:ro,Z
      - /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U
      - /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U
      - /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U
      - /srv/sites/example/public:/srv/sites/example/public:ro,Z
      - /srv/sites/app/public:/srv/sites/app/public:ro,Z
    networks:
      - gateway_net
```

For managed ACME in containers, use the same bind mounts for the gateway and
the one-shot renewal container. A complete example with an external
`fluxheim-acme` service is available at
[examples/podman-compose-acme.yml](../examples/podman-compose-acme.yml).
Start the gateway first, then run due-only renewal with:

```bash
podman compose -f examples/podman-compose-acme.yml up -d fluxheim
podman compose -f examples/podman-compose-acme.yml run --rm fluxheim-acme
```

Keep `tls.acme.automation = "external"` in this mode so the long-running
gateway does not also run the background renewal loop.

### Container ACME First Issuance

For HTTP-01 ACME, the CA must be able to reach Fluxheim on public port `80`.
During first issuance, run Fluxheim with the HTTP listener enabled. Modern
rustls-based builds can also keep `server.tls_listen` enabled while
Fluxheim-managed ACME certificate files are missing; those certificates are
treated as pending until issuance succeeds. Keep `[server.https_redirect]`
disabled until the public HTTP-01 challenge path works, otherwise ordinary
browser traffic may be redirected to HTTPS before a certificate is available.

Example container main config shape for first issuance:

```toml
include_conf_d = true

[server]
listen = ["0.0.0.0:8080"]
# Optional during first issuance on reloadable SNI TLS backends:
tls_listen = ["0.0.0.0:8443"]
default_vhost = "example.com"

[server.https_redirect]
enabled = false
status = 308

[tls]
enabled = true
backend = "rustls"

[tls.acme]
enabled = true
storage = "/var/lib/fluxheim/acme"
contact_email = "admin@example.com"
default_issuer = "actalis"
challenge = "http-01"

[[tls.acme.issuers]]
name = "actalis"
directory_url = "https://acme-api.actalis.com/acme/directory"

[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

For container secret files, mount the files read-only. If the host tree is
already labeled with `container_file_t`, do not add a `:Z` relabel suffix to
individual secret-file mounts:

```bash
-v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro
-v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro
```

Validate the mounted config directly with `podman run --rm`. This avoids
compose-provider differences around one-shot commands:

```bash
podman run --rm \
  --name fluxheim_validate \
  --network gateway_net \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/run:/run/fluxheim:Z,U \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/infra/fluxheim/html:/srv/fluxheim:ro,Z \
  -v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro \
  -v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro \
  ghcr.io/valkyoth/fluxheim:latest-wolfi \
  --config /etc/fluxheim/fluxheim.toml \
  --validate-config
```

Then start Fluxheim, replacing any existing gateway on the published ports. If
you kept `server.tls_listen` enabled, also publish `443:8443`; otherwise publish
only `80:8080` for the first issuance step:

```bash
podman run -d \
  --name fluxheim_gateway \
  --network gateway_net \
  --restart always \
  -p 80:8080 \
  -p 443:8443 \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/run:/run/fluxheim:Z,U \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/infra/fluxheim/html:/srv/fluxheim:ro,Z \
  -v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro \
  -v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro \
  ghcr.io/valkyoth/fluxheim:latest-wolfi \
  --config /etc/fluxheim/fluxheim.toml
```

Run due-only renewal from a second container. Missing certificate files are due
targets, so first issuance does not require `--force-renew`:

```bash
podman run --rm \
  --name fluxheim_acme_due \
  --network gateway_net \
  --entrypoint /usr/local/bin/fluxheim-acme \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/run:/run/fluxheim:Z,U \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/infra/fluxheim/html:/srv/fluxheim:ro,Z \
  -v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro \
  -v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro \
  ghcr.io/valkyoth/fluxheim:latest-wolfi \
  --config /etc/fluxheim/fluxheim.toml \
  renew --vhost example.com
```

If you kept `server.tls_listen` disabled for the first run, enable HTTPS in the
main config after every configured ACME target has renewed:

```toml
[server]
listen = ["0.0.0.0:8080"]
tls_listen = ["0.0.0.0:8443"]

[server.https_redirect]
enabled = true
status = 308
```

Recreate the gateway with both published ports and verify SNI:

```bash
podman rm -f fluxheim_gateway
podman compose -f gateway-fluxheim.yml up -d

openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

Optional mounted error pages should use a path whose parent already exists in
the runtime image, such as `/var/lib/fluxheim/errors`. Avoid nested mountpoints
below read-only image paths such as `/srv/fluxheim/errors`.

The same deployment shape is available as
[examples/podman-compose.yml](../examples/podman-compose.yml), with a matching
container-oriented config at
[examples/container/fluxheim.toml](../examples/container/fluxheim.toml).
For upstream containers on the same Podman network, use the service/container
DNS name and port, for example:

```toml
[vhosts.proxy]
upstreams = ["app-backend:3000"]
upstream_tls = false
```

For services running on the host, use Podman's host gateway name when available:

```toml
[vhosts.proxy]
upstreams = ["host.containers.internal:6010"]
upstream_tls = false
```

Fluxheim resolves direct proxy upstream names when selecting an upstream peer
for a request. If a Podman DNS name is temporarily missing, Fluxheim returns an
upstream failure for that request instead of panicking the worker. Keep Fluxheim
and its upstream containers on the same user-defined network, and avoid using
load-balancer pools for container names that are expected to appear only after
Fluxheim has already started until dynamic pool re-resolution is promoted to a
stable feature.

The container config sets `grace_period_seconds = 2` and
`graceful_shutdown_timeout_seconds = 5`; keep the Podman stop timeout higher
than the sum of those values so normal shutdown does not fall back to `SIGKILL`.

Published images default to the rootless-friendly
[packaging/container/fluxheim.toml](../packaging/container/fluxheim.toml) and a
self-contained default page at
[packaging/default/index.html](../packaging/default/index.html), installed in
the image as `/srv/fluxheim/index.html`. Mount your own config or static root
over those paths when deploying a real site.

If using a root-runtime image, `:U` is usually not needed for ownership, but
keeping separate writable directories for state/cache/logs is still recommended
so the container does not need write access to static site content or TLS keys.

## Native systemd

For manually compiled binaries or RPM-style native installs, Fluxheim ships a
systemd unit, sysusers file, tmpfiles file, and optional environment file under
`packaging/systemd` and `packaging/rpm`. See
[systemd Deployment](systemd.md) for the install steps and default paths.
Native packages use [packaging/default/fluxheim.toml](../packaging/default/fluxheim.toml),
which listens on port `80` by default; the bundled systemd unit grants only
`CAP_NET_BIND_SERVICE` so the service can bind `80/443` while still running as
the unprivileged `fluxheim` user.

For local binary RPM smoke builds, use the containerized helper:

```bash
scripts/build_fluxheim_rpm.py 1.4.5 --target opensuse-tumbleweed
scripts/build_fluxheim_rpm.py 1.4.5 native --target fedora-44
```

Untagged `latest` builds use the package name `fluxheim-unstable` and a date
version so they are clearly separated from stable release packages:

```bash
scripts/build_fluxheim_rpm.py latest native --target opensuse-tumbleweed
scripts/build_fluxheim_rpm.py latest native --target opensuse-tumbleweed --rpm-release 2
```

Those commands produce names shaped like
`fluxheim-unstable-20260508-1.native.x86_64.rpm` and
`fluxheim-unstable-20260508-2.native.x86_64.rpm`. The unstable package
conflicts with the stable `fluxheim` package because both install the same
binary, service, config, and content paths.

This helper is intended for installation testing on RPM-based hosts. The
release-grade RPM source of truth remains `packaging/rpm/fluxheim.spec`.

## Codex And Rootless Podman

When running Codex in a sandbox, include the rootless Podman runtime directories
as writable roots and point Podman at the user socket:

```bash
CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
codex resume <session-id> \
  -a on-request \
  -s workspace-write \
  --add-dir "$XDG_RUNTIME_DIR/podman" \
  --add-dir "$XDG_RUNTIME_DIR/libpod" \
  --add-dir "$XDG_RUNTIME_DIR/containers" \
  -c 'sandbox_workspace_write.network_access=true'
```

Official Podman documentation describes the rootless API socket default as
`unix://$XDG_RUNTIME_DIR/podman/podman.sock`, and `CONTAINER_HOST` has precedence
over configured service destinations for Podman remote connections.

Run rootless on an unprivileged port:

```bash
podman run --rm \
  --name fluxheim \
  -p 8080:8080 \
  -v ./examples/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  fluxheim:dev
```

For TLS, mount certificate files read-only and keep private keys owner-only on
the host. Use the storage check before starting:

```bash
podman run --rm \
  -v ./fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v ./tls:/etc/fluxheim/tls:ro,Z \
  fluxheim:dev \
  --config /etc/fluxheim/fluxheim.toml --check-tls-storage
```

Privileged ports such as `80` and `443` require host-level setup for rootless
containers. Prefer host port forwarding to container ports `8080` and `8443`
unless the deployment environment already grants low-port binding safely.
