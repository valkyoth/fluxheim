# Build And Rootless Podman

For a first installation, start with [package selection and minimal recipes](installation.md).
This longer guide covers custom builds, base variants and persistent mounts.
Cargo aliases are not published package names: consult the compiled-capability
matrix before sharing one configuration across focused images.

Use the checked-in `rust-toolchain.toml`, `Cargo.lock` and Containerfile digest
pins from the same revision. `Cargo.toml` also records the minimum Rust version;
a sufficiently new compiler is not automatically the exact qualified toolchain.

The current development tree reports **1.9.0 (unreleased)**. Published
`v1.8.3` is the stable baseline. The `v1.9.0` tag and release artifacts do
not exist yet; building `main` does not imply HTTP/3 support is ready.

## Local Builds

Run from the repository root. A normal source build uses the target's baseline
CPU settings; host-specific optimization is a separate, optional choice:

```bash
cargo build --locked --release
RUSTFLAGS="-C target-cpu=native" cargo build --locked --release
```

Use `target-cpu=native` only when every deployment CPU supports the instructions
selected on the build host. A family name alone is not a compatibility check.
For portable release artifacts, omit the flag. Binaries appear under
`target/release/`; Cargo does not install them or create a running service.
Use `--bin fluxheim` when you only need the server executable.
The cross-platform profile and archive contract is documented in
[Portable Releases](portable-releases.md).

Native Windows x86_64 release-builder automation is available.
Linux cross-builds do not stand in for the Windows MSVC
SDK, ACL, locking, or live-runtime gates. See
[Windows Release Builders](windows-release-builders.md).

Feature-reduced builds keep the binary small and reduce dependency surface:

```bash
cargo build --locked --release --no-default-features --features proxy
cargo build --locked --release --no-default-features --features proxy,load-balancer
cargo build --locked --release --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --locked --release --no-default-features --features profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --locked --release --no-default-features --features profile-cache-edge,acme-client
cargo build --locked --release --no-default-features --features profile-proxy-edge,acme-client
cargo build --locked --release --no-default-features --features profile-web-server,php-fpm,acme-client
```

The default build enables `proxy`, `web`, `cache`, `tls-rustls`, and
`security`. Cargo does not have a separate `--group` flag, so Fluxheim exposes
grouped build profiles as normal feature aliases such as `profile-core`,
`profile-static-site`, `profile-reverse-proxy`, `profile-cache-server`,
`profile-load-balancer`, `profile-observability`, and `profile-privacy`.
Focused profile aliases include `profile-full`,
`profile-web-server`, `profile-cache-edge`, `profile-proxy-edge`,
`profile-load-balancer-edge`, `profile-wasm`, `profile-fips-openssl`, and
`profile-iso19790-openssl`, `profile-fips-rustls` and
`profile-iso19790-rustls`. FIPS aliases select candidate provider integrations,
not certification of the resulting application.
`profile-development` combines `profile-full` with PHP-FPM, ACME, Prometheus,
OTLP metrics and OTel tracing. It is not an all-features build: Wasm and beta
UDP are not included. Avoid `--all-features` for application builds because
some features deliberately conflict.

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
cargo build --locked --release --no-default-features --features profile-fips-openssl
cargo build --locked --release --no-default-features --features profile-iso19790-openssl
target/release/fluxheim crypto
```

For rustls/AWS-LC FIPS candidate testing, build with `tls-rustls-fips` or a
matching profile and configure `[tls] backend = "rustls"` plus `[tls.fips]
required = true` or `[tls.iso19790] required = true`. This path builds
`aws-lc-fips-sys`, so the build host needs CMake, Go, and a C compiler:

```bash
cargo build --locked --release --no-default-features --features profile-fips-rustls
cargo build --locked --release --no-default-features --features profile-iso19790-rustls
scripts/validate-fips-rustls.sh check
```

For provider qualification, build the exact proof binaries
inside pinned UBI environments and exercise real downstream and upstream TLS:

```bash
scripts/smoke_fips_backend_images.sh all
# or: scripts/smoke_fips_backend_images.sh openssl
# or: scripts/smoke_fips_backend_images.sh rustls
```

These are CI/deep-gate proof images, not release images and not a FIPS
certification claim. They retain compiler, package, dependency, provider, and
binary-hash evidence inside each image. See [FIPS-Capable Deployments](fips.md)
for the exact boundary and operator responsibilities.

Use an AWS-LC-supported FIPS builder for
`scripts/validate-fips-rustls.sh release`. Rolling distribution compilers can be
ahead of AWS-LC FIPS support; newer GCC/Clang families may fail inside
`aws-lc-fips-sys` before Fluxheim code is compiled. The helper fails early for
known newer compiler families. If available, it automatically selects a
matching GCC 13, 12, or 11 `gcc`/`g++` pair; an explicit `CC` remains
authoritative. The investigation-only override is documented in
[FIPS-Capable Deployments](fips.md).

The FIPS/ISO profile aliases are narrow proof profiles, not a limitation of the
FIPS features. For custom cache or PHP-FPM builds, select raw modules so that
the binary has exactly one TLS backend:

```bash
# FIPS/ISO-capable cache edge
cargo build --locked --release --no-default-features \
  --features proxy,cache,security,tls-openssl-fips

# FIPS/ISO-capable PHP-FPM web build
cargo build --locked --release --no-default-features \
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

In required mode, the OpenSSL integration fails closed, loads the OpenSSL FIPS
provider and enables default FIPS properties for the process. Its standalone
diagnostic probe reports availability without activating those properties.
The rustls/AWS-LC candidate installs or
passes the rustls FIPS provider and checks rustls' FIPS indicators for required
configs. Either deployment still needs the selected module's CMVP certificate,
Security Policy, provider/build configuration, and platform evidence. See
[FIPS-Capable Deployments](fips.md).

Required mode also restricts non-TLS paths. Provider-backed admin authentication
is supported; managed ACME and local cache encryption are rejected. OpenBao,
OTLP, auth-request and mirroring permit only the documented numeric-loopback HTTP
boundary. External evidence does not override a configuration rejection. Review
the exact supported operations and deployment limitations in the FIPS guide.

PHP support is selected with `php-fpm`. It is never compiled by default;
build it explicitly with `profile-web-server,php-fpm` when Fluxheim should
serve PHP applications through php-fpm.

See [Feature Matrix](../reference/features.md) for the complete feature/profile list.

Fluxheim's production RPM intentionally compiles
`profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp` for the
current production line. That keeps the normal packaged binary broad while the
container and tarball release assets also provide focused cache/proxy builds.
Custom source builds can still omit `acme-client`, load-balancer, cache, web,
or observability features when they are not needed.

For package scripts or custom CI that accept feature strings, run the feature
preflight before invoking Cargo:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

Preflight is an additional policy check, not a complete expansion of Cargo's
feature graph or a substitute for compilation. Always build the exact selection
and validate the actual deployment config with that binary. Enabling a Cargo
feature does not install an external daemon, provision a certificate, or make
every enabled module active in configuration.

## System Build Dependencies

The default feature set uses the Fluxheim-owned native runtime with rustls,
cache support and static file serving; normal profiles do not compile Pingora
crates. Linux source builds
need a normal C/C++ toolchain plus a few build helpers for transitive native
code.

Required for the default build:

- Rust selected by `rust-toolchain.toml`, normally installed through `rustup`;
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

These package commands prepare Linux build dependencies, not Rust itself or
platform support. Windows needs MSVC/SDK tooling; macOS needs its native toolchain.
Follow [portable builds](portable-releases.md) for those platforms.
Containerfiles install build tools in the builder stage. Runtime packages depend
on the variant and profile; PHP images additionally need PHP-FPM and its modules.

## Container Variants

Fluxheim ships multiple runtime Containerfiles so operators can choose the base
OS that fits their security and operations model.

| Variant | Containerfile | Runtime base | Notes |
| --- | --- | --- | --- |
| `wolfi` | `containers/Containerfile.wolfi` | `cgr.dev/chainguard/wolfi-base:latest` | Recommended minimal security-focused runtime. |
| `alpine` | `containers/Containerfile.alpine` | `alpine:3.23` | Small musl-based runtime with broad availability. |
| `suse-micro` | `containers/Containerfile.suse-micro` | `registry.suse.com/suse/sl-micro/6.2/base-os-container:latest` | SUSE Micro runtime base aligned with Leap Micro-style deployments. |
| `debian` | `containers/Containerfile.debian` | `debian:trixie-slim` | Conservative glibc runtime for broad compatibility. |
| `suse-bci` | `containers/Containerfile.suse-bci` | `registry.suse.com/bci/php:8` | PHP-only SUSE variant with the official BCI PHP repository and managed PHP-FPM. |

The table shows tag names for readability; the actual Containerfiles pin both
builder and runtime images by digest. Rebuilding an unchanged digest pin does
not automatically fetch a newer base just because its tag says `latest`.
See [runtime refresh](container-runtime-refresh.md) for the reviewed refresh flow.

The root `Containerfile` uses `debian:bookworm-slim`, whereas the explicit Debian
variant uses `debian:trixie-slim`. They are not identical recipes. New packaging
and publishing work should use the explicit variant files under `containers/`.

The Alpine, Wolfi, SUSE Micro, and PHP-only SUSE BCI variants build with the official Rust
`1.99.1-alpine3.23` image to keep a musl-linked release binary portable across
small runtime bases. The Debian variant builds with the official Rust
`1.99.1-bookworm` image and runs on `debian:trixie-slim`.

The builder installs `cmake` for native TLS/compression transitives that may
compile C code. The runtime runs as UID/GID `65532`; the Containerfiles prepare
these application directories for that user:

- `/etc/fluxheim`
- `/run/fluxheim`
- `/var/lib/fluxheim`
- `/var/cache/fluxheim`
- `/var/log/fluxheim`
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
  -f containers/Containerfile.wolfi.
```

You can also override the user at runtime with the container engine's `--user`
flag. Prefer a non-root runtime unless a deployment explicitly needs root-owned
filesystem writes or low-port binding inside the container.

Build the default Debian image:

```bash
podman build -t fluxheim:dev -f Containerfile.
```

By default, the root Containerfile and the four general-purpose variants compile
the full production image profile. The PHP-only SUSE BCI recipe is the exception;
it defaults to `profile-web-server,php-fpm,acme-client`:

```text
profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
```

That default image includes proxying, static serving, cache, load balancing,
gzip/Zstandard/Brotli compression codecs, rustls TLS, managed ACME, Prometheus
metrics, and OpenTelemetry export support.
Published releases also build smaller focused profiles:

- `wasm`: `profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp`
- `cache`: `profile-cache-edge,acme-client`
- `proxy`: `profile-proxy-edge,acme-client`
- `php`: `profile-web-server,php-fpm,acme-client`
- `load-balancer`: `profile-load-balancer-edge,acme-client`

The `wasm` image is the full production server plus the reviewed Wasm
proxy-ABI and WASI capability surfaces. The unsuffixed `full` image
intentionally excludes Wasm. The image contains no operator plugin modules;
mount them read-only and point `wasm.plugin_roots` at the mounted path:

```yaml
volumes:
  - /srv/infra/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z
```

Keep logs on their normal writable mount, for example
`/srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U`; a log mount does not make
plugins available. See [Wasm Extensibility](wasm-extensibility.md) for
hash-pinning, bind-mount threat boundaries, and the recommended derivative
image model for high-assurance deployments. A `:ro` mount prevents container
writes but does not prevent a host administrator from replacing its source.

Run the dedicated image proof with:

```bash
scripts/test_starter.py --run wasm-container
```

The smoke builds the Wolfi Wasm profile, mounts a hash-pinned policy module at
the documented path, verifies the mount rejects writes inside the container,
and exercises live allow and deny requests. Include it in local release checks
with:

```bash
FLUXHEIM_RELEASE_PODMAN=1 \
FLUXHEIM_RELEASE_WASM_CONTAINER=1 \
scripts/release_checks.sh
```

These focused profiles use TLS/ACME as shared ingress capabilities. The
`cache` image is TLS-capable and omits local static web serving. The `proxy`
image is TLS-capable and omits cache and static web serving. The `php` image is
TLS-capable, includes static web serving and PHP-FPM support, and omits cache
and proxy-edge extras. The Wolfi, Alpine, Debian, and SUSE BCI `php` images
install managed PHP-FPM plus the common modules listed in
[packaging/container/php-required-modules.txt](../../packaging/container/php-required-modules.txt)
and use
[packaging/container/php-managed.toml](../../packaging/container/php-managed.toml)
so `mode = "managed"` works out of the box for content mounted under
`/srv/fluxheim`. The SUSE PHP image is `php-suse-bci`; `php-suse-micro` is not
published because the minimal SUSE Micro runtime has no matching enabled PHP
package repository. The
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

That workflow publishes `quay.io/<namespace>/<repository>:dev-wolfi` plus a
commit-labelled `dev-<short-sha>-wolfi` tag from `main`. Tags are still mutable;
record the image digest when selecting an exact artifact. The development image is
intentionally not mirrored to GHCR or Docker Hub, and it does not publish from
pull requests, so registry secrets are not exposed to forked PR builds.

Build a specific runtime variant:

```bash
podman build -t fluxheim:wolfi -f containers/Containerfile.wolfi.
podman build -t fluxheim:alpine -f containers/Containerfile.alpine.
podman build -t fluxheim:suse-micro -f containers/Containerfile.suse-micro.
podman build -t fluxheim:debian -f containers/Containerfile.debian.
```

Build the cache-focused profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-cache-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/cache.toml \
  -t fluxheim:cache-wolfi \
  -f containers/Containerfile.wolfi.
```

Build the proxy-focused profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-proxy-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/proxy.toml \
  -t fluxheim:proxy-wolfi \
  -f containers/Containerfile.wolfi.
```

Build an external-PHP-FPM web profile locally (this does not install PHP-FPM):

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/php.toml \
  -t fluxheim:php-fpm-wolfi \
  -f containers/Containerfile.wolfi.
```

This config is a deployment template: replace the example domain and issuer
policy, provide content and a reachable external FastCGI service, and validate
before startup. Container loopback is not the host or another container. Use
[PHP deployment](php.md) for shared document roots and upstream permissions.

Build the self-contained managed PHP-FPM Wolfi profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/php-managed.toml \
  --build-arg FLUXHEIM_RUNTIME_PACKAGES="$(paste -sd ' ' packaging/container/php-wolfi-runtime-packages.txt)" \
  -t fluxheim:php-wolfi \
  -f containers/Containerfile.wolfi.
```

The managed PHP image smoke builds Wolfi, Alpine, Debian, and SUSE BCI images,
rejects extension-load warnings, verifies the common module contract, and
executes `/index.php` through Fluxheim-managed PHP-FPM in each image:

```bash
scripts/smoke_fluxheim_php_images.sh
```

Build the development Wolfi profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-development \
  --build-arg FLUXHEIM_CONFIG=packaging/container/fluxheim.toml \
  -t fluxheim:dev-wolfi \
  -f containers/Containerfile.wolfi.
```

Build the load-balancer profile locally:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-load-balancer-edge,acme-client \
  --build-arg FLUXHEIM_CONFIG=packaging/container/load-balancer.toml \
  -t fluxheim:load-balancer-wolfi \
  -f containers/Containerfile.wolfi.
```

Build a smaller proxy-only binary:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=proxy \
  --build-arg FLUXHEIM_CONFIG=packaging/container/proxy.toml \
  -t fluxheim:proxy \
  -f containers/Containerfile.wolfi.
```

This reduced image has no TLS, cache or static-file support. Its sample origin
is `127.0.0.1:3000` inside the container; replace it for a real deployment.

To check the config pairing without building an image:

```bash
cargo build --locked --no-default-features --features proxy --bin fluxheim
python3 scripts/smoke_build_profiles.py
```

This checks acceptance of the matching proxy config and rejection of the full
static-serving config. It relocates container-only paths into a private local
fixture; it does not launch an origin or qualify a container deployment.

Build a privacy-mode image. The smoke script automatically uses
`examples/privacy.toml` for `profile-privacy`, but explicit builds should pass
the matching config:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=profile-privacy \
  --build-arg FLUXHEIM_CONFIG=examples/privacy.toml \
  -t fluxheim:privacy \
  -f containers/Containerfile.wolfi.
```

Validate the bundled example config:

```bash
podman run --rm --ulimit core=0:0 fluxheim:dev --check-config --config /etc/fluxheim/fluxheim.toml
```

Run the complete local smoke:

```bash
scripts/podman_smoke.sh
```

The smoke script builds the image, validates the packaged config, checks core
limits and confirms the runtime user is `65532`. It does not start an HTTP
listener or prove application behavior. Use the [live installation recipe](installation.md#minimal-container-test)
and the relevant feature smoke for that additional proof.

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

Run the four general-purpose variant build/config smokes (PHP-only SUSE BCI is
covered by the separate PHP image smoke above):

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

FreeBSD is not a qualified release target in the current archive matrix. A
native source build is experimental, not evidence of supported runtime behavior:

```bash
cargo build --locked --release
```

Native FreeBSD packaging should be documented separately after it is tested on a
FreeBSD host. The expected path is a normal Fluxheim binary plus an rc.d service
or jail deployment, not the Linux container images above.

Cross-compiling from Linux to FreeBSD may be possible later, but it needs its
own CI job because native TLS/compression dependencies can require
platform-specific toolchains and libraries.

## Publishing Images

The `Container Images` GitHub workflow builds the four general-purpose variants,
substituting SUSE BCI for SUSE Micro in the PHP profile,
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

The current [image workflow](../../.github/workflows/images.yml) has two entry
points: a pushed `v*` tag or manual dispatch. An ordinary push to `main` does
not by itself run this publishing workflow. Manual dispatch can publish images;
it is not a dry-run test button.

For an approved release tag `vX.Y.Z`, the naming contract is:

| Profile | Variant tags | Wolfi short aliases |
| --- | --- | --- |
| Full | `vX.Y.Z-wolfi`, `vX.Y.Z-alpine`, `vX.Y.Z-debian`, `vX.Y.Z-suse-micro` | `vX.Y.Z`, `vX.Y.Z-base` |
| Wasm | `vX.Y.Z-wasm-<variant>` | `vX.Y.Z-wasm` |
| Cache | `vX.Y.Z-cache-<variant>` | `vX.Y.Z-cache` |
| Proxy | `vX.Y.Z-proxy-<variant>` | `vX.Y.Z-proxy` |
| Load balancer | `vX.Y.Z-load-balancer-<variant>` | `vX.Y.Z-load-balancer` |
| PHP | `vX.Y.Z-php-wolfi`, `vX.Y.Z-php-alpine`, `vX.Y.Z-php-debian`, `vX.Y.Z-php-suse-bci` | `vX.Y.Z-php` |

Non-PHP `<variant>` values are `wolfi`, `alpine`, `debian` and
`suse-micro`. PHP substitutes `suse-bci` for `suse-micro`. The `-base`
alias is the full profile, not a reduced server. These are naming patterns,
not a claim that an unreleased version is downloadable.

Each build also gets a `sha-<12-character-commit>-<profile-and-variant>` tag
(the full profile omits its profile segment). The normal image job adds
`latest-<profile-and-variant>` and corresponding Wolfi short aliases only when
its ref name equals the default branch. A tag-triggered release therefore does
not automatically update `latest`. The separate Quay-only development job
described above has its own tags.

All of these names are mutable registry tags, including commit-labelled ones.
Use `repository@sha256:...` to select a particular image. The separate
[runtime refresh workflow](container-runtime-refresh.md) can update versioned
release aliases without changing the Fluxheim application version. It does not
rewrite `sha-*`, `dev-*` or `latest*` aliases. Preserve the tested digest and
refresh evidence instead of treating a version string as complete provenance.

Load-balancer builds are included for tag pushes. Older-tag and branch manual
dispatches may need `include_load_balancer=true`; the workflow's gate is the
source of truth. The default platform is `linux/amd64`. A custom
`linux/amd64,linux/arm64` input requests additional builds, not qualification:
each selected base, native executable and runtime still needs its tests.

Manual inputs can override the feature selection, copied config and runtime
UID/GID. Keep both IDs at `65532` and leave feature/config overrides empty for
standard profiles. Overrides do not rename profile tags to describe the changed
capabilities; use local custom-image builds for experiments rather than
overwriting standard published profile names.

Use the [release runbook](release-runbook.md), [release checklist](release-checklist.md)
and [refresh guide](container-runtime-refresh.md) for their separate gates and
publication requirements. None of the commands in this guide grants release
approval.

## Config Tester Release Asset

The separate `fluxheim-config-tester` binary target diagnoses
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

Select an appropriate tester filter, such as `--profile full`, `cache`, `proxy`
or `web-php`, but do not treat it as proof of the deployed binary's feature set.
The filters are not complete release-profile models. Validate with the actual
server binary and mounts as well.

`--no-runtime-paths` skips process runtime-path checks and runtime construction,
not every filesystem read. Configuration/include trust checks still apply, and
`--check-tls-storage` still inspects TLS storage when explicitly requested.
`--runtime-cutover` prints diagnostic rows; it is not a strict readiness gate.
See the [standalone tester guide](command-line.md#standalone-configuration-tester)
for the full option table and current boundaries.

Runtime images and RPMs do include `fluxheim-acme`, which is the ACME companion
entry point for service-manager or container-scheduled renewal workflows:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml targets
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
fluxheim-acme --config /etc/fluxheim/fluxheim.toml doctor --online
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
| `/etc/fluxheim/fluxheim.toml` | Main config file. | `ro,Z` after mapping ownership to UID `65532` |
| `/etc/fluxheim/conf.d` | Optional config directory. | `ro,Z` after mapping ownership to UID `65532` |
| `/etc/fluxheim/tls` | Static certificate chains and private keys. | `ro,Z` |
| `/run/fluxheim` | Active runtime sockets and managed PHP temporary state. PID/upgrade paths are currently inactive; see [lifecycle](service-lifecycle.md). | `Z,U` |
| `/var/lib/fluxheim` | Runtime state: configured ACME and snapshots. | `Z,U` |
| `/var/cache/fluxheim` | Disk cache root. | `Z,U` |
| `/srv/fluxheim` | Default static content root if you want one shared root. | `ro,Z` |
| `/srv/sites/<site>` | Per-site static roots referenced by vhosts. | `ro,Z` |
| `/var/log/fluxheim` | Optional file logs when `[logging.file]` is enabled. | `Z,U` |

For Podman on SELinux hosts, `:Z` gives the bind mount a private container
label. `:U` asks Podman to change source ownership for the container user
namespace. Use it for writable paths when that ownership change is intentional.
Read-only paths normally use `:ro,Z`; configuration mounts additionally require
the ownership preparation described below. `:ro,Z,U` is an available shortcut
for configuration only when changing its host ownership automatically is
acceptable.

Do not recursively change ownership on shared application/source trees merely
to make a smoke test pass. These options are for dedicated paths. The examples
using `:Z` assume one container owns the SELinux label. For gateway/renewal
containers intentionally sharing files, establish a shared labeling policy;
repeated private relabels can deny the other container access. Docker does not
support Podman's `:U` mapping shortcut.

The default image user is `65532:65532`, so writable host directories should be
owned or mapped for that user. With rootless Podman, `:U` can prepare dedicated
cache/state/log directories. It recursively changes ownership and is not a
permission repair: runtime and secret directories should be private (`0700`),
and existing private keys, token files and file logs must be `0600`. Do not make
private files group-readable to accommodate a collector; see
[file logging and rotation](logging.md).

### Rootless Config Ownership

Fluxheim validates configuration ownership and permissions before parsing any
TOML. Every config file and directory visible inside the container must be
owned by container root or by the Fluxheim runtime user `65532`, must not be a
symlink, and must not be group- or world-writable. A host file owned by the
interactive user or host root may appear as an unrelated unmapped UID inside a
rootless container; a read-only bind mount does not change that metadata.

Prepare the example config tree explicitly before starting Fluxheim:

```bash
sudo chown -R "$(id -un):$(id -gn)" /srv/infra/fluxheim/config
find /srv/infra/fluxheim/config -type d -exec chmod 0755 {} \;
find /srv/infra/fluxheim/config -type f -name '*.toml' -exec chmod 0644 {} \;
podman unshare chown -R 65532:65532 /srv/infra/fluxheim/config
```

The first command normalizes any host-root-owned fragments so the rootless
user can map them. `podman unshare chown` applies the correct subordinate host
UID/GID for container UID/GID `65532`; host tools may display a numeric owner
such as `165531`, but that value depends on the local subordinate-ID mapping and
must not be hard-coded. New or replaced config fragments need the same mapping.

Alternatively, append `U` to both config mounts (`:ro,Z,U`) and let Podman make
the recursive ownership change. Do not use that shortcut when the source tree
is shared with another service that requires its current host ownership.

Verify ownership as seen by the image before enabling a restart policy:

```bash
podman compose run --rm --entrypoint sh fluxheim -c \
  'id; ls -ld /etc/fluxheim /etc/fluxheim/conf.d /etc/fluxheim/conf.d/*.toml'
```

The process and mounted configuration should report UID `65532` (or container
root for deliberately root-owned config), and directories/files should normally
have modes `0755`/`0644`. Repeated `untrusted owner, symlink, or writable
component` messages under `restart: always` mean the process is failing closed
and the container engine is restarting it.

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

Matching config paths (requires a cache-capable, rustls server image and existing
certificate/key files; it does not issue certificates):

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

[cache]
enabled = true

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

Select a tested image using `FLUXHEIM_GATEWAY_IMAGE`, preferably its immutable
digest, using the [profile matrix](installation.md#choose-a-published-profile).
Create the external `gateway_net` network before either example if it does not
already exist. The following examples expose ports on all host interfaces;
review the host firewall and rootless low-port binding policy first. To test
locally without low-port privileges, use `127.0.0.1:8080:8080` and
`127.0.0.1:8443:8443` instead.

Podman run example:

```bash
podman run --rm --ulimit core=0:0 \
  --name fluxheim \
  --network gateway_net \
  --stop-signal SIGTERM \
  --stop-timeout 45 \
  -p 80:8080 \
  -p 443:8443 \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/tls:/etc/fluxheim/tls:ro,Z \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/sites/example/public:/srv/sites/example/public:ro,Z \
  "${FLUXHEIM_GATEWAY_IMAGE:?Select a tested gateway image}" \
  --config /etc/fluxheim/fluxheim.toml
```

Core-file limits are runtime settings: use `--ulimit core=0:0` for direct
Podman/Docker runs or the `ulimits` block below for Compose, including one-shot
ACME commands. Recreate existing containers after changing Compose settings.
The image alone cannot enforce these limits. Verify a running container with:

```bash
podman exec fluxheim cat /proc/1/limits
```

The `Max core file size` row must have soft and hard limits of `0`.
This limit alone does not stop Linux piped crash collectors. Current Linux
Fluxheim executables also mark themselves non-dumpable before loading config,
including in containers. A custom seccomp policy must allow `PR_SET_DUMPABLE`
and `PR_GET_DUMPABLE`; blocking them rejects startup. See the
[memory-dump policy](../../SECURITY.md#fatal-termination-and-memory-dumps)
for older binaries, external children and remaining operator responsibilities.

Compose example (alternative to the direct run, not a second gateway on the
same ports). Its container is named `fluxheim_gateway`; use that name for
`podman exec` and log inspection when using Compose:

```yaml
name: gateway

networks:
  gateway_net:
    external: true

services:
  fluxheim:
    ulimits:
      core:
        soft: 0
        hard: 0
    image: ${FLUXHEIM_GATEWAY_IMAGE:?Select a tested gateway image}
    container_name: fluxheim_gateway
    restart: always
    stop_signal: SIGTERM
    stop_grace_period: 45s
    command: ["--config", "/etc/fluxheim/fluxheim.toml"]
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

For managed ACME in containers, use the reviewed
[container renewal workflow](certificate-renewal.md#container-renewal) and
[complete companion example](../../examples/podman-compose-acme.yml). It differs
from the single-container recipe above:

- Select tested gateway and renewal images explicitly; their profiles may differ.
  Operation-scoped renewal validation requires 1.9.0; released 1.8.3 images do not
  have it. Normal server validation still checks every enabled runtime feature.
- Share configuration, certificate state, required secrets and the reload socket,
  not every application/cache/log mount. Use shared SELinux labels (`:z`) on
  intentionally shared paths and prepare ownership before starting either service.
  Do not repeatedly relabel those paths privately or chown live state.
- Set `tls.acme.automation = "external"` for an external companion. Start the
  gateway and verify challenge readiness before running the opt-in renewal profile.

After setting the two image variables and preparing the paths as described in
that workflow:

```bash
podman compose -f examples/podman-compose-acme.yml up -d fluxheim
podman compose -f examples/podman-compose-acme.yml --profile renewal run --rm --no-deps fluxheim-acme
```

A successful container start is not challenge readiness. A one-shot renewal is
not a scheduler, and certificate installation is not proof that the new
certificate is being served. Follow the activation checks in the renewal guide.

### Container ACME First Issuance

Use the [first HTTP-01 deployment](acme.md#first-http-01-deployment) recipe for
the complete issuer, vhost and challenge setup. HTTP-01 needs public port 80
reachable at this gateway; the renewal process alone does not serve challenges.
Use the issuer's staging environment where available before production issuance.

Choose the gateway image for the entire server configuration. In particular, the
published PHP profile does not include cache, and the full Wolfi image does not
include PHP-FPM. Neither is a universal replacement for the other.

Review and explicitly accept the issuer's actual terms; do not use a placeholder
terms URL. Prepare secret-file ownership and labels as described in
[secret handling](certificate-renewal.md#secret-handling).
Keep the first-issuance and renewal instructions in those guides as the single
source of truth, including missing-certificate startup, reload and public SNI
verification. Do not force-remove the gateway as a substitute for graceful
shutdown; a direct host-port replacement still has a listener gap.

Optional mounted error pages should use a path whose parent already exists in
the runtime image, such as `/var/lib/fluxheim/errors`. Avoid nested mountpoints
below read-only image paths such as `/srv/fluxheim/errors`.

The same deployment shape is available as
[examples/podman-compose.yml](../../examples/podman-compose.yml), with a matching
container-oriented config at
[examples/container/fluxheim.toml](../../examples/container/fluxheim.toml).
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

The linked container config sets `grace_period_seconds = 2` and
`graceful_shutdown_timeout_seconds = 5`. The shorter inline TOML above leaves
the runtime's default 30-second drain unchanged. Both deployment commands allow
45 seconds before an engine-enforced kill. Size that budget above the configured
pre-drain delay plus drain timeout, with additional teardown margin; the drain
setting is not a total process-exit deadline. Replacing a container that
directly owns its published host ports still has a listener gap; see
[Zero-Downtime Upgrades](zero-downtime-upgrades.md) for the readiness-gated
blue/green design.

Run the optional real-container proof with:

```bash
scripts/smoke_podman_blue_green.sh
```

It builds the reduced static-site profile unless
`FLUXHEIM_UPGRADE_CONTAINER_IMAGE` names an existing image. The smoke proves
that direct host-port replacement conflicts, then exercises failed-green
rollback, external readiness probing, new-connection switching, and blue
keep-alive drain behind a stable front listener.

The full and Wasm images use the rootless-friendly
[packaging/container/fluxheim.toml](../../packaging/container/fluxheim.toml) and a
self-contained default page at
[packaging/default/index.html](../../packaging/default/index.html), installed in
the image as `/srv/fluxheim/index.html`. Mount your own config or static root
over those paths when deploying a real site. Focused profiles select their own
config templates; they do not all serve that bundled static page.

Running the container engine as root does not change the image's configured
runtime user. Prepare ownership for that actual user and engine mapping even
with rootful Podman/Docker. Keep writable state/cache/log directories separate
from read-only static content and TLS inputs; do not run Fluxheim as root merely
to bypass ownership preparation.

## Native systemd

For manually compiled binaries or RPM-style native installs, Fluxheim ships a
systemd unit, sysusers file, tmpfiles file, and optional environment file under
`packaging/systemd` and `packaging/rpm`. See
[systemd Deployment](systemd.md) for the install steps and default paths.
Native packages use [packaging/default/fluxheim.toml](../../packaging/default/fluxheim.toml),
which listens on port `80` by default; the bundled systemd unit grants only
`CAP_NET_BIND_SERVICE` so the service can bind `80/443` while still running as
the unprivileged `fluxheim` user.

For local binary RPM smoke builds, use the containerized helper:

The default `generic` build is portable across the target architecture's baseline
CPUs and is the release gate's RPM mode. `native` adds `target-cpu=native` and
is only for the build CPU's supported instruction set, not general distribution.
Use `FLUXHEIM_GATE_RPM_BUILD_TYPE=native` to explicitly qualify that optimization.
During the 1.9.0 candidate checks, Rust 1.99.1 reproducibly crashed in LLVM while
compiling `p256` with `native` on the tested Zen 5 host. Native RPM optimization
is blocked there; do not treat a generic build as proof that native works.
See the [qualification ledger](../evidence/observability-12.md).

```bash
scripts/build_fluxheim_rpm.py "${RELEASE_VERSION:?Select an existing release tag}" generic --target opensuse-tumbleweed
scripts/build_fluxheim_rpm.py --list-targets
```

Untagged `latest` builds use the package name `fluxheim-unstable` and a date
version so they are clearly separated from stable release packages:

```bash
scripts/build_fluxheim_rpm.py latest generic --target opensuse-tumbleweed
scripts/build_fluxheim_rpm.py latest generic --target opensuse-tumbleweed --rpm-release 2
```

Those commands produce names shaped like
`fluxheim-unstable-YYYYMMDD-1.x86_64.rpm` and
`fluxheim-unstable-YYYYMMDD-2.x86_64.rpm`. A native build adds `.native` to the
RPM release field; a distribution-specific suffix may also appear. The unstable package
conflicts with the stable `fluxheim` package because both install the same
binary, service, config, and content paths.

This helper is intended for installation testing on RPM-based hosts. The
release-grade RPM source of truth remains `packaging/rpm/fluxheim.spec`.

Without `--local-source`, the helper clones the remote repository: `latest`
means its current default-branch checkout, not your working tree or the newest
release tag. `--local-source` snapshots local tracked/non-ignored files instead;
it can include unpublished edits and is not a publication or source-authenticity
gate. Do not transfer a private review worktree to a builder merely to test this
command. Final release builds require the separate release workflow and evidence.

## Codex And Rootless Podman

Sandbox permissions depend on the installed tool and host policy. This is not a
Fluxheim runtime requirement. Check `codex resume --help` and the
[official approval and sandbox guidance](https://learn.chatgpt.com/docs/agent-approvals-security)
before granting access. Keep workspace restrictions and approval prompts enabled;
grant only the required project/runtime paths, not the entire home directory.
Do not enable unrestricted network access merely to solve a local file error.

Local Podman does not require an API socket. If using the remote/API mode, verify
the intended connection first. The usual rootless socket is
`unix://$XDG_RUNTIME_DIR/podman/podman.sock`; `CONTAINER_HOST` selects a service
endpoint. Access to that socket grants control of the account's containers and
can execute code as that account, not merely inside the current checkout. Do not
mount it into Fluxheim or make it world-accessible to bypass a permission error.
See [Podman's API security guidance](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html#security).

From the repository root, use the self-contained static recipe and a tested full
or Wasm image. This foreground command publishes only to host loopback; stop it
normally with Ctrl-C:

```bash
podman run --rm --ulimit core=0:0 \
  --name fluxheim-local-example \
  --stop-timeout 15 \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/examples/installation/container.toml:/etc/fluxheim/fluxheim.toml:ro,Z" \
  "${FLUXHEIM_GATEWAY_IMAGE:?Select a tested full or Wasm image}" \
  --config /etc/fluxheim/fluxheim.toml
```

In another terminal, request `http://127.0.0.1:8080/`. This recipe uses a
five-second drain and disables cache, TLS and persistent logs. See
[the installation walkthrough](installation.md#minimal-container-test) for
detached execution, checks and cleanup. A kitchen-sink example is not a drop-in
container config: it can require missing files, includes and external services.

For TLS, use the [HTTPS guide](tls.md) and the [volume mapping](#volume-mapping)
above. Preserve private-key ownership and mount inputs read-only. An explicit
`--check-tls-storage` can inspect storage; it does not prove a public handshake,
successful issuance or that the intended certificate is being served.

Privileged ports such as `80` and `443` require host-level setup for rootless
containers. Prefer host port forwarding to container ports `8080` and `8443`
unless the deployment environment already grants low-port binding safely.
