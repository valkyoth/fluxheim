# Install And Choose A Package

Choose the operating system, then the capabilities you need. Installing a
larger package does not enable its optional services automatically. Conversely,
TOML cannot enable a module that was not compiled into the executable.

## Choose A Distribution

| Distribution | Intended host | What you get |
| --- | --- | --- |
| Linux portable `.tar.gz` | Linux x86_64 or aarch64 matching the release target | Foreground executables and deployment examples; install a supervisor separately. |
| macOS portable `.tar.gz` | Apple Silicon | CLI executables, not a signed/notarized graphical installer. Intel macOS is not a release target. |
| Windows portable `.zip` | Windows x86_64 | Native `.exe` files; no Windows service installer. Windows ARM64 is deferred. |
| Linux container image | Compatible Linux container host/VM | Executables, a profile-specific starter config and runtime filesystem. Inspect the image's platform before deploying it. |
| RPM | Qualified RPM-based Linux host and architecture | Native install paths, user/directory setup and systemd assets; see [systemd](systemd.md). |

Linux archive names do not distinguish GNU from musl builds. Do not assume a
file named `x86_64-linux` is a statically linked executable for every Linux
distribution. Check the release's target/build evidence and test on the intended
host. A cross-compiled executable is not native runtime qualification.

Native release procedures and unsigned-platform limits are in
[portable releases](portable-releases.md). SHA-256 verification detects changes
relative to a trusted checksum manifest; it is not independent publisher
authentication. Do not disable host security globally to run an unsigned build.

## Choose A Published Profile

This table describes compiled capabilities, not resolved runtime defects or
enabled-by-default services. Read each feature's guide for current limitations.
All six server profiles include HTTP proxying, rustls TLS, all three compression
codecs and the live ACME client. PHP-FPM itself is not part of a native archive.

| Profile | Static files | Cache | Load balancing | PHP/FastCGI | Wasm | Prometheus/OTLP/traces | GeoIP/TCP streams/mirroring |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full` | Yes | Yes | Yes | No | No | Yes | Yes |
| `wasm` | Yes | Yes | Yes | No | Yes | Yes | Yes |
| `cache` | No | Yes | No | No | No | No | No |
| `proxy` | No | No | No | No | No | No | No |
| `load-balancer` | No | No | Yes | No | No | No | No |
| `php` | Yes | No | No | Yes | No | No | No |

The seventh archive, `config-tester`, contains only `fluxheim-config-tester`,
built with `profile-development`. It does not start a server and is not a
substitute for validating/running the executable you will actually deploy.
Its feature set does not include Wasm or an alternative TLS backend.

Important choices:

- `full` does **not** mean every feature. Use `wasm` for plugins, or a custom
  build for PHP together with cache/observability.
- `php` does not contain Fluxheim's cache. Disable cache configuration or build
  a deliberately combined profile. PHP application/database caching is separate.
- `cache` is a proxy-cache edge without local static-file serving. Use `full`
  for a site root plus cache.
- Admin and operational logging are not equivalent to Prometheus/OTLP support.
  Focused server profiles still have the shared admin/logging implementation;
  collectors need their own compile-time features and runtime settings.
- UDP is explicit beta, absent from every official profile. HTTP/3 is parked;
  no listed profile provides it. FIPS-capable builds are separate selections,
  not properties inferred from the base-image name.

The exact archive feature strings are maintained in
[`portable_release_plan.py`](../../scripts/portable_release_plan.py), and the
image matrix in [the image workflow](../../.github/workflows/images.yml).
[Cargo features](../reference/features.md) explains lower-level customization.

## Native Quick Start

After verifying and extracting the chosen archive, run its executable with a
configuration you own. Server archives include `fluxheim`, `fluxheim-acme`,
documentation, examples and packaging material; `.exe` is appended on Windows.
The config-tester archive instead contains its one executable and top-level
README/license/changelog, not the full example tree.
Build and smoke scripts require a source checkout; they are not installed by
extracting a server archive. Linux packaging material in a macOS/Windows archive
is reference material, not a platform-specific service installer.

For a local static test, use `full` or `wasm` and, from the extracted directory:

```bash
./fluxheim --version
./fluxheim --config examples/configuration/single.toml --validate-config
./fluxheim --config examples/configuration/single.toml
```

On Windows PowerShell, use `./fluxheim.exe` for the same commands. A second
terminal can request `http://127.0.0.1:8080/` with Host
`configuration.example.test`. Stop the foreground process normally with Ctrl+C.
This example is HTTP-only on loopback, not a public production TLS deployment.

Do not start a service from an untrusted writable download directory. Move
config/state to owner-controlled paths, protect credentials, and run under the
intended service identity. See [configuration](configuration.md),
[TLS](tls.md), [service lifecycle](service-lifecycle.md) and
[Windows platform limits](portable-releases.md#current-support-level) for their platform rules.

## Container Names And Base Variants

Choose an existing release version from its release page; the following variable
is deliberately a placeholder, not a claim that an unreleased version exists:

```bash
VERSION=REPLACE_WITH_RELEASE_VERSION
IMAGE="ghcr.io/valkyoth/fluxheim:v${VERSION}-wolfi"
podman pull "$IMAGE"
```

| Selection | Explicit release tag suffix |
| --- | --- |
| Full | `vVERSION-wolfi`, `vVERSION-alpine`, `vVERSION-debian`, `vVERSION-suse-micro` |
| Wasm | `vVERSION-wasm-VARIANT` for the same four variants |
| Cache, proxy, load-balancer | `vVERSION-PROFILE-VARIANT` for the same four variants |
| PHP | `vVERSION-php-wolfi`, `vVERSION-php-alpine`, `vVERSION-php-debian`, `vVERSION-php-suse-bci` |

There is no published PHP SUSE Micro variant and no non-PHP SUSE BCI variant.
Wolfi also has short aliases such as `vVERSION` and `vVERSION-php`; explicit
profile/base spelling is clearer. Moving `latest-*`/development tags are not
immutable release selections. The image workflow defaults to `linux/amd64`;
other architectures depend on actual published manifests, not the existence of
an ARM64 native archive.

Resolve and record a manifest digest for deployment, then use
`ghcr.io/valkyoth/fluxheim@sha256:...`. A release-version tag can receive a base
runtime refresh without a Fluxheim version change. Pulling a tag does not update
an already running container: validate, recreate and verify it. Preserve the
previous digest/config for rollback. See [runtime refresh](container-runtime-refresh.md).

PHP images add managed PHP-FPM and the checked common extension set; other
images do not become PHP images merely because they contain `index.php` as an
example file. Use [PHP deployment](php.md) for runtime extensions, writable
application paths, database networking and the external TCP alternative.

## Minimal Container Test

From this repository (or the server archive), the complete
[container recipe](../../examples/installation/container.toml) serves the image's
bundled static page. Use a `full` or `wasm` image. This publishes only on host
loopback; port 8443 being exposed by an image does not configure HTTPS.

```bash
podman run --rm --ulimit core=0:0 \
  -v "$PWD/examples/installation/container.toml:/etc/fluxheim/fluxheim.toml:ro,Z" \
  "$IMAGE" --config /etc/fluxheim/fluxheim.toml --validate-config

podman run -d --name fluxheim-install-example \
  --ulimit core=0:0 --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/examples/installation/container.toml:/etc/fluxheim/fluxheim.toml:ro,Z" \
  "$IMAGE"
curl --fail http://127.0.0.1:8080/
podman logs --tail 30 fluxheim-install-example
podman stop --time 15 fluxheim-install-example
podman rm fluxheim-install-example
```

The example uses a five-second drain with no grace delay. It keeps all mutable
state disposable, disables caching, and does not issue certificates, expose
admin/metrics or configure persistent file logging. Do not use it unchanged for
production state. Images run as `65532:65532` by default; an engine running as
root does not change that image identity.

For persistent deployments, mount only the required dedicated directories:

| Container path | Use |
| --- | --- |
| `/etc/fluxheim` | Read-only config, includes, TLS inputs and reviewed plugins. |
| `/srv/fluxheim` or explicitly configured site root | Read-only public content, except explicitly needed PHP application writes. |
| `/run/fluxheim` | Private runtime sockets and managed PHP temporary data. |
| `/var/lib/fluxheim` | Persistent ACME/snapshot state when configured there. |
| `/var/cache/fluxheim` | Persistent disk cache when enabled. |
| `/var/log/fluxheim` | Private file logs when enabled. |

Read-only mounts do not repair unsafe ownership or modes. Use the
[volume ownership procedure](build-and-podman.md#volume-mapping) and validate as
the actual runtime user. `:U` recursively changes source ownership: do not apply
it to your source checkout, home directory or another service's state. `:Z`
assigns a private SELinux label; deliberately shared gateway/renewal mounts
need a shared labeling policy, not competing private relabels. Docker does not
implement Podman's `:U`; prepare ownership using that engine's mapping instead.

## Build Exactly What You Need

Use the repository's pinned toolchain and lockfile. To build a local static
server, then validate the example without compiling default cache support:

```bash
cargo build --locked --no-default-features --features profile-static-site
target/debug/fluxheim --config examples/configuration/single.toml --validate-config
```

For a custom server with PHP, cache and observability:

```bash
cargo build --locked --no-default-features --features profile-development
```

That custom build does not install PHP-FPM or create an official package name.
Use the [build guide](build-and-podman.md) to supply container feature flags,
matching config and runtime packages together. `profile-full` alone does not
match the published full package's extra ACME/exporter flags.

The explicit `containers/Containerfile.*` build inputs are:

| Build argument | Meaning |
| --- | --- |
| `FLUXHEIM_FEATURES` | Cargo selection with defaults disabled. Most Containerfiles default to the published full string; SUSE BCI defaults to PHP. Keep it consistent with the config. |
| `FLUXHEIM_CONFIG` | Source-tree file copied to `/etc/fluxheim/fluxheim.toml`; full default, or managed PHP for SUSE BCI. A different feature selection does not automatically change this file in a direct local build. |
| `FLUXHEIM_RUNTIME_PACKAGES` | Base-specific package names. PHP builds must supply the matching checked `packaging/container/php-*-runtime-packages.txt`; changing features alone does not install PHP/extensions. |
| `FLUXHEIM_RUNTIME_UID` / `FLUXHEIM_RUNTIME_GID` | Default `65532`; changes image ownership and runtime identity, not the host's existing bind-mount ownership. |
| `RUST_IMAGE` | Compiler/build environment; repository defaults are version/digest pinned. Changing it requires build qualification. |
| `RUNTIME_IMAGE` | Base runtime image; repository defaults are digest pinned. It must remain compatible with the Containerfile's package manager and linked executable. |

For example, the existing Wolfi PHP build recipe supplies all three of feature
selection, `php-managed.toml` and the Wolfi runtime package list. SUSE BCI likewise
needs its package list; do not infer a working custom PHP image from the
Containerfile filename alone. See [container variants](build-and-podman.md#container-variants)
for those complete commands.

`validate-features.sh` is a preliminary check, not authoritative Cargo feature
resolution. Its nonrecursive alias expansion and incomplete privacy checks
currently miss some invalid combinations. Always
run the real locked build and executable validation. Cargo/source guards still
reject the reproduced invalid combinations; a shell-check success is not proof
that a custom package is buildable or supported. Avoid `--all-features` at the
root: mutually exclusive TLS backends and privacy conflicts are intentional.

For reproducible diagnosis, retain the source commit, selected features, Rust
target, image digest, effective config source and test result. `--version` alone
does not enumerate the compiled modules. Do not print secret-bearing effective
configuration into public logs when investigating a deployment failure.
