# Build And Rootless Podman

Fluxheim pins Rust 1.95.0 in `rust-toolchain.toml` and `Cargo.toml`. The local
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
cargo build --release --no-default-features --features profile-load-balancer
```

The default build enables `proxy`, `web`, `cache`, `tls-rustls`, and
`security`. Cargo does not have a separate `--group` flag, so Fluxheim exposes
grouped build profiles as normal feature aliases such as `profile-core`,
`profile-static-site`, `profile-reverse-proxy`, `profile-cache-server`,
`profile-load-balancer`, `profile-observability`, and `profile-privacy`.

TLS backends are mutually exclusive. Select exactly one of `tls-rustls`,
`tls-openssl`, `tls-boringssl`, or `tls-s2n`; `tls-rustls` is the default and
recommended backend.

See [Feature Matrix](features.md) for the complete feature/profile list.

For package scripts or custom CI that accept user-provided feature strings, run
the feature preflight before invoking Cargo:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

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
`1.95.0-alpine3.23` image to keep a musl-linked release binary portable across
small runtime bases. The Debian variant builds with the official Rust
`1.95.0-bookworm` image and runs on `debian:trixie-slim`.

The builder installs `cmake` because Pingora's compression and TLS transitives
compile native C code. The runtime runs as UID/GID `65532` and owns only:

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

Build a specific runtime variant:

```bash
podman build -t fluxheim:wolfi -f containers/Containerfile.wolfi .
podman build -t fluxheim:alpine -f containers/Containerfile.alpine .
podman build -t fluxheim:suse-micro -f containers/Containerfile.suse-micro .
podman build -t fluxheim:debian -f containers/Containerfile.debian .
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
own CI job because Pingora and native TLS/compression dependencies can require
platform-specific toolchains and libraries.

## Publishing Images

The `Container Images` GitHub workflow builds the four variant Containerfiles
and pushes tags to:

- `ghcr.io/<owner>/fluxheim`
- `docker.io/<owner>/fluxheim`, when Docker Hub secrets are configured

Required Docker Hub repository secrets:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

The workflow publishes variant-suffixed tags:

- `v1.0.0-wolfi`, `v1.0.0-alpine`, `v1.0.0-suse-micro`, `v1.0.0-debian`
- `sha-<short-sha>-wolfi`, `sha-<short-sha>-alpine`, etc.
- `latest-wolfi`, `latest-alpine`, etc. when run from the default branch

The workflow defaults to `linux/amd64`. Use manual dispatch to test additional
platforms, for example `linux/amd64,linux/arm64`, once every selected runtime
base has been verified for those architectures.

Manual workflow inputs also allow `runtime_uid` and `runtime_gid`. Keep both at
`65532` for normal images. Use `0` only for a deliberate root-runtime image.

## Volume Mapping

Fluxheim containers use a small set of stable paths. Mount host directories to
these paths instead of writing inside the image layer.

| Container path | Purpose | Mount mode |
| --- | --- | --- |
| `/etc/fluxheim/fluxheim.toml` | Main config file. | `ro,Z` |
| `/etc/fluxheim/conf.d` | Optional config directory. | `ro,Z` |
| `/etc/fluxheim/tls` | Static certificate chains and private keys. | `ro,Z` |
| `/run/fluxheim` | Process runtime files such as PID files and upgrade sockets. | `Z,U` |
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

The same deployment shape is available as
[examples/podman-compose.yml](../examples/podman-compose.yml), with a matching
container-oriented config at
[examples/container/fluxheim.toml](../examples/container/fluxheim.toml).
The container config sets `grace_period_seconds = 2` and
`graceful_shutdown_timeout_seconds = 5`; keep the Podman stop timeout higher
than the sum of those values so normal shutdown does not fall back to `SIGKILL`.

If using a root-runtime image, `:U` is usually not needed for ownership, but
keeping separate writable directories for state/cache/logs is still recommended
so the container does not need write access to static site content or TLS keys.

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
