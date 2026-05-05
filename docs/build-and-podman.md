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
cargo build --release --no-default-features --features web
```

TLS backends are mutually exclusive. The default `tls` feature selects
`tls-rustls`.

## Rootless Podman Image

The image is built from the official Rust `1.95.0-bookworm` builder image and a
small Debian runtime image. The builder installs `cmake` because Pingora's
compression transitives compile native C code. The runtime runs as UID/GID
`65532` and owns only:

- `/etc/fluxheim`
- `/var/lib/fluxheim`
- `/var/cache/fluxheim`
- `/srv/fluxheim`

Build with defaults:

```bash
podman build -t fluxheim:dev -f Containerfile .
```

Build a smaller proxy-only binary:

```bash
podman build \
  --build-arg FLUXHEIM_FEATURES=proxy \
  -t fluxheim:proxy \
  -f Containerfile .
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
