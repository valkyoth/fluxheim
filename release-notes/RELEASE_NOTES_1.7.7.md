# Fluxheim 1.7.7 Release Notes

Fluxheim 1.7.7 adds the first opt-in `wasm-proxy-abi` compatibility preview
boundary. This release does not claim that existing arbitrary proxy-wasm
plugins run unchanged. It establishes the safe shape for that work: explicit
ABI and host-call namespace validation, feature-gated config acceptance, and
deterministic unsupported-call rejection.

## Added

- Add `wasm-proxy-abi` feature propagation through the root, config, server,
  and `fluxheim-wasm` crates.
- Add `host_call_namespace = "proxy-wasm-preview"` support for
  `[[wasm.plugins]]` entries when paired with `abi = "proxy-wasm-preview"`.
- Add manifest validation that rejects mismatched ABI and host-call namespace
  combinations.
- Add native HTTP/1 proxy-ABI preview host-call stubs that reject unsupported
  calls deterministically instead of silently binding to Fluxheim's native
  policy namespace.
- Reject module imports that are not explicitly bound for the selected
  host-call namespace before Wasm instantiation, with a stable import-specific
  error.
- Add a live native HTTP/1 compatibility fixture using the canonical
  proxy-wasm `env.proxy_log(i32, i32, i32) -> i32` import and prove that the
  unsupported call fails closed with `503` before the upstream is reached.

## Security

- `proxy-wasm-preview` host calls remain disabled unless the binary is compiled
  with `wasm-proxy-abi` and config explicitly sets `allow_preview_abi = true`.
- Compiled WebAssembly module identities now include the host-call namespace,
  so future compile-cache reuse cannot cross from `fluxheim-policy-v1` to
  `proxy-wasm-preview`.
- Restrict proxy-ABI preview manifests to `access-decision`, and independently
  prevent native request-header, route, and cache host functions from being
  linked into the preview namespace.
- Enforce `[server.host_routing].strict = true` for native HTTP/1 Host and
  HTTP/2 authority routing. Missing or invalid identity returns `400`; an
  unknown host returns `421` instead of reaching the default tenant.
- Acquire process, cache-vhost, plugin, and attachment Wasm admission before
  `spawn_blocking`; honor bounded `queue_limit` waiters and replace per-request
  watchdog threads with one process-wide shared epoch ticker.
- Use Tokio semaphore admission in narrow-to-global order, preventing a
  saturated plugin or attachment from reserving broader process capacity, and
  cap active/queued Wasm budgets at `256`.
- Bound external-auth work before blocking-pool submission with
  `max_in_flight = 64` by default and a `256` process-wide ceiling shared by
  all routes. Saturation fails closed with `503`.
- Keep source-specific admin lockouts fail closed while allowing correctly
  authenticated operators through a global invalid-attempt lockout.
- Bound persistent storage-bin index files, entry/key counts, cache metadata,
  header counts, and fallible allocations. Decoded local AES cache keys now
  remain in `sanitization::SecretBytes<32>` through key construction.
- Pin third-party GitHub Actions to reviewed commit SHAs, pin `cargo-deny` and
  `cargo-audit` installs, and pin every container builder/runtime base image to
  a reviewed digest.
- Reject duplicate canonical storage-bin roots during native router
  construction and verify persisted object identity before serving, preventing
  cross-policy allocator corruption from becoming cache disclosure.
- Record strict Host/authority routing rejections through the native metrics
  bridge.
- Inspect disk objects through the registered live cache instead of constructing
  a temporary allocator, and hold a lifetime-exclusive storage-bin lock file so
  separate Fluxheim processes cannot allocate the same root concurrently.
- Add one shared `256`-slot request-driven blocking-work budget across Wasm,
  external auth, traffic mirrors, disk-cache operations, and ACME challenge
  reads. Explicitly cap Tokio's blocking pool at `384`, leaving `128` slots
  outside request admission for operational work.
- Acquire storage-bin ownership before any manifest or data-layout mutation,
  preventing a losing process from modifying first-start metadata.
- Document that storage-bin ownership uses advisory filesystem locking: use a
  per-replica local/RWO volume by default, and require verified cross-node
  `flock` behavior plus orchestration-level single-writer enforcement before
  using shared RWX storage in high-assurance deployments.
- Partition blocking work by class under `224` non-critical and `256` total
  ceilings, reserve `32` critical slots, and return `503` rather than contacting
  origin when disk-cache lookup admission is saturated and no stale memory
  object is available.
- Harden the GeoIP runtime boundary: cap fallback databases at eight before
  allocation, admit aggregate descriptor sizes before reading/parsing, decode
  bounded borrowed country strings, require trusted ownership and non-writable
  modes for MMDB files and all parents, and reject files changed during loading.

## Changed

- Update `base64-ng` to 1.3.7, `bytes` to 1.12.1, `regex` to 1.13.0,
  `sanitization` to 1.2.4, and test-only `wat` to 1.253.0.
- Update the workspace MSRV, pinned toolchain, and container builders to Rust
  1.97.0.
- Exercise current MariaDB 12.3 LTS, PostgreSQL 18, and Valkey 9.1 container
  lines in the database and health-check smoke defaults.
- Restore the standalone cargo-fuzz workspace and remove its obsolete Pingora
  dependency patch so the checked-in fuzz targets build against their current
  owning crates again. The fuzz validation gate now compiles every target.
- Replace storage-bin request-path full-index sorting, rewriting, and syncing
  with one fallibly-created process-wide persistence worker. Maintain ordered
  eviction state so selecting the oldest object no longer scans the complete
  object map.
- Add `fluxheim-base-images.txt` to generated release evidence beside SPDX and
  CycloneDX output so reviewed image digests are recorded for each build input.

## Operator Notes

- Existing `wasm` configs using `fluxheim-policy-v1` continue unchanged.
- To test the preview namespace, build with `--features wasm-proxy-abi`, set
  `allow_preview_abi = true`, and declare both:

```toml
[wasm]
enabled = true
allow_preview_abi = true

[[wasm.plugins]]
name = "proxy_preview"
path = "/etc/fluxheim/plugins/proxy-preview.wasm"
abi = "proxy-wasm-preview"
host_call_namespace = "proxy-wasm-preview"
phases = ["access-decision"]
```

- The preview namespace is intentionally narrow in this release. Unsupported
  calls fail closed through the plugin fail mode.
