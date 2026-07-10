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
- Select an installed GCC 13/12/11 compiler pair automatically for release-mode
  rustls/AWS-LC FIPS validation when a rolling distribution's default compiler
  is outside the supported range; explicit compiler selections remain
  authoritative.
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
- Inspect storage-bin objects only through the registered live cache and hold a
  lifetime-exclusive lock file so separate Fluxheim processes cannot allocate
  the same root concurrently. Standalone CLI inspection retains a bounded
  filesystem-backend index rebuild because that backend has no shared allocator.
- Keep generated managed PHP-FPM Unix socket names compact and reject a final
  socket path that exceeds the platform address limit before spawning PHP-FPM.
- Return explicit `431`, `414`, or `400` responses for bounded request-head
  parser failures instead of closing the HTTP/1 connection without a response.
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
- Make reload classification fail closed through an explicit snapshot-safe
  allowlist. Client-authentication, compliance, listener trust/limits, stream,
  UDP, ACME, cache-purger, tracing, and other startup-owned changes now require
  process replacement instead of being accepted as snapshot reloads.
- Extend reload ownership into nested vhosts and routes: managed ACME target
  identity/domain changes and managed PHP-FPM pool/process changes require
  process replacement, while ordinary routing and request-time PHP policy stay
  snapshot-safe. Exhaustive vhost, route, and PHP-FPM schema audits prevent new
  nested fields from silently bypassing review.
- Require config sources, split-config directories, and every existing ancestor
  to have trusted ownership and non-writable group/other modes. Verify path and
  descriptor identity and reject config files modified during bounded reads.
- Restore the all-feature config security suite, including tracing/privacy and
  dual-FIPS-backend feature combinations.
- Bound Brotli, gzip, and Zstandard logical output before accepting excess
  encoded bytes, transfer emitted codec buffers into response bytes without
  copying, and permanently discard a codec after an output or allocation
  failure.
- Fail response compression closed for malformed `Accept-Encoding` fields,
  honor explicit coding rejection over wildcard acceptance, and suppress
  compression for qualified `Cache-Control: private="..."` responses.
- Perform config ownership, permission, and symlink traversal checks through
  no-follow `statat` metadata inspection, and remove environment-derived
  filesystem writes from storage-lease subprocess coverage.

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
- Run filesystem-sensitive local release fixtures below private repository-owned
  smoke roots, using a compact root for Unix-socket tests, so the suite exercises
  the same full-ancestor trust policy enforced in production.

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
