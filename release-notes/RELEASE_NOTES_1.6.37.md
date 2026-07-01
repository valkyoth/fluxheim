# Fluxheim 1.6.37 Release Notes

Fluxheim 1.6.37 is the final pre-Wasm crate-boundary cleanup release after the
Pingora-free runtime cutover and the 1.6.36 structural cleanup.

This release should keep runtime behavior stable while moving obvious remaining
root helpers into focused workspace crates. New substantial code should default
to an existing domain crate, or to a focused new crate when the dependency graph
is clean.

## Highlights

- Start the final pre-Wasm crate-boundary cleanup pass.
- Prepare ACME, observability, header-policy, TLS helper, native proxy, and CLI
  boundaries for smaller crate-owned APIs.
- Remove private root compatibility shims for common errors, filesystem trust
  checks, and OTLP HTTP agents; affected call sites now use
  `fluxheim-common`, `fluxheim-config`, and `fluxheim-observability` directly.
- Remove the single-use root path-safety shim; admin validation now calls the
  `fluxheim-common` path-safety helper directly.
- Remove the root test-support shim; root tests now import shared helpers from
  `fluxheim-common` directly.
- Remove the root cache-header shim; static response planning now calls
  `fluxheim-cache` header helpers directly.
- Remove root reload, snapshot, and load-balancer re-export shims from active
  code; admin and CLI paths now use `fluxheim-config`, `fluxheim-snapshot`, and
  `fluxheim-load-balancer` directly.
- Remove root GeoIP, OTLP trace-exporter, and trace-context re-export shims;
  callers should use `fluxheim-geoip` and `fluxheim-observability` directly.
- Remove unused root `config_*` compatibility modules; remaining callers use
  the owning `fluxheim-config` modules directly.
- Remove root cache API compatibility shims; admin, CLI, metrics, runtime, and
  native proxy code now use `fluxheim-cache` DTOs and helpers directly.
- Move the remaining root header DTOs into `fluxheim-headers` and remove the
  inline root `headers` module.
- Split access-log helper functions out of `fluxheim-observability/src/lib.rs`
  into a focused crate module while preserving the public exports.
- Split metrics label and bounded numeric helpers out of
  `fluxheim-observability/src/lib.rs` into a focused crate module while
  preserving the public exports.
- Split trace-context parsing and generation helpers out of
  `fluxheim-observability/src/lib.rs` into a focused crate module while
  preserving the public exports.
- Split OTLP HTTP agent and OTLP metrics payload helpers out of
  `fluxheim-observability/src/lib.rs` into focused crate modules while
  preserving the public exports.
- Split trusted client-IP restoration and Forwarded header helpers out of
  `fluxheim-headers/src/lib.rs` into a focused crate module while preserving
  the public exports and privacy-mode gating.
- Split background supervision and shutdown primitives out of
  `fluxheim-runtime/src/lib.rs` into focused runtime modules while preserving
  the public exports.
- Move `fluxheim-web` crate tests out of `src/lib.rs` so the production static
  response and directory-listing implementation stays below the line-limit
  target.
- Split stream upstream selection and stream tests out of
  `fluxheim-stream/src/lib.rs`, leaving the stream crate root below the
  line-limit target while preserving public exports.
- Split snapshot runtime validation state from snapshot-store persistence and
  turn `fluxheim-snapshot/src/lib.rs` into a small crate re-export surface.
- Split snapshot symlink-safe filesystem helpers and atomic write logic out of
  `fluxheim-snapshot/src/store.rs` into a focused `store_fs` module.
- Split snapshot metadata, message, and ID validation helpers out of
  `fluxheim-snapshot/src/store.rs` into a focused metadata module.
- Move `fluxheim-cache` request/key/range tests out of `src/request.rs`,
  leaving the production cache request helpers below the line-limit target.
- Move `fluxheim-cache` object/envelope/index tests out of `src/object.rs`,
  leaving the production disk object helpers below the line-limit target.
- Move `fluxheim-cache` storage-bin tests out of `src/storage_bin.rs` as the
  first step toward splitting manifest/layout, allocator, and index helpers.
- Split the storage-bin free-range allocator into a focused
  `storage_bin_alloc` module while re-exporting the existing public API.
- Split storage-bin layout, manifest, and object-location validation into a
  focused manifest module while keeping the `storage_bin` public exports stable.
- Split storage-bin symlink-safe filesystem helpers into a focused private
  module, bringing `fluxheim-cache/src/storage_bin.rs` below the line-limit
  target.
- Split cache admin math, warm summaries, object-lookup summaries, and tests
  out of `fluxheim-cache/src/api.rs`, leaving cache API DTOs below the
  line-limit target.
- Split cache header Cache-Control and Pragma directive parsing into a focused
  private module as the first step toward request/response header policy
  modules.
- Split cache request-side header policy, cookie/query bypass matching, and
  range/slice request selection into a focused private module while preserving
  the existing `fluxheim-cache::headers` exports.
- Split cache Vary header policy and request-hash material helpers into a
  focused private module while preserving the existing `headers` exports.
- Split cache response header policy, freshness helpers, content-type checks,
  and range response admission into a focused private module while preserving
  the existing `headers` exports.
- Split cache stale-if-error and stale-while-revalidate policy helpers into a
  focused private module while preserving the existing `headers` exports.
- Split load-balancer selected-upstream and queue/persistence outcome DTOs out
  of `fluxheim-load-balancer/src/api.rs`, leaving the load-balancer API DTO
  module below the line-limit target.
- Split load-balancer FNV hashing, random selection seeds, and per-process route
  secrets into a focused private selection-hash module.
- Split the nginx-compatible Ketama continuum builder and backend-key iterator
  into a focused private load-balancer selection module.
- Split the Maglev table builder, candidate iterator, and modular-arithmetic
  helper into a focused private load-balancer selection module.
- Split load-balancer candidate filtering, passive-health ejection floor, and
  slow-start permit checks into a focused private selection module.
- Split power-of-two choice selection and weighted random candidate selection
  into a focused private load-balancer selection module.
- Split consistent-hash, nginx-compatible Ketama selection, and bounded-load
  consistent selection into a focused private load-balancer selection module.
- Split FNV hash selection and shared weighted-index expansion into focused
  private load-balancer selection modules, bringing `selection.rs` below the
  line-limit target.
- Keep the root `fluxheim` crate focused on binary, CLI, admin, and runtime
  orchestration glue.
- Continue enforcing modularity, release metadata, Pingora dependency,
  native-runtime, RPM, container, and smoke gates as blocking release evidence.

## Compatibility Notes

- This release should not change runtime configuration semantics.
- Crate moves should preserve public behavior and move tests with the owned
  logic where practical.

## Verification

- `scripts/validate-release-metadata.sh`
- `scripts/validate-modularity-policy.sh check`
- `scripts/validate-pingora-dependency-policy.sh check`
- `scripts/validate-pingora-boundary-policy.sh check`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/stable_release_gate.sh check`
