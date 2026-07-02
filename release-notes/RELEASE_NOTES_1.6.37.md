# Fluxheim 1.6.37 Release Notes

Fluxheim 1.6.37 is the final pre-Wasm crate-boundary cleanup release after the
Pingora-free runtime cutover and the 1.6.36 structural cleanup.

This release should keep runtime behavior stable while moving obvious remaining
root helpers into focused workspace crates. New substantial code should default
to an existing domain crate, or to a focused new crate when the dependency graph
is clean.

## Highlights

- Start the final pre-Wasm crate-boundary cleanup pass.
- Update the pinned Rust toolchain, workspace `rust-version` fields, and
  container builder images to Rust 1.96.1.
- Harden OpenSSL stream-upstream TLS connectors with a TLS 1.2 minimum and an
  explicit modern TLS 1.2/TLS 1.3 cipher allowlist.
- Store serialized ACME account credentials in `sanitization::SecretVec` while
  writing them to disk so account private-key JSON is cleared from heap memory
  on drop.
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
- Move snapshot store regression tests into focused functional and path-safety
  test modules, bringing `fluxheim-snapshot/src/store.rs` below the line-limit
  target.
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
- Move `fluxheim-cache` header policy tests out of `src/headers.rs`, leaving
  the cache header facade below the line-limit target.
- Move load-balancer policy override tests out of `src/policy.rs` as a
  preparatory split for the remaining policy key/snapshot/mutation modules.
- Split load-balancer config-derived backend policy maps and aliases into a
  focused private policy-config module.
- Split load-balancer backend runtime stats assembly into a focused private
  policy-stats module.
- Split load-balancer runtime override and snapshot state into a focused
  private policy-runtime module, bringing `policy.rs` below the line-limit
  target.
- Split load-balancer persistence request-key helpers and managed-cookie
  HMAC/token handling into focused private modules, bringing `persistence.rs`
  below the line-limit target.
- Split the pure load-balancer backend model, backend identity, and backend-set
  helpers out of the runtime module as a focused private module.
- Split load-balancer backend health/discovery state and backend runtime tests
  into focused child modules, bringing `backend.rs` below the line-limit target.
- Split load-balancer HTTP discovery, DNS discovery, and discovery tests into
  focused modules, bringing `discovery.rs` below the line-limit target.
- Split load-balancer HTTP/gRPC health-check construction and response
  validation into a focused health submodule, bringing the production
  `health.rs` dispatcher below the line-limit target.
- Split load-balancer health-check regression tests by transport/protocol
  family, removing the temporary oversized health test exception.
- Split the load-balancer crate-root regression suite into focused test modules,
  reducing `fluxheim-load-balancer/src/lib.rs` to orchestration/facade code.
- Split the load-balancer background-service wrapper into a focused service
  module while preserving the public `UpstreamLoadBalancerService` export.
- Split the load-balancer inner strategy dispatcher and backend member adapter
  helpers into a focused private module, further reducing the crate root to the
  public facade and orchestration glue.
- Split load-balancer runtime-state snapshot/load/save glue into a focused
  private module while preserving the public runtime-state methods.
- Split load-balancer runtime backend mutation and persistence-clear methods
  into a focused private module, leaving the crate root closer to construction,
  selection, and stats orchestration.
- Split load-balancer queue wait/timeout handling into a focused private module,
  leaving the crate root below 800 lines.
- Split load-balancer runtime stats assembly into a focused private stats
  facade module.
- Split load-balancer public construction and background-service factory methods
  into a focused private construction module, bringing the crate root below the
  line-limit target.
- Split PHP-FPM FastCGI request parameter translation into a focused private
  module while preserving the existing crate exports.
- Split PHP-FPM script-name, path-translation, deny-prefix, and static-file
  script mapping helpers into a focused private module.
- Split PHP-FPM response parsing, static-offload target validation, cache-policy
  checks, and response-header strip policy into a focused private module.
- Split managed PHP-FPM config rendering, instance-name generation, sanitized
  PATH fallback, and restart backoff helpers into a focused private module.
- Split managed PHP-FPM spawn safety, private config-file creation, managed
  directory validation, and socket readiness waits into a focused private
  module.
- Split managed PHP-FPM process lifecycle, child cleanup, restart watchdog, and
  process start handling into a focused private module below the line-limit
  target.
- Split the remaining PHP-FPM crate regression suite into focused I/O/policy,
  parameter/script, and response/config test modules, reducing the crate root to
  a small facade below the line-limit target.
- Split native route static-web PHP resolution tests into a focused module,
  bringing the route static-web test module below the line-limit target.
- Split PHP-FPM keepalive pool management and one-shot FastCGI execution into a
  focused private module while preserving the public crate exports.
- Split PHP-FPM endpoint selection, timeout classification, retry policy, and
  retry deadline helpers into a focused private module.
- Split PHP-FPM request-body replay, zeroized memory body ownership, spool-file
  allocation, cleanup, and spool-directory validation into a focused private
  module.
- Split PHP-FPM streamed FastCGI response collection and bounded chunk
  accounting into a focused private module.
- Split native runtime launch-plan TSV report rendering into a focused module,
  bringing the launch-plan assembly file below the line-limit target.
- Split native HTTP/2 response validation and bounded response-data writes into
  a focused private module, bringing the downstream H2 stack below the
  line-limit target.
- Split native HTTP/2 response, trailer, flow-control hold, and HTTP/1 adapter
  regression tests into a focused response test module.
- Split native upstream TLS proxy regression tests into base TLS, Rustls H2
  ALPN, and mTLS modules, removing the oversized TLS test exception.
- Split native upstream HTTP/1 client regression tests into base response,
  h2c-upgrade, forwarded-header/timeout, and PROXY protocol modules, removing
  the oversized client-test exception.
- Split native HTTP/1 runtime proxy tests into plain/PROXY, Rustls TLS, and
  OpenSSL TLS modules, removing the oversized runtime-proxy test exception.
- Split native downstream HTTP/1 tests into base listener/framing, request-view,
  body/limit/timeout, and TLS-listener modules, removing the oversized
  downstream HTTP/1 test exception.
- Split server-plan tests into base policy, native-runtime cutover, manifest,
  and listener-inventory modules, removing the oversized server test exception.
- Split native static-web path resolution, directory listing, response planning,
  and rooted body-opening helpers into focused child modules, removing the
  oversized static-web exception.
- Split native HTTP/1 proxy runtime TLS listener planning and runtime error
  formatting into focused child modules, removing the oversized runtime proxy
  exception.
- Split route redirect config and redirect-template validation into a focused
  config module, bringing `config_route.rs` to the line-limit target.
- Split TLS policy enums/defaults, client-auth config, and static certificate
  path validation into focused TLS config modules, removing the oversized TLS
  config exception.
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
