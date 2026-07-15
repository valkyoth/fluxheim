# Fluxheim Modularity Exceptions

Status: baseline inventory for the 1.7 line

This file records legacy non-generated Rust files above the 500-line target in
[Fluxheim Modularity Policy](modularity-policy.md). The 1.7 line should shrink
this list as the Wasm policy surface settles and large bridge/test modules move
into focused workspace crates.

New or newly split files should not be added here unless the same release
documents why the exception is temporary and how it will be removed.

## Temporary Exceptions

These files crossed the hard target during the 1.7.1 Wasm access-decision
work. They are accepted for the release so the live Wasm behavior can ship
with complete validation and tests, but they should be split before the 1.7
line adds broader Wasm phases.

| File | Baseline lines | Reason | Split target |
| --- | ---: | --- | --- |
| `crates/fluxheim-config/src/config_error_display.rs` | 504 | Public config-error formatter grew with Wasm-specific validation messages. | Move Wasm and reload-specific formatter arms into focused helpers while keeping the public `Display` implementation stable. |
| `crates/fluxheim-config/src/config_error_kind.rs` | 643 | Public `ConfigError` enum variants split away from formatting without changing the public API. | Evaluate domain-specific internal error builders and whether variant groups can move behind smaller public constructors without API churn. |
| `crates/fluxheim-config/src/config_tests_loader_conf_d.rs` | 552 | The conf.d loader regression suite now includes Wasm registry merge coverage. | Split Wasm conf.d merge cases into a dedicated `config_tests_loader_conf_d_wasm.rs` module. |
| `crates/fluxheim-config/src/config_tests_wasm.rs` | 1009 | Wasm validation coverage is intentionally broad for the first live-hook release and now includes the cache-specific process admission ceiling and compiled-artifact bounds. | Split attachment-order, admission-budget, sandbox-limit, and reload-classification cases into focused Wasm test modules. |
| `crates/fluxheim-config/src/config_wasm.rs` | 1061 | The live Wasm schema keeps validation, defaults, attachment planning, security/cache admission limits, and compiled-artifact limits together while the API settles. | Split into `config_wasm_limits`, `config_wasm_attachments`, and `config_wasm_validate` modules after the `1.7.x` behavior is locked. |
| `crates/fluxheim-wasm/src/manifest.rs` | 728 | Manifest parsing and validation now includes ABI/runtime compatibility and final security-phase digest enforcement. | Move manifest validation helpers and tests into focused modules. |
| `crates/fluxheim-server/src/native_http1_proxy_load_balanced.rs` | 624 | The native load-balanced proxy path now carries cache lookup, peer-fill, origin-fill, stale, affinity-cookie, retry orchestration, and bounded Wasm cache-store admission. | Split cache lookup/fill orchestration from load-balanced upstream retry and affinity handling. |
| `crates/fluxheim-server/src/native_http1_proxy_static_dispatch.rs` | 532 | The native static-upstream proxy dispatch path now carries cache lookup, fixed-slice cache lookup, origin-fill, stale, and bounded Wasm cache-store admission. | Split cache lookup/fill orchestration from static upstream dispatch after the cache-policy Wasm ABI settles. |
| `crates/fluxheim-server/src/native_http1_route_proxy_handler.rs` | 591 | The first routing-policy Wasm slice adds final selected-route policy ordering in the central native HTTP/1 handler. | Split normal request, takeover, and Wasm route-decision orchestration into focused handler modules before adding cache-policy Wasm phases. |
| `crates/fluxheim-server/src/native_http1_route_proxy_tests/wasm.rs` | 2719 | Live Wasm hook coverage now includes access decisions, request/response header mutation, rewrite-context behavior, PHP-FPM fallback coverage, configured route decisions, load-balanced route selection, managed-cookie persistence, mirror routing, selected-route policy enforcement, cache-lookup pass/deny behavior, cache-store skip/deny behavior, cache-store deny-wins ordering, cache admission isolation, cache-key variant isolation, cache-store metadata mutation, and negative host-call coverage in one fixture file. | Split access-decision, header-hook, route-decision, load-balancer/persistence, mirror, PHP-FPM fallback, and cache-policy live tests into separate modules before adding deeper cache-policy Wasm phases. |
| `crates/fluxheim-server/src/native_http1_route_wasm.rs` | 2043 | The native hook bridge now owns registry lookup, pre-submission security/cache admission, access decisions, bounded header host calls, bounded route/cache ABIs, and cache metadata aggregation. | Split header host-call state/mutation helpers, route-decision helpers, and cache-policy helpers into focused `native_http1_route_wasm_headers`, `native_http1_route_wasm_route_decision`, and `native_http1_route_wasm_cache_policy` modules. |
| `crates/fluxheim-wasm/src/runtime.rs` | 1494 | Runtime construction includes host bindings, synchronous compile-slot coordination, compiled-artifact admission, bounded async admission, shared epoch interruption, and execution policy checks. | Split admission, engine/ticker, compile-slot/artifact admission, execution, and host-call helpers into separate runtime submodules. |
| `src/metrics.rs` | 505 | Root metrics compatibility wrappers remain just over the target after native/Wasm additions. | Move remaining Wasm metric wiring into the observability crate or a focused root adapter. |

The following files crossed the target during the broader `1.7.8` security and
WASI integration pass. They remain temporary release exceptions with explicit
split destinations; new functionality must not use them as precedent.

| File | Baseline lines | Reason | Split target |
| --- | ---: | --- | --- |
| `crates/fluxheim-geoip/src/lib.rs` | 567 | Runtime policy integration and CIRCL combined-schema support currently share the public model module. | Move runtime loading and provider-specific decoding into focused modules while preserving the public GeoIP types. |
| `crates/fluxheim-server/src/native_http1_host_router.rs` | 545 | Trusted-client GeoIP context and Wasm policy construction expanded the central host-router assembly boundary. | Move GeoIP/Wasm policy assembly into a dedicated router policy builder. |
| `crates/fluxheim-server/src/native_http1_host_router_tests.rs` | 516 | Host-router tests now cover trusted-proxy GeoIP and Wasm policy wiring alongside base routing. | Split GeoIP and Wasm construction regressions into focused test modules. |
| `src/cli.rs` | 531 | Snapshot command dispatch and validated runtime loading remain together in the root CLI adapter. | Move snapshot subcommand execution into a dedicated CLI snapshot module. |

The following files crossed the target during the final `1.7.12` native
buffer, cache, static-response, HTTP/2, and snapshot hardening passes. The
security fixes and their regression coverage are retained for release; these
modules must be split before their next feature expansion in the `1.8` line.

| File | Baseline lines | Reason | Split target |
| --- | ---: | --- | --- |
| `crates/fluxheim-server/src/native_http1_cache.rs` | 538 | The disk-cache facade now coordinates stricter encrypted-root and storage-bin state without weakening the existing internal module boundary. | Move disk-cache construction and capability checks into `native_http1_cache_backend` or a focused facade-support module. |
| `crates/fluxheim-server/src/native_http1_cache_encryption.rs` | 1134 | Root separation, durable nonce state, migration, bounded secret input, and encrypted-envelope tests landed together during the final cache audit. | Split root identity/state persistence, envelope encoding, and provider/key loading into focused encryption submodules; keep tests in separate files. |
| `crates/fluxheim-server/src/native_http1_route_proxy_tests/cache_storage.rs` | 516 | Live route-cache storage coverage now includes filesystem, storage-bin, encrypted, and OpenBao paths. | Split encrypted/OpenBao storage fixtures from plain filesystem and storage-bin tests. |
| `crates/fluxheim-server/src/native_http1_static_web.rs` | 656 | Static response admission and cache-retention accounting expanded the central static dispatcher. | Move memory-cache state and admission helpers into a focused `native_http1_static_web/cache.rs` module. |
| `crates/fluxheim-server/src/native_http1_tests.rs` | 637 | Native HTTP/1 listener tests now include process-wide body admission and retained-owner lifetime coverage. | Split body-budget/lifetime tests from listener framing, context, and takeover tests. |
| `crates/fluxheim-server/src/native_http2_stack.rs` | 518 | Secure geometric request-body growth and temporary-overlap admission moved the protocol stack just above the limit. | Move request validation and body draining into focused HTTP/2 request modules. |
| `crates/fluxheim-server/src/native_http2_tests.rs` | 774 | HTTP/2 listener coverage combines framing, flow control, timeout, transport lifetime, and body-admission regressions. | Split request-body/admission tests from connection, response, and transport-lifetime tests. |
| `crates/fluxheim-snapshot/src/operations_tests.rs` | 548 | Snapshot transaction, recovery, self-healing, and filesystem-hardening cases share one operations fixture. | Split recovery/self-healing tests from create, diff, prune, and rollback operation tests. |
| `crates/fluxheim-snapshot/src/store.rs` | 511 | Store admission, transaction publication, and test-module declarations now sit just above the target after bounded snapshot serialization. | Move transaction-file publication helpers into `store_fs` and keep the store API focused on orchestration. |
| `crates/fluxheim-snapshot/src/store_tests.rs` | 564 | Store tests now include private-directory creation and no-follow metadata regressions alongside capacity and runtime-state cases. | Split filesystem-mode/path tests from capacity, rollback, and runtime-state tests. |
