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
| `crates/fluxheim-config/src/config_tests_wasm.rs` | 567 | Wasm validation coverage is intentionally broad for the first live-hook release and now includes the cache-specific process admission ceiling. | Split attachment-order, admission-budget, and reload-classification cases into focused Wasm test modules. |
| `crates/fluxheim-config/src/config_wasm.rs` | 862 | The first live Wasm schema keeps validation, defaults, attachment planning, security-hook admission limits, and cache-hook admission limits together while the API settles. | Split into `config_wasm_limits`, `config_wasm_attachments`, and `config_wasm_validate` modules after 1.7.1 behavior is locked. |
| `crates/fluxheim-wasm/src/manifest.rs` | 502 | Manifest parsing and validation grew with ABI/runtime compatibility checks. | Move manifest validation helpers and tests into focused modules. |
| `crates/fluxheim-server/src/native_http1_proxy_load_balanced.rs` | 624 | The native load-balanced proxy path now carries cache lookup, peer-fill, origin-fill, stale, affinity-cookie, retry orchestration, and bounded Wasm cache-store admission. | Split cache lookup/fill orchestration from load-balanced upstream retry and affinity handling. |
| `crates/fluxheim-server/src/native_http1_proxy_static_dispatch.rs` | 532 | The native static-upstream proxy dispatch path now carries cache lookup, fixed-slice cache lookup, origin-fill, stale, and bounded Wasm cache-store admission. | Split cache lookup/fill orchestration from static upstream dispatch after the cache-policy Wasm ABI settles. |
| `crates/fluxheim-server/src/native_http1_route_proxy_handler.rs` | 591 | The first routing-policy Wasm slice adds final selected-route policy ordering in the central native HTTP/1 handler. | Split normal request, takeover, and Wasm route-decision orchestration into focused handler modules before adding cache-policy Wasm phases. |
| `crates/fluxheim-server/src/native_http1_route_proxy_tests/wasm.rs` | 2430 | Live Wasm hook coverage now includes access decisions, request/response header mutation, rewrite-context behavior, PHP-FPM fallback coverage, configured route decisions, load-balanced route selection, managed-cookie persistence, mirror routing, selected-route policy enforcement, cache-lookup pass/deny behavior, cache-store skip/deny behavior, cache-store deny-wins ordering, cache admission isolation, cache-key variant isolation, cache-store metadata mutation, and negative host-call coverage in one fixture file. | Split access-decision, header-hook, route-decision, load-balancer/persistence, mirror, PHP-FPM fallback, and cache-policy live tests into separate modules before adding deeper cache-policy Wasm phases. |
| `crates/fluxheim-server/src/native_http1_route_wasm.rs` | 1770 | The native hook bridge now owns registry lookup, security-hook admission, cache-hook admission, access decisions, bounded header host calls, bounded route-decision ABI, bounded cache-lookup ABI, bounded cache-store ABI, and cache metadata aggregation. | Split header host-call state/mutation helpers, route-decision helpers, and cache-policy helpers into focused `native_http1_route_wasm_headers`, `native_http1_route_wasm_route_decision`, and `native_http1_route_wasm_cache_policy` modules. |
| `crates/fluxheim-wasm/src/runtime.rs` | 724 | Runtime construction now includes compile caching, host bindings, compile-slot coordination, and execution policy checks. | Split compile-cache, compile-slot, execution, and host-call helpers into separate runtime submodules. |
| `src/metrics.rs` | 505 | Root metrics compatibility wrappers remain just over the target after native/Wasm additions. | Move remaining Wasm metric wiring into the observability crate or a focused root adapter. |
