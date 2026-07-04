# Fluxheim Modularity Exceptions

Status: baseline inventory for the 1.6 line

This file records legacy non-generated Rust files above the 500-line target in
[Fluxheim Modularity Policy](modularity-policy.md). The 1.6 line should shrink
this list as Pingora adapters, root orchestration, config, cache, admin, and
proxy code move into focused workspace crates.

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
| `crates/fluxheim-config/src/config_tests_wasm.rs` | 531 | Wasm validation coverage is intentionally broad for the first live-hook release. | Split attachment-order, admission-budget, and reload-classification cases into focused Wasm test modules. |
| `crates/fluxheim-config/src/config_wasm.rs` | 840 | The first live Wasm schema keeps validation, defaults, attachment planning, and admission limits together while the API settles. | Split into `config_wasm_limits`, `config_wasm_attachments`, and `config_wasm_validate` modules after 1.7.1 behavior is locked. |
| `crates/fluxheim-wasm/src/manifest.rs` | 502 | Manifest parsing and validation grew with ABI/runtime compatibility checks. | Move manifest validation helpers and tests into focused modules. |
| `crates/fluxheim-wasm/src/runtime.rs` | 583 | Runtime construction now includes compile caching, host bindings, and execution policy checks. | Split compile-cache, execution, and host-call helpers into separate runtime submodules. |
| `src/metrics.rs` | 505 | Root metrics compatibility wrappers remain just over the target after native/Wasm additions. | Move remaining Wasm metric wiring into the observability crate or a focused root adapter. |
