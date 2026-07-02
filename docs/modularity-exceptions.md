# Fluxheim Modularity Exceptions

Status: baseline inventory for the 1.6 line

This file records legacy non-generated Rust files above the 500-line target in
[Fluxheim Modularity Policy](modularity-policy.md). The 1.6 line should shrink
this list as Pingora adapters, root orchestration, config, cache, admin, and
proxy code move into focused workspace crates.

New or newly split files should not be added here unless the same release
documents why the exception is temporary and how it will be removed.

## Legacy Exceptions

| File | Baseline lines | Reason | Split target |
| --- | ---: | --- | --- |
| `src/admin.rs` | 7943 | Legacy admin HTTP endpoint router over every domain. | Reduce after domain APIs stabilize; possible `fluxheim-admin` after `1.6.17`. |
| `src/cli.rs` | 5544 | Legacy command dispatch and release/admin/cache tooling. | Split command handlers by domain after runtime crates settle. |
| `src/acme.rs` | 3909 | ACME account/order/install/renewal and filesystem safety in one root adapter. | Move to `fluxheim-acme` after the native listener/TLS cutover stabilizes. |
| `src/metrics.rs` | 3070 | Root metrics registry/export adapter over many domains after native metrics HTTP app, secret loading, and label mapping moved to focused private modules. | Move remaining pure metrics into `fluxheim-observability`. |
| `crates/fluxheim-config/src/config_error_display.rs` | 837 | Config error `Display`/`Error` formatting split away from the public `config_error` wrapper while preserving `fluxheim_config::ConfigError`. | Split formatting helpers by config domain so each formatter module stays below the 500-line target. |
| `crates/fluxheim-config/src/config_error_kind.rs` | 626 | Public `ConfigError` enum variants split away from formatting without changing the public API. | Evaluate domain-specific internal error builders and whether variant groups can move behind smaller public constructors without API churn. |
| `src/runtime.rs` | 1053 | Native server/bootstrap/listener orchestration after runtime unit tests and logging helpers moved to focused modules; TLS listener planning and server process/listener inventory now come from focused crates while this file remains the compatibility adapter. | Continue replacing through `fluxheim-runtime`/`fluxheim-server` during the remaining `1.6` runtime cutover. |
