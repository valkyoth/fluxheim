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
| `src/admin.rs` | 3062 | Legacy admin HTTP endpoint router over every domain after admin endpoint, auth, cache, load-balancer, snapshot, self-healing, shared regression-test support, cache response helper blocks, and admin security helpers moved to child modules. | Continue splitting admin domain helpers, then evaluate `fluxheim-admin`. |
| `src/cli.rs` | 3831 | Legacy command dispatch and release/admin/cache tooling after CLI regression coverage moved to focused child modules. | Split command handlers by domain after runtime crates settle. |
| `src/acme.rs` | 2305 | ACME account/order/install/renewal and filesystem safety in one root adapter after regression coverage, error typing, challenge stores, renewal queue helpers, and PEM validation moved to focused child modules. | Move to `fluxheim-acme` after the native listener/TLS cutover stabilizes. |
| `crates/fluxheim-config/src/config_error_display.rs` | 837 | Config error `Display`/`Error` formatting split away from the public `config_error` wrapper while preserving `fluxheim_config::ConfigError`. | Split formatting helpers by config domain so each formatter module stays below the 500-line target. |
| `crates/fluxheim-config/src/config_error_kind.rs` | 626 | Public `ConfigError` enum variants split away from formatting without changing the public API. | Evaluate domain-specific internal error builders and whether variant groups can move behind smaller public constructors without API churn. |
