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
| `src/acme.rs` | 2060 | ACME account/order/install/renewal and filesystem safety in one root adapter after regression coverage, error typing, challenge stores, renewal queue helpers, PEM validation, and EAB secret handling moved to focused child modules. | Move to `fluxheim-acme` after the native listener/TLS cutover stabilizes. |
| `crates/fluxheim-config/src/config_error_kind.rs` | 626 | Public `ConfigError` enum variants split away from formatting without changing the public API. | Evaluate domain-specific internal error builders and whether variant groups can move behind smaller public constructors without API churn. |
