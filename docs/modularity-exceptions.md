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
| `crates/fluxheim-config/src/config_tests.rs` | 13952 | Legacy central config regression suite. | Split by config domain as crates stabilize. |
| `src/admin.rs` | 7943 | Legacy admin HTTP endpoint router over every domain. | Reduce after domain APIs stabilize; possible `fluxheim-admin` after `1.6.17`. |
| `src/cli.rs` | 5544 | Legacy command dispatch and release/admin/cache tooling. | Split command handlers by domain after runtime crates settle. |
| `src/acme.rs` | 3909 | ACME account/order/install/renewal and filesystem safety in one root adapter. | Move to `fluxheim-acme` after the native listener/TLS cutover stabilizes. |
| `src/metrics.rs` | 2761 | Root metrics registry/export adapter over many domains. | Move remaining pure metrics into `fluxheim-observability`. |
| `crates/fluxheim-config/src/config_error.rs` | 1461 | Public config error enum and formatting surface moved out of `config.rs` without changing the public `fluxheim_config::ConfigError` API. | Split formatting helpers by config domain, then evaluate whether domain-specific internal error builders can shrink the public enum safely. |
| `src/runtime.rs` | 2013 | Pingora server/bootstrap/listener orchestration; TLS listener planning and server process/listener inventory now come from focused crates while this file remains the compatibility adapter. | Continue replacing through `fluxheim-runtime`/`fluxheim-server` during the remaining `1.6` runtime cutover. |
| `src/tls.rs` | 1456 | Root TLS storage, ACME path resolution, and compatibility glue after `fluxheim-tls` extracted listener planning, provider, ALPN, cipher, and SNI selector policy. | Move remaining ACME/storage helpers to focused crates after native listener cutover. |
| `crates/fluxheim-server/src/native_http1_cache.rs` | 1198 | Native filesystem disk cache and storage-bin disk cache remain grouped after cache tests, memory state/helpers, disk metadata, safe filesystem paths, encryption/OpenBao helpers, and purge/inspection APIs moved to child modules. | Split filesystem disk storage and storage-bin storage before final native runtime cutover. |
