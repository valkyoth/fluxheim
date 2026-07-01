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
| `crates/fluxheim-server/src/native_http1_proxy_tests.rs` | 1839 | Native HTTP/1 proxy parity tests temporarily group plain, TLS, mTLS, failover, pooling, round-robin, weighted round-robin, compression, error-page, and forwarded-header fixtures for the native upstream cutover slices; HTTP/2 parity and unsupported-policy config tests now live in focused child modules. | Split plain failover/round-robin, TLS/mTLS, pooling, compression/error-page, forwarded-header, and remaining config tests after the native proxy API stabilizes. |
| `crates/fluxheim-server/src/native_http1_cache.rs` | 2242 | Native cache entry/state, filesystem disk cache, storage-bin disk cache, local/OpenBao encryption, inspection, and purge helpers were grouped during the `1.6.33` native proxy-cache parity release to keep memory/disk purge behavior and storage format reviewable as one slice. | Split memory state, filesystem disk storage, storage-bin storage, encryption, inspection, and purge/index helpers before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_route_proxy_tests.rs` | 4746 | Native route-proxy tests temporarily group route matching, request/response header overlays, forwarded-header ownership, response rewrites, compression, cache, PHP, and proxy fixtures for the rich route cutover slices after redirect hardening moved to a focused test module. | Split header-policy, forwarded-header, response-rewrite, compression, cache, PHP, and remaining proxy route tests before final native runtime cleanup completes. |
| `crates/fluxheim-server/src/native_http1_plan_tests.rs` | 1132 | Native HTTP/1 cutover planning tests grew during the `1.6.26`-`1.6.29` route/policy parity slices to cover request-header mutations, response-header overlays, response rewrites, compression, static weights, forwarded-header ownership, and redirect-shadowed route proxies together. | Split route-policy candidate tests, vhost/root candidate tests, compression eligibility tests, and forwarded-header eligibility tests before the final Pingora dependency deletion. |
