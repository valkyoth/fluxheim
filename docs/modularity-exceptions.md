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
| `src/native_proxy.rs` | 1404 | Native runtime admin/cache/load-balancer boundary used by root admin, CLI, metrics, and reload code after the Pingora adapter stopped compiling in normal builds. | Split admin handle, cache runtime handle, load-balancer admin handle, and live-config reload glue into focused native modules during the `1.6.36` structural cleanup. |
| `crates/fluxheim-config/src/config.rs` | 2514 | Config root, validation helpers, and shared parsing glue. | Split by shared config primitives. |
| `crates/fluxheim-config/src/config_cache.rs` | 2495 | Cache config, validation, and merge behavior. | Split cache config primitives when `fluxheim-cache` owns more runtime. |
| `src/runtime.rs` | 2013 | Pingora server/bootstrap/listener orchestration; TLS listener planning and server process/listener inventory now come from focused crates while this file remains the compatibility adapter. | Continue replacing through `fluxheim-runtime`/`fluxheim-server` during the remaining `1.6` runtime cutover. |
| `src/tls.rs` | 1456 | Root TLS storage, ACME path resolution, and compatibility glue after `fluxheim-tls` extracted listener planning, provider, ALPN, cipher, and SNI selector policy. | Move remaining ACME/storage helpers to focused crates after native listener cutover. |
| `crates/fluxheim-config/src/config_proxy.rs` | 1807 | Proxy config and validation. | Split proxy/load-balancer subdomains as native proxy APIs land. |
| `crates/fluxheim-config/src/config_load_balance.rs` | 1796 | Load-balancer config and validation. | Split with `fluxheim-load-balancer` independence in `1.6.1`. |
| `src/stream_proxy.rs` | 1026 | Current Pingora service-registration, listener, socket connect, and TLS adapter for stream routes after the 1.6.3 stream crate extraction. | Keep shrinking as background/runtime supervision and TLS connector abstractions move during the remaining `1.6` runtime cutover. |
| `crates/fluxheim-config/src/config_php.rs` | 1641 | PHP-FPM config and validation. | Split managed/runtime/path validation helpers. |
| `src/web.rs` | 1507 | Root static web adapter over `fluxheim-web`. | Reduce to adapter glue after native HTTP runtime lands. |
| `crates/fluxheim-config/src/config_header.rs` | 1060 | Header policy config and validation. | Move with header-policy crate work. |
| `src/udp_proxy.rs` | 1038 | UDP beta runtime. | Split before beta promotion. |
| `crates/fluxheim-config/src/config_stream.rs` | 947 | Stream proxy config and TLS validation. | Split with stream runtime cutover. |
| `crates/fluxheim-config/src/reload.rs` | 809 | Reload classification and diff behavior. | Move snapshot/reload-safe classification into dedicated modules. |
| `crates/fluxheim-config/src/config_admin.rs` | 755 | Admin config and validation. | Split ops socket, snapshots, auth, and status config. |
| `crates/fluxheim-config/src/config_acme.rs` | 719 | ACME config and validation. | Move with `fluxheim-acme`. |
| `src/config_tester.rs` | 716 | Config tester CLI and profile logic. | Split profile checks from CLI output. |
| `crates/fluxheim-config/src/config_tls.rs` | 677 | TLS config and validation. | Split downstream/upstream TLS config helpers. |
| `src/stream_tls.rs` | 657 | Stream upstream TLS adapter. | Move with stream runtime cutover. |
| `crates/fluxheim-config/src/config_route.rs` | 641 | Route config and validation. | Split redirect, methods, cache, and path policy helpers. |
| `crates/fluxheim-server/src/native_http1_proxy_tests.rs` | 805 | Native HTTP/1 proxy parity tests temporarily group plain, TLS, mTLS, failover, pooling, round-robin, weighted round-robin, config-gate, compression, error-page, and forwarded-header fixtures for the native upstream cutover slices. | Split plain failover/round-robin, TLS/mTLS, pooling, compression/error-page, forwarded-header, and config-gate tests after the native proxy API stabilizes. |
| `crates/fluxheim-server/src/native_http1_proxy.rs` | 509 | Native HTTP/1 proxy temporarily groups static upstream selection, pooling, compression, header policy, and error-page handling during the rich-proxy parity slices. | Split upstream selection, request policy, response policy/compression, and error-page handling before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_client.rs` | 740 | Native upstream HTTP/1 client temporarily groups connection pooling, request writing, response parsing, stale-connection retry, timeout handling, and forwarded-header-safe request construction during the final native upstream parity work. | Split pooling, request writer, response parser, retry/timeout policy, and request-construction helpers before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_tls.rs` | 872 | Native upstream TLS connector covers rustls/OpenSSL, trust roots, SNI, hostname policy, mTLS material, and file-safety checks during the staged `1.6.14` cutover. | Split rustls, OpenSSL, file loading, and hostname-policy helpers before production native proxy cutover. |
| `crates/fluxheim-server/src/native_http1.rs` | 673 | Native downstream HTTP/1 listener, TLS accept loop, connection budget, request parsing, request metadata, and response framing remain grouped during the `1.6.19`-`1.6.29` native listener/proxy parity work. | Split plain listener, TLS accept loops, connection serving, request parsing, and response framing before production native HTTP cutover. |
| `crates/fluxheim-server/src/native_http1_cache.rs` | 2242 | Native cache entry/state, filesystem disk cache, storage-bin disk cache, local/OpenBao encryption, inspection, and purge helpers were grouped during the `1.6.33` native proxy-cache parity release to keep memory/disk purge behavior and storage format reviewable as one slice. | Split memory state, filesystem disk storage, storage-bin storage, encryption, inspection, and purge/index helpers before final native runtime cutover. |
| `crates/fluxheim-server/src/server_tests.rs` | 685 | Server-plan and runtime-cutover policy tests grew during the native TLS/listener, background, admin, metrics, stream, UDP, and cutover-report proof work. | Split listener inventory, native-runtime blockers, HTTP policy mapping, background service, and service-intent tests into focused modules. |
| `crates/fluxheim-server/src/native_http1_route_proxy_tests.rs` | 923 | Native route-proxy tests temporarily group route matching, safe redirect expansion including encoded and double-encoded path hardening, request/response header overlays, forwarded-header ownership, response rewrites, compression, and route static-web fixtures for the rich route cutover slices. | Split redirect, header-policy, forwarded-header, response-rewrite, compression, and static-web route tests before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_plan_tests.rs` | 1132 | Native HTTP/1 cutover planning tests grew during the `1.6.26`-`1.6.29` route/policy parity slices to cover request-header mutations, response-header overlays, response rewrites, compression, static weights, forwarded-header ownership, and redirect-shadowed route proxies together. | Split route-policy candidate tests, vhost/root candidate tests, compression eligibility tests, and forwarded-header eligibility tests before the final Pingora dependency deletion. |
| `crates/fluxheim-server/src/native_http1_route_proxy.rs` | 1392 | Native route proxy temporarily groups route matching, safe redirect expansion including multi-pass path validation, request-body limits, request/response-header overlays, forwarded-header ownership, response rewrites, response compression, and static-web route action dispatch during the `1.6.26`-`1.6.29` route/rich-integration parity slices. | Split redirect handling, request header policy helpers, forwarded-header synthesis, response rewrite helpers, compression, and static-web dispatch into focused modules before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_static_web.rs` | 616 | Native static-web route adapter groups path resolution, directory listing, static response planning, method enforcement, and rooted no-symlink body opening for the `1.6.27` security-reviewed route static-web slice. | Split path resolution/opening, directory listing, and response planning helpers before final native runtime cutover. |
| `crates/fluxheim-server/src/native_http1_php.rs` | 829 | Native PHP-FPM route adapter temporarily groups request mapping, PHP-FPM client invocation, response conversion, static offload, cache policy, and error handling while the native proxy/PHP cutover is reviewed together. | Split request mapping, response conversion, offload handling, and cache/error policy helpers before the final native runtime cutover. |
| `crates/fluxheim-server/src/native_runtime_http1_proxy.rs` | 624 | Native runtime HTTP proxy runner temporarily groups listener expansion, HTTP/1/TLS/PROXY dispatch, background supervisor wiring, certificate reload hooks, and fail-fast listener behavior. | Split listener construction, TLS/PROXY dispatch, supervisor wiring, and reload hooks before deleting the Pingora runtime adapter. |
