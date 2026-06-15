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
| `src/proxy.rs` | 19208 | Legacy Pingora `ProxyHttp` orchestration and cross-domain adapter hub. | Split during `1.6.8`-`1.6.12` native HTTP proxy work. |
| `crates/fluxheim-config/src/config_tests.rs` | 13952 | Legacy central config regression suite. | Split by config domain as crates stabilize. |
| `src/cache.rs` | 13486 | Legacy Pingora cache storage/runtime adapter plus remaining cache orchestration. The 1.6.2 native cache adapter temporarily increases this file until the Pingora HTTP runtime edge is removed. | Continue moving pure cache runtime into `fluxheim-cache`; shrink the compatibility adapter during the native HTTP/cache cutover. |
| `src/admin.rs` | 7943 | Legacy admin HTTP endpoint router over every domain. | Reduce after domain APIs stabilize; possible `fluxheim-admin` after `1.6.12`. |
| `src/cli.rs` | 5544 | Legacy command dispatch and release/admin/cache tooling. | Split command handlers by domain after runtime crates settle. |
| `crates/fluxheim-load-balancer/src/lib.rs` | 4013 | Load-balancer orchestration root still hosts many domain pieces; API/runtime DTOs moved to `api.rs` in `1.6.1`. | Continue splitting orchestration and runtime mutation code during the remaining `1.6` load-balancer/background cutovers. |
| `src/acme.rs` | 3909 | ACME account/order/install/renewal and filesystem safety in one root adapter. | Move to `fluxheim-acme` around `1.6.6`. |
| `src/metrics.rs` | 2761 | Root metrics registry/export adapter over many domains. | Move remaining pure metrics into `fluxheim-observability`. |
| `crates/fluxheim-config/src/config.rs` | 2514 | Config root, validation helpers, and shared parsing glue. | Split by shared config primitives. |
| `crates/fluxheim-config/src/config_cache.rs` | 2495 | Cache config, validation, and merge behavior. | Split cache config primitives when `fluxheim-cache` owns more runtime. |
| `src/headers.rs` | 2125 | Header mutation, forwarding, rewriting, and cookie policy. | Move to `fluxheim-headers`/`fluxheim-http-policy` in `1.6.5`. |
| `src/runtime.rs` | 2203 | Pingora server/bootstrap/listener orchestration. | Replace through `fluxheim-runtime`/`fluxheim-server` in `1.6.4`-`1.6.7`. |
| `src/tls.rs` | 1834 | TLS config/runtime helper surface for current listener adapter. | Split with listener/TLS abstraction in `1.6.6`. |
| `crates/fluxheim-config/src/config_proxy.rs` | 1807 | Proxy config and validation. | Split proxy/load-balancer subdomains as native proxy APIs land. |
| `crates/fluxheim-config/src/config_load_balance.rs` | 1796 | Load-balancer config and validation. | Split with `fluxheim-load-balancer` independence in `1.6.1`. |
| `crates/fluxheim-load-balancer/src/health.rs` | 1911 | Multiple active health-check protocols in one file. | Split by protocol after Pingora health adapters are gone. |
| `src/stream_proxy.rs` | 1026 | Current Pingora service-registration, listener, socket connect, and TLS adapter for stream routes after the 1.6.3 stream crate extraction. | Keep shrinking as background/runtime supervision and TLS connector abstractions move in `1.6.4`-`1.6.7`. |
| `crates/fluxheim-config/src/config_php.rs` | 1641 | PHP-FPM config and validation. | Split managed/runtime/path validation helpers. |
| `src/web.rs` | 1507 | Root static web adapter over `fluxheim-web`. | Reduce to adapter glue after native HTTP runtime lands. |
| `crates/fluxheim-cache/src/headers.rs` | 1482 | Cache directive parsing and policy helpers. | Split request/response directive modules. |
| `src/php_fpm.rs` | 1348 | Root PHP-FPM proxy adapter and response handling. | Move remaining pure pieces into `fluxheim-php-fpm`. |
| `crates/fluxheim-snapshot/src/lib.rs` | 1570 | Snapshot store implementation plus self-healing snapshot runtime state in crate root. | Split into store, id, metadata, runtime state, rollback, and fs modules. |
| `crates/fluxheim-observability/src/lib.rs` | 1139 | Observability crate root still hosts multiple exporters/helpers. | Split metrics, tracing, OTLP, and access-log modules. |
| `crates/fluxheim-config/src/config_header.rs` | 1060 | Header policy config and validation. | Move with header-policy crate work. |
| `crates/fluxheim-load-balancer/src/selection.rs` | 1050 | Selection algorithms grouped in one reviewed module. | Keep grouped until algorithm API stabilizes, then split tests/helpers. |
| `src/udp_proxy.rs` | 1038 | UDP beta runtime. | Split before beta promotion. |
| `crates/fluxheim-stream/src/lib.rs` | 948 | Stream upstream selection, source policy, copy-loop limits, DNS guards, and PROXY protocol helpers grouped during the 1.6.3 extraction. | Split selector, source policy, copy loop, and PROXY protocol modules after the stream crate boundary stabilizes. |
| `crates/fluxheim-load-balancer/src/policy.rs` | 977 | Runtime backend policy overrides and keys. | Split keys, snapshots, and mutation policy. |
| `crates/fluxheim-config/src/config_stream.rs` | 947 | Stream proxy config and TLS validation. | Split with stream runtime cutover. |
| `crates/fluxheim-load-balancer/src/backend.rs` | 848 | Backend snapshots and runtime mutation surface. | Split backend set, health snapshot, and mutation helpers. |
| `crates/fluxheim-load-balancer/src/discovery.rs` | 876 | File/DNS/HTTP discovery and validation. | Split discovery backends. |
| `crates/fluxheim-cache/src/api.rs` | 819 | Cache admin/status DTOs. | Split status, lookup, purge, and preview DTOs. |
| `crates/fluxheim-config/src/reload.rs` | 809 | Reload classification and diff behavior. | Move snapshot/reload-safe classification into dedicated modules. |
| `crates/fluxheim-php-fpm/src/lib.rs` | 778 | PHP-FPM crate root still holds several pure domains. | Split params, response, retry, and managed runtime helpers. |
| `crates/fluxheim-config/src/config_admin.rs` | 755 | Admin config and validation. | Split ops socket, snapshots, auth, and status config. |
| `crates/fluxheim-load-balancer/src/persistence.rs` | 753 | Persistence, cookies, and request-view helpers. | Split cookie, header, source-IP, and state table helpers. |
| `crates/fluxheim-config/src/config_acme.rs` | 719 | ACME config and validation. | Move with `fluxheim-acme`. |
| `src/config_tester.rs` | 716 | Config tester CLI and profile logic. | Split profile checks from CLI output. |
| `crates/fluxheim-web/src/lib.rs` | 708 | Static web crate root. | Split range, directory listing, path safety, and response planning. |
| `crates/fluxheim-config/src/config_tls.rs` | 677 | TLS config and validation. | Split downstream/upstream TLS config helpers. |
| `src/stream_tls.rs` | 657 | Stream upstream TLS adapter. | Move with stream runtime cutover. |
| `crates/fluxheim-config/src/config_route.rs` | 641 | Route config and validation. | Split redirect, methods, cache, and path policy helpers. |
| `crates/fluxheim-cache/src/object.rs` | 637 | Cache object envelope, plaintext disk object format, and disk index helpers were grouped during the 1.6.2 cache extraction. | Split disk object format, serialized envelope, and disk index helpers after the root cache adapter shrinks. |
| `crates/fluxheim-cache/src/storage_bin.rs` | 627 | Storage-bin layout, manifest, allocation, and free-map helpers were moved together to preserve allocator review context. | Split manifest/layout, allocator, and index-entry helpers after the storage-bin file adapter moves out of `src/cache.rs`. |
| `src/edge_policy.rs` | 532 | Edge access/rate/geo policy. | Split policy decisions and runtime proof types. |
| `crates/fluxheim-cache/src/request.rs` | 545 | Cache request/range/slice planning plus native cache key identity. | Split key identity and range/slice planning if it grows further. |
