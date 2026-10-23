# Observability Commit 03 Evidence

Base: `74dbb1603fb3eea6aee9e2921e448304d4dcf34f`. Local qualification on
2026-10-23, Linux x86_64, Rust 1.99.1. This checkpoint is not accepted until
the user's pentest and exact-final-SHA GitHub/CodeQL pass. Git records the final
SHA; this document does not self-embed it.

## Scope And Trust

The [structured event contract](../architecture/structured-events.md) now has
runtime producers. Error categories come from resolver, socket, protocol,
TLS, FastCGI, cache and policy owners, not an interpretation of a final HTTP
502/503. Successful recovery can therefore coexist with a failed-attempt event.
An event is not a logical request counter. PHP attempts are one-based; other
owners omit an attempt ordinal when they do not own the retry sequence.

Producers pass finite codes, never raw exception strings, paths, headers,
cookies, query strings, certificate data, plugin output or key material.
Correlation is empty, resources are omitted, and privacy mode remains a
compile-time restriction. No producer derives trust, filter policy or actor
from client headers. Numeric revision is omitted: existing snapshot IDs are
not a stable numeric generation and must not be substituted into this field.

Admin mutation identity comes from an exact method/path whitelist. Both token
and client-certificate authorization precede mutation audits and request-triggered
self-healing deadline enforcement. `admin_token` describes a shared credential
class, not an identified human. Automatic deadline rollback and certificate
renewal/reload use `automatic`. Failure to roll back still prevents confirmation
and keeps recovery pending. Audit outcome describes the operation's result;
it does not assert that the whole server is healthy.

## Coverage Map

The named tests below are permanent. Most exercise real loopback peers or
filesystem failures through the handler and assert both public behavior and
the private event. Explicit owner-only tests are identified, not claimed as
end-to-end networking. Existing success-path tests remain in the same suites.

| Reason / operation | Regression evidence |
| --- | --- |
| `dns` | [operational_events.rs](../../crates/fluxheim-server/src/native_http1_proxy_tests/operational_events.rs): malformed resolver input fails locally, 502/body unchanged, canary absent |
| `connection_refused` | Same file: bound non-listening socket, 502 and exactly one refusal, no protocol error; separate live binary smoke below |
| `connection_timeout`, `read_timeout`, `write_timeout` | [client tests](../../crates/fluxheim-server/src/native_http1_client/tests.rs): explicit owner classification preserves IO kind and excludes raw message; [runtime behavior](../../crates/fluxheim-server/src/native_http1_proxy_tests/runtime_behavior.rs): stalled origin returns 504; operational tests: blocked duplex write times out exactly once |
| HTTP/2 timeout/retry | [h2.rs](../../crates/fluxheim-server/src/native_http1_proxy_tests/h2.rs): stalled handshake/request gets one phase-specific event; client tests preserve retry-safe classification and one event per failed attempt |
| `upstream_protocol` / failover | [static_upstream.rs](../../crates/fluxheim-server/src/native_http1_proxy_tests/static_upstream.rs): accepted-then-closed connection, safe GET failover and unsafe POST rejection retain one failure event |
| `tls_verification`, `tls_handshake` | [TLS tests](../../crates/fluxheim-server/src/native_http1_proxy_tls_tests.rs): wrong hostname versus plaintext peer, 502 and distinct reason; peer canary absent |
| `php_connect`, `php_protocol`, `php_timeout` | [PHP route tests](../../crates/fluxheim-server/src/native_http1_route_proxy_tests/php_fpm.rs): unavailable, malformed and stalled FastCGI peers retain 502/body and finite cause |
| `cache_read`, `cache_write`, `cache_encryption` | [cache event tests](../../crates/fluxheim-server/src/native_http1_cache_event_tests.rs): corrupt stored entry becomes a miss; blocked shard path returns store error; missing key rejects initialization without exposing path |
| `wasm_denied`, `wasm_trap`, `wasm_timeout`, `wasm_execution` | [Wasm tests](../../crates/fluxheim-server/src/native_http1_route_proxy_tests/wasm.rs): denial, trap, fuel/deadline and invalid output remain fail-closed with the matching event |
| `rate_limit`, `admission_rejected` | [rate/concurrency tests](../../crates/fluxheim-server/src/native_http1_route_proxy_tests/rate_concurrency.rs): second requests retain rejection statuses; finite admission events also wired at H2 slots, cache fill/blocking queues, Wasm and PHP limits |
| `host_rejected`, `request_limit`, `path_rejected` | [host tests](../../crates/fluxheim-server/src/native_http1_host_router_tests.rs), [body tests](../../crates/fluxheim-server/src/native_http1_body_policy_tests.rs), PHP tests: original denial/status assertions plus event reason |
| `authentication_rejected`, `authorization_rejected` | [admin provenance](../../src/admin/tests/admin_tests_events.rs) and [auth tests](../../src/admin/tests/admin_tests_auth.rs): invalid token and denied client certificate cannot generate a successful mutation audit |
| `acme`, `reload` / automatic audits | [background event tests](../../src/runtime_background_events.rs): success/failure for each owner helper, finite codes and automatic actor; these are helper tests, not external CA issuance |
| `rollback` / automatic and admin outcomes | [self-heal tests](../../src/admin/tests/admin_tests_self_heal_rollback.rs): successful deadline rollback and failed rollback blocking both confirmation and successful health reports |
| Snapshot/reload mutation audit | [snapshot tests](../../src/admin/tests/admin_tests_snapshot.rs), admin provenance tests: success, authenticated rejection, unknown route exclusion, spoofed actor/correlation/secret canaries |
| Cache and load-balancer mutation audit | [cache purge](../../src/admin/tests/admin_tests_cache_purge_basic.rs), [activity reset](../../src/admin/tests/admin_tests_cache_status.rs), [member state](../../src/admin/tests/admin_tests_lb_status.rs): original mutation result plus authenticated audit |

Cache encryption failures may also have a cache read/write boundary event.
These are distinct causal and operation outcomes, not two logical requests.
No live remote DNS dependency is needed for the resolver rejection test. The
H2 readiness API can complete before peer SETTINGS: its stalled-peer test
accepts the actual connection or response-read phase, never infers it from HTTP.

## Delivery Bounds And Compatibility

The initial implementation used synchronous logging, late admission and shared
security/audit capacity. Pentest identified both as release-blocking. Those
mechanisms are superseded by the [security remediation](observability-03-security.md):
filter/admission before encoding, three independent bounded queues, worker-only
typed-event sink I/O and authenticated status/loss counters. Public security
traffic cannot consume audit admission or queue capacity. The wire envelope and
existing filtering/privacy rules are retained. This is not a durable audit journal.

No collector or configuration option is added. Commit 04 retains the remaining
legacy logging migration and wider resource/performance qualification. The local
test results below record the original checkpoint; the remediation document
records the new tests and reruns. No throughput improvement is claimed here.

Legacy logs are not globally rewritten or sanitized. Background ACME per-target
raw error/domain/issuer messages are intentionally replaced by finite outcomes;
aggregate counts remain. CLI/companion logs, stream/UDP diagnostics and pre-request
downstream TLS logs retain their existing behavior. Access completion/correlation
belongs to Commit 06; this checkpoint does not claim that all existing logs or
all network transports have been migrated.

## Live Linux Proof

```sh
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
python3 scripts/smoke_operational_events.py --binary target/debug/fluxheim
```

Five scenarios passed against fresh Fluxheim processes and real TCP requests:
JSON, text, target disabled, matching message regex and nonmatching message
regex. Every request retained the expected 502 body. Enabled records had one
finite refusal cause, no resource/correlation and no secret canary from the URL,
query, authorization, cookie or spoofed actor/request ID. CI runs this smoke.

This is a live Linux binary test, not a container/collector or Windows/macOS
qualification. Native CI remains required; the later cross-platform and backend
checkpoints retain container, collector, Windows and macOS runtime tests. No
external ACME issuance, FIPS qualification or performance acceptance is claimed.

## Local Verification

Final qualification commands exited 0:

| Command | Result |
| --- | --- |
| `cargo test --locked --workspace -- --quiet` | 1,793 passed, one existing privileged ACME mount-namespace test ignored |
| `cargo test --locked -p fluxheim-server --lib --features wasm,php-fpm,tls-rustls,load-balancer -- --quiet` | 586 passed; includes failure/event and existing behavior assertions |
| `cargo test --locked -p fluxheim --lib --no-default-features --features profile-full,acme-client -- --quiet` | 247 passed, including authenticated mutation, rollback and background outcome tests |
| `cargo test --locked -p fluxheim-server --lib --features tls-openssl native_http1_proxy_tls_tests -- --quiet` | 6 passed with OpenSSL selected, including verification versus handshake failure |
| `cargo test --locked -p fluxheim-observability --all-features -- --quiet` | 35 passed plus compile-fail doc test; includes privacy mode and admission bound |
| `cargo test --locked -p fluxheim-observability --no-default-features -- --quiet` | 14 passed |
| `cargo test --locked -p fluxheim --lib --no-default-features --features profile-privacy admin::tests::events -- --quiet` | 2 passed; request input cannot set trusted actor/correlation |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed |
| `cargo clippy --locked -p fluxheim-server --all-targets --features wasm,php-fpm,tls-rustls,load-balancer -- -D warnings` | Passed |
| `cargo check --locked -p fluxheim-observability --target x86_64-pc-windows-msvc --no-default-features --features structured-events,test-support --tests` | Passed, compile-only; not native execution of the full server |
| `cargo audit --json` / `cargo deny check` | 449 dependencies, zero vulnerabilities/warnings; policies passed; no locked version changes |

Audit database commit: `f7b2f6bc663452200bbe639ebb75e0c762b3422b` (2026-10-23).
Formatting, diff integrity, modularity, Markdown links, documentation layout (4),
observability baseline (3), development scope (7), release metadata (3) and release
metadata validation also passed. Existing public status/body and security-state
assertions were retained; new event assertions supplement them.

Pending: user pentest, exact-final-SHA GitHub/CodeQL, native Windows/macOS CI
results and explicit approval before Commit 04. No release/tag is authorized by
this checkpoint.
