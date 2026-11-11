# Stale-Cache Error Classification Qualification

Local qualification: 2026-11-09. Commit 18 follows
`8159ae69b899da8a0c1d82ebd8b205477c9f27cd`. The owner supplied a clean
pentest through `a6edc73a`, reported GitHub green and authorized Commit 19.
This is acceptance for progression, not final release qualification.

## Delivered

Native upstream errors now retain typed connection, TLS, request-write and
response-read phases. HTTP/2 errors also retain their underlying transport
reason for cache selection. Classification never searches error strings.
The existing outer I/O error kind remains unchanged for transport replay,
connection-pool handling and gateway error responses.

Timeout takes precedence over all phases. Non-timeout handshake failures use
`tls`; outside TLS, reset/closure and protocol failures take precedence over
remaining connection/read/write errors. Permission errors outside TLS remain
`other`. Already-classified failures cannot be overwritten by an outer phase.
HTTP status selection remains separate and subject to its explicit 5xx list.

This corrects previously ineffective `read`, `write` and `tls` selectors.
Narrow policies that depended on TLS or HTTP/2 failures appearing as generic
`other`/`protocol` require review. See the
[category and compatibility guide](../guides/cache.md#choose-the-failure-categories)
and [option reference](../reference/cache-options.md#freshness-and-stale-responses).

TLS verification, freshness windows, cache eligibility, mandatory revalidation,
normal responses and retry admission are not relaxed. Permission to serve a
previously trusted stale object does not admit data from a failed TLS connection.
No Cargo manifests or locked dependencies changed.

## Verification

| Check | Result |
| --- | --- |
| Locked Linux workspace suite | 2,092 passed; one existing privileged test ignored |
| Combined Wasm/PHP/load-balancer/Rustls server suite | 692 passed |
| Linux OpenSSL/load-balancer server suite | 588 passed |
| Native macOS Apple Silicon Rustls/load-balancer server suite | 590 passed |
| Native Windows x86_64 Rustls/load-balancer server suite | 588 passed |
| Live stale-policy smoke: Linux, macOS and Windows binaries | Eight cases per platform passed |
| Fresh non-root Wolfi container stale-policy smoke | Eight cases passed |
| Cache guide, disk restart and backend migration smoke | Passed on Linux, macOS and Windows |
| Strict Clippy | Combined-feature Linux server and native macOS server passed |
| Minimal server without default features | Passed |
| RustSec and cargo-deny | 449 locked dependencies; zero known vulnerabilities; advisories, bans, licenses and sources passed |
| Cache fixture and documentation tests | 15 passed |
| Shared Windows fixture regression tests | 11 passed; one native-Windows-only case skipped on Linux |
| Documentation layout | 28 passed |
| Documentation links, formatting, syntax, modularity and diff checks | Passed |

The error matrix checks precedence, exact allowlists, absent stale permission,
mandatory-revalidation rejection, preservation of transport retry kinds and
independence from arbitrary error text. Deterministic AsyncRead/AsyncWrite
fault injection covers generic read/write failures that real TCP normally
reports more specifically as closure or timeout. HTTP/2 conversion tests obtain
actual h2 I/O errors from a faulty transport rather than matching its text.

A 27-case real TCP matrix covers allowed/denied closed connections, malformed
HTTP and read timeouts across memory, filesystem disk and storage bins. Disk
cases stop and reopen the cache before the failure. Mandatory revalidation and
successful recovery are checked. Separate persistent HTTP/2 fixtures exercise
stream-reset selection through static and load-balanced dispatch and assert
that no hidden retry occurs.

TLS fixtures first cache a valid response, then present a certificate with the
wrong hostname, and finally recover with the valid certificate. Both HTTP/1
and negotiated HTTP/1-or-HTTP/2 configuration paths are exercised. A `tls` policy
can reuse the old response; a `protocol`-only policy cannot. The failed server
handshake must never complete successfully. Existing untrusted-CA and TLS
verification regressions remain in the native suites.

The standalone smoke starts a real server and loopback fault origin. It checks
allowed and denied connection closure, protocol errors, timeouts and HTTP 503;
every case checks cold-cache rejection, stale-window expiry, recovery and the
next cache hit. Linux, macOS and Windows CI now run this smoke. Real TCP tests
and deterministic transport injection are complementary; this is not a claim
of every OS fault in every cache/backend/protocol combination.

The guide harness now uses the existing protected-directory helper on Windows,
prints bounded configuration-validation diagnostics, and waits for the normal
storage-bin checkpoint before a restart test. Windows process termination does
not run Rust destructors. The checkpoint observation is bounded and tolerates
temporary sharing denial during atomic replacement; persistent failures still
fail the test. Runtime ACL checks and restart assertions remain unchanged.

Tested Wolfi image:
`sha256:89fb7304ed206be7758363b89f4abb40158fbbcfba48cef45f3de4f617e19824`.
This identifies the local test image, not independent artifact provenance.

## Boundaries

- Native Linux ARM64 and release archives were not rebuilt for this checkpoint.
  Final release-wide qualification remains required.
- Native Windows lacks Clippy; Linux and macOS provide strict Clippy checks.
- One Linux guide smoke timed out during concurrent build activity; its complete
  rerun passed. No assertion or request timeout was relaxed to obtain that pass.
- The ordinary workspace suite still skips its privileged ACME namespace test.
- No public server, shared-project VM or system certificate store was modified.
- Unresolved correction planning and machine-specific logs remain local.
- These tests do not replace the independent pentest or exact-commit CI gate.
