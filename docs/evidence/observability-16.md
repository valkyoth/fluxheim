# TCP Readiness Port Qualification

Local qualification: 2026-11-08. This checkpoint follows `a62e7094` and covers
Commit 16. Independent pentesting and GitHub CI acceptance remain pending.

## Delivered

TCP health checks now apply `port_override` to a copy of the member's socket
address. The original member identity, application destination, discovery
record and administrative state are unchanged. Omitted overrides retain the
previous destination. TLS still performs the existing verified handshake.

The [load-balancer guide](../guides/load-balancer.md#separate-readiness-port),
[option reference](../reference/load-balancer-options.md) and
[TCP recipe](../../examples/load-balancer/tcp-health.toml) describe the behavior.
TCP reachability is not a substitute for application-level HTTP/gRPC readiness.

## Verification

| Check | Result |
| --- | --- |
| Regression before the fix | Three new tests failed: IPv4 destination, IPv6 destination, readiness failure |
| Locked Linux workspace suite | 2,064 passed; one existing privileged test ignored |
| Combined Wasm/PHP/load-balancer/Rustls server suite on Linux | 683 passed |
| Linux load-balancer suite with Rustls | 166 passed |
| Linux load-balancer suite with OpenSSL instead of Rustls | 166 passed |
| Native macOS Apple Silicon load-balancer suite with Rustls | 166 passed |
| Native Windows x86_64 load-balancer suite with Rustls | 164 passed; Unix-only tests excluded by configuration |
| Port-range and supported-protocol validation regression | Passed on Linux, macOS and Windows |
| Python load-balancer fixture tests | 12 passed on each native platform |
| Live proxy guide, retry, latency and readiness scenarios | Passed on Linux, macOS and Windows |
| Fresh non-root Wolfi load-balancer image | Existing balancing/persistence/failover smoke and separate TCP readiness smoke passed |
| Strict Clippy | Linux configuration and both load-balancer TLS backends; macOS Rustls load balancer passed |
| No-TLS production load-balancer check | Passed |
| RustSec and cargo-deny | No known vulnerabilities or policy failures; no locked package versions changed |
| Documentation layout, links, formatting, workflow syntax and diff checks | Passed |

The tests cover IPv4/IPv6 probe destinations, absent overrides, all-down and
recovery transitions, unchanged application selection, discovery refresh and
runtime retargeting. Separate application/readiness listeners demonstrate that
readiness failure blocks traffic and that application HTTP status does not
change a TCP monitor's result.

TLS fixtures generate ephemeral certificates and use test-local trust stores.
Both Rustls and OpenSSL accept the trusted certificate with the correct SNI,
reject an untrusted certificate, and reject a mismatched hostname on the
overridden port. They do not alter the operating system's certificate store.

The container smoke observes both original application responses and verifies
that the readiness listener receives connections without HTTP payloads. The
qualified local image identity was
`sha256:0d27c5e817e08eedaa739f8008ef7ad8b94d87b275d86602d43cfef9755f3b97`.
This records the tested image, not an independent provenance attestation.

## Boundaries

- The native Windows toolchain lacks Clippy; native compilation, unit tests and
  live proxy scenarios passed. Strict Clippy ran on Linux and macOS.
- No Windows ARM64 or native Linux ARM64 qualification was performed for this
  checkpoint. These results do not replace release-wide platform gates.
- The existing privileged ACME mount-namespace test remains ignored in the
  ordinary workspace run.
- The dedicated Windows VM shut down normally after testing. No shared-project
  VM, signing material or public deployment was modified.
- Outstanding correction planning and machine-specific logs remain local and
  are not part of this record.

## CI Runner Compatibility Follow-Up

The collector job in run `42461692825` failed before starting Fluxheim:
`ubuntu-latest` selected Ubuntu 26.04, which the locked Playwright 1.60.0
does not support for Chromium dependency installation. The collector job now
uses `ubuntu-24.04`; the browser version, lockfile and required collector checks
are unchanged. Other jobs retain their existing runner selection.

The new workflow regression failed before the runner correction and passes
afterward. It checks the qualified OS, locked installation commands and matching
Playwright package versions. Validation also passed for 46 collector fixture
tests, three guide tests, eight browser-input tests, 35 container-refresh tests,
and generated dashboard consistency.

A fresh Ubuntu 24.04 container successfully ran `npm ci --ignore-scripts`,
`playwright install --with-deps chromium`, and a headless page/title assertion
with the checked-in package lock. No host browser dependencies were installed.
This validates the failed installation boundary; the complete collector
workflow must still pass on GitHub after the fix is pushed. No Rust source or
production dependency changed in this follow-up.
