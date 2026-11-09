# Health-Check Connection Reuse Qualification

Local qualification: 2026-11-09. Commit 17 follows
`e15a61c01148ca245f5df0fa52ed9aaa078a53cc`. Independent pentesting and
exact-commit GitHub acceptance were subsequently confirmed by the owner through
`8159ae69`, authorizing Commit 18.

## Delivered

`reuse_connection = true` now enables HTTP/1.1 keep-alive or successive gRPC
HTTP/2 streams. The default false path retains fresh-per-probe behavior.
TCP, exec and database monitors reject unsupported activation, including in
the runtime constructor when configuration validation is bypassed.

Reusable HTTP/1 framing uses Hyper; gRPC retains the existing h2 implementation
and shared bounded response/status validator. Hyper, hyper-util and
http-body-util were already checksum-locked dependencies. This change adds
direct dependency edges, not new package versions.

Connections are scoped to the monitor's immutable transport/TLS configuration
and original backend socket address. Each backend has one slot, with a maximum
of 256 slots per monitor and no waiter queue. Idle connections expire after 30
seconds; five-minute-old connections are retired before reuse. A once-per-second
cleanup task closes expired idle sockets even without another probe.

Successful complete response validation is required before returning a
connection. Failure, cancellation, invalid framing, incomplete/oversized bodies,
server closure and removal invalidate it. Membership identities prevent an old
cancelled lease from deleting or replacing a newly added member's slot. Shutdown
cancels active probes, closes the pool and stops its cleanup task. Parallel
sweeps no longer detach probe tasks when cancelled. Failed exchanges are never
automatically resent.

See the [user guide](../guides/load-balancer.md#reuse-http-and-grpc-probe-connections),
[option reference](../reference/load-balancer-options.md) and
[HTTP recipe](../../examples/load-balancer/http-health.toml).

## Verification

| Check | Result |
| --- | --- |
| Locked Linux workspace suite | 2,079 passed; one existing privileged test ignored |
| Linux load-balancer suite, Rustls | 185 passed |
| Linux load-balancer suite, OpenSSL | 185 passed |
| Combined Wasm/PHP/load-balancer/Rustls server suite | 683 passed |
| Native macOS Apple Silicon load-balancer suite | 185 passed |
| Native Windows x86_64 load-balancer suite | 183 passed; Unix-only tests excluded by configuration |
| Reuse protocol validation | Passed on Linux, macOS and Windows |
| Actual server: balancing, retries, latency, TCP readiness, HTTP reuse/failover/recovery/shutdown | Passed on Linux, macOS and Windows |
| Fresh non-root Wolfi load-balancer image and live reuse smoke | Passed |
| Strict Clippy | Linux load balancer with both TLS backends, combined-feature server, and macOS Rustls load balancer passed |
| No-TLS production load-balancer check | Passed |
| RustSec and cargo-deny | 449 locked dependencies, zero known vulnerabilities; advisories, bans, licenses and sources passed |
| Python reuse/TCP/retry fixture tests | 15 passed on Linux |
| Documentation layout | 28 passed |
| Documentation links, Rust formatting, Python/shell syntax, modularity and diff checks | Passed |

Real TCP HTTP and gRPC fixtures count four accepted connections for four fresh
probes, versus one with reuse. Regression coverage includes concurrent probes,
per-backend isolation despite a common readiness port, chunked trailers, HEAD,
header/trailer/body limits, incomplete frames, gRPC failure/GOAWAY, cancellation,
idle/age expiry, capacity exhaustion, discovery and admin membership hooks,
semantic rejection, recovery and shutdown. Idle-expiry tests also observe the
remote socket closing, not just removal from a map.

Ephemeral TLS fixtures verify successful reuse and rejection of untrusted
certificates and incorrect hostnames. Separate monitor configurations cannot
borrow an earlier monitor's trusted connection. Tests do not modify system
certificate stores.

The full-server HTTP smoke uses separate application and readiness listeners.
Two members sharing one readiness port retain two independent connections with
reuse, while fresh mode accepts one connection per probe. Chunked trailers,
all-down routing, recovery and socket closure on shutdown are checked. This
smoke is included in the existing native guide and container qualification
entrypoints. gRPC connection-count/fault/TLS coverage uses real TCP/TLS fixtures
in the native Rust suite; it is not a claim of a separate full-server gRPC
deployment test.

The tested local Wolfi image was
`sha256:f4663ec97a273d823540a4ecdfd3cdbbc882371ffd12d272cb5abc338973e8ea`.
This identifies the test build, not independently authenticated provenance.

## Boundaries

- Native Windows lacks Clippy; strict Clippy runs on Linux and macOS.
- Native Linux ARM64 and release archives were not rebuilt for this checkpoint.
  Final release-wide platform/archive qualification is still required.
- The privileged ACME mount-namespace test remains ignored in the ordinary
  workspace suite.
- The dedicated Windows VM shut down normally after testing; no shared-project
  VM or public deployment was modified.
- These are correctness and regression tests, not independent artifact
  provenance or a whole-server security certification.
- Unresolved correction planning and machine-specific logs remain local.
