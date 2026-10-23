# Commit 03 Security Remediation

Reviewed base: `ee3192ee0152a598660448e9bf5c8e9095a7a028`. Local verification:
2026-10-23, Linux x86_64, Rust 1.99.1. This is remediation within Commit 03,
not approval to advance to Commit 04. Pentest/retest and exact-SHA CI are pending.

## Confirmed Findings

1. **Late admission and synchronous sink calls.** Rejected events had already
   allocated/encoded two representations and entered env_logger, whose empty
   records could still flush a blocked sink. Admission must precede that work.
2. **Shared security/audit budget.** Public denial traffic could consume the
   capacity intended for authenticated audit outcomes. The unexposed loss counter
   also made this suppression invisible to an operator.

Both mechanisms were replaced, not suppressed or exempted from review. The
[event contract](../architecture/structured-events.md) specifies the new boundary.

## Implementation

- Production `operational::emit` performs no encoding, logger call, write or flush.
  A fixed-message env_logger matcher preserves target/level/regex choices before
  admission. Disabled/uninitialized dispatch never falls back to synchronous I/O.
- Ordinary, security and audit each have a separate 100-record/second admission
  window, admission mutex, 128-entry channel and worker. Each queue contains only
  copyable finite event data and a timestamp. Public events cannot hold the audit
  admission lock, consume its quota or occupy its queue.
- Workers capture the safe envelope and encode only the configured format, then
  write and flush. A sink failure terminates that lane, counts the failure/queued
  discards and rejects new events without retry or recursive diagnostics.
- Admission contention, saturation and unavailable workers drop immediately.
  There are exactly three workers, not per-request threads. Queue memory and
  in-flight encoder allocations are bounded. Shutdown waits at most 500 ms total;
  it never joins indefinitely on an uninterruptible OS write.
- Authenticated `GET /_fluxheim/status` exposes per-lane acceptance, filtering,
  rate/queue losses, unavailable workers, encoded/written records, sink errors,
  discarded records, pending records and worker liveness. Null distinguishes an
  uninstalled dispatcher from a healthy zero-loss one. No secret identifiers,
  filenames or OS error strings enter these counters.
- File targets reuse clones of the securely opened handle. Path, ACL/reparse and
  symlink validation was not weakened. Producer reason/actor provenance, filter
  semantics, public responses and rollback-state protections remain unchanged.

The opt-in thread-local test helper captures producer events directly and is
explicitly not the delivery implementation. Dedicated dispatcher tests and live
process tests exercise the actual queue, admission, encoding and writer path.

## Permanent Regression Proof

[Dispatcher tests](../../crates/fluxheim-observability/src/operational_dispatch_tests.rs):

- A blocked security sink receives only one encoded in-flight event while a
  1,000-event burst admits 100 and rejects 900 before encoding. Holding its budget
  mutex still does not stop an audit being admitted and written independently.
- Advancing admission windows while a writer is blocked fills exactly 128 queued
  records plus one in flight. Further events are rejected without encoding;
  producer completion and shutdown have explicit test deadlines.
- Filter rejection does not even initialize an admission window. JSON/text output
  each has exactly one encoding in the selected format and retains the 8 KiB cap.
- Failed writes and failed flushes are visible, never counted as delivered, never
  retried recursively; queued losses are counted. Other lanes remain usable.
- Window recovery and saturating counters are checked. Admin tests retain
  authentication requirements for status and distinguish an uninstalled dispatcher.

[Live backpressure smoke](../../scripts/smoke_operational_backpressure.py):

```sh
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
python3 scripts/smoke_operational_events.py --binary target/debug/fluxheim
python3 scripts/smoke_operational_backpressure.py --binary target/debug/fluxheim
```

The first smoke passes seven JSON/text/filter/privacy-canary scenarios, including
the original five and added stdout/file-output checks.
The new smoke starts real Fluxheim processes with a prefilled, unread stderr pipe.
Each receives 1,200 strict-host rejection requests, still serves normal static
content, reports security losses through authenticated status, and accepts a
snapshot with independent audit admission. Draining the pipe produces exactly
one snapshot audit with the proper actor/outcome and no secret canary. A second
run keeps the pipe blocked and verifies process shutdown within six seconds.
Both scenarios are required in Linux CI.

These tests enable only typed event targets to isolate this delivery boundary.
They do not prove that unrelated legacy startup/shutdown/free-form logging is
asynchronous; that remains explicit Commit 04 work.

## Local Regression Results

- Full locked workspace tests: 1,799 passed; one pre-existing privileged ACME test ignored.
- Native server with Wasm, PHP, rustls and load balancing: 586 passed.
- Application with `profile-full,acme-client`: 248 passed.
- Observability all-feature suite: 40 passed plus compile-fail doc test.
- Privacy-profile admin event tests: 3 passed.
- Workspace all-target Clippy and all-feature observability Clippy: warnings denied.
- Observability tests cross-checked for `x86_64-pc-windows-msvc`; compile-only.
- Audit: 449 locked dependencies, no advisories/warnings; cargo-deny policies passed.
  RustSec database: `6e868779ba1c38dc4a1bc8090b8c22d15dc69e56` (2026-10-23).

## Limits And Review Gate

Audit logging is **best effort**, not a transactional/durable journal. Audit
traffic can exhaust its own lane. Public traffic cannot consume its reservation,
but all writers may depend on the same blocked or failed OS sink. An accepted
audit is not proof of persistence. Mutations do not reserve durable audit storage
or fail closed on audit loss; operator filters can disable auditing deliberately.
Deployments requiring such guarantees need an explicit future durability policy,
not an assumption that this queue provides one. No military/compliance guarantee
is made. Worker-only sink I/O prevents these typed events from blocking serving;
it does not make disk, container logging or stdout inherently reliable.

No dependencies or lockfile versions changed. Native Windows/macOS execution
was not performed locally and must be checked by native CI. Do not reinstate the
shared protected bucket or formatter-time admission to address future test/CI
failures. Broader Commit 04 logging work remains gated on this retest and CI.
