# Commit 03 Audit Admission Remediation

Reviewed base: `12eb1e30d7a5da2760f6df9dfe50ecf92d8d5065`. This follow-up
addresses the pentest's minimum remedy for administrative audit bypass. It is
not a durable journal or a military-grade assurance claim. Retest and exact-SHA
CI remain required before Commit 04.

## Finding And Boundary

Previously an authenticated caller could exhaust the audit rate/queue, then
successfully mutate server state while the outcome was dropped. Authentication
and public/security lane isolation did not prevent this authenticated bypass.

Admin mutations now acquire a single-use permit **after authentication but before
dispatch or deadline recovery**. Admission checks all possible outcome filters,
worker availability, the independent audit rate limit and a shared atomic credit
pool. Audit credits cover held permits, queued events and the in-flight write,
bounded to 128 total. Background audit producers use the same pool. They cannot
consume a held permit. Completing a permit never repeats rate/filter admission.
An unused permit refunds capacity but not rate budget.

Unavailable admission returns 503 `audit_unavailable` without executing the
requested mutation. Automatic deadline rollback also reserves before changing
state, including watchdog and authenticated-read paths. It leaves pending
recovery intact if admission fails. Existing failed-rollback protections remain.

All audit outcomes must be enabled, including INFO success. The normal INFO
configuration works; a quieter configuration can use
`RUST_LOG=warn,fluxheim::event::audit=info`. Filtering any outcome deliberately
blocks mutations. Existing Linux/macOS admin, snapshot and cache smoke fixtures,
and the native Windows fixture, now use INFO to exercise this contract.

## Permanent Tests

- [Reservation tests](../../crates/fluxheim-observability/src/operational_audit_tests.rs)
  cover quota exhaustion without double admission, held/queued/in-flight capacity,
  competing background traffic, concurrent producers, unused permit refunds,
  outcome filtering and shutdown between reserve and completion.
- [Admin tests](../../src/admin/tests/admin_tests_audit_admission.rs) cover every
  mutating route's pre-dispatch rejection, missing/stopping dispatch, authentication
  ordering, read-only availability, no snapshot side effects under saturation,
  recovery after capacity returns, retained pending rollback and ambiguous
  completion errors. They use real isolated dispatchers, not an always-successful
  production bypass. Existing producer provenance and rollback tests remain.
- [Live smoke](../../scripts/smoke_operational_backpressure.py) starts real servers
  with stderr already full. It sends 1,200 hostile public requests, fills audit
  credits with authenticated attempts, verifies a new snapshot returns 503 with
  an unchanged snapshot listing, and verifies ordinary serving still works.
  Draining the pipe delivers 128 admitted audits and permits another successful
  snapshot. Shutdown with a permanently blocked sink stays bounded. The existing
  seven output/filter scenarios also remain required in CI.

Run the live scenarios with a freshly built binary:

```sh
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
python3 scripts/smoke_operational_events.py --binary target/debug/fluxheim
python3 scripts/smoke_operational_backpressure.py --binary target/debug/fluxheim
```

## Deliberate Limitations

Memory reservation is not persistence acknowledgment. A sink failure can race a
reservation or enqueue; a process crash can lose records or interrupt an operation.
If completion detects unavailable delivery, it returns 503
`audit_delivery_failed` with `operation_may_have_completed: true`, not false
success or an assurance that retry is safe. Later worker failure cannot rewrite
an already sent response. Inspect runtime state before retrying an ambiguous
operation. `written` means write plus flush, not fsync or remote acknowledgment.

Administrative requests and automatic rollback can become unavailable when their
audit lane is disabled/full/failed. Public security traffic cannot spend audit
credits, but a shared broken OS sink can eventually fill every lane. Background
ACME outcomes remain best effort; CLI operations are outside this admin API
contract. Legacy synchronous logging is still Commit 04 work.

For durable/high-assurance auditing, a separate design must write and synchronize
integrity-protected intent before mutation, record its outcome and recover
incomplete transactions, preferably with independent trusted persistence. That
larger capability is not silently implied by this fix.

## Local Verification

2026-10-23, Linux x86_64, Rust 1.99.1:

- Locked workspace: 1,811 passed, one existing privileged ACME test ignored.
- Application `profile-full,acme-client`: 253 passed; native server with Wasm,
  PHP, rustls and load balancing: 586 passed.
- Observability all features: 47 passed plus compile-fail doc test; feature-off
  tests passed. Privacy-profile admin suite: 60 passed.
- Seven live event scenarios, blocked-sink audit exhaustion/recovery and bounded
  shutdown, admin listener, snapshot lifecycle, proxy-cache and load-balancer smokes passed.
- Workspace and all-feature observability Clippy passed with warnings denied.
- Windows-target observability tests compiled; Windows release-script validator
  passed. No native Windows/macOS execution was performed here; CI must supply it.
- Dependency audit: 449 packages, no reported vulnerabilities; cargo-deny policies,
  formatting, documentation links, modularity and diff integrity passed.

No dependency versions, filesystem trust rules or authentication checks changed.
