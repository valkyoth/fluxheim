# HTTP/3 Migration Feasibility

**Deferred research as of 2026-10-21**, retained for future Brynja/Vef and
transport evaluation. This is not an active 1.9.0 gate. The API gap remains
unresolved; see the [resumption conditions](../roadmap/http3-quic-commit-plan.md).

Investigation date: 2026-10-09. Comparison baseline: `d53388e5`.
This is a Commit 1 source-qualification result, not Commit 2, production
HTTP/3 support, or a vulnerability report against deployed Fluxheim.

## Outcome

**Transport continuity works in the isolated fixture. The selected application
policy contract is not qualified with the pinned public APIs.**

Quinn 0.11.12 / quinn-proto 0.11.19 and h3 0.0.8 / h3-quinn 0.0.10 preserve
an ongoing HTTP/3 POST and its response through port and IP changes in Linux
loopback tests. However, `remote_address()` can expose a new peer, and stream
bytes can reach the application, before new-path validation completes.
The reviewed public connection event API has no validated-path admission
transaction that serializes those changes with application policy and queued
response transmission.

The machine contract records `address_policy_evidence = blocked-api-gap`.
Structural CI can pass with this explicit result; `--acceptance` must fail.
Commit 2 remains blocked under the agreed checkpoint order. No dependency
versions, production code, or Brynja integration changed in this investigation.

## Executable Evidence

The [migration probes](../../tools/http3-source-probe/src/tests/migration.rs) run
inside the isolated source workspace with both ring and AWS-LC.

| Case | Evidence / result |
| --- | --- |
| Ongoing HTTP/3 port change | One POST uploads 512 KiB and receives a byte-for-byte echo, switching client sockets halfway through. Same request stream ID, stable connection IDs, TLS exporter result, and one connection per endpoint; response trailers complete. Pass. |
| Ongoing HTTP/3 IP change | Same fixture, moving from `127.0.0.1` to `127.0.0.2`. Linux-only loopback routing, with no host changes. Pass. |
| Peer identity before validation | Pause receives on both old and new client sockets before rebinding. The client cannot receive the new challenge. The server exposes the new peer and receives continuation bytes and another raw QUIC stream while its received PATH_RESPONSE count remains zero. Pass as characterization of the gap. |
| Fixture positive control | Resume client receives and require the server to receive a PATH_RESPONSE; the transport remains usable. This count is not used as a production validation signal. Pass. |
| Reject a policy-denied new IP before protected activity | Not qualified. No Fluxheim policy adapter exists in this probe; the timing/API gap prevents claiming a correct boundary. |
| Atomically reserve a new prefix budget before releasing the old charge | Not qualified. Counter arithmetic alone cannot synchronize admission with transport path selection and queued data. |
| Safe failure recovery, hostile path churn, and concurrent policy changes | Not qualified; require the missing integration boundary and later adversarial tests. |

The tests use verified ephemeral TLS and real UDP sockets. Futures are joined
under a 15-second outer deadline, with no detached new test tasks. The fixture
pauses network input, not Quinn's cryptography, and does not forge or parse
protected QUIC packets. New-stream input in the timing fixture is raw QUIC,
not a claim that an HTTP/3 handler has already authorized that input.

Scope limits: this is one sequential bidirectional POST, not concurrent H3
streams or two independent client implementations. Rebinding loopback sockets
models a peer-address change; it is not a physical Wi-Fi/mobile transition,
real NAT appliance, container, macOS, or Windows deployment proof. The live
matrix in Commits 18-21 remains mandatory. Existing `migration(false)` probes
remain negative controls; reconnect is not the chosen product contract.

## Source Review

Review uses the exact registry sources bound by
[the probe lock](../../tools/http3-source-probe/Cargo.lock), not an unpinned branch.

| Source | Observation |
| --- | --- |
| quinn `src/connection.rs`, `Connection::remote_address` | Locks and reads the transport's current address; does not return validation state or hold the lock through application admission and later writes. |
| quinn-proto `src/connection/mod.rs`, `Connection::remote_address` | Returns `self.path.remote`. |
| quinn-proto `Connection::migrate` and `src/connection/paths.rs` | Replaces the current path and initiates a challenge. The new path begins unvalidated. |
| quinn-proto `Frame::PathResponse` handling | A matching token from the current remote marks the path validated internally. |
| quinn-proto `Event` and quinn `forward_app_events` | Exposes handshake, connected/lost, stream and datagram events, but no path-proposed/validated/rejected admission transaction. |
| quinn `src/runtime.rs`, `AsyncUdpSocket` | Can filter socket input/output, but sees encrypted datagrams and addresses, not an authenticated connection/path generation and its application-policy reservation. |

Versioned API references:
[Quinn connection](https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html),
[transport events](https://docs.rs/quinn-proto/0.11.19/quinn_proto/enum.Event.html),
[socket adapter](https://docs.rs/quinn/0.11.12/quinn/trait.AsyncUdpSocket.html).

This is **not evidence that Quinn violates QUIC**. QUIC permits sending data
before path validation completes, subject to transport constraints. Our
selected requirement additionally gates IP/trusted-proxy authorization and
resource accounting; that stronger application contract must be implemented
explicitly. See [RFC 9000 section 9.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3).

## Why Simple Workarounds Are Insufficient

- Polling the current address cannot make a later dispatch/write atomic with a
  transport migration. It also does not identify a validated path.
- A PATH_RESPONSE counter does not identify which path was validated or prove
  the response token was accepted. It is a test observation, not authorization.
- Pausing application writes does not necessarily stop data already queued
  inside the transport from moving to a new destination.
- An address-wide UDP filter can enforce a coarse listener-wide network rule,
  but does not supply authenticated per-connection/vhost identity or atomic
  per-prefix permit transfer. A new source address alone is not authority to
  allocate trusted connection state.
- Pinning the original IP's privileges forever would be a different product
  policy. Disabling migration would lose seamless support. Neither is an
  approved substitute for the current contract.

These results reject those simple approaches, not every possible integration
strategy. A lower-level adapter could offer different control, but it needs its
own proof and must not reimplement QUIC security or rely on private internals.

## Recommended Next Decision

Prefer a narrowly scoped, upstream-supported Quinn admission interface before
replacing the whole stack. Merely adding an asynchronous notification is not
enough. The feasibility contract for that interface is:

1. Expose authenticated candidate/current path generations and validation
   state without exposing secret keys or using addresses as connection IDs.
2. Permit bounded application authorization and prefix-budget reservation
   before protected dispatch and queued application data can use the new path.
   Retain upstream challenge/response, anti-amplification and recovery logic.
3. Atomically commit or reject the transition, retaining the old charge until
   the new one is reserved. Handle rapid changes, stale decisions, cancellation
   and validation failure without permit leaks or unbounded pending work.
4. Demonstrate allowed movement, denied IP, exhausted target budget, and queued
   response data with executable adverse scheduling tests on both providers.

This is a proposed upstream capability, not an implemented or accepted upstream
patch, and its size/maintenance cost has not been established. No issue or PR
was published as part of this investigation. Do not start a private transport
fork silently. If a maintainable interface is unavailable, compare alternative
stacks against the same requirements, supported OS targets, and future Brynja
crypto boundary before changing the source lock. Do not weaken the gate to
make the current candidate pass.

## Reproduction

Local verification: all 7 probe tests passed with each provider, plus 10 repeated
runs of the 4 new multi-threaded migration tests per provider (80 additional
case executions). Both provider clippy runs passed with warnings denied; all
20 source-gate tests, probe dependency policy, formatting, Markdown links, and
release metadata checks passed. Acceptance correctly returned nonzero for
`blocked-api-gap`. Production workspace tests and native Windows/macOS tests
were not rerun for this isolated probe/documentation change. Fresh pentest and
GitHub results are still required for the new revision.

```sh
cargo test --locked --manifest-path tools/http3-source-probe/Cargo.toml
cargo test --locked --manifest-path tools/http3-source-probe/Cargo.toml --no-default-features --features aws-lc
cargo clippy --locked --manifest-path tools/http3-source-probe/Cargo.toml --all-targets -- -D warnings
cargo clippy --locked --manifest-path tools/http3-source-probe/Cargo.toml --no-default-features --features aws-lc --all-targets -- -D warnings
python3 scripts/test_http3_source_lock.py
python3 scripts/validate_http3_source_lock.py
# Expected nonzero exit: the known API gap still blocks acceptance.
python3 scripts/validate_http3_source_lock.py --acceptance
```
