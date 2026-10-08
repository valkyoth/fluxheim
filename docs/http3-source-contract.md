# HTTP/3 Commit 1 Source Contract

Candidate reviewed on 2026-10-08. This is source admission evidence, not a
claim that Fluxheim serves HTTP/3. Commit 2 requires revised source qualification,
pentest, retest, and GitHub green. The [commit plan](http3-quic-commit-plan.md) remains
the sequencing authority; [the JSON contract](http3-source-lock.json) assigns
each finite requirement exactly one implementation owner.

## Baseline And Refresh

- Review baseline: `fc1b5983af97434786065c08cab2202cb544be6b`.
- Released runtime baseline: `v1.8.2`, commit
  `6ed82b5a9ebd5b8f1bb4bc03f986edd9a33ae855`.
- The user authorized both Commit 1 and a full tooling/dependency refresh.
  Existing cross-platform release evidence is historical, not execution of
  this candidate on Windows or macOS. Those native CI jobs must pass again.
- Rust 1.99.0, matching workspace minimums, RPM minimum and digest-pinned Rust
  builder images replace 1.98.1. At the user's request, the development
  workspace and RPM metadata now report 1.9.0 (unreleased); published tags and
  historical release evidence remain unchanged.
- Stable direct dependencies and both production/fuzz lockfiles were refreshed,
  including Wasmtime/WASI 49.0.2 and MaxMind DB 0.32.0. The UDP session counter
  uses Rust 1.99's `try_update` name instead of deprecated `fetch_update`, with
  the existing atomic ordering/admission behavior preserved and retested.
- Docker setup-qemu v4.4.0, setup-buildx v4.4.1 and build-push v7.4.0 use
  resolved immutable commit pins. Checkout v7.0.1 and login v4.6.0 remain current.
- cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-sbom 0.10.0 and rustup 1.29.1
  remain current. Sanitization 2.1.0 and base64-ng 2.0.4 remain current.
  Prereleases were not selected. This review does not upgrade OS release lines
  or claim the existing runtime/container base images were rebuilt here.

## Exact Dependency Boundary

The [isolated probe workspace](../tools/http3-source-probe/Cargo.toml) has no
Fluxheim dependency and is not a root workspace member. Its checked-in
[Cargo.lock](../tools/http3-source-probe/Cargo.lock) pins the complete transitive
graph with registry checksums. The JSON contract also pins the lockfile hash;
changes require renewed review. Production `Cargo.lock` contains no QUIC/H3
or Brynja package. Cargo's existing feature profiles are unchanged.

| Package | Version | License | Role |
| --- | --- | --- | --- |
| quinn | 0.11.12 | MIT OR Apache-2.0 | Async endpoint/connection and crypto integration |
| quinn-proto | 0.11.19 | MIT OR Apache-2.0 | Transport state, loss/recovery, tokens and migration policy |
| quinn-udp | 0.5.16 | MIT OR Apache-2.0 | OS-specific datagram/ancillary-data handling |
| h3 | 0.0.8 | MIT | HTTP/3 control, request streams and stateless QPACK |
| h3-quinn | 0.0.10 | MIT | Quinn transport implementation of h3 traits |
| rustls | 0.23.45 | Apache-2.0 OR ISC OR MIT | TLS 1.3 QUIC session integration |
| tokio | 1.53.2 | MIT | Runtime, sockets and cancellation |
| http / bytes | 1.5.0 / 1.12.1 | MIT / MIT | HTTP fields and body buffers |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | Probe-only ephemeral certificate fixture |

Versioned upstream API references:
[Quinn](https://docs.rs/quinn/0.11.12/quinn/),
[QUIC crypto traits](https://docs.rs/quinn-proto/0.11.19/quinn_proto/crypto/),
[h3 server](https://docs.rs/h3/0.0.8/h3/server/),
[h3-quinn](https://docs.rs/h3-quinn/0.0.10/h3_quinn/).
Upstream [h3 status](https://github.com/hyperium/h3#status) still calls the
library experimental. A passing compatibility probe is not full conformance
or an upstream maintenance guarantee; keep the default-off dedicated profile
and repeat advisory/maintenance review at Commit 23.

### Feature And Platform Decisions

- Disable defaults on Quinn, rustls and the integration crates. Enable only
  Tokio and the explicitly selected ring or AWS-LC rustls provider. No platform
  trust-store helper is needed by the ingress probe. h3-quinn transitively
  enables Quinn's futures-io support; this is admitted and source-locked.
- Test providers separately, with expected compile rejection for neither/both.
  The probe's AWS-LC build is not FIPS evidence. Existing FIPS requirements and
  platform availability require separate qualification in Commit 5; do not
  substitute ordinary AWS-LC for a configured FIPS provider.
- The future stock profile includes full, HTTP/3, PHP/FastCGI, ACME and
  observability as enumerated in JSON. Wasm is separately selected. None of
  these future feature declarations are activated in Commit 1.
- Candidate targets: Linux x86_64/aarch64, macOS Apple Silicon, Windows x64
  MSVC. The transport has Unix/Windows backends; this is not native execution
  proof. Commits 18-20 and the final candidate require actual packaged tests.
- Static/literal QPACK only. h3's `server/stream.rs` uses `encode_stateless`,
  and its request/trailer paths use `decode_stateless`. No configurable dynamic
  table is exposed by the selected builder. RFC 9204's default zero local table
  capacity/blocked-stream allowance is the initial contract. Commit 8 must
  test wire settings and rejection of references violating those bounds.
- Streaming body and trailer APIs are available. `send_trailers` still requires
  `finish` to finalize the stream. The probe proves first-byte receipt before
  producer completion with a channel handshake, then validates trailing fields.
  It does not prove Fluxheim shared-handler streaming; that belongs to Commit 4.
- Advanced priority scheduling, dynamic QPACK, Extended CONNECT, WebTransport,
  DATAGRAM, 0-RTT, server push and H3 origins are not admitted. Ordinary
  informational response semantics still need the Commit 2/10 parity tests.

## Standards And Ownership

| Standard | Owned obligations | Implementation checkpoint |
| --- | --- | --- |
| [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999.html) | Version/header invariants, reject unadmitted versions | 1 source classification; 6/21 implementation/proof |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) | Socket/stream lifecycle, address validation, anti-amplification, bounded transport state | 6, 7, 8, 16 by requirement ID |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) | TLS 1.3, ALPN, packet/header key ownership, no 0-RTT | 5; lifecycle integration in 16 |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) | Use upstream loss/congestion implementation, impaired-network evidence | 21 |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html) | Control/settings, message semantics, routing, GOAWAY | 8-13 and 16 by requirement ID |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html) | Zero dynamic-table/blocked-stream policy, bounded decoded fields | 8 |
| [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218.html) | Bounded priority parsing; advanced scheduling not promised | 8 |

This is a requirement allocation, not a claim that every RFC obligation is
already verified. The scope gate rejects missing, duplicate, unclassified or
reassigned requirements and forbidden extensions. Future additions need an
explicit reviewed contract update, not a relaxed validator to hide a failure.

## Address Policy Decision

**User-selected scope (2026-10-08):** seamless validated NAT rebinding and active
client migration, preserving the existing connection and HTTP/3 streams.
Reconnect-required behavior is not the release contract. Source qualification
for this expanded requirement remains pending; do not advance to Commit 2.

Source inspection of quinn-proto 0.11.19:
`transport_parameters.rs` sets `disable_active_migration` when migration is
false; `connection/mod.rs` drops packets from changed remote socket addresses
in that mode. The switch does not distinguish NAT rebinding from intentional
migration. RFC 9000 section 9 distinguishes active migration from involuntary
NAT changes, so disabling active migration must not be advertised as seamless
NAT rebinding support. This disabled configuration cannot satisfy the selected
scope; it remains a negative characterization fixture, not a proposed runtime
setting or permission to weaken address validation.

The executable source-port and Linux source-IP probes establish TLS, transfer
bytes and rebind the client socket. They prove no data is delivered on the old
connection, observe the bounded idle timeout, then reconnect and transfer bytes
successfully. A
migration-enabled control case proves the fixture can actually traverse the
new path. The IP fixture uses Linux's loopback routing for `127.0.0.2`, not a
real NAT or multi-interface deployment. Deliberate endpoint rebinding and NAT
rebinding present the same changed-peer-address input to this server switch;
neither is separately admitted by `migration(false)`.

These probes do not establish ongoing HTTP/3 stream continuity, real network
switching, or safe application authorization during path changes. Before
recording `address_policy_evidence = source-qualified`, extend the source
review and executable adapter-feasibility probes to demonstrate validated-path
events, policy gating before new dispatch and continued sensitive delivery,
and bounded atomic prefix-budget transfer without identity races. Reading
`remote_address()` after the fact is insufficient. If the exact pinned stack
cannot support the boundary, revise the dependency choice or obtain an upstream
capability; do not silently downgrade to reconnect-only or add custom QUIC
security. The current lock is a candidate, not a capability certification.

Commit 4 owns the provider-neutral path-event/admission boundary; Commit 7
implements original/current peer identity, IP/trusted-proxy re-evaluation,
bounded validation/churn, budget transfer and failed-path recovery. Commits
9/10/12 preserve streams and avoid origin replay. Commits 18-21 execute the
[live continuity fixture](http3-quic-commit-plan.md#live-continuity-fixture)
against actual Linux/container, macOS, and Windows artifacts, with independent
clients and impairment. Long outages or denied new paths may fail closed; a
reconnect or TCP fallback never counts as successful seamless migration.

## Crypto Replaceability And Brynja Gaps

Brynja is future-only. Its inspected revision is
`af1401e7f086d16657d7b1ec9b32a3e1a363701a` in the local sibling checkout.
The TLS facade, TLS 1.3 handshake and QUIC-TLS crates explicitly expose
`IMPLEMENTED = false`, for example `crates/brynja-quic-tls/src/lib.rs`
within that checkout. This is local source evidence, not a publicly available
release or a build prerequisite.
This does not assert that Brynja lacks all underlying primitives; it means
there is no qualified protocol/provider integration for Fluxheim to select.

| Capability | Initial owner / replacement interface | Future Brynja gap / required evidence |
| --- | --- | --- |
| Transcript and handshake state | rustls QUIC session / Quinn `crypto::Session` | Complete record-independent TLS 1.3 engine or rustls provider integration |
| Transcript hashes, HKDF, traffic secrets | rustls suite/provider | Complete supported-suite contract and independent derivation vectors |
| Key exchange groups | rustls `CryptoProvider` | Admitted groups, peer-key validation and differential handshakes |
| Certificate signing and verification | rustls signer/verifier/provider | Key decoding, signature algorithms, chain/name/time/client-auth policy parity |
| Packet AEAD and header protection | Quinn `PacketKey`/`HeaderKey`, rustls QUIC algorithms | QUIC-specific packet-number/nonce/key-phase contracts and vectors |
| Initial protection and Retry integrity | quinn-proto crypto implementation | Mandatory version-specific Initial/Retry algorithms even with different negotiated suites |
| Resumption and exporters | TLS session/ticket owner | Reviewed lifetimes, secret derivation, exporter binding; 0-RTT remains disabled |
| Key updates and packet transitions | rustls session plus quinn-proto transport | Ordering/retention/key-phase transition tests, not independent app-level rekeying |
| Address tokens | Quinn `HandshakeTokenKey`/`AeadKey` | Authenticated format, expiry/rotation, replay and anti-amplification tests |
| Stateless reset and connection IDs | Endpoint config and `HmacKey`/CID generator | Explicit key owner, rotation, CID privacy and bounded state |
| Randomness | Provider and endpoint RNG | Reviewed platform entropy/failure semantics, no silent fallback |
| Secret destruction | Provider/session/key owners | Ownership, intermediate buffers, drop/zeroization and cancellation review |

All rows are **not yet qualified for Brynja integration**. Commit 4 freezes
Fluxheim-owned opaque interfaces; it must not create custom cryptographic
algorithms or expose library layouts to request policy. The initial adapters
can later be replaced through a real rustls provider, Quinn session contract,
or private transport/TLS adapter replacement. A future substitute must pass
the same vector, malformed-input, side-channel and native-platform gates.

The existing crypto-owner allowlist in JSON covers root CLI/runtime, TLS,
server origin TLS/cache encryption, ACME, load-balancer health TLS, and snapshot
integrity. Those existing dependencies are not removed or declared unsafe by
this train. New QUIC-specific dependencies remain inside the approved adapter;
the allowlist is not permission to spread QUIC types through those crates.

## Unsafe And Supply-Chain Inventory

| Boundary | Reviewed source locations / risk | Required treatment |
| --- | --- | --- |
| Probe | `tools/http3-source-probe/src/lib.rs` | `unsafe_code = forbid`, loopback only, ephemeral verified certificate, bounded test deadlines |
| h3 / h3-quinn | `h3/src/proto/varint.rs` unchecked constructor; no unsafe block found in h3-quinn source scan | Treat compressed/frame input as hostile; keep protocol fuzz and malformed-input gates |
| quinn | Runtime/socket adapter; unsafe raw-waker helpers in upstream tests | No transfer of dependency types to application APIs |
| quinn-proto | `varint.rs`, send-buffer offsets, connection frame sizing | Integer/length invariants and malformed packet tests; no local unchecked helpers |
| quinn-udp | Unix/Windows syscalls, ancillary-message alignment and pointer handling, fallback I/O slices | Native tests on all admitted OS/architectures; source re-review when updated |
| ring / AWS-LC | Native cryptographic implementation/build scripts | Exact lock/checksums, existing license/advisory policy, provider-specific qualification |
| rustls / Tokio / bytes / socket2 / libc / windows-sys | Shared TLS, runtime, buffer and OS interfaces | Existing dependency trust plus concurrency/cancellation/native tests; not newly written crypto |

This is a review inventory, not an unsafe-code absence or memory-safety proof.
The full transitive graph is in the lockfile; upstream build scripts execute
as normal Cargo dependencies and must stay on trusted build infrastructure.
Duplicate versions such as syn 2/3 and getrandom 0.2/0.4 are inherited by
fixture/native/provider dependencies; the admitted protocol/TLS packages have
one version each. Recheck using `cargo tree --duplicates` and separate provider
feature trees, not an all-provider runtime build.

## Verification And Remaining Gates

Run from the repository root:

```sh
python3 scripts/validate_http3_source_lock.py
python3 scripts/test_http3_source_lock.py
cargo fmt --manifest-path tools/http3-source-probe/Cargo.toml --check
cargo test --locked --manifest-path tools/http3-source-probe/Cargo.toml
cargo test --locked --manifest-path tools/http3-source-probe/Cargo.toml --no-default-features --features aws-lc
sh scripts/validate_http3_probe_features.sh
cargo deny --manifest-path tools/http3-source-probe/Cargo.toml --config tools/http3-source-probe/deny.toml --locked check
```

The tooling refresh also requires the existing runtime regression gates:

```sh
sh scripts/checks.sh
cargo test --workspace --locked --features profile-development,wasm-proxy-abi,wasm-wasi
cargo clippy --workspace --locked --features profile-development,wasm-proxy-abi,wasm-wasi --all-targets -- -D warnings
cargo check --locked --manifest-path fuzz/Cargo.toml --bins
cargo test --locked --features udp-proxy udp_proxy
sh scripts/smoke_1_0_core.sh
sh scripts/smoke_native_http2_preview.sh
sh scripts/smoke_wasm_policy_examples_binary.sh
sh scripts/smoke_acme_mount_boundary.sh
```

The structural gate requires the selected seamless scope and its complete case
inventory, but permits explicitly pending source qualification during review.
`python3 scripts/validate_http3_source_lock.py --acceptance` must reject it until
source qualification is recorded. That field is a reviewed evidence declaration,
not automated proof: acceptance also requires review of the source/probe results
and external pentest/CI gates. No test result automatically authorizes Commit 2.

Local evidence at `ba3959f6`: the full `scripts/checks.sh` gate passed with workspace version
1.9.0, all 21 workspace package versions matched, and the rebuilt executable
reported 1.9.0. All nine fuzz targets compile with the refreshed lockfile.
14 gate regression tests passed; 3 isolated tests for each provider
on Linux plus both invalid-provider compile-rejection checks;
2,066 workspace tests passed, 1 ignored mount-namespace test subsequently passed
in the isolated ACME smoke; 11 UDP tests passed; expanded-workspace and both
probe-provider clippy checks clean; core live HTTP/static/proxy/TLS, HTTP/2 and
Wasm policy smoke passed. Production
and probe license/advisory/source checks passed. Cargo audit used RustSec
revision `550efd3d587a29b2e2c2b21b17a440da4fede999` (1,295 advisories); no known
vulnerabilities reported for either lockfile. Yanked checks remain enabled in
cargo-deny. New native Windows/macOS execution, final container builds, full
fuzzing, independent HTTP/3 clients and pentest are not claimed by these probes.

Scope/CI revision on 2026-10-08: 19 gate regression tests, both three-test
provider suites, probe dependency policy, formatting, documentation links, and
release metadata pass. The provider-rejection script now requests uncolored
Cargo diagnostics: GitHub's `CARGO_TERM_COLOR=always` previously split the
expected error text with ANSI escapes. The failure reproduced before the fix;
the new forced-color regression passes afterward. Source acceptance still
correctly rejects pending migration qualification. No production Rust or
dependency changes were made in this revision; the full runtime suite above
was not rerun for these documentation/gate changes.
