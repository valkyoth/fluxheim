# HTTP/3 And QUIC Commit Plan

Status: planned `1.9.0` implementation train. Commit 1 is not authorized yet.
Do not begin protocol code until the `1.8` cross-platform parity closeout is
accepted at an exact commit hash. That closeout does not require a `1.8.3`
release tag unless it contains an end-user fix or feature worth publishing.

## Decision Summary

HTTP/3 will use numbered implementation commits followed by one public `1.9.0`
release. The commits are accepted review boundaries on `main`, not partially
supported `1.9.x` releases. Each commit must be locally green, must preserve
HTTP/1.1 and HTTP/2 behavior, and must receive the same incremental pentest,
remediation, retest, and GitHub-green loop used for other security-sensitive
trains.

`1.9.0` is the first public release because a QUIC listener without routing,
admission control, reload, graceful shutdown, observability, packaging, and
cross-platform evidence is not independently useful to operators. Patch and
minor releases after `1.9.0` are reserved for complete user-facing additions or
bug and security fixes.

The estimated train is **23 planned commits**. `Commit N` is a logical accepted
checkpoint, not a promise that exactly one Git object will exist for that
scope. Remediation and evidence commits can increase the Git commit count
without changing the numbered scope. If a commit becomes too large for one
review, split its implementation without widening its scope; the accepted
`HEAD` still becomes the named baseline.

## Public Outcome

`1.9.0` adds opt-in downstream HTTP/3 ingress over QUIC v1 while preserving the
existing HTTP/1.1 and HTTP/2 listeners. It must support the normal Fluxheim
request path for static content, redirects, reverse proxying to existing
HTTP/1.1 or HTTP/2 origins, PHP/FastCGI dispatch, cache, load balancing, header
and access policy, Wasm policy when separately compiled, metrics, tracing,
configuration reload, certificate reload, and graceful process shutdown.

The release adds a dedicated precompiled HTTP/3 profile so operators can use
the feature without maintaining a custom Rust build. The existing `full`
profile remains free of the experimental QUIC dependency surface. HTTP/3 stays
disabled until explicitly configured.

## Standards And Dependency Baseline

Implementation must be based on the final IETF standards rather than draft
behavior:

- [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999.html), QUIC invariants;
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), QUIC transport;
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), QUIC TLS;
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html), loss detection and
  congestion control;
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html), HTTP/3;
- [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html), QPACK; and
- [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218.html), extensible HTTP
  priorities, only after base request handling is proven.

The initial implementation should use the Rust
[`quinn`](https://github.com/quinn-rs/quinn) transport and
[`h3`](https://github.com/hyperium/h3) protocol stack through a narrow
Fluxheim-owned adapter crate. Before admission, lock exact versions, features,
licenses, transitive dependencies, unsafe-code inventory, platform support,
security advisories, and upstream maintenance status. Do not expose dependency
types through Fluxheim's configuration or shared runtime APIs.

## Cryptographic Replaceability And Brynja

HTTP/3 must be designed so its cryptographic implementation can be replaced in
the future by the sibling
[`brynja`](https://github.com/valkyoth/brynja) project once Brynja has
complete, independently reviewed, production-ready capabilities for the
required QUIC and TLS 1.3 profiles. This is an architecture requirement, not a
claim that Brynja is ready for production use or that `1.9.0` will ship a
Brynja backend.

QUIC cryptography is not a generic collection of interchangeable hash calls.
TLS 1.3 key establishment, transcript processing, traffic-secret derivation,
packet and header protection, key phases, retries, resumption, and transport
state have protocol-specific contracts. Fluxheim must not create an ad hoc
cryptographic trait that weakens those contracts merely to appear provider
neutral.

The required boundary is:

1. `fluxheim-http3` owns provider-neutral endpoint, certificate-generation,
   connection, request, response, error, readiness, and shutdown types.
2. A private QUIC TLS adapter owns all `quinn`, `h3`, rustls, ring, and AWS-LC
   types. Those dependency types cannot cross into routing, cache, proxy,
   configuration, observability, or runtime ownership APIs.
3. Provider selection is represented by a bounded Fluxheim-owned capability
   identity. Application code must not branch on ring-specific or AWS-LC-
   specific algorithms, concrete key types, error strings, or global provider
   installation.
4. The adapter receives opaque certificate/key generations from the existing
   TLS ownership boundary and returns provider-neutral readiness and error
   classes. Secret-bearing intermediate state stays inside the selected
   provider adapter.
5. QUIC token, retry, reset, connection-ID, ticket, and packet-protection key
   derivation must each have an explicit owner. No direct crypto dependency may
   appear outside the approved TLS/QUIC adapter merely because the initial
   stack exposes a convenient helper.
6. Tests use protocol vectors and behavior at the provider boundary rather than
   concrete rustls, ring, or AWS-LC object layout. Provider-specific tests
   remain in the adapter.
7. Cargo features remain additive but mutually exclusive at the admitted QUIC
   provider boundary. Enabling unrelated profiles must not accidentally select
   or combine cryptographic implementations.

Commit 1 must record the exact Brynja capability gaps for QUIC/TLS 1.3 without
adding a Brynja dependency. Commit 4 freezes the adapter contract. Commit 5
proves that the initial rustls providers use only that boundary. Commit 23 must
recheck that no implementation-specific types or assumptions escaped during
the train.

A future Brynja integration is admitted only when one of these routes is real
and reviewed:

- Brynja implements the complete rustls cryptographic-provider contract needed
  by QUIC, allowing the existing rustls/QUIC adapter to select it;
- Brynja exposes a complete TLS 1.3 and QUIC cryptographic session boundary
  compatible with a maintained transport integration point; or
- Fluxheim replaces the private transport/TLS adapter while preserving the
  public `fluxheim-http3` and shared HTTP semantics.

The Commit 1 gap matrix must at minimum classify TLS 1.3 transcript hashing,
HKDF and traffic-secret derivation, admitted key-exchange groups, certificate
signature generation/verification, AEAD suites, resumption, exporters, key
updates, secure randomness, and certificate/key decoding. It must separately
classify QUIC Initial secret derivation and mandatory Initial protection, packet
AEAD, header protection, Retry integrity, address-validation tokens, stateless
reset keys, connection-ID derivation where used, packet-number/key-phase
transitions, and secret destruction. Each row identifies its protocol owner,
initial implementation, public integration point, error behavior, and future
Brynja capability rather than assuming that a TLS provider automatically owns
all QUIC cryptography.

The future migration must include independent vectors, differential handshakes,
packet/header-protection tests, key-update and resumption tests, malformed-input
and side-channel review, secret-lifecycle evidence, and native qualification on
every supported platform. It must fail closed when a required capability is
missing. It may not silently fall back to another provider after cryptographic
work starts. FIPS or other certification claims remain provider- and operating-
environment-specific and are never inherited from this abstraction.

## Scope Rules

1. HTTP/3 is disabled by default and has a dedicated Cargo feature and release
   profile.
2. The first release supports downstream HTTP/3 only. Origin connections remain
   HTTP/1.1 or HTTP/2 until a later user-facing release.
3. QUIC v1 is the only admitted transport version in `1.9.0`.
4. HTTP/3 requires TLS 1.3 and the reviewed rustls provider path. OpenSSL-only
   builds must reject HTTP/3 configuration clearly at validation time.
5. Existing TCP TLS listeners remain authoritative for HTTP/1.1 and HTTP/2.
   HTTP/3 uses a separate UDP socket, which may use the same numeric port.
6. UDP proxying and HTTP/3 are separate domains. Generic UDP routes must never
   receive QUIC packets or inherit HTTP/3 listener privileges.
7. Zero-RTT is disabled. No route can opt in during `1.9.0`.
8. Active connection migration, preferred addresses, multipath QUIC, QUIC
   DATAGRAM, CONNECT-UDP, MASQUE, WebTransport, and generic tunnels are excluded.
9. HTTP/3 WebSocket Extended CONNECT is deferred; clients continue to use the
   existing HTTP/1.1 or HTTP/2 path for WebSockets.
10. Server push is not implemented.
11. `Alt-Svc` is emitted only when the configured QUIC listener is ready. It is
    never a decorative static promise.
12. SNI, `:authority`, vhost selection, Host policy, request limits, and access
    policy must produce the same decisions as HTTP/1.1 and HTTP/2.
13. Protocol and transport errors use bounded, low-cardinality public and metric
    classifications. Packet contents, connection IDs, tokens, addresses, and
    TLS details are not logged by default.
14. No numbered commit can weaken existing HTTP/1.1, HTTP/2, TLS, ACME, cache,
    filesystem, or shutdown behavior to make HTTP/3 easier.
15. A numbered commit cannot silently implement scope assigned to a later
    commit.
16. No protocol-neutral module may import or name the selected QUIC
    cryptographic implementation. Future Brynja substitution must remain
    possible without rewriting routing, cache, proxy, policy, or observability.

## Configuration Direction

The exact names are frozen at Commit 3, not by this sketch:

```toml
[server.http3]
enabled = true
listen = ["0.0.0.0:8443", "[::]:8443"]
advertise = true
advertise_port = 443
max_idle_timeout_secs = 30
max_concurrent_connections = 10000
max_connections_per_ip = 100
max_concurrent_request_streams = 100
require_address_validation = true
```

Global and vhost request/header/body/concurrency policies continue to apply.
HTTP/3-specific values are bounded transport limits, not alternate application
policy. Unsupported combinations fail during configuration validation rather
than being ignored at runtime.

## Commit Checkpoint Workflow

`Commit N` names an accepted implementation checkpoint, not one literal Git
object and not a release. Work remains on `main` throughout the train:

1. Commit 1 begins from the approved `1.8` closeout hash. Every later commit
   begins from the preceding accepted commit hash.
2. Implement only the numbered scope and add permanent regression coverage.
3. Run the complete applicable local gate, including HTTP/1.1 and HTTP/2
   regression suites.
4. Commit the implementation and test evidence normally.
5. Pentest the complete diff from the preceding accepted hash to `HEAD`.
6. Commit every remediation normally and retest the same complete range until
   the pentest is green.
7. Push the candidate and wait for all required GitHub CI and CodeQL checks to
   be green. A local pass or pentest does not authorize the next commit while
   GitHub is pending or failing.
8. Record the final accepted `HEAD` hash in this plan and use it as the next
   commit's comparison baseline.

The status paragraph under every commit is the acceptance register. When a
commit is accepted, replace `planned` with the exact accepted `HEAD`, reviewed
range, pentest/retest result, and GitHub result before changing the following
commit from blocked to authorized. Evidence-only and remediation Git objects
belong to the same numbered commit until that status is accepted.

Protocol code remains impossible to enable until its safety dependencies are
present. Intermediate commits must not be packaged or described as HTTP/3
support.

## Commit 1 - Finite Scope And Source Lock

Commit status: planned; do not begin until the `1.8` closeout baseline is
recorded and the user authorizes Commit 1.

Goal: freeze the standards, dependency, feature, and non-goal boundaries before
network code exists.

Deliverables: standards matrix; exact `quinn`, `h3`, rustls, Tokio, and HTTP
crate compatibility record; dependency feature graph; unsafe-code and advisory
review; supported-platform statement; a finite requirement-to-commit matrix;
and a Brynja gap matrix covering every TLS 1.3 and QUIC cryptographic capability
without adding a runtime or build dependency on Brynja.

Verification: dependency tree and duplicate-version checks, feature-unification
fixtures, license and advisory gates, source-link validation, and a gate that
rejects unclassified requirements or forbidden extensions.

Exit criteria: every `1.9.0` requirement is assigned once, every exclusion is
explicit, and no runtime dependency is enabled in existing profiles.

Pentest stop: pentest the exact Commit 1 source-lock, scope-classification,
dependency, and future-provider boundary. Remediate, retest, and wait for green
GitHub checks before authorizing Commit 2.

## Commit 2 - HTTP Semantic Parity Baseline

Commit status: planned; blocked on accepted Commit 1 pentest, retest, and
GitHub checks.

Goal: define the shared request/response behavior HTTP/3 must reuse.

Deliverables: protocol-neutral fixtures for authority routing, methods, headers,
body limits, trailers, cancellation, informational responses, static files,
redirects, proxy, PHP, cache, load balancing, errors, and policy hooks.

Verification: run the fixtures through HTTP/1.1 and HTTP/2 and record expected
status, headers, body, cache state, metrics, and cancellation behavior.

Exit criteria: HTTP/3 parity is measured against executable behavior rather
than a separate interpretation of configuration.

Pentest stop: pentest the exact Commit 2 shared-semantics fixture boundary.
Remediate, retest, and wait for green GitHub checks before authorizing Commit 3.

## Commit 3 - Feature, Profile, And Configuration Contract

Commit status: planned; blocked on accepted Commit 2 pentest, retest, and
GitHub checks.

Goal: add an inert, fully validated operator contract.

Deliverables: `http3` feature, dedicated
`profile-http3 = ["profile-full", "http3"]`, typed bounded configuration,
listener collision checks, rustls/TLS 1.3 requirements, OpenSSL-only rejection,
platform validation, config-tester output, examples, and redacted diagnostics.

Verification: default-off dependency graph, all valid and invalid combinations,
duplicate/broad/zero/overflowing limits, IPv4/IPv6 listener conflicts, unknown
fields, profile compile checks, and proof that existing configurations are
unchanged.

Exit criteria: configuration can be reviewed independently and cannot start a
listener yet.

Pentest stop: pentest the exact Commit 3 feature, profile, configuration, and
provider-selection boundary. Remediate, retest, and wait for green GitHub checks
before authorizing Commit 4.

## Commit 4 - Fluxheim HTTP/3 Crate Boundary

Commit status: planned; blocked on accepted Commit 3 pentest, retest, and
GitHub checks.

Goal: isolate external QUIC and HTTP/3 APIs behind Fluxheim-owned types.

Deliverables: `crates/fluxheim-http3`; endpoint, connection, request, response,
error, readiness, and shutdown interfaces; a private QUIC TLS provider adapter;
dependency adapters; module-size and unsafe-code policy; and test-only in-memory
boundaries. Freeze which owners create, rotate, expose, and destroy every
secret-bearing TLS, packet-protection, token, ticket, and reset-key value.

Verification: forbidden dependency-direction checks, default/all-feature builds,
public API inspection, mock transport and crypto-provider tests, and proof that
other domain crates do not import or name `quinn`, `h3`, rustls, ring, AWS-LC,
or Brynja directly.

Exit criteria: protocol dependencies have one reviewable ownership boundary.

Pentest stop: pentest the exact Commit 4 crate, dependency, unsafe-code,
secret-owner, and replaceable-provider boundary. Remediate, retest, and wait for
green GitHub checks before authorizing Commit 5.

## Commit 5 - QUIC TLS And Certificate Generations

Commit status: planned; blocked on accepted Commit 4 pentest, retest, and
GitHub checks.

Goal: construct QUIC-compatible TLS safely from existing vhost certificates.

Deliverables: TLS 1.3-only server configuration, ALPN `h3`, SNI resolver
integration, certificate/key generation snapshots, client-auth policy mapping,
ring and AWS-LC capability checks where supported, provider-neutral failure
classes, and atomic certificate publication through the Commit 4 adapter.

Verification: valid SNI, unknown SNI, missing certificate, malformed chains,
wrong keys, expired/not-yet-valid certificates, client authentication,
concurrent reload, provider mismatch, unavailable capability, no mid-operation
fallback, secret redaction, old-generation connection retention, and compile-
time checks that concrete provider types remain private.

Exit criteria: TLS material can be built and reloaded without opening UDP.

Pentest stop: pentest the exact Commit 5 TLS, certificate-generation,
cryptographic-provider, fallback, and secret-lifecycle boundary. Remediate,
retest, and wait for green GitHub checks before authorizing Commit 6.

## Commit 6 - UDP Listener Lifecycle

Commit status: planned; blocked on accepted Commit 5 pentest, retest, and
GitHub checks.

Goal: add supervised QUIC sockets without mixing them with generic UDP proxying.

Deliverables: IPv4/IPv6 bind, socket ownership, runtime manifest entry,
readiness barrier, startup rollback, shutdown signal, listener metrics, and
platform adapters for Linux, macOS, and Windows.

Verification: bind conflicts, partial multi-listener failure, dual-stack
behavior, privileged ports, cancellation, repeated start/stop, no descriptor or
handle leak, and proof that generic UDP routes cannot receive the socket.

Exit criteria: a feature-gated listener can accept and immediately close QUIC
connections under runtime supervision.

Pentest stop: pentest the exact Commit 6 UDP socket, listener lifecycle,
platform, and runtime-supervision boundary. Remediate, retest, and wait for
green GitHub checks before authorizing Commit 7.

## Commit 7 - Connection Admission And Address Validation

Commit status: planned; blocked on accepted Commit 6 pentest, retest, and
GitHub checks.

Goal: bound pre-authentication CPU, memory, bandwidth, and state.

Deliverables: global/per-listener/per-prefix connection limits, handshake caps,
address-validation retry policy, rotating authenticated token keys, idle and
handshake timeouts, bounded connection IDs, and overload shedding.

Verification: spoofed-source simulations, invalid/replayed/expired tokens,
token rotation, retry amplification accounting, connection floods, per-prefix
fairness, IPv4-mapped IPv6 handling, limit recovery, and clock-boundary tests.

Exit criteria: unauthenticated input cannot create unbounded retained state or
amplify more bytes than the admitted policy.

Pentest stop: pentest the exact Commit 7 unauthenticated admission, token,
amplification, resource-limit, and address-handling boundary. Remediate, retest,
and wait for green GitHub checks before authorizing Commit 8.

## Commit 8 - HTTP/3 Control Streams And QPACK Limits

Commit status: planned; blocked on accepted Commit 7 pentest, retest, and
GitHub checks.

Goal: establish bounded HTTP/3 protocol state before application dispatch.

Deliverables: settings validation, required unidirectional streams, QPACK
capacity and blocked-stream limits, stream-type handling, GOAWAY primitives,
priority parsing policy, and protocol error mapping.

Verification: duplicate/invalid settings, missing control streams, forbidden
stream closure, unknown stream types, oversized fields, QPACK blocking and
decompression failures, cancellation races, and low-cardinality errors.

Exit criteria: malformed control traffic fails deterministically without panic,
unbounded allocation, or application dispatch.

Pentest stop: pentest the exact Commit 8 HTTP/3 control-stream, settings, QPACK,
priority, cancellation, and error-mapping boundary. Remediate, retest, and wait
for green GitHub checks before authorizing Commit 9.

## Commit 9 - Request Stream Adaptation

Commit status: planned; blocked on accepted Commit 8 pentest, retest, and
GitHub checks.

Goal: convert admitted HTTP/3 requests into the shared Fluxheim request model.

Deliverables: pseudo-header validation, SNI/authority consistency, method and
scheme checks, header normalization, request-target limits, streaming body
budget, trailers, cancellation, and body timeout integration.

Verification: duplicate/missing pseudo-headers, forbidden connection headers,
authority confusion, content-length mismatch, oversized headers and bodies,
early stream reset, slow body, trailers, CONNECT rejection, and differential
HTTP/1.1/HTTP/2 fixture results.

Exit criteria: an HTTP/3 request reaches a protocol-neutral handler with no
weaker parsing or limit behavior.

Pentest stop: pentest the exact Commit 9 request parsing, authority, body,
trailer, timeout, and cancellation boundary. Remediate, retest, and wait for
green GitHub checks before authorizing Commit 10.

## Commit 10 - Response Streaming And Backpressure

Commit status: planned; blocked on accepted Commit 9 pentest, retest, and
GitHub checks.

Goal: send shared Fluxheim responses without buffering or cancellation leaks.

Deliverables: status/header encoding, informational-response policy, streaming
body writes, trailers, HEAD/no-body handling, flow-control backpressure,
response timeout, reset propagation, and completion accounting.

Verification: empty/large/streamed bodies, HEAD, 1xx, 204, 304, trailers,
client cancellation, blocked writers, partial writes, handler failure, shutdown,
and memory bounds under many slow readers.

Exit criteria: request and response streams have symmetric bounded lifecycle
and existing handlers do not depend on an HTTP/3 type.

Pentest stop: pentest the exact Commit 10 response encoding, flow-control,
backpressure, timeout, cancellation, and resource-lifecycle boundary.
Remediate, retest, and wait for green GitHub checks before authorizing Commit
11.

## Commit 11 - Static, Redirect, And Error Paths

Commit status: planned; blocked on accepted Commit 10 pentest, retest, and
GitHub checks.

Goal: deliver the first complete application paths through shared routing.

Deliverables: vhost/route selection, static serving, range and conditional
requests, redirects, generated errors, hardening headers, digest behavior, and
access-log completion.

Verification: parity corpus across all three HTTP versions, traversal and
symlink tests, range/conditional combinations, compression variants, Host/SNI
mismatch, error redaction, and static-file cancellation.

Exit criteria: a real HTTP/3 client can serve a representative static site with
the same observable semantics as HTTP/1.1 and HTTP/2.

Pentest stop: pentest the exact Commit 11 routing, static-file, range,
conditional, redirect, error, and logging boundary. Remediate, retest, and wait
for green GitHub checks before authorizing Commit 12.

## Commit 12 - Proxy And PHP Bridges

Commit status: planned; blocked on accepted Commit 11 pentest, retest, and
GitHub checks.

Goal: route HTTP/3 requests through existing origin transports and FastCGI.

Deliverables: HTTP/3-to-HTTP/1.1 and HTTP/2 proxy adaptation, forwarded-header
policy, request/response streaming, retry eligibility, upstream cancellation,
PHP external/managed platform rules, and generated 502/503 behavior.

Verification: verified TLS and mTLS origins, chunking removal, trailers,
Expect/continue policy, slow/failed origins, retry boundaries, upload spooling,
FastCGI errors, cancellation, and no accidental HTTP/3 origin attempt.

Exit criteria: normal proxy and PHP applications work over downstream HTTP/3;
WebSocket upgrade receives an explicit fallback-compatible response.

Pentest stop: pentest the exact Commit 12 proxy, upstream TLS, retry, FastCGI,
upload, cancellation, and protocol-downgrade boundary. Remediate, retest, and
wait for green GitHub checks before authorizing Commit 13.

## Commit 13 - Security And Header Policy Parity

Commit status: planned; blocked on accepted Commit 12 pentest, retest, and
GitHub checks.

Goal: apply every request-aware policy before side effects.

Deliverables: request and response header policy, CORS/preflight, authentication
subrequests, rate and concurrency limits, body admission, GeoIP, privacy mode,
mirroring restrictions, retry-after, digest fields, and tracing context.

Verification: policy ordering, spoofable header stripping, CORS `Vary`, denied
request non-dispatch, credential bypass rules, mirrored-body limits, overload
responses, privacy redaction, and three-protocol differential tests.

Exit criteria: choosing HTTP/3 cannot bypass or reorder a security policy.

Pentest stop: pentest the exact Commit 13 request/response policy ordering,
identity, admission, privacy, CORS, digest, and denial boundary. Remediate,
retest, and wait for green GitHub checks before authorizing Commit 14.

## Commit 14 - Cache, Load Balancer, And Wasm Parity

Commit status: planned; blocked on accepted Commit 13 pentest, retest, and
GitHub checks.

Goal: integrate stateful and programmable request paths without protocol forks.

Deliverables: cache keys and variants, stale/revalidation behavior, fill locks,
range/slice policy, load-balancer selection and health, persistence, circuit and
queue behavior, and separately enabled Wasm access/header/route/cache hooks.

Verification: hit/miss/stale parity, credential bypass, coalescing, encrypted
disk cache, backend retry/cancellation, queue timeout, affinity, Wasm deny/trap/
timeout, and no QUIC identifiers in cache or persistence keys.

Exit criteria: application state is protocol-neutral and HTTP/3 adds no cache
poisoning or backend-selection dimension.

Pentest stop: pentest the exact Commit 14 cache, load-balancer, persistence,
Wasm, retry, and state-isolation boundary. Remediate, retest, and wait for green
GitHub checks before authorizing Commit 15.

## Commit 15 - Observability And Operations

Commit status: planned; blocked on accepted Commit 14 pentest, retest, and
GitHub checks.

Goal: make HTTP/3 diagnosable without exposing high-cardinality transport data.

Deliverables: connection/handshake/request/error/drain metrics, protocol labels,
bounded transport reason classes, access logs, traces, admin status, readiness,
and optional explicitly enabled qlog diagnostics with private-file policy.

Verification: metric cardinality, secret and address redaction, disabled qlog by
default, private qlog paths, exporter failure, status bounds, trace cancellation,
and load tests that prove telemetry cannot dominate packet processing.

Exit criteria: operators can distinguish healthy, overloaded, malformed, and
draining HTTP/3 service without packet-level public logs.

Pentest stop: pentest the exact Commit 15 telemetry, cardinality, diagnostic-
file, admin, privacy, and exporter-failure boundary. Remediate, retest, and wait
for green GitHub checks before authorizing Commit 16.

## Commit 16 - Reload, Drain, And Alt-Svc

Commit status: planned; blocked on accepted Commit 15 pentest, retest, and
GitHub checks.

Goal: define safe lifecycle and client discovery semantics.

Deliverables: atomic route and certificate reload, listener readiness state,
readiness-gated `Alt-Svc`, bounded advertisement lifetime, GOAWAY drain, stop-new-
connection behavior, stream completion deadline, forced close code, and stale
advertisement guidance.

Verification: failed reload rollback, certificate generation rollover, no
advertisement before readiness, disabled-listener suppression, TCP/UDP port
translation, graceful active requests, drain timeout, repeated signals, and
restart behavior for clients with cached `Alt-Svc`.

Exit criteria: enabling advertisement cannot point clients at an unavailable
listener, and shutdown has deterministic bounded behavior.

Pentest stop: pentest the exact Commit 16 reload, readiness, discovery, GOAWAY,
drain, shutdown, and stale-advertisement boundary. Remediate, retest, and wait
for green GitHub checks before authorizing Commit 17.

## Commit 17 - Cross-Platform Packaging And Container Artifacts

Commit status: planned; blocked on accepted Commit 16 pentest, retest, and
GitHub checks.

Goal: make the feature obtainable in artifacts that the following native live
commits can execute without Cargo.

Deliverables: `http3` archives for Linux x86_64/aarch64, macOS Apple Silicon,
and Windows x86_64; matching container variants; UDP port documentation;
rootless Podman guidance; checksums, SBOM, and reproducibility evidence; and
platform test-starter entries.

Verification: native archive binary inspection, container UDP exposure,
read-only configuration and certificate mounts, archive profile validation,
dependency isolation in non-HTTP/3 profiles, exact-tag release-helper
aggregation, and checks that live tests consume extracted archives or published-
shape local images rather than `target/debug` binaries.

Exit criteria: every supported platform has a precompiled candidate artifact
and deployment recipe ready for the mandatory live qualification commits.

Pentest stop: pentest the exact Commit 17 feature graph, archive, container,
filesystem, UDP publication, provenance, and artifact-consumption boundary.
Remediate, retest, and wait for green GitHub checks before authorizing Commit
18.

## Commit 18 - Linux And Rootless Container Live Proof

Commit status: planned; blocked on accepted Commit 17 pentest, retest, and
GitHub checks.

Goal: prove the packaged HTTP/3 profile serves real traffic on supported Linux
architectures and through the production rootless container boundary.

Deliverables: a live script that starts the extracted Linux `profile-http3`
binary and a separate script that starts the release-shape rootless Podman
image with the same numeric TCP and UDP ports published; ephemeral TLS material;
static, proxy, cache, load-balancer, PHP/external FastCGI where available, and
generated-error routes; and retained bounded evidence containing artifact/image
identity, config, client version, negotiated protocol, response markers, logs,
metrics, reload, drain, and exit status.

Verification: use a pinned independent client process with an explicit HTTP/3-
only mode and prove `HTTP/3` negotiation from client evidence, not merely a 200
response. Exercise at least one request across the container network and host
UDP publication boundary, verify TCP HTTP/1.1 or HTTP/2 fallback on the same
service, reload certificates/configuration, stop and restart the container, and
prove graceful and forced shutdown cleanup. Run Linux x86_64 and aarch64 native
jobs; cross-compilation does not satisfy either row.

Exit criteria: a clean host can start the packaged binary and rootless image,
receive an independently negotiated HTTP/3 response through mapped UDP, retain
HTTP/1.1/HTTP/2 service, and shut down without leaked processes or sockets.

Pentest stop: pentest the exact Commit 18 Linux process, rootless container,
network namespace, UDP publication, TLS mount, evidence, and cleanup boundary.
Remediate, retest, and wait for green GitHub checks before authorizing Commit
19.

## Commit 19 - Apple Silicon macOS Native Live Proof

Commit status: planned; blocked on accepted Commit 18 pentest, retest, and
GitHub checks.

Goal: prove HTTP/3 on an actual supported Apple Silicon macOS host rather than
assuming Unix behavior matches Linux.

Deliverables: an Apple Silicon native live script that extracts the macOS
`profile-http3` release archive into a fresh directory, starts Fluxheim as a
separate foreground process, drives it with a pinned independent HTTP/3 client,
and retains bounded artifact identity, architecture, macOS version, client
version, negotiated protocol, response, log, reload, drain, and exit evidence.

Verification: prove the binary is Mach-O arm64, verify ad-hoc signature state
without treating it as publisher trust, perform HTTP/3-only static, proxy,
cache, load-balancer, and representative body-stream requests, confirm TCP
HTTP/1.1/HTTP/2 fallback, reload configuration and certificates, reject an
invalid reload without losing service, and exercise graceful and deadline-
forced shutdown. The server and client must be different processes; Rust unit
tests, cross-compilation, and a same-process QUIC peer do not satisfy this gate.

Exit criteria: the extracted unsigned macOS archive runs on a real supported
Apple Silicon host and independently negotiates HTTP/3 across a UDP socket with
the same application semantics and lifecycle guarantees as Linux.

Pentest stop: pentest the exact Commit 19 macOS archive, process, filesystem,
UDP socket, TLS material, reload, evidence, and cleanup boundary. Remediate,
retest, and wait for green GitHub checks before authorizing Commit 20.

## Commit 20 - Windows x86_64 Native Live Proof

Commit status: planned; blocked on accepted Commit 19 pentest, retest, and
GitHub checks.

Goal: prove the MSVC archive serves real HTTP/3 on a disposable native Windows
x86_64 host, including traffic that crosses the host firewall.

Deliverables: a PowerShell live script that extracts the Windows
`profile-http3` ZIP into a fresh directory, starts the packaged executable,
configures only the required temporary TCP/UDP firewall rules, and retains
bounded artifact identity, PE architecture, Windows build, client version,
negotiated protocol, response, event/log, reload, drain, and exit evidence. The
test must support a pinned independent client on the host and a remote Linux
HTTP/3 client against an explicitly provided test hostname or address.

Verification: prove native MSVC execution, HTTP/3-only static, proxy, cache,
load-balancer, external FastCGI/PHP, request-body, and generated-error paths;
verify TCP HTTP/1.1/HTTP/2 fallback; confirm UDP is externally reachable rather
than inferring success from a local request; reload configuration and
certificates; reject invalid reload; stop/restart; enforce graceful and forced
shutdown; and remove temporary services, processes, files, and firewall rules.
Cross-compilation, Wine, WSL, or a Windows container does not satisfy this
native gate.

Exit criteria: a fresh disposable Windows Server host can run the extracted
release ZIP and serve independently verified HTTP/3 over external UDP while
preserving supported routing, policy, fallback, reload, and shutdown behavior.

Pentest stop: pentest the exact Commit 20 Windows archive, PowerShell, ACL,
firewall, UDP reachability, TLS material, evidence, and cleanup boundary.
Remediate, retest, and wait for green GitHub checks before authorizing Commit
21.

## Commit 21 - Interoperability And Impaired Networks

Commit status: planned; blocked on accepted Commit 20 pentest, retest, and
GitHub checks.

Goal: prove behavior beyond platform-specific happy-path clients and networks.

Deliverables: pinned independent client matrix, browser-compatible smoke,
version negotiation, IPv4/IPv6, loss/reordering/duplication/delay scenarios,
NAT rebinding behavior with migration disabled, MTU boundaries, and long-lived
transfer tests.

Verification: at least two independent HTTP/3 implementations, malformed packet
corpus, handshake loss, stream loss, reorder, duplicate packets, black-hole MTU,
idle transitions, server overload, and mixed HTTP/1.1/HTTP/2/HTTP/3 traffic.

Exit criteria: success does not depend on Fluxheim's own test peer or a perfect
loopback network.

Pentest stop: pentest the exact Commit 21 independent-client, malformed-packet,
loss, reordering, MTU, overload, migration-disabled, and mixed-traffic
boundary. Remediate, retest, and wait for green GitHub checks before authorizing
Commit 22.

## Commit 22 - Documentation And Release Gates

Commit status: planned; blocked on accepted Commit 21 pentest, retest, and
GitHub checks.

Goal: turn the implementation into an explicit support contract.

Deliverables: configuration reference, migration guide, UDP firewall/container
examples, protocol and TLS limitations, Alt-Svc rollback procedure, metrics and
capacity guidance, release notes, feature/profile matrix, stable/deep gate
integration, and test-starter entries.

Verification: documentation links, examples parsed by the config tester,
release-plan validation, packaged-binary smokes, source/archive/SBOM checksums,
and proof that release gates fail if HTTP/3 evidence is absent.

Exit criteria: no supported behavior or operational limitation exists only in
source code or test names.

Pentest stop: pentest the exact Commit 22 documentation, configuration example,
test-starter, release-helper, and fail-closed release-gate boundary. Remediate,
retest, and wait for green GitHub checks before authorizing Commit 23.

## Commit 23 - Security Stabilization And Release Candidate

Commit status: planned; blocked on accepted Commit 22 pentest, retest, and
GitHub checks.

Goal: freeze scope and qualify `1.9.0`.

Deliverables: full-project pentest, dependency re-audit, fuzz/adversarial results,
cross-platform CI, sustained mixed-protocol load evidence, leak/handle checks,
final release metadata, and explicit residual-risk record.

Verification: complete stable and deep gates, all native platform jobs, CodeQL,
dependency/license policy, SBOM, reproducible builds, container smokes, TLS scan,
packet-loss suite, clean worktree, signed-tag gate dry run, and final retest.

Exit criteria: HTTP/3 is still opt-in, every `1.9.0` requirement is proven, no
release-blocking finding remains, and HTTP/1.1/HTTP/2 regression evidence is
green. Only then select, tag, and publish `v1.9.0`.

Pentest stop: run a full-project pentest, not only an incremental review. Commit
all remediation, rerun the full pentest and release gate, and wait for every
required GitHub and CodeQL check to be green. Tagging and publication require a
separate explicit user decision after this final accepted hash is recorded.

## Public 1.9.x Release Plan

Later versions are candidate vertical slices, not a promise to publish every
number. Skip a version rather than releasing an internal refactor with no user
value.

### v1.9.0 - Downstream HTTP/3

User value: clients can reach static, proxy, PHP, cache, and load-balanced
Fluxheim applications over standards-based QUIC/HTTP/3 using an explicit
precompiled profile, with automatic readiness-gated discovery and fallback to
HTTP/1.1 or HTTP/2.

### v1.9.1 - HTTP/3 Origins

Candidate user value: Fluxheim can connect to explicitly configured HTTP/3
origins with certificate verification, SNI, mTLS where supported, bounded QUIC
connection pooling, origin protocol policy, health checks, and deterministic
fallback. Learned `Alt-Svc` must not silently change authority, credentials, or
cache identity.

Release only when upstream HTTP/3 is measurably useful and has parity for retry,
timeouts, cancellation, load balancing, proxy status, and origin TLS policy.

### v1.9.2 - HTTP/3 WebSocket Extended CONNECT

Candidate user value: compatible clients can carry WebSockets through HTTP/3
without falling back to TCP. This requires explicit Extended CONNECT protocol
negotiation, tunnel byte and lifetime limits, cancellation, backpressure,
authentication, observability, and mixed-version fallback tests.

This release does not imply WebTransport, CONNECT-UDP, MASQUE, or arbitrary UDP
tunneling.

### v1.9.3 - QUIC Edge Operations

Candidate user value: deployments with mobile clients, NAT rebinding, multiple
frontends, or frequent process replacement gain reviewed connection-migration
and connection-ID routing behavior, plus platform-specific UDP activation and
drain guidance where technically supportable.

Do not claim seamless cross-process QUIC handoff unless cryptographic connection
state and packet routing are genuinely preserved. A reconnecting client is not
zero-downtime connection migration.

### Future 1.9.x - Controlled Zero-RTT

Zero-RTT has no assigned release. Consider it only for explicitly replay-safe
GET/HEAD routes after single-node and clustered anti-replay semantics are
defined. If those semantics cannot be made clear and testable, keep zero-RTT
disabled permanently. QUIC DATAGRAM, WebTransport, MASQUE, and multipath remain
separate future decisions rather than automatic `1.9.x` scope.

## Live Evidence Rules

The platform commits and final release gate distinguish executable behavior
from compile and unit-test evidence:

1. Fluxheim runs as a separate operating-system process from an extracted
   release-shape archive or release-shape container image. `cargo test`, an
   in-process endpoint, or a binary invoked from `target/debug` cannot satisfy a
   native or packaged live row.
2. At least one pinned client from an implementation independent of Fluxheim's
   server stack sends a request in explicit HTTP/3-only mode. Client output or
   a protocol API must prove HTTP/3 was negotiated; response status alone is
   insufficient because it could have used TCP fallback.
3. TLS verification remains enabled. Tests use a bounded ephemeral CA explicitly
   trusted by the client or a staging/production certificate for an authorized
   test hostname. An insecure client flag cannot satisfy the release gate.
4. The fixture returns an unpredictable per-run marker and checks the exact
   marker, status, selected vhost, security headers, access-log protocol, and
   low-cardinality metrics. A response from another process or stale server
   must not pass.
5. TCP and UDP use the documented deployment ports concurrently. Tests prove
   HTTP/1.1 or HTTP/2 fallback separately and prove HTTP/3 over UDP rather than
   inferring UDP availability from configuration or `Alt-Svc`.
6. Every live run has bounded startup, request, reload, drain, shutdown, and
   cleanup deadlines. Failure retains bounded diagnostics; success removes
   temporary processes, containers, firewall rules, certificates, and files.
7. Required platform rows fail when prerequisites or clients are absent. They
   may not print `skipped` and return success. Optional developer convenience
   runs are kept separate from release evidence.
8. Evidence records the exact source commit, archive or image digest, Fluxheim
   version, OS and architecture, independent-client name/version, configuration
   digest, negotiated protocol, route results, and cleanup result.
9. The release candidate reruns the Linux/container, macOS, and Windows live
   scripts against final artifacts. Evidence from an earlier implementation
   commit cannot substitute for final-candidate execution.

## Required Test Matrix

The `1.9.0` release candidate must cover:

- Linux x86_64 and aarch64, macOS Apple Silicon, and Windows x86_64;
- extracted release archives running as separate native processes on all four
  platform/architecture rows;
- IPv4, IPv6, dual-stack, and same numeric TCP/UDP ports;
- static, redirect, proxy, PHP, cache, load balancer, and policy routes;
- rustls ring and rustls AWS-LC provider builds where QUIC APIs permit the
  existing reviewed provider separation;
- valid, expired, malformed, reloaded, SNI-selected, and client-auth TLS;
- HTTP/1.1, HTTP/2, and HTTP/3 differential semantics;
- independent command-line and browser-family clients;
- loss, delay, reordering, duplication, MTU, cancellation, idle, and overload;
- rootless containers with explicit UDP publication;
- external Windows UDP reachability and real Apple Silicon HTTP/3 negotiation;
- configuration reload, certificate reload, drain, shutdown, and restart; and
- malformed protocol, fuzz, memory-bound, descriptor/handle, logging-redaction,
  and metric-cardinality checks.

Any matrix row that cannot run on a platform must be rejected by configuration
or documented as an intentional limitation before release. It must never be
silently skipped while the artifact remains advertised as supported.
