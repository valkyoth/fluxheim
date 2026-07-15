# Fluxheim 1.7.12 Release Notes

Fluxheim 1.7.12 adds standards-based response metadata generated from native
runtime outcomes and final response bytes. It also adds reproducible,
CI-only proof environments for both FIPS-capable TLS backend profiles.

All new response metadata remains opt-in. Existing configurations and response
headers are unchanged unless an operator enables the new metadata policy.

## Snapshot Lifecycle Proof and Hardening

- Add a dedicated real-binary smoke that captures a running baseline through
  the authenticated admin API, publishes and live-applies a candidate config,
  verifies changed serving behavior, performs a live rollback, runs snapshot
  integrity doctor, and proves the rolled-back current pointer survives restart.
- Serialize snapshot candidates behind one clone-shared admission lock, bounding
  concurrent near-limit serialization buffers without creating store state for
  rejected oversized candidates.
- Create snapshot directories as `0700` at the operating-system creation call,
  closing the permissive-umask interval before any follow-up mode enforcement.
- Build a complete replacement host router before atomically swapping it into
  the native listener. Snapshot-safe reload and rollback now affect real data
  plane requests while each in-flight HTTP/1 or HTTP/2 request retains one
  router generation across all handler phases.
- Reject live router replacement while background load-balancer health or
  discovery services are active, avoiding a router/service state split; use a
  zero-downtime process upgrade for those deployments.

## Standards-Based Response Metadata

- Add RFC 9211 `Cache-Status` derived from actual cache results, including hit,
  URI miss/store, stale forwarding, revalidation, expiry, and bypass outcomes.
- Add RFC 9209 `Proxy-Status` for Fluxheim-generated proxy failures using only
  standardized low-cardinality error tokens.
- Require a bounded Structured Fields token as the public Fluxheim deployment
  identifier when either status field is enabled.
- Do not expose cache keys, internal storage tiers, policy reasons, backend
  addresses, DNS names, certificate details, or raw error strings.
- Preserve existing origin status members and append Fluxheim's member, making
  multi-proxy status chains visible only when the operator explicitly opts in.

Example:

```toml
[headers.response.metadata]
identifier = "edge-gateway"
cache_status = true
proxy_status = true
content_digest = true
repr_digest = true
```

The metadata policy inherits through global, vhost, and route response-header
configuration. Every field defaults to disabled.

## Response Digests

- Add RFC 9530 SHA-256 `Content-Digest` over final HTTP message content.
- Add `Repr-Digest` only when Fluxheim holds a complete selected
  representation: a complete `GET` response with status `200`, no range, and a
  body consistent with its declared content length.
- Compute digest fields after Fluxheim compression so they describe the bytes
  actually delivered to the client.
- Suppress `Repr-Digest` for `HEAD`, `206`, `304`, and other incomplete
  representation paths instead of guessing an unseen full representation.
- Cover bodyless `HEAD` and `304` content as empty message content and cover a
  `206` response's returned range with `Content-Digest`.
- Remove origin digest fields when Fluxheim compression changes the body and
  digest generation is disabled, preventing stale integrity metadata.
- Apply digest metadata once after Wasm response-header hooks, and share one
  SHA-256 computation when both digest fields describe the same bytes.
- Compute immutable cache-body digests once when objects are stored and reuse
  them for memory and disk hits. New disk metadata is versioned and existing
  v1 and v2 cache objects remain readable.
- Invalidate a precomputed cache digest whenever compression replaces the body,
  then hash the final encoded bytes before emission.

The native response model remains bounded and buffered. Digest generation
hashes the final response buffer without another body copy; unbuffered digest
trailers are not part of this release.

## Wasm Loader Hardening

- Require SHA-256 pins at the final public manifest and loader boundary for
  access-decision, route-decision, and cache-store phases, matching the
  existing configuration invariant.
- Remove detached Wasmtime compilation workers. Compilation is synchronous,
  limited to two process-wide startup/reload slots, and releases its permit
  before an over-deadline result is returned.
- Add `max_compiled_artifact_bytes`, defaulting to 32 MiB and capped at 256
  MiB, and reject compiled modules above that ceiling before registry
  admission.
- Document `compile_timeout_ms` accurately as an in-process result deadline,
  not native compiler preemption; hard cancellation requires future
  process-isolated compilation and execution.
- Open plugin files with no-follow/reparse-point semantics during validation,
  retain that exact regular-file handle, and read module bytes from it without
  reopening the pathname. This closes final-file replacement races on Windows,
  ReFS, Unix, and macOS without identity inference or unsafe code.

## Downstream TLS Hardening

- Add optional `tls.client_auth.crl_path` support to rustls and OpenSSL with an
  8 MiB input bound, a 1-to-64 PEM CRL bundle limit, strict full-chain
  revocation, and expired-CRL rejection. Root/intermediate/client regression
  handshakes prove hierarchical mTLS succeeds only when every required issuer
  CRL is present.
- Require a CRL bundle when required client authentication is combined with a
  FIPS/ISO-required compliance mode; ordinary client auth retains explicit
  opt-in revocation behavior.
- Stage OpenSSL CRLs from the exact bounded bytes already admitted by Fluxheim,
  preventing an OpenSSL pathname reopen from bypassing input admission.
- Index one-label wildcard SNI certificates by normalized suffix, replacing an
  attacker-triggerable linear scan with expected constant-time lookup.
- Build complete, policy-equivalent OpenSSL contexts for every SNI certificate
  and atomically switch contexts during ClientHello processing. Certificate/key
  mismatches now reject reload before the active context store is replaced.
- Parse OpenSSL client-auth policy once per SNI store generation, share admitted
  CA objects across contexts, reject projected active-plus-reload policy input
  above 128 MiB, and divide a 4096-entry session cache budget across contexts.
- Serialize OpenSSL SNI reload construction and attach generation leases to
  selected SSL connections. A reload that would create a third live generation
  now marks the oldest generation for drain; native OpenSSL HTTP/1, HTTP/2, and
  takeover streams use per-connection wake registrations so every retained
  connection closes before a bounded automatic retry. Reloads still fail closed
  if the generation cannot drain within 10 seconds. The connection lease uses
  one process-global OpenSSL ex-data index, preventing index growth when
  certificate stores are reconstructed in-process. Every attachment is read
  back immediately, and Fluxheim terminates if OpenSSL cannot preserve the
  lease.

## Shared Cache Policy Hardening

- Always bypass shared-cache lookup and storage for requests carrying
  `Authorization` or `Proxy-Authorization`.
- Parse response `Cache-Control` as a strict quoted-string-aware policy,
  prioritize `s-maxage` over `max-age`, and reject malformed or conflicting
  security/freshness directives instead of falling back to configured TTLs.
- Parse response `Cache-Control` without a directive vector and reject more
  than 16 KiB or 128 directives cumulatively.
- Remove unused compatibility helpers that could collapse malformed freshness
  into an absent policy or split quoted extension values at commas.
- Preserve the first received `Age` list member when calculating peer-fill
  remaining freshness.
- Persist mandatory-revalidation state with native disk-cache metadata and
  prohibit stale reuse for `must-revalidate`, `proxy-revalidate`, and
  `s-maxage`; v1 and v2 metadata remain readable and derive the restriction
  from stored response headers.
- Require one consistent satisfied `Content-Range` and `Content-Length` before
  range admission, reject impossible totals and duplicate metadata, and make
  zero-sized public slice planning return no slices instead of dividing by
  zero.
- Reject percent-decoded forward-path segments that are not canonical UTF-8 or
  contain encoded Unicode control characters, preventing disagreement with
  permissive upstream decoders.
- Detect symlinks in every existing configured web-path prefix even when a
  later child is absent, and deny non-UTF-8 dotfile components by their OS path
  representation.
- Bound storage-bin manifests to 4 KiB and use no-follow, nonblocking regular
  file reads so oversized or special persistent files fail closed at startup.

## Native Buffer and Cache-Encryption Hardening

- Add `server.limits.max_buffered_request_body_bytes`, defaulting to `1GiB`, as
  one weighted process-wide admission budget shared by HTTP/1 and HTTP/2.
  Fluxheim reserves validated `Content-Length` values in 64 KiB units and grows
  unknown-length HTTP/1 chunked and HTTP/2 reservations before each buffer
  extension. Public native-server handlers without an explicit policy share a
  mandatory 1 GiB process budget, and pinned HTTP/1 handlers provide the
  effective request budget. Exhaustion returns a bounded `503` with retry
  guidance.
- Move content-length bodies out of the reusable HTTP/1 parser buffer without
  constructing a second full-body copy, release oversized connection-buffer
  capacity before keep-alive, and clear full body and chunk-decoder
  allocations through `sanitization`.
  Request types are no longer cloneable; compression, static, cache, and
  revalidation workers receive metadata-only snapshots, while body-bearing
  requests are never automatically retried or failed over.
- Transfer HTTP/1 request-body ownership directly into HTTP/2 DATA frames
  through an owner-backed `Bytes` value instead of making two additional body
  copies. The process-budget reservation travels with the sanitizing body owner
  and every queued H2 slice, so handler completion cannot admit replacement
  memory before the transport releases the original allocation. H2C
  negotiation retains the body until fallback is decided, secure HTTP/1 and
  HTTP/2 growth admits old-plus-new allocation overlap, unknown-length HTTP/2
  bodies use budgeted geometric growth instead of repeated exact-size copies,
  and fragmented final chunks preserve pipelined request bytes before clearing
  the read buffer.
- Move static-file resolution and reads to the bounded blocking-work pool and
  cap retained static response bodies with a weighted 256 MiB process-wide
  budget. Fluxheim resolves metadata first, admits the planned response bytes
  before reading or cloning a body, and conservatively accounts for a second
  local-static cache copy. The permit follows an HTTP/1 response through HTTP/2
  adaptation and remains held until the downstream write completes.
- Give generic native HTTP/1 responses bounded defaults: a 30-second write
  timeout, a 300-second total response lifetime, and an 8 KiB/s minimum send
  rate. Explicit proxy policies continue to override these defaults.
- Write confidential disk-cache envelope v2 objects without plaintext combined
  cache keys. Encrypted filesystem names and storage-bin indexes now use
  HMAC-SHA-256 identities derived separately from the data-encryption key, so
  offline candidate URLs cannot be verified against persisted lookup metadata.
- Create a persistent random cache-root identity and derive independent local
  data and index keys for every root. Replace advisory process-local AES-GCM
  invocation tracking with a locked, durable counter for that effective root
  key; missing or damaged established state fails closed.
- Remove encrypted envelope v1 compatibility. The first startup with the new
  root-bound format, and every local-key rotation, cold-purges that encrypted
  cache root before serving traffic. OpenBao protects its random index key with
  Transit rather than deriving persisted identities from the bearer token.

## Socket-Activation Hardening

- Bound `LISTEN_FDS` to 1 through 128 inside the focused systemd adoption crate
  before libsystemd can allocate descriptor storage, independently preserving
  the root runtime's existing launch-environment validation.
- Require every inherited internet stream listener to report
  `SO_PROTOCOL=TCP`, in addition to the existing socket-family, stream-type,
  listening-state, planned-address, and one-shot ownership checks.

## Stream Proxy Hardening

- Reject IANA special-purpose IPv4 and IPv6 DNS answers that can represent
  translation, transition, discard-only, benchmarking, documentation,
  site-local, or SRv6 SID destinations. Explicit IP-literal upstreams and the
  existing trusted private-DNS opt-in remain unchanged.
- Add `proxy_header_timeout_secs`, defaulting to 10 seconds and capped at 60,
  as one absolute deadline for the complete downstream PROXY v1/v2 preamble.
  Byte-drip input from a trusted proxy cannot refresh this deadline.
- Refresh the shared stream idle deadline after every successful partial write
  and immediately sanitize each forwarded plaintext range, preserving active
  connections under slow backpressure without extending truly idle sessions.

## Snapshot Store Hardening

- Reject filesystem roots as snapshot stores and require pre-existing store
  directories to already be private. Fluxheim never chmods an arbitrary
  existing directory; only a dedicated directory it creates is initialized as
  `0700`.
- Enforce the 16 MiB snapshot reader limit before store locking, generation
  allocation, transaction publication, or `current` updates.
- Give persisted self-healing state a symmetric 64 KiB read/write envelope and
  limit impact and rollback diagnostics to 4 KiB without control characters.
- Preserve existing `current`, generation, snapshot, and recovery files when
  any new size or diagnostic admission check rejects input.
- Create new snapshot-store directories relative to a no-symlink parent
  directory handle, closing the path-resolution race around directory
  creation and keeping filesystem safety checks effective under concurrency.

## Reproducible FIPS-Backend Evidence

- Add separately pinned OpenSSL-FIPS and rustls/AWS-LC-FIPS proof
  Containerfiles under `containers/fips/`.
- Build the exact `profile-fips-openssl` and `profile-fips-rustls` binaries
  inside their corresponding proof environments.
- Run the built binary, verify the selected provider and dependency boundary,
  exercise real downstream TLS and certificate-verified upstream TLS, and
  prove incompatible TLS policy fails closed.
- Record compiler, provider, dependency, binary, and image identity evidence.
- Add a manual GitHub workflow, a deep-gate entry, a static plan validator, and
  an interactive test-starter entry for the proof.

These proof containers are CI evidence environments, not Fluxheim release
images. They do not claim that Fluxheim as a complete product or deployment is
FIPS validated. Operators remain responsible for the validated module,
platform, configuration, key handling, and required compliance evidence.

## Testing

- Live native listener tests cover complete-body digests, compressed wire-byte
  digests, conditional `304`, `HEAD`, `206`, cache MISS/HIT, and refused-origin
  proxy status.
- Live Wasm route coverage verifies post-hook digest emission and rejects
  duplicate `Content-Digest` output; unit coverage verifies cache-digest reuse,
  compression invalidation, and v1/v2 disk-metadata compatibility.
- Config tests cover opt-in parsing, identifier validation, missing-identifier
  rejection, and inherited overlay behavior.
- Status metadata application is idempotent when a response policy is applied
  more than once.
- Shared-cache unit and live-listener tests cover credential bypass, malformed
  freshness with an operator TTL, `s-maxage` precedence, mandatory
  revalidation, contradictory range metadata, zero-sized slice policy, and
  oversized/FIFO storage-bin manifests.
- Body-admission tests cover process-shared defaults, pinned HTTP/1 handlers,
  exact HTTP/2 declared lengths, incremental unknown-length growth, aggregate
  exhaustion, logarithmic growth under highly fragmented HTTP/2 DATA frames,
  owner-backed H2 DATA retention, post-handler body retention, and permit
  recovery. Static error-page and cache tests preserve fallback behavior while
  admission precedes body materialization.
- Cache-encryption tests cover cross-root key separation, opaque HMAC lookup
  identities, restart continuity, missing-counter failure, local-key rotation,
  v1 rejection, and cold removal of legacy encrypted filesystem objects.
- Cache-header tests cover cumulative byte/directive ceilings and quoted-comma
  parsing.
- Shared path-safety and live redirect tests cover invalid UTF-8, overlong
  slash encodings, encoded Unicode controls, and valid encoded Unicode.
- Static-web tests cover missing children below valid and broken symlinked
  parents plus hidden non-UTF-8 Unix filenames.
- Systemd unit and process-level smoke coverage verifies explicit TCP protocol
  admission, bounded declarations before receipt, one-shot ownership,
  complete-set closure on validation failure, and normal listener adoption.
- Paused-time stream tests prove v1 and v2 PROXY byte-drip input cannot extend
  the absolute preamble deadline and that partial writes keep an active,
  backpressured stream alive beyond one idle period.
- The real-binary stream smoke drip-feeds an incomplete PROXY preamble beyond
  its deadline, verifies rejection, and then proves the listener still accepts
  a complete authenticated preamble and proxies traffic.
- Stream DNS-admission tests cover the blocked IANA special-purpose ranges and
  the two globally reachable IPv4 protocol-assignment anycast exceptions.
- Snapshot tests prove filesystem roots and existing non-private directories
  are rejected without permission changes, oversized snapshots publish no
  layout or state, and invalid recovery diagnostics preserve prior state.
