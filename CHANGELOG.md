# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## 1.7.12 - Unreleased

### Added

- Add opt-in RFC 9211 `Cache-Status` generated from real cache outcomes and
  low-cardinality RFC 9209 `Proxy-Status` for Fluxheim-generated proxy failures.
- Add opt-in RFC 9530 SHA-256 `Content-Digest` and `Repr-Digest` generated from
  final response bytes, with live cache, compression, conditional, `HEAD`, and
  range-response coverage.
- Add pinned CI-only OpenSSL-FIPS and rustls/AWS-LC-FIPS proof environments
  that build and execute the exact profile binary, exercise downstream and
  verified upstream TLS, reject incompatible policy, and capture provider,
  compiler, dependency, binary, and image evidence.

### Changed

- Make standards-based response metadata inherit through global, vhost, and
  route response policies while remaining disabled by default.
- Strip origin digest fields whenever Fluxheim compression changes response
  bytes; opt-in digest generation then recomputes fields from the final encoded
  content.
- Apply route digest metadata once at the final post-Wasm response boundary,
  and share one SHA-256 result when both RFC 9530 digest fields are enabled.
- Precompute immutable cache-body SHA-256 values when objects are stored and
  reuse them across memory and disk cache hits. The versioned disk metadata
  remains backward-compatible with existing v1 cache objects.
- Include the reproducible FIPS-backend image proof in the deep release gate
  and expose it as a separate manual workflow and test-starter entry.

### Security

- Bound public response-metadata identifiers to Structured Fields token grammar
  and prevent status output from exposing backend addresses, DNS names,
  certificate details, cache keys, internal tiers, or arbitrary error text.
- Suppress `Repr-Digest` instead of guessing when Fluxheim does not hold the
  complete selected representation, including `HEAD`, `206`, and `304` paths.
- Invalidate cached body digests whenever compression replaces response bytes,
  ensuring cache-hit optimization cannot produce stale integrity metadata.
- Keep the FIPS proof containers separate from release images and document that
  provider evidence is not product-level FIPS validation.
- Reject additional IANA special-purpose IPv4 and IPv6 DNS answers from stream
  hostname upstream admission, including translation and transition prefixes.
- Bound each complete downstream stream PROXY preamble with one absolute,
  configurable 10-second deadline instead of refreshing a long idle timeout
  for every byte received from a trusted proxy.
- Refresh stream idle deadlines after every successful partial write so active
  backpressured connections are not terminated between write progress events.

## 1.7.11 - 2026-07-14

### Added

- Start zero-downtime process-upgrade support by making native listener drain
  behavior explicit and testable before inherited listener handoff is enabled.
- Add a real-binary `SIGTERM` smoke proving the old listener closes while an
  established keep-alive connection completes within the shutdown bound.
- Add strict systemd socket activation for public native HTTP/HTTPS listeners,
  with exact descriptor-count/address matching and a real inherited-FD smoke.
- Add systemd `READY=1`, status, and stopping notifications after complete
  native startup, including abstract notification-socket smoke coverage.
- Add a two-generation real-binary upgrade smoke proving failed replacement
  rollback, readiness-gated handoff, uninterrupted accepts, and old keep-alive
  drain on one externally owned listener.
- Ship a disabled-by-default `fluxheim.socket` unit matching the packaged port
  80 config, including RPM payload and deterministic activation instructions.
- Add an optional real Podman blue/green smoke proving direct host-port conflict,
  failed-green rollback, stable-front switching, and old-container drain.
- Wait for every configured background service to report its explicit ready
  point before sending systemd `READY=1`, and fail startup if a service exits
  before doing so.
- Prepare public, admin, and local-ops listeners without starting their accept
  loops until background readiness succeeds; late startup failures leave the
  outgoing generation serving and cannot capture replacement traffic.

### Changed

- Apply configured process grace and graceful-shutdown timeout policy in the
  native runtime instead of retaining those values only in the launch plan.
- Reject partial, wrong-process, unbounded, duplicate, missing, or unexpected
  inherited-listener activation instead of mixing inheritance with fresh binds.
- Reject inherited TCP descriptors that are sockets but are not in listening
  state, with a live connected-stream regression in the activation smoke.
- Abort listener and background tasks explicitly when the graceful-drain bound
  expires, including when Fluxheim is embedded as a library.
- Replace `listenfd` with the focused `fluxheim-systemd` descriptor-adoption
  boundary. Systemd descriptors are received without mutating `LISTEN_*` after
  Tokio starts, then validated and transferred through one audited unsafe
  ownership conversion.
- Enforce process-wide one-shot systemd descriptor adoption and establish
  ownership of the complete inherited set before validation, preventing double
  close, partial consumption, and retry against reused descriptor numbers.

### Fixed

- Canonicalize HTTP/1 authority before routing: absolute-form and CONNECT
  targets must agree with `Host`, malformed authorities fail closed, and only
  validated HTTP(S) absolute targets are accepted.
- Make the public HTTP/1 request-head parser return only a validated type:
  authority/`Host`, request-target, framing, and persistence checks now complete
  before callers can inspect or route a parsed request.
- Reject HTTP/1.0 transfer coding before persistence is decided, enforce the
  RFC 3986 ASCII path/query grammar, and reject malformed raw or percent-encoded
  request-target characters before routing.
- Bound chunk lines/count/extensions/encoded bytes, scan fragmented metadata
  incrementally, stream decoded bytes into caller-owned output, and compact
  consumed wire data instead of retaining duplicate complete bodies. Treat a
  trailing partial CRLF consistently so maximum-length chunk lines decode the
  same way across every network fragmentation boundary.
- Restrict parsed upstream status codes to `100..=599` and make PROXY v1/v2
  parsers enforce their exported line/payload bounds and exact v2 length.
- Make protocol header fields constructible only through validation, centralize
  `Connection` option and hop-by-hop identification in a focused module, parse
  option sets in linear expected time, and add five protocol fuzz targets
  covering heads, targets, chunking, and PROXY framing.
- Make HTTP/2 `:authority` authoritative over any supplied `Host` fields,
  preventing cross-vhost routing confusion.
- Strip upstream response headers nominated by `Connection`, including before
  cache admission, and reject malformed connection options and unsupported
  transfer-coding chains.
- Consume a bounded sequence of HTTP/1 informational upstream responses before
  returning the final response, while reserving status 101 for explicit
  validated takeover paths.
- Bound public HTTP/1 connection-limit builders and validate every listener
  semaphore construction instead of allowing oversized values to panic.
- Restrict critical watchdog registration to ownership-checked critical task
  handles, returning noncritical handles intact instead of dropping and
  cancelling their running services.
- Remove caller-controlled executable and temporary-root arguments from the
  zero-downtime and Podman blue/green smokes, closing CodeQL command/path
  injection findings in release-test tooling.
- Make the proxy-cache smoke tolerate the bounded interval between an SWR
  memory-cache publish and completion of its awaited disk-tier persistence.

### Packaging

- Update the interactive RPM build menu to Fedora 44 and openSUSE Leap 16.0,
  and remove the end-of-life Leap 15 target.

## 1.7.10 - 2026-07-13

### Added

- Add independently selectable `scripts/test_starter.py` entries for the F5
  iRules-style, nginx Lua/OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like
  Wasm policy examples while retaining one aggregate release-gate smoke.
- Extend arbitrary guest-integer property coverage across symbolic host-call
  IDs and every current Wasm outcome decoder.
- Run decoder totality property coverage from the complete Wasm smoke and
  document the finite, non-blocking in-process host-callback boundary.
- Add opt-in `baseline` and `cross-origin-isolated` response-hardening profiles,
  typed Permissions-Policy, COOP, CORP, COEP, legacy cross-domain policy, CSP
  report-only, and validated Reporting-Endpoints controls.
- Add request-aware CORS with validated exact/wildcard origins, local preflight
  handling, credential safety, upstream-header ownership, and automatic `Vary`.
- Add `Retry-After: 1` to generated rate, concurrency, PHP-FPM capacity, and
  ACME blocking-work saturation responses.

### Changed

- Require the Wasm acceptance validator to prove that every migration family
  is exposed by the test starter and that the deep release gate enables the
  complete Wasm smoke.

### Fixed

- Strip `Client-IP` and `Proxy-Connection`, reject malformed quoted forwarding
  hops, and validate typed `Forwarded` host/protocol inputs before emission.
- Strip additional deployment identity headers including Envoy, Azure, Fly,
  original-forwarding, proxy-user, and forwarded-client-certificate fields.
- Correct quoted exact-origin `Refresh` rewriting and avoid treating a cookie
  named `Domain` or `Path` as a `Set-Cookie` attribute.
- Add fuzz coverage for the header parsers and rewrite boundaries changed by
  this hardening pass.
- Enforce configured CORS methods on actual responses, not only preflights.
- Serialize Reporting-Endpoints as a bounded RFC 9651 dictionary with strict
  lowercase keys, escaped ASCII strings, and HTTPS-only collectors.

## 1.7.9 - 2026-07-12

### Added

- Add bounded ACME HTTP transport, RFC 9773 ARI scheduling, explicit
  terms-of-service records, per-issuer CA bundles, `fluxheim-acme doctor`, and
  confirmation-gated account deactivation and certificate revocation. Account
  rollover now fails before remote mutation until the client supports a
  caller-generated, pre-journaled replacement key.
- Serialize TLS-ALPN challenge install and cleanup under the ACME mutation lock,
  with race coverage proving cleanup cannot leave a partial certificate pair.
- Bound ARI planning by lookup concurrency, per-target timeout, and total budget;
  execute due work progressively and cache issuer guidance through Retry-After.
- Namespace ARI cache entries by issuer and certificate identity, force renewal
  inside the seven-day emergency window, and reject issuer windows extending
  beyond certificate validity.
- Make account deactivation and certificate revocation transactional. Pending
  account state fails closed, while revocation quarantines the active pair before
  the remote operation, preserves ambiguous outcomes for operator resolution,
  and requests live reload after success even when scheduled renewal is disabled.
  Ordinary synchronous and async credential store/removal APIs now reject both
  bootstrap and ambiguous deactivation journals while holding the lifecycle lock.
- Journal revocation quarantine phases durably so pre-remote crashes restore the
  complete pair, ambiguous remote outcomes stay fail-closed, and confirmed
  quarantine survives crashes while permitting replacement issuance.
- Bind revocation to the exact certificate moved into quarantine while holding
  the certificate mutation lock, and make the advisory ARI cache recover from
  poisoned locks and timestamp overflow without aborting the process.
- Persist a directory-bound ACME account key before remote account activation,
  serialize bootstrap per issuer, and recover ambiguous creation with the same
  key before atomically promoting credentials. A pinned `instant-acme 0.8.5`
  API patch preserves configured contacts and EAB with caller-provided keys.
- Keep blocking account files and locks off Tokio workers. Async ACME paths use
  nonblocking lifecycle-lock attempts on blocking workers, bounded asynchronous
  retry, contention diagnostics, and a 10-second lock-wait deadline. Public
  bounded async credential load, store, and removal APIs prevent downstream
  Tokio callers from falling back to indefinitely blocking lifecycle methods.
- Verify unchanged vendored `instant-acme 0.8.5` files against published hashes
  and intentionally modified files against reviewed patched hashes plus an
  aggregate digest in CI and release gates, without creating
  attacker-addressable temporary paths.
- Validate online ACME directories structurally and require exact advertised ToS
  agreement, with an explicit private-directory override only for omitted terms.
- Parse every advertised ACME endpoint as a bounded HTTPS URI with a real
  authority, and expose unavailable safe account rollover in doctor output.
- Remove the unmaintained direct `rustls-pemfile` dependency in favor of the
  maintained `rustls-pki-types` PEM parser already provided through rustls.

- Add the checked-in F5 iRules-style route access policy and configuration
  example, with real listener coverage for normal origin traffic, pre-origin
  denial, and fail-closed plugin traps.
- Add a dedicated Wasm policy-example smoke to the human test starter and the
  opt-in Wasm release gate.
- Add the checked-in nginx Lua/OpenResty-style bounded request/response header
  policy and config example, compiled directly by its real listener tests.
- Add the checked-in HAProxy Lua/SPOE-style symbolic route policy and config
  example, with live canary, load-balancer, persistence, mirror, and selected
  route-policy coverage.
- Complete the VCL-like cache-policy example gate with schema validation and
  live pass, variant, TTL, metadata, tag-purge, and negative mutation coverage.
- Add a deterministic builder for all migration policies that emits real Wasm
  modules and SHA-256 sums under `target/`, plus one complete Wasm smoke shared
  by the human launcher and release gate.
- Fix the human test starter's Wasm entry so sandbox and policy scripts are no
  longer passed as unused arguments to the registry validator.
- Add a standalone binary smoke that loads generated modules from a private
  plugin root with exact digests and exercises all four migration families
  through a file-based configuration and real HTTP traffic.

### Fixed

- Do not initialize or log errors for the native disk-cache backend when a
  cache policy enables only the memory tier.

### Security

- Validate issued certificate chains, key matches, validity, server-auth usage,
  and exact DNS SANs before publication; serialize writers and TLS readers with
  advisory leases; recover interrupted pair publication through a durable
  journal; preserve primary renewal errors; redact challenge secrets; and keep
  ACME account, EAB, and private-key material in `sanitization` containers.
- Keep ACME account PKCS#8 bytes in `sanitization::SecretVec` across the patched
  client credential boundary, including drop-cleared Base64 serialization and
  deserialization buffers, bootstrap creation, and account recovery.
- Create ACME account, certificate, and challenge directories component by
  component with descriptor-relative no-follow operations on Unix, and reuse
  the same traversal for account mutation and certificate read locks.

- Open snapshot files with no-follow semantics before validating the opened
  descriptor, closing the check-then-open race while preserving typed unsafe
  path rejection.
- Route snapshot corruption fixtures through the atomic store writer and
  descriptor-based permission changes so security tests do not normalize raw
  path mutation patterns.
- Anchor Unix snapshot publication to one no-follow parent-directory
  descriptor and use descriptor-relative create, link, rename, cleanup,
  metadata, and durability operations, preventing pathname re-resolution and
  parent replacement during atomic writes.
- Open the private snapshot mutation lock relative to the same no-symlink parent
  descriptor, with component-wise fallback traversal on platforms without
  Linux `openat2`.

## 1.7.8 - 2026-07-11

### Added

- Start the opt-in WASI Preview 1 capability boundary for non-request-body
  access-decision plugins with separate clock and randomness grants.
- Add checked-in WASI randomness policy/config examples, standalone real-Wasm
  smoke coverage, and live native HTTP/1 listener coverage.
- Restore trusted-client GeoIP context lookup in the native HTTP router for
  HTTP/1 and HTTP/2 access policy.
- Support CIRCL Geo Open's combined Country and ASN MMDB schema and add an
  opt-in checksum-pinned real-database smoke covering static, proxy, and
  load-balanced country/ASN policy.
- Add authenticated snapshot manifests, explicit rollback ancestry and
  generations, persisted self-healing state, resilient listing, store doctor,
  show/diff/verify commands, and protected pruning.

### Security

- Normalize IPv4-mapped and legacy IPv4-compatible IPv6 stream DNS answers
  before rebinding policy checks, preventing loopback, private, link-local,
  carrier-grade NAT, benchmark, and other reserved IPv4 targets from bypassing
  the stream SSRF guard.
- Replace cancellation-unsafe inline bidirectional stream copies with two
  persistent pinned direction futures and a shared last-activity idle timer,
  preventing partial writes from losing or duplicating plaintext under
  simultaneous traffic and backpressure.
- Clear forwarded stream plaintext immediately and clear each full 16 KiB copy
  buffer on drop with `sanitization`.
- Enforce positive per-upstream and checked aggregate stream weights inside the
  public runtime selector boundary, independently of config validation.
- Serialize snapshot mutations with a private advisory lock, publish history
  with create-new semantics, clean failed transactions, retain rollback state
  until completion, authenticate configured stores with HMAC-SHA-256, redact
  invalid IDs, and return clock failures without terminating the data plane.
- Require owner-only snapshot state and integrity-key files, keep integrity keys
  outside the store, parse the exact authenticated bytes, preserve published
  snapshots when current-pointer durability fails, and escape corrupt filenames
  before operator output.
- Persist an authenticated generation high-water mark so pruning cannot reuse
  audit generations, and authenticate explicit pruning boundaries so intentional
  history retention does not appear as snapshot corruption.
- Route snapshot SHA-256 and HMAC-SHA-256 through Fluxheim's selected Ring,
  OpenSSL-FIPS, or AWS-LC-FIPS provider without duplicating snapshot plaintext
  into a concatenation buffer.
- Return snapshot crypto-provider failures to the administrative caller instead
  of aborting the process, and reject missing or replayed generation state when
  retained snapshot metadata proves a higher generation.
- Verify generation freshness through bounded per-snapshot HMAC witnesses rather
  than rereading and hashing every retained config under the store lock, and
  remove the snapshot crate's unused direct logging dependency.
- Preserve authenticated snapshot manifests created before generation witnesses:
  legacy manifests remain fully verifiable for current, rollback, and doctor
  operations and are atomically migrated after verification during the next
  locked snapshot creation.
- Bootstrap authenticated generation state for a fully verified store whose
  retained manifests all predate generation witnesses. Fluxheim persists the
  authenticated high-water mark before migrating those manifests and publishing
  generation `max + 1`; missing state still fails closed for V2 or mixed stores.
- Make OpenSSL cipher allow-lists deterministic across protocol families:
  omitting all TLS 1.2 or TLS 1.3 suites now disables that protocol version
  instead of retaining Mozilla acceptor defaults. Use the current Mozilla v5
  acceptor baseline so configured TLS 1.3 policy is not disabled by the legacy
  v4 template.
- Replace the rustls TLS-ALPN handshake loader callback with an atomically
  published, bounded in-memory SNI certificate store.
- Bound downstream certificate chains, private keys, and client-auth CA
  bundles by bytes and certificate count for both rustls and OpenSSL.
- Protect transient rustls private-key PEM and decoded DER allocations with
  `sanitization::SecretVec` through provider key construction, including
  partial-read and concurrent-growth error paths. Decode PEM key material with
  staged constant-time-oriented Base64 and expose only redacted error classes.
- Disable rustls and tokio-rustls default provider features so normal Ring
  builds no longer compile AWS-LC; FIPS profiles continue to select AWS-LC
  explicitly.
- Make `base64-ng` optional in `fluxheim-tls` and activate it only for Rustls
  key parsing, keeping it out of the crate's default and OpenSSL-only graphs.
- Validate every `wasi_snapshot_preview1` import against the plugin's explicit
  capability grants before instantiation. Environment, arguments, inherited
  stdio, filesystem, sockets/network, polling, and process state remain denied.
- Include WASI capability grants in compiled-module identity equality and
  preserve the existing digest, fuel, memory, table, timeout, admission, and
  fail-closed controls.
- Isolate WASI/proxy preview hooks from native policy hooks with a dedicated
  configurable admission pool and a fixed 32-slot blocking-work class.
- Document that the opt-in clock capability exposes full host clock resolution
  and is unsuitable for untrusted plugins colocated with secret-dependent work.
- Bound complete FastCGI request/response operations with one deadline, retain
  anonymous request-body spool descriptors with independent positional reader
  offsets, protect memory and spool-read buffers with
  `sanitization::SecretVec`, and fix the managed child `PATH`.
- Bind managed PHP-FPM spawn to a trusted executable descriptor and terminate
  its complete dedicated process group during shutdown and watchdog recovery.
- Bound GeoIP database reads to an exact admitted-length allocation with a
  separate growth probe, and validate every publicly constructed `GeoContext`.
- Make directory-listing timestamp formatting checked and preserve the
  `SafeRelativePath` invariant through validated incremental components,
  preventing panic-abort and latent traversal paths in static serving.
- Add crate-level Wasm resource ceilings, checked execution deadlines,
  semaphore-capacity validation, fallible compile-worker creation, and
  before/after deadline checks for the finite non-blocking host-call boundary.
- Make panic-free, total-over-`i32` behavior part of the native Wasm host-call
  contract and property-test every current guest-ID decoder.

## 1.7.7 - 2026-07-10

### Added

- Add an opt-in `wasm-proxy-abi` compatibility preview boundary for
  `proxy-wasm-preview` plugin manifests.
- Add explicit host-call namespace validation so `fluxheim-policy-v1` and
  `proxy-wasm-preview` plugins cannot accidentally share host-call surfaces.
- Add deterministic unsupported-call rejection stubs for the proxy-ABI preview
  namespace and reject unbound host imports before Wasm instantiation.
- Add live native HTTP/1 coverage using the canonical proxy-wasm
  `env.proxy_log(i32, i32, i32) -> i32` import, proving that an unsupported
  proxy-oriented call fails closed before reaching the upstream.

### Changed

- Select an installed GCC 13/12/11 compiler pair automatically for
  release-mode rustls/AWS-LC FIPS validation when the system default compiler
  is outside the supported range.
- Update direct dependency baselines to `base64-ng 1.3.7`, `bytes 1.12.1`,
  `regex 1.13.0`, `sanitization 1.2.4`, and test-only `wat 1.253.0`.
- Update the workspace MSRV, pinned toolchain, and container builders to Rust
  1.97.0.
- Update container-backed compatibility smoke defaults to MariaDB 12.3 LTS,
  PostgreSQL 18, and Valkey 9.1.
- Make reload safety allowlist-based and require process replacement for
  startup-owned TLS, listener, stream, UDP, ACME, cache-purger, and tracing
  changes.
- Classify nested managed ACME targets and managed vhost/route PHP-FPM process
  definitions as startup-owned while retaining snapshot reload for ordinary
  routing and request-time PHP policy.
- Enforce trusted ownership and non-writable permissions across complete config
  source and sensitive-path ancestor chains, with descriptor identity and
  mid-read modification checks for TOML sources.
- Repair all-feature config tests across tracing/privacy and dual FIPS backend
  combinations.
- Restore `fuzz/` as an intentionally standalone cargo-fuzz workspace, remove
  its obsolete Pingora patch, refresh its dependency lockfile, and make the
  fuzz validation gate compile every target automatically.
- Run filesystem-sensitive smoke fixtures below private repository-owned roots
  and use compact paths for Unix-socket integration tests.

### Security

- Include the host-call namespace in native WebAssembly compiled-module
  feature identities, preventing future compile-cache reuse across ABI
  compatibility surfaces.
- Keep `proxy-wasm-preview` disabled unless both the config opts into preview
  ABIs and the binary is built with `wasm-proxy-abi`.
- Restrict `proxy-wasm-preview` manifests to `access-decision` and prevent the
  server from binding `fluxheim_policy_v1` phase capabilities into preview
  namespaces.
- Enforce strict host routing in native HTTP/1 and HTTP/2, returning `400` for
  missing/invalid identity and `421` for unknown hosts.
- Acquire bounded Wasm admission before blocking-work submission, honor
  `queue_limit`, and replace per-invocation watchdog threads with one
  process-wide epoch ticker.
- Replace custom Wasm waiter notification with Tokio semaphores, acquire narrow
  policy permits before global capacity, and cap active/queued budgets at 256.
- Add bounded pre-submission external-auth admission and preserve valid
  operator access during global invalid-credential throttling.
- Add a process-wide 256-request external-auth ceiling across route-specific
  service limits.
- Bound persistent cache index/metadata parsing and keep decoded local cache
  encryption keys in `sanitization::SecretBytes<32>`.
- Reject duplicate canonical storage-bin roots, verify persisted cache object
  keys before serving, and record strict Host-routing rejections in metrics.
- Route storage-bin cache inspection through registered live allocators and
  hold an exclusive filesystem lease for every active storage-bin root, while
  retaining standalone filesystem-backend CLI inspection.
- Shorten generated managed PHP-FPM socket names and validate the complete Unix
  socket address before spawn instead of permitting PHP-FPM path truncation.
- Map native HTTP/1 request-head limit and syntax failures to explicit `431`,
  `414`, and `400` responses before closing the connection.
- Bound aggregate request-driven blocking work across Wasm, auth, mirrors,
  disk cache, and ACME at 256 beneath an explicit 384-thread Tokio blocking
  pool, preserving operational headroom.
- Acquire storage-bin leases before layout initialization, partition blocking
  work by subsystem with critical capacity reserved, and fail closed when a
  disk lookup cannot obtain blocking admission.
- Qualify storage-bin leases as advisory and require per-replica storage or
  verified cross-node locking plus orchestration-level single-writer controls.
- Pre-admit bounded GeoIP database descriptors before allocation/parsing,
  enforce the eight-database runtime ceiling, decode bounded borrowed country
  values, and require trusted immutable MMDB file paths during loading.
- Pin publishing actions, security-tool installs, and container base images to
  immutable reviewed versions and digests.
- Bound Brotli, gzip, and Zstandard logical output before accepting excess
  encoded bytes, avoid a second body copy when draining codec buffers, and
  discard failed encoders.
- Fail malformed `Accept-Encoding` negotiation closed, honor explicit coding
  rejection over wildcard acceptance, and treat qualified `private` cache
  directives as compression-blocking security policy.
- Move config trust traversal to no-follow `statat` inspection and remove the
  environment-derived marker-file write from storage-lease subprocess tests.

### Fixed

- Replace storage-bin request-path full-index rewrites and map-scanning LRU
  selection with one process-wide coalescing persistence worker and ordered
  eviction index.

## 1.7.6 - 2026-07-09

### Added

- Add explicit compiled WebAssembly module identities covering plugin SHA-256
  digest, ABI version, native hook feature surface, and Fluxheim crate version.
- Add complete bounded Prometheus labels for the current Wasm hook outcomes,
  including route selection, cache-store skip, and cache-specific global
  admission and per-vhost cache admission rejection.
- Add the cache-policy process-wide Wasm admission budget to authenticated
  admin status output.
- Add a derived per-vhost Wasm cache-hook admission layer under the process-wide
  cache budget.
- Add a live native HTTP/1 regression test proving access decision, request
  headers, route selection, cache-key mutation, cache-store metadata, and
  response headers compose on one request chain.
- Add reload classification regressions proving Wasm plugin digest changes and
  attachment phase changes require a process upgrade rather than a snapshot
  reload.
- Add runtime tests proving identical plugin bytes get distinct identities when
  ABI or feature surfaces differ.

### Security

- Guard the compiled WebAssembly module API against identity digest mismatches
  so future compile-cache lookups cannot reuse a module under the wrong plugin
  digest.
- Wire the native HTTP/1 hook registry through manifest-derived module
  identities so future compile-cache reuse cannot cross ABI, feature, or
  release boundaries.
- Prevent one vhost's cache-lookup/cache-store hooks from exhausting the whole
  process-wide Wasm cache-hook budget for other vhosts.
- Keep Wasm metrics labels bounded while preserving visibility for every
  current hook family and admission scope.

## 1.7.5 - 2026-07-08

### Added

- Add a bounded native HTTP/1 Wasm cache-key component host call for
  `cache-lookup` hooks.
- Add symbolic `X-Device-Class` context and fixed
  `wasm-device-class=mobile|desktop` cache-key variants.
- Add fixed-ID Wasm cache-store TTL overrides and cache tag assignment.
- Add fixed-ID Wasm cache-store response-header metadata for stored objects.
- Add symbolic cache-store response content-type class inspection without raw
  response-header exposure.
- Add live listener tests proving separate mobile and desktop cache variants
  MISS independently and HIT the original variant on repeat.
- Add live listener tests proving Wasm-selected cache-key components isolate
  fixed-slice range-cache objects for ranged responses.
- Add live listener tests proving a plugin TTL override expires an otherwise
  longer-lived origin response.
- Add live listener tests proving fixed stored response-header metadata appears
  on cache HIT and forbidden stored-header IDs fail closed.
- Add live listener coverage proving duplicate stored-header mutations fail
  closed, plus unit coverage for stored-header mutation-count caps.
- Add unit coverage for aggregate cache-key component caps, cache-tag caps, and
  TTL singleton merge behavior.
- Add a checked-in Wasm cache-policy example plus a config template for the
  bounded `1.7.5` cache ABI.
- Add live listener coverage that compiles the checked-in example sources and
  validates their documented image-only cache-key, TTL, and stored-header
  behavior.

### Security

- Reject unknown cache-key component IDs, unknown values, duplicate labels, and
  component counts above the hard cap through the plugin fail mode.
- Enforce duplicate-label rejection and the aggregate component cap across the
  full `cache-lookup` hook chain.
- Reject unknown TTL IDs, duplicate TTL overrides, unknown tag IDs, and tag
  counts above the hard cap through the plugin fail mode.
- Reject unknown stored-header IDs, duplicate stored-header mutations, and
  stored-header mutation counts above the hard cap through the plugin fail
  mode.
- Scope cache-store tag and stored-header mutation caps independently, and
  reject oversized cache-store candidates before cloning response bodies for
  stored-header metadata.
- Keep arbitrary request headers, raw cache-key bytes, request bodies, cached
  objects, arbitrary TTLs, arbitrary tag strings, arbitrary response-header
  inspection, and arbitrary stored response headers unavailable in this slice.

## 1.7.4 - 2026-07-07

### Added

- Add live native HTTP/1 Wasm `cache-lookup` hooks under the bounded
  `fluxheim_policy_v1` preview ABI.
- Add `continue`, `pass`, `bypass`, and `deny` cache lookup outcomes before
  slice lookup, normal lookup, peer-fill, request collapsing, origin-fill
  protection, and store admission.
- Add `continue`, `skip`, and `deny` cache store outcomes after origin response
  and before memory/disk cache writes.
- Add `wasm.max_total_cache_concurrent_executions` as a separate process-wide
  admission ceiling for cache-lookup/cache-store hooks.
- Add live listener tests proving a plugin can pass selected `/api/*` requests
  without storing while normal cacheable paths still produce MISS then HIT.
- Add live listener tests proving cache-store skip avoids storage and
  cache-store deny blocks delivery before cache write.
- Add live listener tests proving cache-store `deny` wins over an earlier
  cache-store `skip`.

### Security

- Keep cache hooks constrained to integer outcomes and coarse path/status
  context in this slice; raw headers, bodies, cache-key bytes, TTL override,
  tag assignment, and response-store mutation remain unavailable.
- Preserve built-in access, rate-limit, route, and header-policy ordering
  before cache-lookup hooks run.
- Fail closed with `503` when a cache-lookup plugin errors under fail-closed
  mode, and deny with `403` when a plugin explicitly returns deny.
- Isolate cache-policy hook admission from the shared security-decision hook
  admission pool so hot cache routes cannot starve access, route, or header
  hooks on unrelated vhosts.
- Use most-restrictive-wins cache-store aggregation so an earlier `skip` cannot
  mask a later `deny`.
- Update `crossbeam-epoch` to `0.9.20` to clear `RUSTSEC-2026-0204`.

### Changed

- Record `cache-lookup` pass and bypass outcomes as distinct cache-policy
  activity while preserving the external `BYPASS` cache status header.

## 1.7.3 - 2026-07-06

### Added

- Add live native HTTP/1 Wasm `route-decision` hooks under the bounded
  `fluxheim_policy_v1` preview ABI.
- Add symbolic route branch selection for a configured matching `canary` route.
- Add live listener tests with two local origins proving a request carrying
  `x-canary: 1` can be routed to the configured canary branch.

### Security

- Keep route decisions constrained to existing configured routes that still
  match the current request method and path.
- Fail closed with `503` when a plugin selects an unavailable route branch.
- Preserve built-in Fluxheim ACL, rate-limit, concurrency, body-limit, redirect,
  and header-policy enforcement after Wasm route selection.

## 1.7.2 - 2026-07-05

### Added

- Add native HTTP/1 Wasm `request-headers` and `response-headers` hooks using
  bounded integer host calls instead of exposing raw request headers, response
  headers, bodies, filesystem, network, or admin APIs to plugins.
- Add a small `fluxheim_policy_v1` host-call surface for symbolic request
  context, approved synthetic request header mutation, approved response header
  mutation, and approved response header removal.
- Add live listener tests proving an origin observes a plugin-added
  `x-policy-tier` request header, the client observes a plugin-added
  `x-fluxheim-policy-branch` response header, and origin `x-powered-by` can be
  removed before delivery.

### Security

- Reject forbidden or oversized-preview Wasm header mutations by failing closed
  under the existing plugin fail-mode and admission-budget behavior.
- Keep sensitive headers such as `Authorization`, `Cookie`, and `Set-Cookie`
  outside the current Wasm host-call ABI.
- Apply vhost-level Wasm header hooks and fallback response header policy to
  PHP-FPM fallback responses, closing the only fallback path that skipped the
  new hook family.
- Classify Wasm header-hook path context from the matched pre-rewrite request
  path so route tiering remains consistent when `strip_prefix` or rewrite
  policy changes the upstream target.

## 1.7.1 - 2026-07-04

### Added

- Add validation-only WASM config integration for root plugin registries and
  root-scoped vhost/route attachment declarations.
- Add config fixtures that accept valid plugin declarations and reject unknown
  plugin references, attachment phase mismatches, unsafe `fail_open` security
  decisions, disabled registries, and invalid execution admission budgets.
- Add deterministic Wasm attachment priorities and process-wide, per-plugin,
  and per-attachment execution admission ceilings.
- Wire live native HTTP/1 `access-decision` Wasm hooks with `first-deny-wins`
  composition, fail-closed execution behavior, and non-overridable built-in
  ACL decisions.
- Add Wasm status and low-cardinality metrics coverage for execution limits,
  invocations, duration, and admission rejections.

### Changed

- Compile live Wasm modules once at native hook-registry construction time,
  then instantiate isolated stores per request.
- Classify Wasm registry, attachment, limit, and admission changes as
  `wasm-runtime-changed` reload-impact changes until atomic compiled-module
  hot reload is implemented.
- Update Docker GitHub Action pins, Prometheus smoke coverage to `v3.13.0`,
  and `base64-ng` to `1.3.5`.
- Document the 1.7.1 Wasm/config modularity exceptions with explicit split
  targets for the follow-up 1.7 cleanup work.

## 1.7.0 - 2026-07-03

### Added

- Start the `1.7` WebAssembly extensibility line with the new optional
  `fluxheim-wasm` workspace crate.
- Add the compile-time `wasm`, `wasm-proxy-abi`, and `wasm-wasi` feature
  switches. The `wasm` feature is optional and remains incompatible with
  `privacy-mode`.
- Add strict Wasm plugin file loading from approved absolute directories with
  regular-file, symlink-parent, module-size, and SHA-256 recording checks.
- Add a Wasmtime-backed runtime foundation with bounded module execution using
  fuel, memory, table-element, instance/table limits, compile timeout, and a
  per-call wall-time watchdog.
- Bound concurrent Wasm module compilation workers so timed-out compilations
  cannot create unbounded orphaned CPU/thread pressure.
- Add `scripts/smoke_wasm_sandbox.sh` and a test-starter entry that execute
  real Wasm modules, including a successful decision function and a trapped
  infinite-loop module. The smoke also validates an accepted plugin manifest
  and proves unsafe `fail_open` security-decision manifests are rejected.
- Add a typed Wasm plugin manifest boundary with ABI, phase, fail-mode, path,
  and sandbox-limit validation so later hook wiring consumes validated plugin
  declarations instead of ad hoc config.
- Add a manifest-backed plugin loader API that validates the manifest and then
  loads the exact approved plugin path with the validated per-plugin limits.
- Extend Wasm sandbox tests and smoke coverage for symlinked approved-root
  rejection, compile-timeout validation, table-growth denial, and unrelated
  engine epoch ticks before an invocation's own deadline.

### Security

- Avoid cross-request Wasm timeout interference by using a per-store epoch
  deadline callback that only interrupts when that invocation's own wall-clock
  deadline has elapsed.
- Cap Wasm table elements in addition to linear memory so plugins cannot grow
  host-side table storage outside the configured sandbox budget.
- Open Wasm plugin files with Unix `O_NOFOLLOW` where available and verify the
  opened file identity still matches the pre-open metadata before reading.

### Changed

- Update the Wasm extensibility plan from future-only planning to active
  `1.7` implementation status while keeping request/response policy hooks,
  proxy ABI compatibility, and WASI capabilities staged for later `1.7.x`
  releases.
- Expand the `1.7` roadmap into concrete staged releases through stabilization
  and add an enforced Wasm example parity plan for F5 iRules-style policy,
  nginx Lua/OpenResty-style header policy, HAProxy Lua/SPOE-style routing and
  load-balancer policy, and VCL-like cache policy examples.

## 1.6.37 - 2026-07-03

### Security

- Harden OpenSSL stream-upstream TLS connectors with a TLS 1.2 minimum and an
  explicit modern TLS 1.2/TLS 1.3 cipher allowlist, matching the native HTTP
  upstream OpenSSL baseline.
- Store serialized ACME account credentials in `sanitization::SecretVec` while
  writing them to disk so account private-key JSON is cleared from heap memory
  on drop.

### Changed

- Start the final pre-Wasm crate-boundary cleanup release with release metadata
  bumped through the workspace and RPM spec.
- Update the pinned Rust toolchain, workspace `rust-version` fields, and
  container builder images to Rust 1.96.1.
- Prepare ACME, observability, header-policy, TLS helper, native proxy, and CLI
  boundaries for smaller crate-owned APIs while keeping runtime behavior stable.
- Retry disposable Prometheus and Jaeger startup with freshly allocated ports in
  the local observability smoke when auto-allocated host-network ports race with
  other runner processes.
- Remove private root compatibility shims for common errors, filesystem trust
  checks, and OTLP HTTP agents; callers now use the owning workspace crates
  directly.
- Remove the single-use root path-safety shim; admin validation now calls the
  `fluxheim-common` path-safety helper directly.
- Remove the root test-support shim; root tests now import shared helpers from
  `fluxheim-common` directly.
- Remove the root cache-header shim; static response planning now calls
  `fluxheim-cache` header helpers directly.
- Remove root reload, snapshot, and load-balancer re-export shims from active
  code; admin and CLI paths now use `fluxheim-config`, `fluxheim-snapshot`, and
  `fluxheim-load-balancer` directly.
- Remove root GeoIP, OTLP trace-exporter, and trace-context re-export shims;
  callers should use `fluxheim-geoip` and `fluxheim-observability` directly.
- Remove unused root `config_*` compatibility modules; remaining callers use
  the owning `fluxheim-config` modules directly.
- Remove root cache API compatibility shims; admin, CLI, metrics, runtime, and
  native proxy code now use `fluxheim-cache` DTOs and helpers directly.
- Move the remaining root header DTOs into `fluxheim-headers` and remove the
  inline root `headers` module.
- Split access-log helper functions out of `fluxheim-observability/src/lib.rs`
  into a focused crate module while preserving the public exports.
- Split ACME External Account Binding helpers out of `src/acme.rs` into a
  focused helper module so EAB secret loading, bounded file reads, and HMAC-key
  decoding are isolated from the ACME renewal/install adapter.
- Split ACME account credential pathing, bounded JSON loading, safe writes, and
  symlink rejection into a focused account-store helper module.
- Split ACME managed-certificate path construction, certificate expiration
  observation, and regular-file certificate reads into a focused helper module.
- Split ACME TLS-ALPN challenge cleanup and temporary challenge-certificate
  generation into a focused helper module.
- Move ACME HTTP-01 cleanup and redacted challenge URL error context helpers
  beside the HTTP-01 challenge store.
- Move the instant-acme client error to renewal error adapter into the ACME
  error module.
- Move ACME domain normalization, managed certificate name hashing, and HTTP-01
  token validation helpers into a focused naming/validation module.
- Split ACME managed certificate installation, backup/restore, ownership, and
  symlink-safe file replacement helpers into focused certificate installer
  modules that stay below the modularity target.
- Split instant-acme account creation and HTTP-01/TLS-ALPN renewal execution
  into a focused ACME client module, bringing `src/acme.rs` below the
  modularity target.
- Split `fluxheim-acme` companion command execution, config loading, and
  certificate reload socket handling into focused child modules while keeping
  `src/acme_companion.rs` as CLI parser/dispatcher glue.
- Move ACME account, challenge, renewal, certificate install, and certificate
  observation logic into the new `fluxheim-acme` workspace crate; the root
  `src/acme.rs` module now stays as a compatibility re-export for existing
  runtime and companion wiring.
- Point internal ACME runtime, companion, config-tester, and TLS helper calls at
  `fluxheim_acme` directly so the root ACME module is no longer part of the
  internal dependency path.
- Move the cache preview request DTO from the root HTTP type shim into
  `fluxheim-cache`, removing another root compatibility module from active
  code.
- Split the ACME init issuer CLI value enum into a focused child module so
  `src/cli.rs` keeps room under the modularity target after test-profile
  import gating.
- Split ACME init TOML rendering into a focused CLI child module so the
  command runner no longer owns serialization DTOs.
- Split config-tester regression coverage into a child module so the production
  tester entrypoint stays focused on command orchestration.
- Split route path, regex, rewrite-template, and method validation helpers out
  of the route config DTO module while preserving the existing helper exports.
- Split primitive cache value validators out of the cache config validator so
  the main validator stays focused on policy ordering and cross-field checks.
- Split FIPS/ISO cache encryption compliance validation out of the cache config
  DTO module while preserving the existing public helper export.
- Split proxy default helper functions out of the proxy config DTO module while
  preserving serde defaults and upstream policy validation behavior.
- Split managed PHP-FPM child spawn, cleanup, termination, and watchdog
  lifecycle helpers out of the process ownership module.
- Split the native HTTP/2 stack error type out of the connection driver module
  while preserving the `fluxheim-server` public re-export.
- Split disk cache object index and LRU tracking types out of the cache object
  serialization module while preserving the existing `object` exports.
- Split server listener, limit, HTTPS redirect, and process default helpers out
  of the server config DTO module while preserving serde defaults and
  validation behavior.
- Split UDP config regression tests out of the production UDP config DTO module
  while preserving the existing UDP validation coverage.
- Split static-web directory listing DTOs, path rendering, HTML escaping, and
  timestamp formatting into a focused `fluxheim-web` child module while
  preserving the public crate exports.
- Split stream route default values and optional-timeout validation glue out of
  the stream config DTO module while preserving `DEFAULT_STREAM_MAX_CONNECTIONS`
  as a public `config_stream` export.
- Split cache purge request and result DTOs out of the cache API aggregation
  module while preserving the existing `fluxheim-cache` public exports.
- Split load-balancer runtime mutation request/result DTOs and backend-state
  parsing into a focused API child module while preserving the existing
  `fluxheim-load-balancer` public exports.
- Split PHP preset, runtime, path-info, try-files, stderr log-level, FPM mode,
  and process-manager enums into a focused config child module while preserving
  the existing `config_php` re-exports.
- Split exec and database load-balancer health-check negative config coverage
  into a focused config test module.
- Split proxy config merge, upstream helper, path-resolution, and validation
  methods out of the proxy config DTO module while preserving the existing
  inherent `ProxyConfig` API.
- Split load-balancer config merge and validation methods out of the DTO
  module while preserving the existing inherent `LoadBalanceConfig` API.
- Split load-balancer selection enum helpers and metric-label coverage into a
  focused config child module while preserving the existing public re-export.
- Split stream config merge, path-resolution, upstream-selection, and
  validation methods out of the stream DTO module while preserving the existing
  inherent stream config APIs.
- Refresh release-checklist, runtime-baseline, cache-backend, and FIPS docs so
  they describe the current native runtime, empty Pingora dependency surface,
  Fluxheim-owned cache paths, and direct OpenSSL integration.
- Move UDP metric label bounding helpers into `fluxheim-observability` and
  remove the root `metrics_labels` forwarding shim; root metrics now import
  label helpers directly from `fluxheim-observability` and `fluxheim-cache`.
- Move native metrics bearer-token secret loading into `fluxheim-observability`
  behind a scoped `metrics-secret` feature, keeping the root metrics adapter
  focused on listener and Prometheus response handling.
- Move CLI test-only compatibility imports into a focused child module so
  `src/cli.rs` stays below the modularity target after command-helper splits.
- Split metrics label and bounded numeric helpers out of
  `fluxheim-observability/src/lib.rs` into a focused crate module while
  preserving the public exports.
- Split trace-context parsing and generation helpers out of
  `fluxheim-observability/src/lib.rs` into a focused crate module while
  preserving the public exports.
- Split OTLP HTTP agent and OTLP metrics payload helpers out of
  `fluxheim-observability/src/lib.rs` into focused crate modules while
  preserving the public exports.
- Split native metrics bearer-token secret loading and safe token-file opening
  out of the root metrics adapter into a focused private module.
- Split admin cache status, activity reset, and bulk purge regression tests
  into focused child modules while preserving the admin endpoint behavior.
- Split admin cache purge, index, prefix, tag, stale, and wildcard endpoint
  regression tests into focused child modules.
- Split admin UDP and load-balancer regression tests into focused child
  modules and align the test helper with the production native LB admin-pool
  wiring.
- Split admin snapshot, rollback, reload, and self-healing regression tests
  into focused child modules.
- Split admin status, auth-throttle, and request limit regression tests into a
  focused child module.
- Split shared admin regression-test support helpers into a focused child
  module.
- Split admin cache status, purge JSON shaping, cache metric, and repeated
  purge batch helpers into a focused child module.
- Split admin bearer-token loading, auth throttling, and client-certificate
  authorization helpers into a focused child module.
- Split admin native HTTP response builders, request-target parsing helpers,
  and token-store filesystem helpers into focused child modules.
- Split admin cache purge request validation helpers into the cache helper
  module.
- Split admin metric wrapper, status JSON, query parsing, boolean flag, and
  timestamp helpers into a focused child module.
- Split admin load-balancer and UDP status/mutation endpoint handlers into
  focused child modules.
- Split the admin request router and Unix ops-socket dispatcher into a focused
  child module.
- Split admin cache status/activity and cache purge endpoint handlers into
  focused child modules.
- Split admin snapshot reload, live rollback, self-healing, and watchdog
  runtime handlers into a focused child module so `src/admin.rs` now satisfies
  the 500-line modularity target.
- Split CLI crypto diagnostics and cache-key generation helpers into a focused
  child module.
- Split CLI ACME renewal and managed ACME initializer helpers into focused
  child modules.
- Split CLI cache-warm command orchestration and support helpers into focused
  child modules.
- Split CLI cache-key preview command handling and shared cache CLI request
  validation helpers into focused child modules.
- Split CLI cache object lookup command handling, parsing, and expectation
  validation into focused child modules.
- Split CLI compiled-module/runtime validation and TLS storage checks into
  focused child modules while preserving the public `crate::cli` exports.
- Split CLI command dispatch, command option DTOs, and public entrypoint
  helpers into focused child modules so `src/cli.rs` now satisfies the
  500-line modularity target.
- Split the native `/metrics` HTTP app, listener background service, and bearer
  authorization checks out of the root metrics registry into a focused private
  module.
- Split root metrics bounded-label mapping into a focused private module while
  preserving the existing Prometheus label normalization behavior.
- Split trusted client-IP restoration and Forwarded header helpers out of
  `fluxheim-headers/src/lib.rs` into a focused crate module while preserving
  the public exports and privacy-mode gating.
- Split proxy dynamic upstream discovery validation out of
  `fluxheim-config/src/config_proxy.rs` into a focused config module while
  preserving the existing validation behavior.
- Split proxy static upstream attribute validation for weights, priority
  groups, locality, aliases, max-in-flight, and tags into a focused
  `fluxheim-config` module.
- Split proxy upstream transport validation for TLS material, SNI, upstream
  protocol selection, H2 knobs, socket options, and upstream timeouts into a
  focused `fluxheim-config` module.
- Split proxy config fragments into a focused `fluxheim-config` module while
  preserving the existing `config_proxy` re-export and merge behavior.
- Split final proxy config validation orchestration into a focused
  `fluxheim-config` module so `config_proxy.rs` can stay below the 500-line
  modularity target.
- Split config error `Display` formatting for cache, TLS/ACME, and
  route/vhost domains into focused `fluxheim-config` modules so the main
  formatter satisfies the 500-line modularity target.
- Split proxy timeout validation coverage out of the central config regression
  suite into a focused child test module.
- Split load-balancer config regression coverage out of the central config
  suite into focused selection, health, passive-health, persistence, and retry
  child test modules.
- Split cache config regression coverage out of the central config suite into
  focused core, header/bypass, key/TTL, origin/peer/purger, disk, encryption,
  and memory child test modules.
- Split PHP-FPM config regression coverage out of the central config suite into
  focused parsing, managed-process, TCP endpoint, spool/limit, header/error,
  retry, and params/path child test modules.
- Split TLS, ACME, and FIPS config regression coverage out of the central config
  suite into focused policy, compliance, certificate, and ACME child test
  modules.
- Split admin, observability, and logging config regression coverage out of the
  central config suite into focused child test modules.
- Split proxy upstream config regression coverage out of the central config
  suite into focused core, discovery, attribute, transport, TLS/policy, and
  error-page child test modules.
- Split header policy config regression coverage out of the central config
  suite into focused generic, request, response, and vhost child test modules.
- Split server listener, limit, trusted-proxy, HTTPS redirect, and TLS-listener
  config regression coverage out of the central config suite into a focused
  child test module.
- Split vhost, route, config-list limit, ACME challenge, redirect, and
  default-host validation coverage out of the central config suite into focused
  child test modules.
- Split config loading, `conf.d` merge policy, parse-error hint, path-safety,
  static-web index, and generic config validation coverage out of the central
  config suite so the parent test module is only a small module registry and
  shared helper host.
- Split the public config-error module into a small stable re-export wrapper,
  a focused error-kind module, and a separate formatting/source module as
  preparation for domain-specific error formatting cleanup.
- Split runtime unit tests out of the root runtime adapter into a focused test
  module while preserving private-helper coverage.
- Split runtime log-file opening and JSON/text log record formatting out of the
  root runtime adapter into a focused private module.
- Split native runtime background task implementations and cutover diagnostics
  out of the root runtime adapter, and move logging initialization into the
  runtime logging helper, bringing `src/runtime.rs` below the modularity line
  target.
- Split metrics registry/export regression coverage out of the root metrics
  adapter into a focused test module while preserving metrics-feature coverage.
- Split root metrics regression coverage into focused child test modules for
  core proxy/stream/UDP labels, load-balancer/PHP counters, native metrics app
  behavior, config/cache gauges, and bounded label helpers.
- Split metrics `OnceLock` registry storage and Prometheus constructor helpers
  into focused private modules for core, PHP/OTLP, cache gauge, and cache
  activity metrics.
- Split cache runtime totals, cache activity metrics, purger metrics, and
  native cache/proxy Prometheus recorders out of the root metrics adapter,
  bringing `src/metrics.rs` below the modularity target.
- Split TLS storage and downstream certificate-selector unit tests out of the
  root TLS adapter into focused test modules while preserving private-helper
  coverage.
- Split TLS storage issue typing and CLI-facing formatting out of the root TLS
  adapter into a focused private module.
- Split TLS storage validation and permission/path-safety preflight logic out of
  the root TLS adapter, bringing `src/tls.rs` below the modularity line target.
- Split ACME renewal, certificate-install, account-store, HTTP-01, EAB, and
  retry regression coverage into focused child test modules.
- Split ACME secret-loading, account-store, certificate-install, instant-client,
  and renewal error types into a focused private module while preserving the
  public `crate::acme::*Error` re-exports.
- Split ACME HTTP-01 and TLS-ALPN-01 challenge stores into a focused private
  module while preserving the public `crate::acme` re-exports.
- Split ACME renewal queue planning, retry backoff, and TOML datetime
  conversion helpers into a focused private module while preserving the public
  `crate::acme` re-exports.
- Split ACME certificate/private-key PEM validation helpers into a focused
  private module shared by managed certificate install and TLS-ALPN challenge
  handling.
- Split CLI regression coverage into focused child test modules for core
  command handling, cache warm, cache lookup, cache-key, and cache-key preview
  validation, reducing the root CLI adapter without changing command behavior.
- Split admin core response/health/status tests and auth/client-certificate
  secret-file tests into focused child modules while preserving existing admin
  helper coverage.
- Split native proxy traffic-mirror request construction, sampling, in-flight
  limits, recursion marker handling, and constant-time marker checks into a
  focused server module.
- Split native proxy peer-fill transport, shared-secret loading, nonce/HMAC
  authentication, and internal marker stripping into focused server modules.
- Split native proxy range/slice cache response composition, bounded range
  parsing, multipart assembly, and origin-slice request construction into a
  focused server module.
- Split native proxy upstream construction, static/dynamic load-balancer
  eligibility checks, HTTP/2 upstream policy mapping, and TCP socket option
  builders into a focused server module.
- Split native proxy custom error-page loading, rendering, and fallback status
  reason mapping into a focused server module.
- Split native proxy cache fill concurrency permits and cache-lock writer
  cleanup into a focused server module.
- Split native proxy cached-hit rendering, conditional `304 Not Modified`
  handling, and cached range-response selection into a focused server module.
- Split native proxy cache freshness, stale-window, stale-error, and predictor
  counter helpers into a focused server module.
- Split native proxy cache revalidation, `only-if-cached`, response header
  filtering, tag extraction, and Vary-key helpers into a focused server module.
- Split native proxy configuration error typing and diagnostics into a focused
  server module.
- Split native proxy request/timeout helper functions into a focused server
  module.
- Split native proxy peer-fill/cache unit tests into a focused server test
  module.
- Split native proxy memory-cache lookup, slice-fill, peer-fill, store, and
  predictor runtime into a focused server module.
- Split native proxy memory-cache range/slice response lookup, origin-slice
  fill, and slice storage into a focused child module.
- Split native proxy memory-cache origin, peer-fill, revalidation, Vary,
  memory-store, and disk-store admission into a focused child module.
- Split native proxy memory-cache disk lookup, stale/revalidation lookup, and
  memory promotion from disk hits into a focused child module.
- Split native proxy memory-cache peer-fill concurrency, request dispatch,
  response storage, and fail-open/fail-closed accounting into a focused child
  module.
- Split native proxy memory-cache lookup, key selection, memory hit selection,
  stale lookup, and revalidation lookup into a focused child module, bringing
  `native_http1_proxy_memory_cache.rs` below the modularity target.
- Split native proxy HTTP/2 upstream parity tests into a focused child test
  module while keeping shared proxy fixtures private to the parent test module.
- Split native proxy HTTP/2 upstream test fixtures into a focused support module
  so the H2 test module stays below the modularity target.
- Split native proxy unsupported-policy and config-blocker tests into a focused
  child test module.
- Split native proxy static upstream failover, round-robin, weighted
  round-robin, and unsafe-method retry tests into a focused child test module.
- Split native proxy request/response header policy and forwarded-header tests
  into a focused child test module.
- Split native proxy compression and configured error-page tests into a focused
  child test module.
- Split native proxy static and load-balanced WebSocket takeover tests into a
  focused child test module with distinct upstreams for the native load-balancer
  path.
- Split native proxy auth-request and traffic-mirror integration tests into a
  focused feature-gated child test module.
- Split native proxy static construction, timeout, pool, proxy-protocol, and
  socket-option config tests into a focused child test module.
- Split native proxy pooling, upstream PROXY protocol, upstream timeout, and
  request-body timeout runtime tests into a focused child test module, bringing
  `native_http1_proxy_tests.rs` below the modularity target.
- Split native HTTP/1 plan root/protocol, WebSocket, auth-request, and
  traffic-mirror candidate tests into a focused child test module.
- Split native HTTP/1 plan cache, static-web, and PHP-FPM candidate tests into
  a focused child test module.
- Split native HTTP/1 plan route header-policy, forwarded-header, and
  path-rewrite candidate tests into a focused child test module.
- Split native HTTP/1 plan access-policy, rate-limit, and concurrency
  candidate tests into a focused child test module.
- Split native HTTP/1 plan load-balancer, cutover-summary, and compression
  candidate tests into focused child test modules, bringing
  `native_http1_plan_tests.rs` below the modularity target.
- Split native route-proxy config/admission tests for redirect-only routes,
  vhost/route cache policies, PHP root validation, and peer-fill cache
  eligibility into a focused child test module.
- Split native route-proxy routing selection, request-body timeout, gRPC
  policy, and rewritten-path safety tests into a focused child test module.
- Split native route-proxy response-header overlay/rewrite, request-header
  mutation/template, inherited-header, disabled-header, and forwarded-header
  ownership tests into focused child test modules.
- Split native route-proxy compression negotiation/inheritance and disabled
  route-response-header tests into a focused child test module.
- Split native route-proxy access-policy, trusted-forwarded identity, client
  certificate, GeoIP, rate-limit, and concurrency tests into focused child test
  modules.
- Split native route-proxy PHP-FPM routing tests and FastCGI responder fixtures
  into a focused child test module.
- Split native route-proxy memory, disk, encrypted disk, storage-bin, OpenBao,
  and tiered cache storage tests into a focused child test module.
- Split native route-proxy cached range responses, range-miss bypasses, and
  slice-cache composition tests into a focused child test module.
- Split native route-proxy peer-fill, only-if-cached, and peer Age admission
  tests into a focused child test module.
- Split native route-proxy min-uses, predictor, stale-while-revalidate, and
  stale-if-error freshness tests into a focused child test module.
- Split native route-proxy origin-protection, cache-lock, authorization/no-store
  bypass, Age normalization, and Vary isolation tests into a focused child test
  module.
- Split native route-proxy prefix and regex rewrite tests into a focused child
  test module.
- Split native route-proxy ACME challenge-route and managed HTTP-01 tests into
  a focused child test module.
- Split native route-proxy WebSocket upgrade/tunnel tests into a focused child
  test module.
- Split native route-proxy header-default and privacy-mode spoofable-header
  tests into a focused child test module.
- Split native route-proxy test cache/request/header/config support builders
  into a focused child support module.
- Split native route-proxy cache/peer-fill upstream fixture servers into a
  focused child module, bringing `native_http1_route_proxy_tests.rs` below the
  modularity target.
- Split native HTTP/1 cache unit tests into a focused child test module.
- Split native HTTP/1 disk cache metadata serialization and safe filesystem
  path helpers into focused child modules.
- Split native HTTP/1 disk cache encryption and OpenBao Transit helpers into
  focused child modules.
- Split native HTTP/1 disk cache purge registry, purge API, and object
  inspection into a focused child module.
- Split native HTTP/1 memory cache entries, state, TTL helpers, pruning, and
  cache-status decoration into a focused child module.
- Split native HTTP/1 disk cache backend/state/store-key definitions into a
  focused child module.
- Split native HTTP/1 storage-bin allocation, rebuild, release, and index
  persistence into a focused child module.
- Split native HTTP/1 filesystem disk-cache index rebuild, shard-path writes,
  atomic file replacement, and soft-purge rewriting into a focused child
  module.
- Split native HTTP/1 disk-cache object inspection into a focused child module.
- Moved native HTTP/1 disk-cache private purge methods and shared mutation/state
  helpers into focused child modules, bringing `native_http1_cache.rs` below the
  500-line modularity target.
- Split compression config regression coverage out of the central config test
  suite into a focused child test module.
- Split GeoIP config regression coverage out of the central config test suite
  into a focused child test module.
- Split basic server/process/static-web config regression coverage out of the
  central config test suite into a focused child test module.
- Moved invalid server-process and static cache-header config regression
  coverage into the focused basic config test module.
- Split generic header-name/value validation regression coverage out of the
  central config test suite into a focused child test module.
- Split native proxy request handling, cache fill orchestration, static
  upstream retry, load-balanced dispatch, WebSocket takeover, and response
  finishing into a focused handler module.
- Split native proxy response finalization, cache-status header application,
  response-header policy, compression, metrics accounting, and authenticated
  peer-fill response signing into a focused server module.
- Split native proxy stale-while-revalidate refresh, cache revalidation request
  dispatch, and origin slice-fill fetches into a focused server module.
- Split native proxy load-balanced dispatch, selected-upstream health reporting,
  managed-affinity cookie injection, cache-aware retry, and WebSocket takeover
  handling into a focused feature-gated server module.
- Split native proxy static-upstream cache-aware dispatch, retry/failover,
  stale fallback, peer-fill, cache-lock waiting, and origin-fill budget handling
  into a focused server module, bringing the proxy handler under the 500-line
  modularity target.
- Split native proxy static and load-balanced WebSocket connection takeover
  into a focused server module, bringing the load-balanced dispatch module
  under the 500-line modularity target.
- Split native proxy construction, config mapping, weighted upstream setup, and
  equality handling into a focused builder module, leaving the core proxy type
  definition small.
- Split native proxy cache-support checks, cache attachment helpers, and
  equality comparison out of the builder so proxy construction stays below the
  modularity target.
- Split root native-proxy load-balancer admin statistics and mutation handlers
  into a focused child module while preserving the existing admin API surface.
- Split root native-proxy cache runtime statistics, activity-reset summaries,
  and native totals overlay logic into a focused cache-stats child module.
- Split root native-proxy cache selection, exact/bulk/indexed/stale purge
  handlers, and purge activity accounting into a focused cache-purge child
  module.
- Split root native-proxy cache snapshot, cache-key preview, disk-object lookup,
  and cache-preview route matching into a focused cache-snapshot child module,
  bringing `src/native_proxy.rs` below the modularity target.
- Split the root static-web proxy body reader into a focused child module so
  symlink-safe static body opening and buffering limits are isolated from route
  resolution and response planning.
- Split root static-web resolution and response tests into focused child test
  modules, bringing `src/web.rs` below the modularity target.
- Split root stream-proxy connection dialing/proxying helpers and stream tests
  into child modules, bringing `src/stream_proxy.rs` below the modularity
  target.
- Split native PHP-FPM response conversion and tests into focused modules,
  bringing `native_http1_php.rs` below the modularity target.
- Removed an unused import from the native traffic-mirror module that failed
  warning-as-error CI profiles.
- Split the UDP beta proxy listener bootstrap, runtime state/session helpers,
  and tests into child modules, bringing `src/udp_proxy.rs` below the
  modularity target.
- Split native upstream TLS file loading and symlink-safety tests into a child
  module so certificate/key/CA bundle file handling is isolated from backend
  connector setup.
- Split native upstream TLS Rustls connector setup, trust-store loading,
  client-certificate parsing, ALPN mapping, SNI validation, and verifier policy
  into a focused backend module, bringing `native_http1_tls.rs` below the
  modularity target.
- Split native downstream HTTP/1 response type, framing, header validation,
  timeout wrapping, and minimum send-rate enforcement into a focused child
  module while preserving the public response API.
- Split native downstream HTTP/1 request metadata, TLS/Geo context DTOs, cache
  request view, and load-balancer request view into a focused child module
  while preserving the public request API.
- Split native downstream HTTP/1 PROXY protocol v1/v2 source parsing and trust
  checks into a focused child module while preserving listener behavior.
- Split native downstream HTTP/1 request-body reading, content-length handling,
  chunked decoding, and body timeout wrapping into a focused child module.
- Split native downstream HTTP/1 plain TCP/Unix listener accept loops and
  Rustls/OpenSSL TLS listener accept loops into focused child modules, bringing
  `native_http1.rs` below the modularity target.
- Split native upstream HTTP/1 client socket setup and HTTP/2 request/response
  conversion helpers into focused child modules while preserving upstream
  pooling, h2c, and fallback behavior.
- Split native upstream HTTP/1 h2c/WebSocket upgrade response validation and
  downstream WebSocket upgrade head assembly into a focused child module.
- Split native upstream HTTP/1 request writing, forwarded-header ownership,
  hop-by-hop filtering, peer-fill internal header filtering, and Host
  validation into a focused child module shared with HTTP/2 upstream requests.
- Split native upstream HTTP/1 and HTTP/2 pool state, stale-connection retry
  predicates, and pooled-connection cleanup into a focused child module.
- Split native upstream HTTP/2 send orchestration, stream-slot admission,
  pooled-connection setup, negotiated-stream handling, and h2c upgrade probing
  into a focused child module.
- Split native upstream HTTP/1 send, WebSocket tunnel, pooled-stream reuse,
  connection setup, PROXY protocol write, and client unit tests into focused
  child modules, bringing `native_http1_client.rs` below the modularity target.
- Split native route proxy request dispatch, route selection, rate/concurrency
  enforcement, fallback static/PHP/proxy handling, and connection takeover into
  a focused handler module.
- Split native route proxy route selection, decoded-policy selection,
  trusted-client-IP restoration, traceparent application, rate-limit decisions,
  concurrency permits, and route action wrappers into a focused policy module,
  bringing the route-proxy handler below the modularity target.
- Split native route proxy route builders, redirect/static/PHP/proxy action
  construction, inherited route config mapping, and route helper accessors into
  a focused route module.
- Split native route proxy upstream/load-balancer construction into a focused
  server module so route dispatch keeps shrinking without changing serving
  behavior.
- Split native route proxy type, error, and build-context definitions into a
  focused server module while preserving the existing public re-exports.
- Split native route proxy managed ACME HTTP-01 route ownership into an
  ACME-gated server module, bringing the route-proxy construction file below
  the modularity target.
- Split native route redirect hardening tests into a focused server test module
  while preserving the existing live-listener coverage.
- Split native route traceparent propagation into a focused server module while
  preserving the existing trusted-peer behavior.
- Move native HTTPS redirect response assembly into the route redirect module
  beside the existing redirect target validation helpers.
- Split native proxy auth-request handling into a focused server module while
  preserving secret redaction, response header replacement, and denial mapping.
- Split pure PHP config validators and public PHP validation limits into a
  focused `fluxheim-config` module while preserving the existing `config_php`
  and root `config` re-exports.
- Split managed PHP-FPM config validation into a Unix-gated
  `fluxheim-config` module while preserving the existing PHP config API.
- Split external PHP-FPM endpoint, retry, timeout, and keepalive validation
  into a focused `fluxheim-config` module while preserving
  `PhpFpmConfig::validate`.
- Split PHP root, request-spool directory, and PHP error-page validation into
  a focused `fluxheim-config` path module while preserving existing validation
  behavior.
- Split PHP numeric, body-spooling, response-size, and stderr-size validation
  into a focused `fluxheim-config` limit module.
- Split PHP default and preset helper logic into focused `fluxheim-config`
  modules, bringing `config_php.rs` under the 500-line modularity target.
- Split cache purger config and validation into a focused `fluxheim-config`
  module while preserving the top-level config API.
- Split cache range and slice config into a focused `fluxheim-config` module
  while preserving the existing public re-exports.
- Split cache lock, predictor, and origin-protection config into a focused
  `fluxheim-config` controls module.
- Split cache memory-tier config into a focused `fluxheim-config` module while
  preserving the existing public re-export.
- Split cache peer-fill config and peer URL validation into a focused
  `fluxheim-config` module while preserving the existing public re-exports.
- Split cache storage-bin config into a focused `fluxheim-config` module while
  preserving the existing public re-export.
- Split cache disk-encryption and OpenBao Transit config into a focused
  `fluxheim-config` module while preserving existing public re-exports.
- Split cache disk-tier config into a focused `fluxheim-config` module while
  preserving the existing public re-exports and merge behavior.
- Split cache key, stale-error, default, and preset helper primitives into a
  focused `fluxheim-config` policy module while preserving public re-exports.
- Split cache validation into a focused `fluxheim-config` module, bringing
  `config_cache.rs` down to the 500-line modularity target.
- Split the public `ConfigError` enum and formatting implementation out of
  `config.rs` into a focused error module while preserving the existing
  `fluxheim_config::ConfigError` re-export.
- Split `VhostConfig` and its validation/path-resolution behavior into a
  focused `fluxheim-config` module while preserving the existing public
  re-export.
- Split TOML config fragment loading and relative-path resolution into a
  focused `fluxheim-config` module.
- Split root config loading, preset application, `conf.d` merge, and fragment
  merge behavior into a focused `fluxheim-config` module.
- Split root config validation orchestration and cross-domain compliance checks
  into a focused `fluxheim-config` module, bringing `config.rs` below the
  line-limit target.
- Split native HTTP/1 proxy cache runtime stats, memory purge registries, and
  Prometheus recorder hooks into focused server modules while preserving the
  existing public exports.
- Split native route-proxy response-compression negotiation and response
  mutation helpers into a focused server module while preserving compression
  behavior.
- Split native route redirect response construction and safe redirect URL
  expansion into a focused server module while preserving redirect validation.
- Split native route request-header mutation, template rendering, and trusted
  forwarded-header synthesis into a focused server module while preserving
  route regex capture expansion.
- Split native route response-header policy overlays and response rewrite
  helpers into a focused server module while preserving header behavior.
- Split native route access checks, token-bucket rate limiting, and concurrency
  permits into focused server modules while preserving route policy behavior.
- Split native route PHP-FPM handling and PHP path canonicalization helpers into
  focused server modules while preserving PHP fallback behavior.
- Split native gRPC route rejection checks into a focused server module while
  preserving method and content-type enforcement.
- Split native route matcher and regex-capture helpers into a focused server
  module while preserving route priority and rewrite capture behavior.
- Split native route request-target parsing and rewrite expansion into a
  focused server module while preserving prefix and regex rewrite behavior.
- Split native ACME HTTP-01 route responses into a focused server module while
  preserving challenge method, lookup, and response handling.
- Split native route action dispatch into a focused server module while
  preserving proxy, redirect, static-web, ACME, PHP, and upgrade behavior.
- Split native route cache-policy eligibility checks into a focused server
  module while preserving config validation behavior.
- Move decoded route-policy path handling into the native route limits module
  so access/rate/concurrency policy matching stays grouped.
- Split background supervision and shutdown primitives out of
  `fluxheim-runtime/src/lib.rs` into focused runtime modules while preserving
  the public exports.
- Move `fluxheim-web` crate tests out of `src/lib.rs` so the production static
  response and directory-listing implementation stays below the line-limit
  target.
- Split stream upstream selection and stream tests out of
  `fluxheim-stream/src/lib.rs`, leaving the stream crate root below the
  line-limit target while preserving public exports.
- Split snapshot runtime validation state from snapshot-store persistence and
  turn `fluxheim-snapshot/src/lib.rs` into a small crate re-export surface.
- Split snapshot symlink-safe filesystem helpers and atomic write logic out of
  `fluxheim-snapshot/src/store.rs` into a focused `store_fs` module.
- Split snapshot metadata, message, and ID validation helpers out of
  `fluxheim-snapshot/src/store.rs` into a focused metadata module.
- Move snapshot store regression tests into focused functional and path-safety
  test modules, bringing `fluxheim-snapshot/src/store.rs` below the line-limit
  target.
- Move `fluxheim-cache` request/key/range tests out of `src/request.rs`,
  leaving the production cache request helpers below the line-limit target.
- Move `fluxheim-cache` object/envelope/index tests out of `src/object.rs`,
  leaving the production disk object helpers below the line-limit target.
- Move `fluxheim-cache` storage-bin tests out of `src/storage_bin.rs` as the
  first step toward splitting manifest/layout, allocator, and index helpers.
- Split the storage-bin free-range allocator into a focused
  `storage_bin_alloc` module while re-exporting the existing public API.
- Split storage-bin layout, manifest, and object-location validation into a
  focused manifest module while keeping the `storage_bin` public exports stable.
- Split storage-bin symlink-safe filesystem helpers into a focused private
  module, bringing `fluxheim-cache/src/storage_bin.rs` below the line-limit
  target.
- Split admin ops-socket, remote transport/client-certificate, and
  health/throttle/self-healing config sections into focused
  `fluxheim-config` modules, leaving `config_admin.rs` as the schema entry
  point and re-export surface.
- Split ACME vhost challenge routing and issuer/EAB validation into focused
  `fluxheim-config` modules, leaving `config_acme.rs` below the modularity
  target without changing the public config exports.
- Split root stream upstream TLS backend helpers into rustls and OpenSSL
  modules, leaving `stream_tls.rs` as the shared connector orchestration and
  warning-policy surface.
- Split config-tester profile validation, native-runtime cutover reporting, and
  upstream resolution helpers into focused root modules, leaving the config
  tester entry point below the modularity target.
- Split header response-policy structs and header validation helpers into
  focused `fluxheim-config` modules, leaving the header config facade below the
  modularity target while preserving existing re-exports.
- Split stream TLS policy validation, stream connection-slot accounting, and
  stream config tests into focused `fluxheim-config` modules, leaving the
  stream config facade below the modularity target.
- Move reload-classification tests into focused base and load-balancer test
  modules, leaving `fluxheim-config/src/reload.rs` as the small runtime reload
  classifier.
- Split load-balancer health-check schema and validation into focused
  `fluxheim-config` modules while preserving the existing public
  `LoadBalanceHealthCheck*` exports.
- Split load-balancer passive-health config and validation into a focused
  `fluxheim-config` module while preserving the public config exports.
- Split load-balancer retry config, defaults, and validation into a focused
  `fluxheim-config` module while preserving the public config exports and safe
  retry method constant.
- Split load-balancer queue config, defaults, and validation into a focused
  `fluxheim-config` module while preserving the public config exports.
- Split load-balancer persistence config, managed-cookie settings, defaults,
  and validation into a focused `fluxheim-config` module while preserving the
  public config exports.
- Split load-balancer slow-start config, defaults, and validation into a
  focused `fluxheim-config` module, bringing the load-balancer config facade
  below the line-limit target.
- Split proxy auth-request config, defaults, and validation into a focused
  `fluxheim-config` module while preserving the public proxy config exports.
- Split proxy traffic-mirror config, defaults, and validation into a focused
  `fluxheim-config` module while preserving the public proxy config exports.
- Split proxy error-page config, path resolution, and validation into a focused
  `fluxheim-config` module while preserving the public proxy config export.
- Split proxy upstream subset validation, static IP-upstream detection, and
  load-balancer backend-key collision checks into a focused private
  `fluxheim-config` module.
- Split shared proxy upstream HTTP/proxy-protocol enums into a focused
  `fluxheim-config` module while preserving the existing proxy config
  re-exports.
- Split cache admin math, warm summaries, object-lookup summaries, and tests
  out of `fluxheim-cache/src/api.rs`, leaving cache API DTOs below the
  line-limit target.
- Split cache header Cache-Control and Pragma directive parsing into a focused
  private module as the first step toward request/response header policy
  modules.
- Split cache request-side header policy, cookie/query bypass matching, and
  range/slice request selection into a focused private module while preserving
  the existing `fluxheim-cache::headers` exports.
- Split cache Vary header policy and request-hash material helpers into a
  focused private module while preserving the existing `headers` exports.
- Split cache response header policy, freshness helpers, content-type checks,
  and range response admission into a focused private module while preserving
  the existing `headers` exports.
- Split cache stale-if-error and stale-while-revalidate policy helpers into a
  focused private module while preserving the existing `headers` exports.
- Split load-balancer selected-upstream and queue/persistence outcome DTOs out
  of `fluxheim-load-balancer/src/api.rs`, leaving the load-balancer API DTO
  module below the line-limit target.
- Split load-balancer FNV hashing, random selection seeds, and per-process route
  secrets into a focused private selection-hash module.
- Split the nginx-compatible Ketama continuum builder and backend-key iterator
  into a focused private load-balancer selection module.
- Split the Maglev table builder, candidate iterator, and modular-arithmetic
  helper into a focused private load-balancer selection module.
- Split load-balancer candidate filtering, passive-health ejection floor, and
  slow-start permit checks into a focused private selection module.
- Split power-of-two choice selection and weighted random candidate selection
  into a focused private load-balancer selection module.
- Split consistent-hash, nginx-compatible Ketama selection, and bounded-load
  consistent selection into a focused private load-balancer selection module.
- Split FNV hash selection and shared weighted-index expansion into focused
  private load-balancer selection modules, bringing `selection.rs` below the
  line-limit target.
- Move `fluxheim-cache` header policy tests out of `src/headers.rs`, leaving
  the cache header facade below the line-limit target.
- Move load-balancer policy override tests out of `src/policy.rs` as a
  preparatory split for the remaining policy key/snapshot/mutation modules.
- Split load-balancer config-derived backend policy maps and aliases into a
  focused private policy-config module.
- Split load-balancer backend runtime stats assembly into a focused private
  policy-stats module.
- Split load-balancer runtime override and snapshot state into a focused
  private policy-runtime module, bringing `policy.rs` below the line-limit
  target.
- Split load-balancer persistence request-key helpers and managed-cookie
  HMAC/token handling into focused private modules, bringing `persistence.rs`
  below the line-limit target.
- Split the pure load-balancer backend model, backend identity, and backend-set
  helpers out of the runtime module as a focused private module.
- Split load-balancer backend health/discovery state and backend runtime tests
  into focused child modules, bringing `backend.rs` below the line-limit target.
- Split load-balancer HTTP discovery, DNS discovery, and discovery tests into
  focused modules, bringing `discovery.rs` below the line-limit target.
- Split load-balancer HTTP/gRPC health-check construction and response
  validation into a focused health submodule, bringing the production
  `health.rs` dispatcher below the line-limit target.
- Split load-balancer health-check regression tests by transport/protocol
  family, removing the temporary oversized health test exception.
- Split the load-balancer crate-root regression suite into focused test modules,
  reducing `fluxheim-load-balancer/src/lib.rs` to orchestration/facade code.
- Split the load-balancer background-service wrapper into a focused service
  module while preserving the public `UpstreamLoadBalancerService` export.
- Split the load-balancer inner strategy dispatcher and backend member adapter
  helpers into a focused private module, further reducing the crate root to the
  public facade and orchestration glue.
- Split load-balancer runtime-state snapshot/load/save glue into a focused
  private module while preserving the public runtime-state methods.
- Split load-balancer runtime backend mutation and persistence-clear methods
  into a focused private module, leaving the crate root closer to construction,
  selection, and stats orchestration.
- Split load-balancer queue wait/timeout handling into a focused private module,
  leaving the crate root below 800 lines.
- Split load-balancer runtime stats assembly into a focused private stats
  facade module.
- Split load-balancer public construction and background-service factory methods
  into a focused private construction module, bringing the crate root below the
  line-limit target.
- Split PHP-FPM FastCGI request parameter translation into a focused private
  module while preserving the existing crate exports.
- Split PHP-FPM script-name, path-translation, deny-prefix, and static-file
  script mapping helpers into a focused private module.
- Split PHP-FPM response parsing, static-offload target validation, cache-policy
  checks, and response-header strip policy into a focused private module.
- Split managed PHP-FPM config rendering, instance-name generation, sanitized
  PATH fallback, and restart backoff helpers into a focused private module.
- Split managed PHP-FPM spawn safety, private config-file creation, managed
  directory validation, and socket readiness waits into a focused private
  module.
- Split managed PHP-FPM process lifecycle, child cleanup, restart watchdog, and
  process start handling into a focused private module below the line-limit
  target.
- Split the remaining PHP-FPM crate regression suite into focused I/O/policy,
  parameter/script, and response/config test modules, reducing the crate root to
  a small facade below the line-limit target.
- Split native route static-web PHP resolution tests into a focused module,
  bringing the route static-web test module below the line-limit target.
- Split PHP-FPM endpoint selection, timeout classification, retry policy, and
  retry deadline helpers into a focused private module.
- Split PHP-FPM request-body replay, zeroized memory body ownership, spool-file
  allocation, cleanup, and spool-directory validation into a focused private
  module.
- Split PHP-FPM streamed FastCGI response collection and bounded chunk
  accounting into a focused private module.
- Split PHP-FPM keepalive pool management and one-shot FastCGI execution into a
  focused private module while preserving the public crate exports.
- Split native runtime launch-plan TSV report rendering into a focused module,
  bringing the launch-plan assembly file below the line-limit target.
- Split native HTTP/2 response validation and bounded response-data writes into
  a focused private module, bringing the downstream H2 stack below the
  line-limit target.
- Split native HTTP/2 response, trailer, flow-control hold, and HTTP/1 adapter
  regression tests into a focused response test module.
- Split native upstream TLS proxy regression tests into base TLS, Rustls H2
  ALPN, and mTLS modules, removing the oversized TLS test exception.
- Split native upstream HTTP/1 client regression tests into base response,
  h2c-upgrade, forwarded-header/timeout, and PROXY protocol modules, removing
  the oversized client-test exception.
- Split native HTTP/1 runtime proxy tests into plain/PROXY, Rustls TLS, and
  OpenSSL TLS modules, removing the oversized runtime-proxy test exception.
- Split native downstream HTTP/1 tests into base listener/framing, request-view,
  body/limit/timeout, and TLS-listener modules, removing the oversized
  downstream HTTP/1 test exception.
- Split server-plan tests into base policy, native-runtime cutover, manifest,
  and listener-inventory modules, removing the oversized server test exception.
- Split native static-web path resolution, directory listing, response planning,
  and rooted body-opening helpers into focused child modules, removing the
  oversized static-web exception.
- Split native HTTP/1 proxy runtime TLS listener planning and runtime error
  formatting into focused child modules, removing the oversized runtime proxy
  exception.
- Split route redirect config and redirect-template validation into a focused
  config module, bringing `config_route.rs` to the line-limit target.
- Split TLS policy enums/defaults, client-auth config, and static certificate
  path validation into focused TLS config modules, removing the oversized TLS
  config exception.

## 1.6.36 - 2026-06-30

### Changed

- Start the post-cutover structural cleanup release with release metadata bumped
  through the workspace and RPM spec.
- Begin replacing the temporary native proxy shim with direct crate-owned APIs
  now that normal Fluxheim builds are Pingora-free.
- Rename the temporary native proxy shim module to `native_proxy`, keeping the
  historical `crate::proxy` re-export stable while the owning crate APIs are
  split out.
- Stop re-exporting cache admin DTOs through the native proxy compatibility
  boundary; admin and CLI code now use the dedicated `cache_api` module
  directly.
- Replace active root/admin/CLI/runtime imports of the historical `crate::proxy`
  compatibility alias with direct `crate::native_proxy` imports.
- Move load-balancer admin request/result DTOs from the native proxy boundary
  into the `fluxheim-load-balancer` crate.
- Remove the historical `crate::proxy` re-export from normal builds; active
  code now uses `crate::native_proxy` and crate-owned APIs directly.
- Delete inert Pingora-era root source files that were permanently gated behind
  `cfg(any())`, including the old proxy, cache, header, auth-request, edge
  policy, PHP-FPM, traffic-mirror, and proxy-protocol adapters.
- Remove stale disabled Pingora compatibility runner/test code from
  `runtime.rs` so dead `cfg(any())` paths no longer reference non-existent
  native proxy methods or Pingora traits.
- Remove the stale Pingora HTTP boundary exception rows now that normal source
  no longer carries quarantined Pingora HTTP adapter code.
- Consolidate native proxy config storage so hot reload refreshes the same
  config snapshot used by cache purge, cache preview, cache stats, activity
  reset, and load-balancer stats paths.
- Add native HTTP/1 chunked-body regression coverage for the historical
  overflow-sized chunk header crash class; the native parser rejects the
  `ffffffffffffffff` chunk size before routing reaches the proxy handler.
- Pin observability smoke images to stable Prometheus and Jaeger tags instead
  of `latest` so CI pulls deterministic container versions.

## 1.6.35 - 2026-06-30

### Changed

- Start the Pingora-free runtime stabilization release with release metadata
  bumped through the workspace and RPM spec.
- Fix the version-bump helper so semantic versions beginning with digits do not
  get interpreted as regex backreferences during package-version replacement.
- Begin the first-party secret-memory cleanup pass by auditing direct
  `zeroize` usage for practical migration to Fluxheim's `sanitization` crate.
- Move legacy root auth subrequest forwarded-header secrets from direct
  `zeroize::Zeroizing<String>` wrappers to `sanitization::SecretString`.
- Move native auth-request forwarded and allowed response-header secrets to
  `sanitization::SecretString`.
- Move native metrics bearer-token storage and candidate comparison buffers to
  `sanitization` secret containers.
- Move managed load-balancer cookie HMAC key-ring clearing from direct
  `zeroize` calls to `sanitization::SecureSanitize`.
- Move HTTP discovery bearer-token storage and Fluxheim-owned Authorization
  header assembly to `sanitization::SecretString`.
- Move native OpenBao disk-cache encryption token storage to
  `sanitization::SecretString`.
- Align the legacy cache OpenBao token holder with the native cache token
  migration.
- Move admin bearer-token digest clearing from `ZeroizeOnDrop` to an explicit
  `sanitization::SecureSanitize` drop implementation.
- Update the release checklist to prefer `sanitization::ct` for constant-time
  secret comparisons and remove an unused `zeroize` derive feature from the
  load-balancer crate.
- Move native upstream TLS client private-key PEM buffers for rustls and
  OpenSSL backends to `sanitization::SecretVec`.
- Move stream-proxy upstream TLS client private-key PEM buffers for rustls and
  OpenSSL backends to `sanitization::SecretVec`.
- Abort if native `auth_request` response-header application cannot access its
  secret container, matching other poisoned security-control locks and avoiding
  a repeated inconsistent 502 path.
- Clear the admin token digest and stored token length through
  `sanitization::SecureSanitize` during drop.
- Align runtime performance baseline capture with its load-balancer fixture by
  building the `profile-load-balancer` release profile by default.
- Tighten native vhost-level PHP-FPM/static fallback routing so executable PHP,
  PHP directory redirects, denied PHP paths, and fail-closed resolution errors
  stay on the PHP-FPM path, while non-PHP static files can still be served by
  `[vhosts.web]`.
- Carry the native PHP-FPM fallback script-resolution result into the handler
  so vhost PHP/static routing does not resolve the same path twice across a
  deployment race window.
- Make `validate_runtime_config()` run the central structural
  `Config::validate()` checks itself, so standalone runtime validation catches
  cross-field invariants such as peer-fill policy shape before startup.
- Snapshot native disk-cache purge targets before running purge callbacks, so
  stale and indexed maintenance batches no longer hold the global purge
  registry mutex while deleting cache objects.
- Serialize native disk-cache same-key mutations with bounded lock stripes so
  store, purge, and eviction cannot interleave state updates with filesystem
  object removal for the same combined cache key.
- Preserve the client request `Host` as the HTTP/2 upstream `:authority`,
  matching the documented upstream virtual-hosting behavior already used by the
  native HTTP/1 and WebSocket paths.
- Narrow native PHP-FPM fallback fail-closed routing so resolver errors for
  explicit or protected PHP targets still avoid static source exposure, while
  ordinary non-PHP front-controller probe errors defer to static fallback first.
- Harden the WordPress PHP-FPM smoke fixture with explicit private TCP upstream
  opt-in and MariaDB readiness waiting, and verify the full native WordPress
  PHP-FPM plus proxy/TLS smoke coverage.
- Add `scripts/test_starter.py` as a human-facing selector for the maintained
  live smoke scripts and release gates.
- Add `scripts/check_smoke_images.sh` so maintainers can pull and record the
  configured WordPress, OpenBao, MariaDB, PostgreSQL, and Valkey smoke images.
- Add a privacy-mode live smoke that builds `profile-privacy`, verifies
  client-IP headers are stripped before the upstream, and checks Fluxheim logs
  do not retain the test IP, path, cookie, user-agent, or request ID.
- Extend local and container load-balancer smokes with native
  nginx-compatible Ketama coverage, and extend the container smoke with
  backend failover, recovery, and all-down 503 checks.
- Wire optional deep-gate flags for OpenBao cache encryption, database health
  checks, WordPress, PHP Wolfi, RPM build, privacy mode, and smoke dependency
  image freshness.
- Make the observability smoke self-contained by starting disposable
  Prometheus and Jaeger containers when external URLs are not configured,
  requiring Prometheus scrape plus OTLP metrics ingestion and keeping Jaeger
  trace ingestion opt-in until native span export is implemented.
- Require `cache.peer_fill.shared_secret_file` for non-loopback `http://`
  peer-fill URLs, closing the remaining unauthenticated cross-host plaintext
  peer-fill cache-poisoning configuration.
- Add `cache.peer_fill.shared_secret_file` so peer-fill clusters can require
  response-bound HMAC verification: outbound peer-fill requests include a
  nonce/request signature, peers sign the status, canonical response headers,
  and body digest, and unsigned or tampered peer responses are discarded before
  cache storage.
- Add `scripts/smoke_ports.py` and wire the newer privacy, observability, and
  load-balancer container smokes through the shared randomized localhost port
  allocator instead of repeating ad-hoc allocation snippets.

## 1.6.34 - 2026-06-29

### Changed

- Start the final Pingora-free proof release after native proxy-cache parity.
- Remove the remaining Pingora compatibility runtime from normal Fluxheim
  builds and tighten dependency-policy gates so default, full, edge, PHP,
  privacy, RPM, source, and container release artifacts fail if they compile
  Pingora crates.
- Wire native admin cache purge, cache object lookup, stale disk-cache purge,
  and live load-balancer stats/mutation handlers to the Fluxheim-owned runtime
  handles used by traffic.
- Align native cache-key/cache-lookup previews with route-scoped cache policy
  selection, preserve the documented `HEAD` temporary-bypass reason, and record
  native disk-cache purge activity metrics.
- Refresh the OWASP Top 10 2025 release-gate inventory to reference the native
  HTTP/1 controls that replaced the legacy Pingora-era test names.
- Centralize native cache user-tag formatting in `fluxheim-cache` so disk-cache
  indexing and admin purge paths cannot drift.
- Keep native-runtime compatibility reporting explicit for any configuration
  shape that still needs a future native feature instead of silently falling
  back to a Pingora adapter.
- Harden native admin cache-preview and cache-purge paths by normalizing host
  selection, matching regex routes consistently with the serving path, failing
  closed on poisoned live config state, avoiding registry-lock disk I/O during
  stale purges, and restoring explicit cache API re-exports.
- Refactor native route-proxy construction contexts so release clippy profiles
  enforce smaller, typed builder boundaries instead of long argument lists.

## 1.6.33 - 2026-06-28

### Changed

- Start the final native proxy-cache parity release with a Fluxheim-owned
  native memory-cache adapter for ordinary HTTP/1 proxy responses.
- Native proxy cache now supports safe memory-tier `GET` lookup/fill for
  static and native load-balanced upstream pools, emits configured cache
  status/reason headers,
  preserves HEAD bypass behavior, and reuses shared Fluxheim cache admission
  checks for request bypass, response `no-store`/`private`, `Set-Cookie`,
  content type, status TTL, and object-size policy.
- Native cache readiness now accepts root, vhost, and route proxy cache
  policies for the supported native proxy-cache subset.
- Native HTTP/1 TLS startup now recognizes managed ACME certificate sources on
  `server.default_vhost`, allowing the rustls native listener to bind while the
  default-vhost certificate is still pending first issuance.
- Harden native proxy memory cache by bypassing shared-cache lookup/fill for
  requests carrying `Authorization`, preserving `BYPASS` cache status headers
  on upstream error responses, and replacing upstream `Age` headers with a
  single recomputed cache-hit age.
- Native proxy memory cache now isolates origin `Vary` variants and configured
  `cache.vary_request_headers` variants in the Fluxheim-owned in-memory cache
  key space.
- Native proxy memory cache now honors `stale_if_error_secs` for expired
  memory-cache entries when the single-upstream native proxy sees an upstream
  connection/protocol error or configured 5xx status.
- Native proxy memory cache now supports `cache.origin_protection` fill budgets
  for the supported single-upstream memory-cache path.
- Native proxy memory cache now uses checked expiry arithmetic and bypasses
  caching if a platform cannot represent the configured freshness/stale window.
- Native proxy memory cache now serves bounded single `Range` requests from
  fresh cached full objects, returns cached `416` responses for unsatisfiable
  ranges, and bypasses cache fill on range misses to avoid storing partial
  upstream responses under full-object keys.
- Native proxy memory cache now works with native load-balanced upstream pools;
  cache hits return before backend selection and misses fill from the selected
  backend.
- Native proxy memory cache now supports `cache.min_uses`,
  `cache.pass_uncacheable_after`, and opt-in `[cache.predictor]` cache-pass
  decisions with bounded Fluxheim-owned counters and live native listener
  coverage.
- Native proxy memory cache now supports `stale_while_revalidate_secs` for
  expired memory objects, serving `STALE-UPDATING` responses while a bounded
  background refresh updates the cached object through the same admission path.
- Native proxy memory cache now supports `[cache.lock]` same-key request
  collapsing for concurrent memory-cache misses, allowing waiting readers to
  serve the completed origin fill as a `HIT`.
- Native proxy memory cache now supports memory-tier `[cache.range.slice]`
  composition for fixed-size slices, including bounded origin slice fills,
  slice identity checks, single-range responses, multipart range responses, and
  live tests that prove the native listener sends bounded `Range` subrequests.
- Native proxy memory cache now supports peer-fill over HTTPS and constrained
  plaintext HTTP peers. HTTPS peer-fill uses the native upstream TLS connector;
  HTTP peer-fill remains limited to loopback peers unless
  `cache.peer_fill.allow_insecure_http = true`.
- Native peer-fill preserves the peer-fill loop marker, `only-if-cached`
  request mode, bounded peer-fill concurrency, local storage of successful peer
  `200` responses, and `PEER-HIT` status reporting.
- Native proxy cache now supports unencrypted filesystem disk cache and
  memory+filesystem-disk tiering, with live listener tests proving disk
  persistence across native proxy instances and memory refill from disk.
- Native proxy cache now supports local-key encrypted filesystem disk cache,
  reusing the existing AES-256-GCM disk-object envelope and safe key-source
  loading while preserving plaintext rejection when encryption is enabled.
- Move storage-bin file-set, manifest, and index I/O helpers into
  `fluxheim-cache` with crate-local safe `openat`/`NOFOLLOW` coverage,
  preparing the native storage-bin adapter without depending on root
  compatibility cache code.
- Native proxy cache now supports the `storage-bin` disk backend, including
  manifest/index preparation, bin-slot allocation, native index recovery,
  oldest-object eviction, and live restart `MISS` then `HIT` coverage.
- Native proxy cache now supports local-key encrypted storage-bin disk cache,
  proving encrypted bin-file persistence across a native proxy restart without
  storing the origin response body in plaintext.
- Native proxy cache now supports OpenBao Transit encrypted disk cache through
  the native cache adapter, including redirect-disabled Transit requests,
  bounded Transit response bodies, zeroized token-file/credential loading, and
  live storage-bin restart coverage that exercises both validation and hit-time
  decrypts.
- Harden native peer-fill by subtracting upstream `Age` during admission,
  returning bounded `504` misses for `only-if-cached` cache misses, and
  preventing a client-supplied peer-fill marker alone from forcing origin
  traffic.
- Harden native cache internals by using checked static-web cache expiry
  arithmetic, suppressing duplicate stale-while-revalidate refresh tasks per
  cache key before task spawn, and avoiding full predictor-counter table scans
  on the hot miss path.
- Harden native cache admin purge parity by adding a Fluxheim-owned native
  memory-cache purge index and wiring exact, bulk, prefix, tag, wildcard,
  route-scope, and stale purges through live native memory state as well as
  disk state. The proxy-cache smoke now fails if a purge leaves a native memory
  `HIT` or `STALE` response behind while the origin is stopped.
- Close native observability parity gaps by regenerating forwarded
  `traceparent` span IDs, recording native proxy request counters, exporting
  native cache memory/disk runtime gauges, and publishing native cache lookup
  duration histograms through the Prometheus metrics surface.
- Fix native disk-cache purge parity by registering live disk-cache instances,
  adding a native disk purge index, and wiring exact, path, tag, wildcard, and
  stale admin purges through active filesystem and storage-bin state instead
  of reconstructing throwaway cache instances.
- Move native disk-cache lookup/store work, including OpenBao Transit calls and
  storage-bin index writes, onto Tokio's blocking pool and batch storage-bin
  eviction index persistence to avoid request-worker stalls under disk or
  Transit latency.
- Harden native cache encryption and purge edge cases by bounding filesystem
  cache-object reads before startup rebuild parsing, zeroizing transient
  decrypted OpenBao/native serialized-object buffers, warning on local
  AES-GCM random-nonce invocation limits, and logging clock-regression stale
  purge behavior.
- Harden native filesystem disk-cache startup scans by routing root and shard
  directory listing through the native safe disk-cache path wrapper, and update
  `arc-swap` to 1.9.2 plus `env_logger` to 0.11.11.

## 1.6.32 - 2026-06-28

### Changed

- Continue the native-runtime cutover by adding native metrics service token
  loading, native service handoffs for stream/UDP/load-balancer refresh tasks,
  and native runtime dispatcher coverage.
- Add native proxy HTTP/1 listener startup paths for plaintext, Rustls, OpenSSL,
  trusted downstream PROXY protocol, and certificate reload integration while
  keeping unsupported HTTP/2 listener dispatch fail-closed.
- Tighten native load-balancer compatibility by rejecting nginx-compatible
  Ketama tables with dynamic discovery sources and warning when CRC32 ring
  collisions reduce compatibility points.
- Harden native HTTP/2 per-stream failures so validation/body/handler errors
  return stream-local HTTP errors without terminating sibling streams.
- Harden native WebSocket upgrade handling by releasing concurrency permits
  before tunnel entry, stripping upstream hop-by-hop headers, and rebuilding
  downstream `101 Switching Protocols` responses from an allowlist.
- Store native HTTP request bodies in zeroizing memory and preserve that
  behavior across the native HTTP/2-to-HTTP/1 adapter.
- Compare native metrics bearer tokens through fixed-size digests and document
  `metrics.token_file` as the preferred high-assurance token source.
- Extend Pingora dependency cutover enforcement with manifest-scoped
  compatibility dependency tracking.

## 1.6.31 - 2026-06-24

### Changed

- Split native HTTP/1 proxy cutover diagnostics for cache policy and PHP-FPM
  into explicit `CachePolicy` and `PhpFpm` blockers instead of reporting both
  as a generic HTTP policy gap.
- Make direct native route-proxy construction fail closed for vhost/route cache
  and PHP-FPM policies until those adapters are implemented, preventing API
  callers from accidentally dropping those policies outside the planner.
- Move image/static cache request eligibility and cache-key construction into
  the Pingora-independent `fluxheim-cache` crate, leaving the root crate with
  only the Pingora key wrapper for compatibility runtime use.
- Implement `fluxheim-cache::CacheRequestView` for `NativeHttp1Request`, giving
  the native proxy a Pingora-free request adapter for cache bypass,
  revalidation, range, and slice policy helpers.
- Move PHP-FPM response parsing into the Pingora-independent
  `fluxheim-php-fpm` crate, returning plain status/header/body parts while the
  root proxy path keeps only the current runtime response-header conversion.
- Move PHP FastCGI parameter value validation and request-header-to-param-name
  mapping into `fluxheim-php-fpm`, giving native and compatibility paths one
  shared policy for bounded, control-free PHP params.
- Move PHP `SERVER_NAME` fallback selection into `fluxheim-php-fpm`, keeping
  host/fallback sanitization shared by native and compatibility paths.
- Move PHP FastCGI request-header param translation, resolved `HTTP_HOST`
  insertion, `CONTENT_TYPE` value selection, and runtime custom-param filtering
  into `fluxheim-php-fpm`, leaving the current proxy path as a thin adapter to
  `fastcgi_client::Params`.
- Move PHP split-container path mapping for `SCRIPT_FILENAME` and safe
  `PATH_TRANSLATED` generation into `fluxheim-php-fpm`, sharing dot-segment,
  hidden path, backslash, and control-byte rejection.
- Move PHP request-path to `SCRIPT_NAME`/`PATH_INFO` parsing,
  allowed-extension matching, and deny-prefix checks into `fluxheim-php-fpm`,
  while the proxy keeps static-file lookup and final execution decisions.
- Move PHP static-file to script-name mapping and slashless directory-index
  redirect decisions into `fluxheim-php-fpm`, so native and compatibility paths
  share root confinement, hidden path rejection, and extension checks.
- Move PHP static-offload target validation into `fluxheim-php-fpm`, including
  X-Accel-Redirect control-byte rejection, X-Sendfile `fpm_root` mapping, and
  PHP-script offload blocking.
- Move PHP X-Accel-Expires TTL parsing and restrictive origin cache-policy
  detection into `fluxheim-php-fpm`, so native PHP response handling can share
  the same cache safety rules.
- Move PHP response-header stripping policy into `fluxheim-php-fpm`, including
  hop-by-hop headers, `Connection` tokens, configured hidden headers, and
  static-offload internal headers.
- Move PHP custom error-page/status interception decisions into
  `fluxheim-php-fpm`, keeping native and compatibility response handling on one
  status policy.
- Harden shared PHP response/request policy by pre-reserving bounded
  `CONTENT_TYPE` joins, rejecting extensionless static-offload files, ignoring
  invalid `Connection` header tokens before response stripping, and asserting
  ASCII-only parser invariants.
- Cap and validate PHP `CONTENT_TYPE` values during accumulation, avoiding an
  oversized intermediate joined string before rejecting over-limit input.
- Change pure local-static cache keys to use the explicit
  `fluxheim-static-v1;` prefix, matching the compatibility static-cache
  namespace and improving raw key inspection clarity.
- Add the first native cache adapter: route-level static web can now use the
  supported memory-only `cache.local_static` path with shared cache admission,
  bypass, revalidation, TTL, status-header, and file-identity key policy.
- Extend that native memory local-static cache adapter to vhost-level static
  web while preserving fallback-to-proxy behavior on static misses.
- Harden native static-web memory cache accounting with conservative per-entry,
  key, reason, and response-header overhead before admission, and reduce store
  lock work by moving pruning out of the initial insert critical section.
- Use a single stored/expiry `Instant` sample for native static-web memory
  cache entries and prune expired/oldest entries without full-table vector
  allocation and sorting.
- Keep unsupported native cache shapes fail-closed: vhost cache, proxy/image
  cache, disk cache, and non-static route cache still report explicit native
  cache blockers until their adapters are implemented.
- Align native HTTP/1 cutover planning with the new static cache adapter, so
  static-web routes using the supported memory local-static cache no longer
  make an otherwise native-ready vhost fallback proxy look unsupported.
- Move PHP request-body replay/spooling and bounded FastCGI stdout/stderr
  response collection into `fluxheim-php-fpm`, leaving the root crate as a thin
  compatibility adapter for the current PHP runtime.
- Move PHP-FPM keep-alive pool ownership into `fluxheim-php-fpm` with a small
  metrics callback boundary, so connection reuse, stale idle pruning, pool
  labels, and bounded response collection are owned by the PHP crate.
- Add native HTTP/1 upstream PROXY protocol v1/v2 send support for
  `proxy.upstream_proxy_protocol`, using the same Fluxheim-owned frame builder
  as the compatibility path.
- Keep upstream PROXY protocol connection-scoped in the native path by
  disabling HTTP/1 origin connection pooling for those upstreams and rejecting
  HTTP/2 upstream combinations until multiplexed identity can be represented
  safely.
- Thread native listener local addresses and trusted-forwarded effective
  client addresses through `NativeHttp1Request`, so upstream PROXY protocol
  frames use the same client identity as native ACL/rate-limit/header policy.
- Document that native upstream PROXY protocol uses source port `0` when the
  effective client IP came from forwarded headers, because that path does not
  carry the original client source port.
- Add a native HTTP/1 host router that builds one native route proxy per vhost
  and dispatches exact and wildcard Host matches to the same default-vhost
  fallback behavior used by the compatibility runtime.
- Add a native runtime manifest surface that refuses blocked plans and exports
  the Fluxheim-owned service/listener/background-task graph for blocker-free
  plans, preparing the final runner replacement without changing production
  execution yet.
- Validate native runtime launch-plan listener binds before reporting the
  native adapter as the target: duplicate TCP or duplicate UDP bind intents now
  fail closed, while TCP and UDP listeners may still share the same address.
- Emit native runtime launch-plan errors in the cutover evidence report, so
  concrete runner-contract failures are visible even when the high-level
  blocker summary is otherwise ready.
- Include downstream HTTP/1 and HTTP/2 launch-policy rows in the native runtime
  cutover evidence report, giving the final runner hardening values a stable
  diffable contract.
- Add a `fluxheim-server/load-balancer` feature and implement
  `LoadBalancerRequestView` for `NativeHttp1Request`, preparing native
  load-balancer persistence/hash selection to consume native request metadata
  without a Pingora request adapter.
- Add stable address/authority accessors on `SelectedUpstream`, giving native
  callers a public bridge from Fluxheim-owned load-balancer selection to
  upstream connection setup without reaching into backend internals.
- Add selected-upstream accessors for aliases, persistence outcomes, managed
  affinity cookies, reporters, and permit presence, completing the native
  routing metadata bridge without exposing more backend internals.
- Add a concrete native metrics HTTP handler around the existing Prometheus
  response generator, giving the future native runner a direct handler for the
  metrics service.
- Restrict the native metrics handler to `GET`/`HEAD /metrics`, with HEAD
  returning the Prometheus content length without a body, while listener
  loopback/network ACLs remain the metrics access-control boundary.
- Add a root-config native HTTP/1 proxy constructor and move root cutover
  planning to it, so root response headers and root compression are carried
  into native proxy parity instead of being validated separately from runtime
  construction.
- Teach the native host router to instantiate root-only proxy configs without
  `[[vhosts]]`, matching the root proxy candidate that the native cutover
  planner already marks ready.
- Add root static-web fallback construction to the native host router and make
  root local-static memory cache visible in the native cutover planner while
  keeping unsupported root cache backends as explicit cache blockers.
- Teach the native cutover planner to report vhost fallback-only static-web,
  cache, and PHP-FPM blockers even when the vhost has no configured upstream
  proxy candidate.
- Teach the native cutover planner to report route fallback-only static-web,
  cache, and PHP-FPM candidates when a route has no upstream proxy, so
  route-level native blockers are visible in cutover evidence.
- Make native rate-limit delay mode acquire vhost/route concurrency permits
  before sleeping, so delayed requests count against configured concurrency
  budgets instead of bypassing those limits while waiting.
- Replace native rate-limit whole-shard expiry sweeps with bounded,
  incremental per-shard prune queues so table-full handling no longer scans
  every bucket while holding the request-path lock.
- Hash the full IPv4/IPv6 client address for native rate-limit shard selection
  instead of using only the final byte, reducing predictable hot-shard
  concentration for forwarded-client identities.
- Add a per-process random FNV seed to native rate-limit shard selection and
  route indeterminate-client buckets through that seeded hash instead of
  pinning them to shard zero.
- Use saturating `Instant` arithmetic for native rate-limit refill and prune
  decisions so future-dated bucket samples cannot panic the request path.
- Reject residual percent-encoding in native static-web filesystem path
  segments after the initial decode pass, avoiding ambiguous double-encoded
  traversal forms on fallback static serving.
- Let the native metrics handler require a bearer token with `sanitization`
  constant-time comparison; the compatibility metrics listener still relies on
  listener binding and network ACLs until final native-runner service wiring.
- Document that native rate-limit delay mode intentionally holds vhost/route
  concurrency permits while sleeping, so delayed tasks stay inside the
  configured concurrency budget.
- Update `sanitization` to 1.2.2 and `base64-ng` to 1.2.3 across the root,
  server, TLS, and load-balancer crates.
- Move the remaining normal-profile Pingora dependency exception target to
  `1.6.32`, matching the revised plan where 1.6.31 handles cache/PHP native
  integration and 1.6.32 is the final Pingora-free proof release.

### Tests

- Add native server-plan tests proving root, vhost, and route cache policies
  report cache-specific native blockers, and vhost/route PHP-FPM policies
  report PHP-specific native blockers.
- Add native route-proxy builder tests proving vhost/route cache and PHP-FPM
  policies are rejected directly until native adapters own those paths.
- Add a live native HTTP/1 proxy test proving safe-method failover skips
  duplicate weighted upstream slots before trying the next unique backend.
- Add live native static-web route and fallback tests for double-encoded
  traversal rejection.
- Add native metrics handler tests for bearer-token rejection and acceptance.
- Add `fluxheim-cache` tests for image/static cache-key construction,
  namespace/query/host normalization, and local-static file identity.
- Add native HTTP/1 tests proving `NativeHttp1Request` feeds cache request
  policy helpers for origin-form and absolute-form targets, duplicate header
  visits, and range-policy rejection.
- Add standalone `fluxheim-php-fpm` tests for plain PHP response parsing,
  unsafe header rejection, and response/header size limits, plus root parser
  compatibility tests with `php-fpm` enabled.
- Add standalone `fluxheim-php-fpm` tests for FastCGI param value bounds,
  control-byte rejection, and deterministic HTTP header param-name mapping.
- Add standalone and compatibility tests for PHP `SERVER_NAME` fallback
  behavior when the request host is unsafe.
- Add standalone `fluxheim-php-fpm` tests for duplicate request-header joining,
  `Proxy` header blocking, joined-value caps, safe `HTTP_HOST` insertion,
  content-type selection, and runtime custom-param filtering.
- Add standalone `fluxheim-php-fpm` tests for split-container script filename
  mapping and unsafe `PATH_INFO` rejection, plus the existing root
  compatibility test for PHP `fpm_root` mapping.
- Add standalone `fluxheim-php-fpm` tests for direct script detection,
  front-controller fallback, PATH_INFO split mode, unsafe segment rejection,
  allowed-extension matching, and deny-prefix matching.
- Add standalone `fluxheim-php-fpm` tests for static file script-name mapping
  and directory-index redirect decisions, plus existing root compatibility
  coverage for slashless PHP directory indexes.
- Add standalone `fluxheim-php-fpm` tests for PHP static-offload path policy,
  plus root compatibility coverage for X-Accel-Redirect and X-Sendfile
  handling.
- Add standalone `fluxheim-php-fpm` tests for X-Accel-Expires TTL parsing and
  restrictive origin cache-policy detection, plus existing root compatibility
  coverage for absolute-epoch parsing.
- Add standalone `fluxheim-php-fpm` tests for PHP response-header strip lists
  and internal static-offload header names, plus existing root compatibility
  coverage for hidden response headers.
- Add standalone `fluxheim-php-fpm` tests for PHP error-page/status
  interception decisions, plus existing root compatibility coverage for PHP
  custom error pages.
- Extend PHP-FPM tests for extensionless static-offload rejection and invalid
  `Connection` token filtering.
- Add PHP-FPM tests proving `CONTENT_TYPE` rejects control bytes and over-limit
  joined values without retaining the oversized joined result.
- Update standalone `fluxheim-cache` tests to assert local-static keys use the
  `fluxheim-static-v1;` prefix.
- Add live native route static-web tests proving a memory local-static cache
  returns `MISS` on first request and `HIT` on the second request through the
  native listener.
- Add live native vhost static-web tests proving memory local-static cache
  returns `MISS`/`HIT`, plus cutover-plan coverage for the supported vhost
  static-cache shape.
- Add native static-web memory-cache tests for conservative entry weight
  accounting and expired/oldest-entry pruning behavior.
- Add route-config coverage proving static-web routes accept the supported
  memory local-static cache adapter.
- Add native planning coverage proving static-web memory local-static cache
  routes do not block native HTTP/1 proxy cutover candidates.
- Add standalone `fluxheim-php-fpm` tests for in-memory request-body replay,
  secure spool-file replay/cleanup, and combined FastCGI stdout/stderr response
  size accounting, while keeping root PHP compatibility tests green.
- Add standalone and root compatibility tests proving PHP-FPM keep-alive pool
  labels remain stable after the pool move.
- Add native upstream-client tests proving PROXY protocol v1 and v2 bytes are
  written before HTTP request bytes, plus a live native proxy listener test
  proving the listener destination address reaches the upstream PROXY line.
- Add native proxy config tests proving HTTP/1 upstream PROXY protocol is
  accepted, origin pooling is disabled for it, and HTTP/2 combinations fail
  closed.
- Add live native host-router tests proving exact Host dispatch, wildcard
  longest-suffix matching, unknown/missing Host fallback, and default-vhost
  config validation.
- Add native runtime manifest tests proving blocked plans return explicit
  blockers and blocker-free multi-service plans expose proxy, admin, metrics,
  stream, UDP, ops-socket, and listener bindings.
- Add native metrics-handler tests proving the Prometheus text response is
  served through the `NativeHttp1Handler` boundary and a live native HTTP/1
  listener.
- Add a live native admin listener test proving the authenticated health
  endpoint is served correctly through the native HTTP/1 listener.
- Log a native runtime manifest preview at startup for blocker-free plans,
  showing the Fluxheim-owned service/listener/background-task graph while the
  compatibility runtime remains active.
- Extend the native runtime cutover evidence report with manifest service and
  background-task rows, so CI archives the exact native service graph that the
  final runner will consume.
- Move native runtime manifest TSV rendering into `fluxheim-server`, so the
  config tester reports the same service/listener/background-task graph format
  that the final native runner contract owns.
- Add a native runtime target-adapter line to the cutover evidence report:
  production still starts through the Pingora compatibility adapter, while
  blocker-free plans now explicitly report `NativeRuntime` as the target.
- Add a native runtime launch-plan contract that bundles the process,
  PROXY-protocol, downstream HTTP/1 and HTTP/2 policy, and service manifest the
  final native runner will consume. Blocked plans reject launch-plan creation,
  and the cutover report now emits a ready launch-plan row for blocker-free
  configs.
- Extend the native runtime launch plan with concrete listener launch intents:
  service kind, service name, listener protocol, bind address, and downstream
  PROXY-protocol expectation now appear in the cutover evidence.
- Extend the native runtime launch plan with background-task launch intents, so
  cache purging, metrics export, ACME renewal, certificate reload, and watchdog
  tasks are represented by the same native runner contract as listeners.
- Add launch-plan validation tests proving duplicate TCP listener binds keep
  the native target adapter disabled, while TCP and UDP listeners on the same
  address remain valid because they use distinct kernel transports.
- Add cutover-report coverage for native launch-plan error rows, including
  duplicate listener binds.
- Add native launch-policy TSV coverage for representative HTTP/1 and HTTP/2
  hardening values.
- Add feature-gated native request-view tests proving URI keys, repeated header
  values, and Cookie headers are exposed to `fluxheim-load-balancer`.
- Add a feature-gated native server test proving `NativeHttp1Request` drives
  real load-balancer header-hash selection through the shared request-view
  boundary.
- Update load-balancer selection tests to exercise the new public
  selected-upstream metadata accessors.
- Re-run targeted tests for native HTTP/1 client encoding, load-balancer
  persistence constant-time comparisons, and TLS secret handling after the
  dependency refresh.
- Re-run the native runtime cutover and Pingora dependency policy evidence for
  the 1.6.31 planning state.

## 1.6.30 - 2026-06-23

### Changed

- Move native upstream HTTP/2 support for plaintext h2c/prior-knowledge
  origins into the native HTTP/1 proxy path when
  `proxy.upstream_http_version = "http2"` and `upstream_tls = false`.
- Add a native upstream HTTP/2 connection pool that keeps the h2 connection
  driver alive across requests, reserves stream capacity with
  `proxy.upstream_h2_max_streams`, invalidates stale handles on h2 errors, and
  retries safe methods once after a pre-response pooled-handle failure.
- Map `proxy.read_timeout_secs`, `proxy.send_timeout_secs`, and
  `proxy.upstream_h2_max_streams` onto the native HTTP/2 upstream policy while
  keeping TLS ALPN HTTP/2, `http1-and-http2` fallback negotiation, and upstream
  H2 keepalive pings as explicit compatibility-runtime blockers.
- Add live native proxy tests that forward downstream HTTP/1 requests to an
  in-process HTTP/2 origin and prove two downstream requests reuse one upstream
  H2 connection.
- Add live native proxy tests proving native HTTP/2 upstreams reconnect after an
  origin closes a pooled H2 connection and round-robin across multiple static
  H2 upstreams.
- Add explicit, disabled-by-default plaintext h2c Upgrade compatibility for
  `proxy.upstream_http_version = "http1-and-http2"` origins that implement
  HTTP/1.1 Upgrade to `h2c`.
- Update `base64-ng` to 1.2.2 and use its fixed-input infallible encoder for
  native h2c `HTTP2-Settings` header construction.

### Security

- Bound native upstream H2 handshakes with the selected H2 policy timeout so a
  TCP-accepted origin cannot stall the upstream setup indefinitely.
- Bound native upstream H2 stream-slot waits with the read timeout so a slow
  origin cannot park later downstream requests indefinitely behind exhausted H2
  stream capacity.
- Reuse the native H2 client-side limits for upstream requests and responses,
  including decoded header-count/list caps, URI/body caps, response-body
  timeout, request upload lifetime, response header validation, and prohibited
  hop-by-hop response-header rejection.
- Validate pooled native upstream H2 requests against H2-specific header-count,
  URI, and body limits before acquiring stream capacity or opening an upstream
  connection.
- Replace the generic native upstream-H2 blocker message with an unsupported
  HTTP/2 mode diagnostic so valid plaintext H2 support is no longer described
  as entirely unsupported.
- Fail closed for invalid programmatic upstream H2 stream limits instead of
  silently falling back to the default policy.
- Avoid holding the native upstream H2 pool mutex across TCP connect and H2
  handshake work, preventing cold-start failures from serializing all waiting
  requests behind one lock.
- Serialize native upstream H2 pool creation with a dedicated setup lock,
  preventing cold-pool or post-invalidation reconnect storms without holding the
  connection map lock across network I/O.
- Map `proxy.read_timeout_secs` to native H2 handler phases, covering request
  readiness and response-header waits in addition to response-body reads.
- Apply `proxy.upstream_total_connection_timeout_secs` to native H2 setup and
  the first stream-readiness/response-header phase on a freshly initialized H2
  connection.
- Keep stream-scoped H2 errors from invalidating the whole H2 pool unless the h2
  error is a GOAWAY/connection-level condition.
- Reject H2-only knobs on HTTP/1 upstream configs instead of silently ignoring
  them.
- Share one Fluxheim-owned upstream-header stripping predicate between the
  native H1 and H2 upstream request writers.
- Keep explicit h2c Upgrade fallback limited to refused/closed probe
  connections, and do not downgrade/replay a request after an upstream H2
  stream has already been opened.
- Treat h2c probe timeouts as ambiguous and non-replayable while still allowing
  clean HTTP/1.1 fallback for closed/reset upgrade probes.
- Validate h2c Upgrade responses with a bounded response-head reader that
  preserves post-upgrade H2 frames without an O(n²) terminator scan.

## 1.6.29 - 2026-06-23

### Changed

- Move inherited global/vhost compression policy into the native HTTP/1 proxy
  and native route proxy.
- Move root/vhost/route header-policy inheritance into the native HTTP/1 route
  proxy, including request mutation, response mutation, response rewrites, and
  standard security response headers.
- Move safe forwarded-client-IP header ownership into the native HTTP/1 proxy
  path for `off`/`replace` modes plus `X-Real-IP`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`, and RFC `Forwarded`.
- Move vhost-level redirect routes and explicit ACME HTTP-01 upstream challenge
  routes into native route-proxy construction and the native cutover inventory.
- Move trusted-chain `X-Forwarded-For = append` support into the native
  request-header policy using the same trusted-source matcher as downstream
  PROXY protocol planning.
- Move regex route matching and path-only `rewrite_template` capture expansion
  into the native HTTP/1 route proxy, preserving exact/longest-prefix/first-regex
  route precedence.
- Move IP/CIDR vhost and route access allow/deny policy into the native HTTP/1
  route proxy, including trusted `X-Forwarded-For` client restoration.
- Move vhost and route concurrency limits into the native HTTP/1 route proxy,
  including immediate reject and bounded queue timeout behavior.
- Move vhost and route local rate limiting into the native HTTP/1 route proxy,
  including token-bucket rejection and delay-mode admission.
- Move route-scoped gRPC request validation into the native HTTP/1 route proxy,
  rejecting non-POST requests, duplicate `Content-Type` headers, and
  non-gRPC content types before proxy forwarding.
- Align the compatibility proxy's gRPC route `Content-Type` gate with the
  native path by rejecting duplicate `Content-Type` headers and accepting
  RFC-compliant case-insensitive gRPC media types.
- Move per-proxy downstream response write timeout, total response timeout, and
  minimum send-rate policy onto native HTTP/1 proxy responses, and move
  per-proxy downstream request-read timeout onto native HTTP/1 request-body
  parsing.
- Move `proxy.upstream_total_connection_timeout_secs` onto the native HTTP/1
  upstream establishment path, covering DNS, TCP connect, and TLS handshake.
- Move `proxy.upstream_tcp_recv_buffer_bytes` and `proxy.upstream_dscp` onto
  native HTTP/1 upstream socket creation before connect.
- Move the upstream TCP keepalive triple
  (`upstream_tcp_keepalive_idle_secs`,
  `upstream_tcp_keepalive_interval_secs`, and
  `upstream_tcp_keepalive_count`) onto native HTTP/1 upstream sockets before
  connect.
- Move `proxy.upstream_tcp_user_timeout_ms` onto native HTTP/1 upstream sockets
  on targets where the OS exposes `TCP_USER_TIMEOUT`.
- Document that `proxy.upstream_tcp_fast_open` remains compatibility-runtime
  only during the 1.6 native preview until Fluxheim has a safe native socket
  path with parity tests.
- Add native HTTP/1 request context slots for TLS client identity and Geo
  context, populate downstream TLS identity from the native rustls/OpenSSL
  listener paths, and let handlers attach Geo context before policy evaluation.
- Teach the native route-proxy access evaluator to enforce client-certificate
  fingerprint and Geo country/ASN allow/deny policy when typed request context
  is present, so cert/Geo policy no longer blocks the native HTTP/1 cutover
  inventory.
- Move managed local ACME HTTP-01 challenge serving onto the native route
  proxy, including alias-vhost ownership, safe token-file loading, GET/HEAD
  handling, and method rejection parity with the compatibility path.
- Move native ACME HTTP-01 token-file loading onto Tokio's blocking pool so
  filesystem stalls cannot block the async worker thread.
- Move safe-method traffic mirroring onto the native HTTP/1 proxy when the
  `traffic-mirror` feature is compiled, preserving recursion protection,
  sampling, forwarded-header selection, response-body caps, and per-target
  in-flight limits.
- Move `proxy.auth_request` onto the native HTTP/1 proxy when the
  `auth-request` server feature is compiled, including trusted context header
  synthesis, bounded blocking subrequests, response-header allowlisting, and
  deny-before-forwarding behavior.
- Add native cutover-plan tests proving auth-request and safe-method traffic
  mirroring are native-ready only when their matching server feature gates are
  compiled.
- Shard native route/vhost rate-limit tables so stale-entry pruning only blocks
  one shard of identities at a time.
- Strip inbound native traffic-mirror marker headers before origin forwarding,
  while still using valid signed internal markers for recursion suppression.
- Zeroize native auth-request 2xx response bodies that are read only for the
  configured size cap, and keep allowlisted auth response headers in zeroizing
  temporary storage before copying them into the upstream request.
- Add native proxy and cutover-plan tests proving upstream HTTP/2 and H2 tuning
  knobs remain explicit native blockers for the dedicated 1.6.30 upstream H2
  connection-manager slice.
- Relax native HTTP/1 cutover inventory checks so root/vhost compression is
  native-ready when a compression feature is compiled, while still failing
  closed without gzip/brotli/zstd support.
- Keep cache, PHP-FPM, dynamic discovery, upstream TCP Fast Open, upstream
  HTTP/2 connection-manager parity, and advanced load-balancer state reported
  as explicit compatibility blockers.

### Security

- Add live native listener tests proving inherited request-header removal/set
  rules before upstream forwarding.
- Add live native listener tests proving default forwarded-header synthesis and
  `X-Forwarded-For = off` policy behavior on the native proxy path.
- Add live native route tests proving builder-applied request-header overlays
  start from the secure forwarded-header defaults and that strip-plus-append
  cannot preserve a spoofed inbound forwarding chain.
- Add live native route tests proving vhost synthetic-route construction sends
  ACME HTTP-01 challenge paths to the configured upstream before the vhost
  redirect fallback is applied.
- Reject native cutover for route request-header overlays that explicitly
  disable the request header policy, preventing fallback to unsanitized
  forwarded-client-IP headers.
- Apply merged root/vhost header policy to native vhost fallback proxy traffic
  so requests that miss named routes still strip spoofable client-IP headers and
  synthesize owned forwarding context.
- In privacy-mode builds, strip spoofable client-IP headers after request
  header mutations so operator `set`/`append` rules cannot reintroduce
  forwarded-client-IP fields.
- Initialize programmatic native route constructors with the safe default
  request-header policy instead of a no-op policy.
- Add native route tests proving trusted append preserves the forwarded chain
  for trusted peers and strips untrusted spoofed chains for direct clients.
- Add native route tests proving regex rewrite templates percent-encode bounded
  captures and reject traversal-producing captures before proxying upstream.
- Encode slash characters in native regex rewrite captures and reject the
  resulting unsafe path, keeping path hierarchy in the static template rather
  than attacker-controlled capture data.
- Add live native route tests proving vhost and route access policies deny
  before redirects, static-web actions, or upstream proxying can run.
- Add live native route tests proving trusted proxy sources restore the
  effective client IP from `X-Forwarded-For` before native access allow/deny
  decisions.
- Add live native route tests proving route access policy also checks a
  percent-decoded policy path, preventing encoded path variants from falling
  through to a less restricted route.
- Add live native route tests proving vhost and route concurrency limits reject
  a second request while the first request still holds the native upstream path.
- Add live native route tests proving vhost and route rate limits reject
  excess requests before the native upstream path is reached.
- Join duplicate inbound `X-Forwarded-For` headers before native trusted-proxy
  client restoration, preventing an attacker-controlled earlier duplicate from
  steering native ACL or rate-limit identity.
- Reject malformed `X-Forwarded-For` trusted-proxy chains on both the native
  header crate path and the compatibility proxy path, falling back to the
  direct peer instead of skipping poisoned hops.
- Run delay-mode rate-limit sleeps before native concurrency permit
  acquisition, so delayed requests cannot exhaust vhost or route concurrency
  budgets while waiting.
- Bound native rate-limit table eviction sweeps to avoid repeated full-table
  scans on every new identity when the bucket table is full.
- Add native proxy config and live listener tests proving response-side
  downstream policy and downstream request-read timeout are enforced on the
  native path.
- Add live native route tests proving gRPC route policy rejects non-gRPC
  requests, rejects duplicate `Content-Type`, emits gRPC status metadata on
  local rejections, and forwards valid case-insensitive `application/grpc*`
  requests.
- Add compatibility-path gRPC policy tests proving duplicate `Content-Type`
  headers are rejected and case-insensitive `application/grpc*` media types are
  accepted.
- Add native proxy config tests proving total upstream connection timeout is
  accepted and propagated to native upstreams while other advanced TCP socket
  knobs still block native cutover.
- Add native proxy config and live loopback tests proving native upstream
  receive-buffer, DSCP, TCP keepalive, and supported TCP user-timeout socket
  options are accepted and still connect.
- Add a live native HTTP/1 listener test proving plain listener requests leave
  TLS client identity and Geo context unset by default.
- Add native route-proxy tests proving client-certificate fingerprint policy
  and Geo country/ASN policy deny before upstream forwarding when request
  context does not satisfy the route policy.
- Add a live native HTTP/1 proxy test proving a mirrored request reaches a
  local mirror endpoint while the origin response remains unchanged.
- Add live native HTTP/1 proxy tests proving auth-request allow responses can
  inject configured upstream headers and auth-request deny responses stop
  before any upstream connection is made.
- Harden native traffic mirroring so client-supplied `X-Fluxheim-Mirror`
  headers cannot suppress mirroring; only Fluxheim's signed internal mirror
  marker is honored for loop prevention.
- Compare native traffic-mirror marker signatures with
  `sanitization::ct::ConstantTimeEq` and update the project to
  `sanitization` 1.2.1 and `rustls` 0.23.41.
- Send `408 Request Timeout` before closing native HTTP/1 connections that
  exceed the selected request-body timeout, and ensure redirect/static routes
  do not inherit fallback proxy body-read timeouts.
- Keep native DSCP socket-option fallback compilation portable across targets
  without Tokio IPv6 traffic-class support, and reject an impossible oversized
  receive-buffer conversion with a dedicated diagnostic instead of silently
  dropping it.
- Set identical NFA and DFA regex cache limits for config validation and native
  regex route compilation.
- Strip spoofable `X-Forwarded-Host` and `X-Forwarded-Proto` headers in
  privacy-mode native route proxy handling.
- Harden native trusted-source CIDR matching against directly constructed
  invalid prefix lengths, so invalid values fail closed without shift overflow.
- Align `RequestHeaderPolicyConfig::default()` with the TOML missing-field
  default for `x_real_ip`, keeping config-driven and programmatic native route
  construction consistent.
- Add live native listener tests proving inherited response-header and standard
  security-header emission on route responses.
- Add live native listener tests proving plain-proxy gzip compression and
  inherited route gzip compression strip stale entity headers and emit
  `Vary: accept-encoding`.
- Document the dual opt-out risk of disabling inbound forwarded-header
  stripping while also disabling owned `X-Forwarded-Host` or
  `X-Forwarded-Proto` synthesis.

## 1.6.28 - 2026-06-21

### Changed

- Continue the native rich-proxy parity work by adding route-level response
  compression to the native HTTP/1 route proxy.
- Wire `fluxheim-server` to the existing `fluxheim-compression` crate for
  gzip, brotli, and zstd feature builds.
- Add native route compression eligibility checks matching the compatibility
  path: safe methods/status, content negotiation, cache-control and privacy
  exclusions, and configured input/output bounds.
- Move `proxy.error_pages` onto the native HTTP/1 proxy for static 502/504
  fallback pages backed by `fluxheim-web`.
- Preserve configured static proxy error-page bodies while keeping the original
  proxy failure status.
- Keep the final Pingora dependency deletion later in the 1.6 line so the
  remaining cache, PHP-FPM, auth-request, traffic mirror, inherited
  compression, forwarded-client-IP, and advanced load-balancer blockers can be
  removed with their own parity tests.

### Security

- Native compression strips origin `ETag` and `Content-Length`, appends
  `Vary: accept-encoding`, and lets native response framing compute the final
  compressed length.
- Native compression skips the transform if encoder initialization or output
  bounds fail instead of emitting a partially transformed response.
- Native proxy error pages use the same symlink-safe static-web resolution and
  rooted file-open behavior as native static routes.
- Custom proxy error pages fall back to standard 502/504 responses if the
  configured page is missing, forbidden, a directory listing, or too large.

## 1.6.27 - 2026-06-21

### Changed

- Continue the native rich-integration parity work by adding a native HTTP/1
  route static-web adapter backed by the `fluxheim-web` crate.
- Serve route-level native static files through the Fluxheim-owned HTTP/1
  listener with conditional requests, ETags, byte ranges, `HEAD`, cache-control
  metadata, and directory listings.
- Apply route-level native request-header mutation overlays before matched
  proxy routes are forwarded upstream.
- Round-robin successful requests across multiple configured static upstreams
  in the native HTTP/1 proxy, while preserving safe-method failover.
- Apply route-level native response rewrite rules for `Location`, `Refresh`,
  and `Set-Cookie` through the shared `fluxheim-headers` rewrite helpers.
- Honor static `proxy.upstream_weights` in the native HTTP/1 proxy with a
  bounded weighted round-robin slot table.
- Keep native static-web route tests split from generic route-proxy tests so
  the feature proof stays reviewable.
- Add `fluxheim-web` as an explicit `fluxheim-server` dependency for the native
  static-web boundary instead of reaching back into the root compatibility
  adapter.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.27`.

### Security

- Reuse the existing symlink-safe web-root validation and per-request path
  containment model in the native static-web route adapter.
- Reject percent-decoded dot-segment, backslash, NUL, and denied-dotfile paths
  before static files are resolved.
- Open static response bodies with rooted component-by-component `openat`
  calls and no-symlink flags, closing the symlink-swap window between metadata
  checks and body reads.
- Return `405 Method Not Allowed` from the native static-web handler for
  methods other than `GET` and `HEAD`, even when the route method list matches
  all methods.
- Validate native redirect `Location` URL paths with the shared bounded
  multi-pass forward-path safety check so encoded and double-encoded dot
  segments or slashes cannot be introduced through `{query}`, `{path}`, or
  `{uri}` expansion.
- Bound native buffered static responses to 64 MiB until the final native
  streaming body path is enabled.
- Keep forwarded-client-IP ownership shortcuts on the compatibility path while
  allowing only the explicit route request-header mutation subset natively.
- Keep health-aware, persistence, dynamic-discovery, priority-group,
  backup/drain, and hash-based load-balancer policies on the compatibility path
  while moving static upstream round-robin and static weights native.
- Keep cache, PHP-FPM, auth-request, traffic mirror, compression, and advanced
  load-balancer policy integrations on the compatibility path until their
  native execution has dedicated parity tests.

## 1.6.26 - 2026-06-21

### Changed

- Continue the native route/policy parity slice by adding route redirect
  actions to the native HTTP/1 route proxy.
- Support native redirect expansion for `{uri}`, `{path}`, and `{query}` with
  the same absolute `http://` / `https://` location safety model used by the
  compatibility proxy path.
- Enforce route-level `max_request_body_bytes` in the native HTTP/1 route proxy
  before forwarding matched requests.
- Apply route-level native response header overlays for native route proxy
  responses, including set, append, unset, and the standard security header
  shortcuts.
- Allow `NativeHttp1RouteProxyRoute::from_config` to build redirect-only route
  actions without requiring a dummy native upstream proxy.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.26`.

### Security

- Reject unsafe native redirect expansions, including ambiguous double-slash
  request paths, control characters, whitespace, braces, backslashes, and
  non-HTTP(S) redirect targets.
- Reject expanded native redirect `Location` URL paths containing dot segments
  or double slashes, including `{query}` path-position traversal attempts.
- Reject redirect templates that would place `{path}` or `{uri}` immediately
  after a literal slash in the URL path, preventing predictable `//` expansion.
- Do not count route proxy configs shadowed by route redirects as native proxy
  cutover candidates.
- Return `413 Payload Too Large` from the native route proxy when a matched
  route-specific body limit is exceeded.
- Keep regex routes, request-header mutation, response-header rewrites, access
  policy, and richer proxy integrations on the compatibility path until their
  native execution has dedicated parity tests.

## 1.6.25 - 2026-06-21

### Changed

- Start the final Pingora-removal checkpoint with explicit compatibility
  evidence instead of deleting the remaining runtime adapter before rich proxy
  parity is complete.
- Extend `fluxheim-config-tester --runtime-cutover` with
  `native-http1-proxy-candidate` rows that show each configured proxy scope,
  whether it is native-ready, and the compatibility reason when it is not.
- Add the first native HTTP/1 route-proxy execution primitive for exact,
  prefix, and fallback routes, including method filters, longest-prefix
  selection, prefix stripping, prefix rewriting, query preservation, and
  shared path-safety checks.
- Re-scope the remaining Pingora dependency exception target to `1.6.31`, with
  the next 1.6.x releases reserved for the remaining native policy and rich
  proxy integration parity.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.25`.

### Security

- Keep the native runtime cutover gate strict for blocker rows while allowing
  non-blocking candidate-detail rows in the evidence report.
- Fail closed in the native route-proxy primitive for invalid request targets
  and unsafe rewritten paths.
- Reject interior double-slash forward paths in the native route-proxy path so
  stripped or rewritten targets cannot be misclassified as upstream failures or
  forwarded with ambiguous path semantics.
- Mark regex routes as native HTTP/1 compatibility blockers until the native
  route proxy supports regex matchers, and validate candidate-row shape in the
  native runtime cutover gate before ignoring candidate-detail rows.
- Reject single-dot route path segments at config validation time so invalid
  strip/rewrite prefixes fail at startup instead of at request time.
- Keep Pingora dependency exceptions enforced by target version so the final
  deletion cannot drift past the documented release without CI failing.

## 1.6.24 - 2026-06-20

### Changed

- Promote the native HTTP/2 downstream safety preview to cutover-ready after
  proving every required safety hook with focused tests.
- Make the representative native runtime cutover report blocker-free for the
  simple HTTP/1 + HTTP/2 + admin + metrics + stream + UDP configuration.
- Move the final Pingora dependency-removal target to `1.6.25` so deleting the
  remaining runtime/listener/TLS adapter crates is reviewed as its own focused
  release.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.24`.

### Security

- Document native HTTP/2 header-count protection as satisfied by decoded
  header-count enforcement before routing plus `h2` `max_header_list_size`
  bounds on decoded header-list bytes.
- Keep HTTP/2 body, URI, trailer, response lifetime, flow-control, reset, and
  handler-timeout parity covered by the native server test suite.
- Join aborted native stream and UDP listener tasks during shutdown so listener
  sockets are released before the background task returns.
- Make the native runtime cutover evidence script assert that the
  representative config has zero blockers instead of relying on an empty
  expected-blocker set.
- Keep the Pingora dependency policy active and enforce all remaining Pingora
  crates against the next deletion target.

## 1.6.23 - 2026-06-20

### Changed

- Cut stream and UDP proxy service startup over to Fluxheim-owned native task
  boundaries while keeping the Pingora runtime adapter as a thin compatibility
  registration layer.
- Mark config-derived stream and UDP service plans native-ready in the runtime
  cutover report.
- Extend native runtime cutover evidence with a representative UDP route and
  prove that stream/UDP no longer remain 1.6.23 blockers.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.23`.

### Security

- Add a native shutdown wait primitive that handles both already-requested and
  future shutdown requests, avoiding stalled service tasks during supervisor
  handoff.
- Make native background-task joins abort-on-cancel and make the shutdown waiter
  cancellation-safe for native `tokio::select!` loops.
- Preserve query strings on pathless absolute-form admin request targets instead
  of dropping them during native admin request parsing.
- Preserve live stream and UDP smoke coverage while changing their startup
  lifecycle, including real listener-backed stream and UDP proxy checks.
- Keep HTTP/2 and final HTTP proxy runtime parity as the remaining native
  runtime blockers for the final Pingora-free proof release.

## 1.6.22 - 2026-06-20

### Changed

- Start the native admin/metrics serving slice of the Pingora-exit line.
- Keep production admin and metrics compatibility conservative while native
  control-plane HTTP handlers and parity tests are introduced behind Fluxheim-owned
  server primitives.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.22`.

### Security

- Preserve auth-first admin behavior as the required compatibility contract for
  native admin/control-plane serving.
- Mark config-derived admin, ops-socket, and metrics service plans native-ready
  only after adding native handler parity tests.
- Harden native background handles so dropped handles abort instead of silently
  detaching tasks, document critical-handle abort behavior, and make shutdown
  initiation results `#[must_use]`.
- Reject newline-bearing native runtime cutover evidence paths before generating
  TOML fixtures.
- Document that native admin target matching intentionally uses raw,
  percent-encoded paths.
- Keep the native runtime cutover blocker gate active for stream, UDP, HTTP/2,
  and final proxy-runtime blockers while this slice advances.

## 1.6.21 - 2026-06-20

### Changed

- Start the native background-service orchestration slice of the Pingora-exit
  line for Fluxheim-owned tasks such as certificate reload, ACME renewal, cache
  maintenance, observability export, and load-balancer refresh.
- Add `fluxheim_runtime::NativeBackgroundSupervisor` as the first Pingora-free
  task-runner primitive for typed background services, raw async tasks,
  readiness callbacks, shutdown fan-out, and join/abort supervision.
- Keep the final Pingora-free proof target at 1.6.24 while this release focuses
  on task-supervision boundaries instead of changing production listener
  behavior.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.21`.

### Notes

- Normal proxy profiles still retain the Pingora compatibility runtime in this
  release.
- The first-party `zeroize` to `sanitization` migration remains planned for the
  post-Pingora stabilization release so it can be tested as a focused
  hardening pass.

### Security

- Add native critical background-task watchdog support so critical tasks can
  request supervisor shutdown when they exit unexpectedly before the production
  background-task wiring moves off Pingora.
- Harden native supervisor shutdown delivery for pre-spawn shutdown, last-handle
  drop, and clone-drop edge cases.
- Harden the native runtime cutover evidence script against unsafe TOML path
  interpolation and missing expected blocker rows in the representative report.
- Mark background-service `threads()` as Pingora compatibility-only so native
  task supervision cannot be mistaken for a per-service thread-pool contract.

## 1.6.20 - 2026-06-20

### Changed

- Start the next Pingora-exit slice as a native runtime cutover contract rather
  than a premature production switch.
- Re-scope the remaining Pingora runtime removal across focused 1.6.x releases:
  native background task orchestration, admin/metrics serving, stream/UDP
  listener startup, final Pingora-free proof, and stabilization.
- Move the remaining Pingora dependency exception targets to the documented
  1.6.24 final proof release while keeping the cargo-tree policy gate active.
- Add a native runtime cutover evidence gate that runs blocker-summary,
  native HTTP/2 preview, native HTTP/1 proxy, and Pingora dependency policy
  checks during release gates.
- Add `fluxheim-config-tester --runtime-cutover` with stable native-runtime
  blocker keys and target releases.
- Add a committed native-runtime cutover target map and validate generated
  blocker reports against it during release gates.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.20`.

### Notes

- Normal proxy profiles still use the Pingora compatibility runtime in this
  release. Native TLS-only web proof profiles remain Pingora-free.
- The dependency policy still rejects new undocumented Pingora edges and will
  fail once the documented final proof target is reached if any listed Pingora
  crate remains.

### Security

- Wrap OpenSSL downstream private-key PEM file buffers in `sanitization::SecretVec`
  before parsing, so Fluxheim's owned PEM copy is wiped after the OpenSSL key
  import path completes.

## 1.6.19 - 2026-06-19

### Changed

- Add an explicit `pingora-compat` feature for the remaining root compatibility
  runtime, making the Pingora boundary visible in Cargo features instead of
  hiding it behind the generic `ingress` feature.
- Stop native TLS-only web builds from enabling `pingora/rustls` or
  `pingora/openssl` when the Pingora compatibility runtime is not selected.
- Move rustls downstream SNI certificate resolution, reloadable certificate
  storage, and PEM certificate/private-key parsing into `fluxheim-tls` so the
  native listener cutover no longer depends on Pingora's listener key-loading
  helper.
- Add a Fluxheim-owned native rustls downstream `ServerConfig` builder covering
  cipher suites, key-exchange groups, minimum protocol, ALPN, client-auth
  verifier construction, and FIPS reporting checks without Pingora listener
  panic paths.
- Add a Fluxheim-owned native OpenSSL downstream `SslAcceptor` builder for the
  fallback-certificate listener path, covering certificate/key loading,
  ciphers, curves, minimum protocol, ALPN, and client-auth CA policy with typed
  errors.
- Move OpenSSL downstream SNI certificate storage, reload, pending-managed-cert
  handling, and certificate application into `fluxheim-tls`; the root runtime
  now keeps only the Pingora `TlsAccept` adapter.
- Add a native rustls HTTP/1 downstream listener preview in `fluxheim-server`
  that reuses the existing native HTTP/1 parser/handler path, listener
  connection budget, and request-head timeout as the TLS handshake bound.
- Add the matching native OpenSSL HTTP/1 downstream listener preview for
  OpenSSL-only builds, with the same connection budget, bounded TLS handshake,
  and real client/server TLS socket coverage.
- Add a native runtime cutover summary to `ServerPlan` so startup diagnostics
  and release tests can report the remaining compatibility blockers before the
  1.6.20 runtime removal slice.
- Add a root integration test proving the `fluxheim-tls` rustls downstream
  server-config builder can drive the native `fluxheim-server` HTTP/1 listener
  with a real client handshake and request.
- Add the matching OpenSSL integration test proving the `fluxheim-tls`
  acceptor builder can drive the native OpenSSL HTTP/1 listener.
- Update the test-only `rcgen` dependency to `0.14.8`.
- Extend the Pingora dependency policy with a `native-web-tls` cargo-tree
  profile that proves `--no-default-features --features web,tls-rustls` does
  not compile Pingora crates.

### Notes

- Root proxy profiles still use the compatibility runtime in this cut. The
  remaining server/admin/metrics/proxy compatibility removal is moved to the
  next Pingora-exit slice so it can be tested as a runtime change rather than
  hidden inside a feature cleanup.
- The vendored Pingora rustls listener still wraps downstream TLS accepts until
  listener cutover, but Fluxheim now owns SNI selection and cert/key parsing.
- The native rustls server-config builder is available for the listener cutover;
  the compatibility runtime still applies the same TLS policy to Pingora's
  temporary listener shim in this release.
- The native rustls and OpenSSL listeners are test-backed but not wired into
  official proxy profiles yet; production traffic remains on the compatibility
  runtime until the full listener/runtime cutover.
- The native runtime cutover summary is diagnostic-only in this release. It
  does not select the native runtime yet.

## 1.6.18 - 2026-06-19

### Changed

- Start the next Pingora-exit slice for normal builds. This release focuses on
  shrinking the remaining root compatibility surface and preparing the
  proxy/cache/runtime paths for release-gate proof that official profiles no
  longer compile Pingora proxy/cache/pool crates.
- Keep the load-balancer crate Pingora-free after 1.6.17 and plan the native
  health-check implementation split by protocol so each probe can be reviewed
  independently.
- Split native HTTP/1.1 and gRPC/h2 health-check helpers out of the
  load-balancer health orchestration module. The new protocol helper files stay
  below the modularity policy's 500-line target.
- Split Redis, MySQL, and PostgreSQL active health probes into a database
  health helper module, keeping each new protocol/probe module below the
  modularity policy target.
- Split exec active health checks into a small helper module covering command
  launch, environment scrubbing, timeout handling, and exit-status mapping.
- Split TCP health checks, TCP/TLS handshake setup, ALPN selection, and shared
  HTTP health-stream connection handling into a transport helper module.
- Move root-profile Pingora dependency exception targets to 1.6.19 while
  keeping the dedicated `fluxheim-load-balancer` crate covered by the
  Pingora-free policy gate.

### Security

- Carry forward the 1.6.17 native load-balancer health-probe hardening as the
  baseline for 1.6.18 release gates.
- Preserve the 1.6.17 HTTP/1.1 CR/LF rejection, gRPC h2 flow-control release,
  and h2 driver abort-on-drop behavior across the protocol split.
- Guard native gRPC health-check frame length conversion, validate
  `grpc-status: 0` trailers, reject overlarge protobuf varints, and reject
  userinfo in configured health-check hosts.
- Limit native HTTP/1.1 health response headers to 8 KiB instead of sharing the
  64 KiB body cap.
- Re-enforce `exec_allowed_commands` inside the native exec health-check
  builder so programmatic `ProxyConfig` construction cannot bypass the config
  validator's allowlist check.

## 1.6.17 - 2026-06-19

### Changed

- Remove the direct Pingora dependency from the `fluxheim-load-balancer` crate.
  HTTP health checks now use a Fluxheim-owned bounded HTTP/1.1 probe, and gRPC
  health checks now use a Fluxheim-owned h2 client probe.
- Keep TCP, Redis, MySQL, PostgreSQL, exec, passive-health, persistence, and
  selection logic on the existing native load-balancer code paths.
- Add `fluxheim-load-balancer` to the Pingora dependency policy so future
  changes cannot reintroduce Pingora into the load-balancer core unnoticed.

### Security

- Bound native HTTP health-check response headers and bodies independently of
  Pingora's HTTP session machinery.
- Preserve TLS handshake timeouts for HTTP/gRPC health checks through the
  Fluxheim-owned TCP/TLS connector path.
- Add real listener-backed tests proving native HTTP/1.1 health checks send
  configured headers, validate JSON responses, and apply degraded health
  weights.
- Add a real h2 server test proving native gRPC health checks send the
  standard health-check request body and accept a `SERVING` response.

## 1.6.16 - 2026-06-19

### Changed

- Start the native proxy cutover gate by tightening `fluxheim-server`'s native
  HTTP/1.1 proxy eligibility checks. Configurations using auth subrequests,
  traffic mirroring, proxy error pages, advanced upstream transport options,
  per-proxy downstream throttling, advanced load-balancer policy, vhost ACME
  challenge routing, vhost redirects, or route strip/rewrite transforms now
  stay explicitly on the Pingora compatibility adapter until those semantics
  are implemented in the native pipeline.
- Add a native HTTP/1.1 proxy cutover summary on `ServerPlan` so future runtime
  wiring can distinguish no-proxy, fully native-ready, mixed, and
  compatibility-required configurations without reinterpreting individual
  candidate rows.
- Log native HTTP/1.1 proxy cutover readiness at startup, including the
  compatibility-only reason for each unsupported proxy path.
- Align TOML serde defaults for proxy downstream write and total-response
  timeouts with `ProxyConfig::default()` so native cutover readiness uses the
  same baseline for parsed production configs and test-built configs.

### Security

- Fail closed in native HTTP/1.1 cutover planning when a route would require
  request-path transformation before upstream forwarding. This prevents the
  staged native path from being marked eligible for route configurations whose
  strip/rewrite behavior it does not yet enforce.
- Add focused native HTTP/1.1 proxy and server-plan tests covering the new
  compatibility blockers so future cutover work cannot silently accept
  unsupported policy layers.
- Add server-plan tests for aggregate native HTTP/1.1 cutover readiness states.
- Add TOML parsing coverage for proxy downstream timeout defaults and make
  native HTTP/1.1 TLS proxy test fixture cleanup panic-safe.

## 1.6.15 - 2026-06-18

### Added

- Add a Fluxheim-owned native HTTP/2 upstream client primitive in
  `fluxheim-server`, including request body/trailer sending, response
  body/trailer collection, bounded response header counts, bounded response
  bodies, and absolute request-write / response-read deadlines.
- Add in-memory h2 client/server tests proving native HTTP/2 upstream trailer
  preservation for gRPC-style responses, oversized response rejection, response
  header-count rejection, upstream stream reset surfacing, and request
  flow-control write timeout behavior.

### Changed

- Share native HTTP/2 prohibited response-header validation between the
  downstream stack probe and the new upstream client path.
- Share the native HTTP/2 bounded DATA sender between downstream responses and
  upstream request bodies.
- Keep production HTTP/2 cutover gated until the native path has full
  pre-routing HPACK/header-count allocation proof and integration through the
  production proxy pipeline.

### Security

- Stage native HTTP/2 upstream request bodies in zeroizing memory before
  copying them into h2 DATA frames.
- Add a dedicated native HTTP/2 upstream response-body timeout so upstream
  response reads no longer reuse the downstream request-body timeout setting.
- Document the current native HTTP/2 upstream client as a one-request preview
  client whose hard connection-driver abort must not be copied into future
  pooled upstream connections.

## 1.6.14 - 2026-06-18

### Added

- Add native rustls and OpenSSL upstream TLS support to the staged HTTP/1.1
  proxy path in `fluxheim-server`, including explicit SNI, configured CA
  bundles, optional upstream client certificates, and certificate verification
  controls.
- Add real native HTTPS upstream proxy coverage with an in-test CA and
  localhost SAN leaf certificate.
- Add real native upstream mTLS coverage for rustls and OpenSSL by requiring a
  client certificate on the test origin, including the failure path when the
  proxy has no upstream client certificate configured.
- Fix native HTTP/1 server-plan TLS failure-reason coverage for OpenSSL-only
  builds.
- Add real native upstream TLS hostname-policy coverage for default mismatch
  rejection, `upstream_alternative_cn`, and `upstream_verify_hostname = false`
  across rustls and OpenSSL builds.
- Add direct native upstream TLS file-reader tests for oversized-file and final
  symlink rejection.
- Make the native HTTP/1 proxy builder fail closed on invalid upstream TLS
  material combinations even when called outside the full config loader.
- Restrict native HTTP/1 stale pooled-connection retries to safe methods so
  unsafe requests are not replayed after a pooled socket failure.
- Harden the native OpenSSL upstream TLS connector with a TLS 1.2 minimum and
  explicit AEAD-only TLS 1.2 / TLS 1.3 cipher suite allowlists.
- Make the native upstream TLS file reader canonicalize the parent directory
  before opening certificate/key material so CodeQL and reviewers see the
  filesystem trust boundary explicitly.
- Add native HTTP/1 ordered static upstream failover for safe request methods,
  with socket tests proving `GET` can fall through to the next configured
  upstream while unsafe methods are not replayed.

### Changed

- Store native HTTP/1 upstream pooled connections as Fluxheim-owned boxed IO
  streams so the same retry/reuse path works for plain TCP and TLS upstreams.
- Wire root rustls and OpenSSL feature aliases into `fluxheim-server` so native
  upstream TLS is compiled in the same TLS profiles operators use today.
- Keep dynamic upstream discovery and advanced load-balancer policy on the
  Pingora compatibility path; the native HTTP/1 path now accepts only plain
  static upstream lists as ordered failover candidates.

### Security

- Fail closed when native HTTPS upstream conversion sees any IP-addressed
  configured static upstream with certificate verification enabled and no
  explicit `upstream_sni`.
- Read native upstream TLS CA, certificate, and key files through bounded
  no-follow regular-file handling.

## 1.6.13 - 2026-06-18

### Added

- Add bounded native HTTP/1.1 upstream connection pooling in
  `fluxheim-server` for safe content-length and no-body origin responses.
- Wire `server.process.upstream_keepalive_pool_size` into native HTTP/1 proxy
  candidates and honor `proxy.upstream_idle_timeout_secs` for native pooled
  upstream connections.

### Hardened

- Keep the native HTTP/1.1 pool conservative: do not reuse close-delimited
  responses, chunked responses, responses with `Connection: close`, or
  responses where extra bytes were buffered beyond the declared body.
- Keep unsupported upstream TLS/mTLS, HTTP/2 upstreams, dynamic discovery,
  load balancing, upstream PROXY protocol, websocket upgrade, and broader
  policy layers on the Pingora compatibility path until later 1.6 cutover
  releases prove parity.

### Tests

- Add real socket tests for native upstream connection reuse, idle-pool expiry,
  and `Connection: close` non-reuse behavior.

## 1.6.12 - 2026-06-18

### Added

- Add a reusable native HTTP/2 connection primitive in `fluxheim-server` with
  handler-owned request/response types, bounded request-body collection, and
  response trailer support for gRPC-style status propagation.
- Add native HTTP/2 tests that pass request trailers into the handler and send
  response trailers back to the client over a real h2 client/server exchange.

### Hardened

- Refresh non-Pingora dependency patches: `getrandom` 0.4.3, `openssl`
  0.10.81, `brotli` 8.0.4, and `h2` 0.4.15. Keep Pingora pinned at 0.8.0
  while the 1.6 exit line removes it.
- Add an explicit downstream HTTP/2 response-write lifetime budget and wrap the
  whole response send path in one absolute timeout, so flow-control window holds
  cannot keep a response write alive indefinitely.
- Add an explicit native HTTP/2 handler execution timeout so slow handler work
  cannot hold a stream indefinitely between request-body drain and response
  write.
- Send response DATA through h2 capacity reservation/polling instead of
  unbounded implicit buffering.
- Reject HTTP/2-prohibited response headers and trailers before sending
  responses from the native HTTP/2 primitive.
- Zeroize collected native HTTP/2 request bodies on drop and preallocate the
  request-body buffer with a bounded hint.
- Treat a zero-capacity h2 send-side wakeup as a closed response-capacity path
  to avoid a defensive spin loop.
- Advance the native HTTP/2 preview gate: response-write lifetime and
  trailer/gRPC preservation are now satisfied; pre-routing HPACK/header-count
  allocation proof remains the explicit blocker before production cutover.

### Tests

- Add a regression test that holds the client response flow-control window and
  confirms the native HTTP/2 response lifetime expires.
- Add regression tests for handler timeout, prohibited response headers, and
  empty-body response trailers.

## 1.6.11 - 2026-06-17

### Added

- Add a native HTTP/2 runtime preview gate in `fluxheim-server` that records
  every required safety hook before any production cutover is allowed.
- Add a native HTTP/2 stack probe using the Rust `h2` stack with bounded
  header-list, decoded header-count, URI, request-body, stream, frame,
  send-buffer, and rapid-reset policy values.
- Add real HTTP/2 probe tests for successful responses, bounded request
  bodies, oversized request bodies, oversized URIs, decoded header-count
  rejection, body flow-control release, and slow-body timeouts.
- Add downstream HTTP/1.0 socket tests for missing-Host acceptance, default
  close semantics, and explicit keep-alive handling.

### Hardened

- Keep native HTTP/2 cutover blocked until pre-routing HPACK/header-count
  allocation bounds, absolute response-write lifetime, and trailer/gRPC
  pass-through parity are implemented and fixture-covered.
- Release HTTP/2 request-body flow-control capacity after consumed DATA frames
  and keep the h2 connection driven while request bodies drain so WINDOW_UPDATE
  frames can flush.
- Enforce `[server.limits].max_uri_bytes` on native HTTP/2 request URIs, matching
  the HTTP/1 request-target budget.
- Log post-shutdown HTTP/2 probe streams at debug level instead of silently
  dropping them.

### Tests

- Add `scripts/smoke_native_http2_preview.sh` and register it in the runtime
  parity fixture inventory.
- Extend native HTTP/1 coverage with real downstream HTTP/1.0 socket behavior.

## 1.6.10 - 2026-06-17

### Added

- Add a Fluxheim-owned bounded native HTTP/1 upstream client for plain static
  upstream proxying, including request serialization, response-head parsing,
  fixed-length, chunked, and close-delimited response body reads.
- Add native proxy candidate inventory in `fluxheim-server` so eligible
  vhost/route proxy configurations can be identified before production cutover.
- Add a staged native proxy handler for plain static upstreams, while keeping
  the production default on the Pingora compatibility adapter until full route,
  policy, cache, PHP-FPM, ACME, observability, and failure-semantics parity is
  green.
- Add native proxy-owned `Via` and `X-Forwarded-For` forwarding parity, with
  privacy-mode builds suppressing `X-Forwarded-For`.

### Hardened

- Native upstream forwarding now strips inbound hop-by-hop framing headers,
  prior `Via`, and prior `X-Forwarded-For` before writing Fluxheim-owned proxy
  headers.
- Native close-delimited upstream responses now accept exact-size bodies and
  reject oversized bodies immediately instead of waiting for EOF.
- Native proxy eligibility fails closed for unsupported policy layers,
  dynamic discovery, load balancing, upstream TLS, upstream PROXY protocol,
  HTTP/2 upstreams, and websocket upgrade.

### Tests

- Add native upstream tests for chunked responses, close-delimited responses,
  exact body limits, oversized bodies, timeout handling, invalid headers, and
  Fluxheim-owned proxy headers.
- Extend the native HTTP/1 smoke script with a real TCP downstream listener to
  native proxy to upstream socket test.
- Add a privacy-mode regression test proving native upstream forwarding does
  not emit `X-Forwarded-For`.

## 1.6.9 - 2026-06-17

### Added

- Add a Fluxheim-owned native HTTP/1 connection and listener runtime over Tokio
  IO, using the bounded HTTP/1 parser from `fluxheim-protocol` and keeping the
  production proxy path on the Pingora compatibility adapter until parity is
  green.
- Add a staged native static-file adapter that reuses Fluxheim's safe web-root
  resolver, conditional-response planner, and body reader while writing through
  native HTTP/1 response types.
- Map `[server.limits]` request-head, URI, header-count, and request-body
  limits into the native downstream HTTP/1 policy.
- Add real TCP socket tests for native HTTP/1 keep-alive, fixed-length and
  chunked bodies, listener shutdown, static files, HEAD framing, directory
  listings, slow-client timeouts, peer-address propagation, and connection-cap
  shedding.

### Hardened

- Bound native HTTP/1 request-head and request-body reads with explicit
  deadlines to prevent slowloris and slow-body tasks from living indefinitely.
- Bound native HTTP/1 listener concurrency with a policy connection cap and
  safe zero-cap fallback to the default.
- Make native HTTP/1 response framing runtime-owned for `Content-Length`,
  `Connection`, and `Date`, and validate handler-supplied headers before
  writing.
- Sanitize native static 500 responses so filesystem and OS error details stay
  in logs instead of HTTP response bodies.
- Tighten native HTTP/1 head and chunked-body secondary buffer guards, and keep
  derived start-line limits within the total request-head limit.

## 1.6.8 - 2026-06-17

### Added

- Add a Fluxheim-owned HTTP/1.0/HTTP/1.1 request-head parser in
  `fluxheim-protocol` with bounded head size, header count, start-line length,
  header-line length, CRLF termination, UTF-8 validation, and obs-fold
  rejection.
- Add downstream HTTP/1 policy defaults to `fluxheim-server` so the native
  server cutover can carry HTTP/1 limits through the Fluxheim server plan before
  production traffic leaves the Pingora compatibility adapter.
- Add an incremental HTTP/1 request-head buffer for future native socket reads,
  including fragmented-head handling and bounded storage for oversized
  incomplete heads.
- Add strict HTTP/1 request body-framing classification for `Content-Length`
  and `Transfer-Encoding`, rejecting ambiguous `Content-Length` /
  `Transfer-Encoding` combinations before the native runtime cutover.
- Add HTTP/1.1 required `Host` boundary validation for the native parser,
  rejecting missing, duplicate, empty, or whitespace-containing host fields.
- Add HTTP/1 connection persistence classification for the native parser,
  covering HTTP/1.0 close-by-default, HTTP/1.1 persistent-by-default, explicit
  `Connection: close`, and HTTP/1.0 `Connection: keep-alive`.
- Add a bounded complete-buffer HTTP/1 chunked body decoder that writes into a
  caller-owned output buffer and enforces chunk, body, output, and CRLF limits.
- Split the HTTP/1 chunked decoder into a focused `fluxheim-protocol` module so
  the native HTTP parser remains under the reviewability target as the 1.6
  Pingora-exit line grows.
- Add native HTTP/1 request-target classification for origin-form,
  absolute-form, CONNECT authority-form, and OPTIONS asterisk-form requests,
  including percent-encoding and forbidden-fragment/backslash checks.
- Add a bounded native HTTP/1 response-head parser for future upstream response
  handling, reusing the same strict header-count, line-length, UTF-8, and
  obsolete-folding checks as request-head parsing.
- Harden the native HTTP/1 parser by rejecting deprecated authority userinfo,
  non-ASCII obs-text in strict header values and response reason phrases, all
  duplicate `Content-Length` fields, and unbounded chunked body defaults.

## 1.6.7 - 2026-06-16

### Changed

- Start the 1.6.7 server bootstrap cutover by making `fluxheim-server` build
  a Fluxheim-owned `ServerPlan` from validated config.
- Move HTTP, HTTPS, admin, metrics, stream, and UDP listener inventory plus
  process bootstrap settings into `fluxheim-server` plan types while keeping
  the current Pingora server as the compatibility adapter.
- Route the ACME certificate-reload control socket path through
  `fluxheim-server` process planning instead of reading it directly from root
  runtime config.
- Update root runtime to consume the server plan for process configuration and
  HTTP, HTTPS, admin, and metrics listener registration.
- Update root background-service registration gates to consume Fluxheim
  server-plan task metadata for cache purging, cache metrics, OTLP metrics
  export, ACME renewal, and certificate reload control.
- Add Fluxheim-owned foreground service intent metadata for proxy, admin, ops
  socket, metrics, stream proxy, and UDP proxy service registration, then make
  the root Pingora adapter consume those gates for non-proxy services.
- Add an explicit `RuntimeAdapterKind::PingoraCompatibility` marker to the
  server plan so the current Pingora runtime remains a named adapter boundary
  before the native server cutover.
- Add `ServerPlan` listener lookup helpers and route HTTP, HTTPS, admin, and
  metrics listener address lookups through `fluxheim-server` instead of
  hand-rolled adapter-side filtering.
- Remove duplicated downstream TLS listener-address storage from
  `fluxheim-tls`; HTTPS listener addresses now come from `fluxheim-server`
  while TLS planning owns certificate selection and policy.
- Move downstream PROXY protocol listener policy and trusted-source parsing
  into `fluxheim-server`, leaving root runtime as a Pingora listener-policy
  adapter.
- Split `fluxheim-server` process planning and PROXY protocol planning into
  focused modules so the new server crate stays below the 500-line target while
  the bootstrap cutover continues.
- Move private Unix listener creation for the certificate reload control socket
  into `fluxheim-server`, including stale socket replacement, mode `0600`, and
  nonblocking setup.
- Split server listener and foreground service inventory types into focused
  `fluxheim-server` modules before the native bootstrap work adds more runtime
  state.
- Move downstream HTTP/2 hardening limits into a Pingora-neutral
  `fluxheim-server` policy plan, with the root runtime only adapting those
  values into Pingora `H2Options`.
- Move certificate reload control socket policy into `fluxheim-server` so the
  socket path, concurrency cap, and request read timeout are planned outside
  the Pingora runtime adapter.
- Add server-plan lookup helpers for foreground services and background tasks,
  then make the root runtime adapter consume planned names when registering
  services.
- Add load-balancer health-check service intent to `ServerPlan` so load-balancer
  foreground registration is planned alongside proxy, admin, metrics, stream,
  and UDP services.
- Split server service-intent and background-task intent detection into focused
  `fluxheim-server` modules, reducing the server crate root while preserving the
  same runtime plan.
- Split listener inventory construction into the `fluxheim-server` listener
  module, keeping HTTP, HTTPS, admin, metrics, stream, and UDP listener parsing
  out of the server crate root.
- Move certificate reload control-plan construction into the focused
  `fluxheim-server` control module beside the control socket policy type.
- Add listener-protocol ownership to foreground service specs so the server
  plan can map proxy, admin, metrics, stream, and UDP services back to their
  planned listeners.
- Update the admin and metrics runtime adapters to consume service-owned
  listener lookups from the server plan.
- Add protocol-filtered service listener lookup and move proxy HTTP/HTTPS
  listener registration onto the service-owned lookup path.
- Add a background-service adapter helper that consumes planned
  `BackgroundTaskSpec` values directly, removing duplicated task kind/name
  wiring from plan-driven runtime services.
- Update admin service construction to consume planned control-plane and
  ops-socket service names from `ServerPlan`.
- Convert the admin self-healing watchdog registration to the typed background
  task spec path and remove the old name/kind free helper.
- Add admin self-healing watchdog intent to `ServerPlan` so the admin adapter
  consumes the planned `RuntimeWatchdog` task instead of creating it locally.
- Split the `ServerPlan` implementation into a focused `fluxheim-server` plan
  module, leaving the crate root as the public export and error surface.
- Add an admin ops-socket endpoint plan to `ServerPlan` and update the admin
  adapter to consume planned socket path and mode values.
- Add a first-service-listener lookup to `ServerPlan` and update admin service
  construction/logging to use the planned admin listener.
- Add borrow-based service listener iterators to `ServerPlan`, keeping the
  allocation-based address helpers as adapter conveniences.
- Update proxy HTTP and metrics listener registration to consume the
  borrow-based service listener views directly before adapting into Pingora.
- Harden private Unix listener setup by binding under a temporary private
  umask, using fd-based `fchmod` after bind, and using `rustix` path operations
  for stale socket cleanup.
- Remove the duplicate admin ops-socket mode parser from `fluxheim-server`;
  server planning now delegates to the validated config accessor.
- Document that `ListenerSpec::proxy_protocol_enabled()` reports only the
  server-level HTTP/HTTPS downstream PROXY protocol policy.

### Tests

- Add focused `fluxheim-server` tests for listener inventory, background-task
  intent, process-plan adaptation, invalid listener handling, and shutdown
  runner boundaries.
- Add a live admin-listener smoke test that starts Fluxheim and verifies the
  normal HTTP listener, admin health/status endpoints, and local read-only ops
  socket.
- Verify plan-gated foreground service registration with live admin,
  observability, stream proxy, and UDP proxy smokes.
- Split `fluxheim-server` tests into a separate module so new server code stays
  under the 500-line modularity target.
- Verify the split server crate modules remain below the modularity target with
  the release-gated modularity policy check.
- Add a `fluxheim-server` regression test proving private Unix listener paths
  replace stale sockets, reject non-socket files, and enforce private
  permissions.
- Add a `fluxheim-server` regression test for the downstream HTTP/2 hardening
  defaults consumed by the runtime adapter.
- Add a `fluxheim-server` regression test for the certificate reload control
  socket plan and keep the live admin listener smoke in the verification set.
- Extend `fluxheim-server` tests to cover planned service and background-task
  lookup by kind.
- Add a `fluxheim-server` regression test for load-balancer service intent and
  verify the runtime path with the live load-balancer smoke.
- Keep the split server intent modules covered by `cargo test -p
  fluxheim-server` and the release-gated modularity policy check.
- Verify the listener-planning split with `cargo test -p fluxheim-server` and
  the live admin listener smoke.
- Split private Unix listener regression coverage into a focused Unix-only test
  module so the main server test module remains well below the 500-line target.
- Add `fluxheim-server` regression coverage for service-owned listener address
  lookup.
- Add `fluxheim-server` regression coverage for protocol-filtered service
  listener lookup.
- Extend `fluxheim-server` background-task inventory coverage to include the
  planned admin self-healing watchdog.
- Split server background-task inventory tests into a focused module so the
  main server test file stays comfortably below the 500-line target.
- Add `fluxheim-server` regression coverage for admin ops-socket path and mode
  planning.
- Add `fluxheim-server` regression coverage for first service-listener lookup.
- Add `fluxheim-server` regression coverage for service listener iterator
  views.
- Add `proxy,acme-client` runtime test coverage for disabled certificate reload
  control service planning.

## 1.6.6 - 2026-06-16

### Changed

- Continue the 1.6 Pingora-exit line by adding `fluxheim-tls` as the
  Fluxheim-owned downstream TLS listener planning and provider-policy
  boundary.
- Move downstream TLS listener plans, SNI certificate selection, wildcard
  matching, ALPN/cipher/curve policy helpers, and rustls/OpenSSL provider/FIPS
  checks into `fluxheim-tls`.
- Update the runtime TLS listener adapter to consume `fluxheim-tls` plans while
  the current Pingora listener path remains the compatibility adapter for this
  release.
- Keep `pingora-rustls` documented as a temporary dependency until the native
  server/listener cutover, since 1.6.6 extracts planning but does not yet
  replace the active listener adapter.

### Security

- Fix `fluxheim-tls` feature gates so default, OpenSSL-only, and OpenSSL-FIPS
  builds do not re-export rustls-only policy/provider helpers.
- Harden downstream SNI certificate lookup to fall back to the default
  certificate instead of direct-indexing if a future selector refactor violates
  the internal index invariant.
- Move PROXY protocol v2 signature validation into the public parser instead of
  relying on every caller to satisfy the precondition.
- Reject non-canonical trusted PROXY protocol CIDR entries with host bits set.

## 1.6.5 - 2026-06-16

### Changed

- Continue the 1.6 Pingora-exit line with the first dedicated
  `fluxheim-headers` boundary for header policy helpers that do not need
  Pingora session or header types.
- Move response `Location`, `Refresh`, and `Set-Cookie` rewrite algorithms,
  spoofable client-IP header constants, trusted X-Forwarded-For restoration,
  `Forwarded` header construction, hop-by-hop request header policy, and
  repeated-header joining helpers into `fluxheim-headers`.
- Move stream downstream PROXY protocol v1/v2 byte parsers and size constants
  into `fluxheim-protocol`.
- Broaden the Pingora boundary policy gate so direct `pingora::` usage remains
  documented at adapter boundaries during the 1.6 removal line.
- Gate privacy-sensitive forwarded-client-IP parsing helpers in privacy-mode
  builds and reject PROXY-protocol trusted CIDR prefixes that exceed the
  address family width.
- Align access-policy and header-forwarding X-Forwarded-For parsing so both
  skip malformed hops and continue walking the trusted chain.

## 1.6.4 - 2026-06-15

### Changed

- Continue the 1.6 Pingora-exit line by moving shared background task lifecycle
  primitives into `fluxheim-runtime`.
- Replace the root background implementation with a narrow Pingora
  service-registration adapter around Fluxheim-owned shutdown, readiness, and
  background-service handles.
- Reuse the shared runtime background primitives from the load-balancer crate
  and tag background services with typed task metadata.
- Move OTLP metrics export and the ACME certificate reload control socket into
  the Fluxheim background task lifecycle.
- Move admin self-healing snapshot runtime state, pending validation, validation
  metrics, and rollback decisions into `fluxheim-snapshot`.
- Harden the local certificate reload control socket with a concurrency cap,
  reject over-one-day shared timeout values, and extend HTTP discovery
  private-backend filtering for 6to4/Teredo embedded IPv4 literals.

## 1.6.3 - 2026-06-15

### Changed

- Continue the 1.6 Pingora-exit line by adding `fluxheim-stream` as the
  internal TCP stream proxy runtime boundary.
- Move stream upstream selection, weighted primary ordering, backup/drain
  policy, selected-upstream labels, source allow/deny matching, and trusted
  PROXY source parsing into `fluxheim-stream`.
- Move stream DNS-rebinding guard decisions, copied-byte accounting,
  byte-limited copy-loop timeout handling, and max-connection-byte enforcement
  into `fluxheim-stream`.
- Move downstream PROXY protocol v1/v2 parsing and upstream PROXY protocol
  header writing into `fluxheim-stream` while reusing the shared
  `fluxheim-protocol` header builders.
- Keep the root stream adapter as the temporary Pingora service-registration,
  socket accept/connect, and TLS connector boundary until the broader
  background/runtime cutovers.
- Add direct `fluxheim-stream` unit coverage and preserve the stream proxy
  smoke/runtime tests for PROXY protocol, limits, and timeout behavior.

## 1.6.2 - 2026-06-14

### Changed

- Start the cache-independence release in the 1.6 Pingora-exit line.
- Move cache key identity, serialized object envelopes, disk index entries, and
  disk index management into `fluxheim-cache`.
- Move plaintext disk cache object header sizing, encoding, and parsing into
  `fluxheim-cache`; encrypted disk cache handling remains in the root adapter
  until the native HTTP/cache cutover.
- Move storage-bin layout, manifest, index-entry, object-location, and free-map
  allocation helpers into `fluxheim-cache` while leaving safe file opening and
  symlink checks in the root adapter.
- Add a Pingora-neutral `FluxCacheStorage` interface in `fluxheim-cache` with
  serialized metadata, hit handlers, miss handlers, purge, and metadata-update
  semantics.
- Adapt memory, filesystem disk, storage-bin disk, disk-backend, and tiered
  cache storage to the crate-owned cache interface while preserving the current
  Pingora HTTP runtime adapter.
- Move cache-tag grammar, normalization, encoding, decoding, limits, and
  default tag-header names into `fluxheim-cache`.
- Add regression coverage proving memory and tiered cache backends can
  round-trip objects through the native cache interface.
- Add a Rust integration test that enforces
  `docs/pingora-dependency-exceptions.tsv` removal targets against
  `Cargo.lock`, so expired Pingora dependency exceptions fail in normal
  `cargo test` runs as well as release gates.
- Keep final `pingora-cache` compile removal scheduled for the native HTTP
  runtime cutover because the current Pingora proxy runtime still imports
  `pingora::cache`.

## 1.6.1 - 2026-06-14

### Changed

- Start the first Pingora-exit implementation release after the `1.6.0`
  foundation tag.
- Fix the container image workflow so load-balancer images are built for
  normal `v1.6.x` tag pushes instead of being limited to `v1.5.x` refs.
- Bump workspace, RPM, release notes, and image documentation to `1.6.1`.
- Remove the remaining `pingora-load-balancing` and `pingora-ketama`
  dependencies from full and load-balancer image profiles by storing
  Fluxheim-native backend sets in `fluxheim-load-balancer`.
- Replace Pingora's TCP health-check backend adapter with a Fluxheim-owned TCP
  connector and rustls/OpenSSL handshake paths.
- Add a focused Podman load-balancer runtime smoke that builds the
  load-balancer-edge image, runs it against two local origins, verifies
  round-robin/header persistence behavior, and checks that the image profile
  does not compile Pingora load-balancing crates.
- Split load-balancer API/runtime DTOs and parser helpers into
  `crates/fluxheim-load-balancer/src/api.rs`, keeping public re-exports stable
  while reducing the crate root orchestration surface.
- Move the Pingora `ServiceWithDependents` adapter for load-balancer discovery
  and health-check background work into the root runtime crate. The
  load-balancer crate now exposes Fluxheim-owned shutdown/ready service
  primitives and no longer imports Pingora service/listener/shutdown types.
- Move load-balancer request-key extraction behind a public
  `LoadBalancerRequestView` trait. The root proxy now adapts Pingora request
  headers at the runtime boundary, keeping load-balancer selection and
  persistence logic transport-neutral.
- Bound native TLS TCP health-check handshakes with the configured connect
  timeout so a backend that accepts TCP and stalls TLS cannot freeze the
  load-balancer health/discovery loop.

## 1.6.0 - 2026-06-14

### Added

- Start the 1.6 Pingora-exit foundation line. Runtime behavior is intended to
  remain unchanged in this first 1.6 release while the project records baseline
  evidence and guardrails for staged dependency removal.
- Add `docs/modularity-exceptions.md` and
  `scripts/validate-modularity-policy.sh` to make the 500-line modularity
  policy measurable at release time. Existing oversized Rust files are listed
  as legacy exceptions with split targets instead of hidden as normal debt.
- Add `docs/runtime-baseline.md` and
  `scripts/capture-runtime-baseline.sh` to record locked dependency trees,
  per-profile Pingora dependency presence, release metadata, and default
  release-binary size before the runtime cutover work begins.
- Add `scripts/capture-runtime-performance-baseline.sh` and wire it into
  release-mode runtime baseline capture. It records local startup time, idle
  RSS/file descriptors, static HTTP latency, cache MISS/HIT latency,
  load-balancer route timing, keep-alive throughput, and fresh TLS connection
  timing.
- Add `docs/pingora-dependency-exceptions.tsv` and
  `scripts/validate-pingora-dependency-policy.sh` so the 1.6 line has a
  release-gated inventory of allowed Pingora crates per official profile.
- Add `docs/runtime-parity-fixtures.md`, `docs/runtime-parity-fixtures.tsv`,
  and `scripts/validate-runtime-fixtures.sh` to pin the smoke scripts,
  examples, and TLS fixtures that define runtime parity before
  HTTP/cache/LB/TLS cutovers begin.
- Add initial `fluxheim-runtime` and `fluxheim-server` workspace crates for
  Fluxheim-owned shutdown, background task, listener, and server-runner
  boundary traits. The current Pingora runtime path is unchanged.
- Add typed `PolicyEpoch`, `PolicyProof`, `RuntimeFact`, decision, reason, and
  visibility primitives in `fluxheim-runtime` for later policy-proof adoption.
  They are not wired into request handling in this release.
- Add `docs/extraction-dependency-graph.md` to record the intended split order
  for `snapshot`, protocol, tracing/observability, headers, ACME,
  runtime/server, cache, proxy, and admin modules before the Pingora cutover.
- Add `docs/runtime-facts-and-policy-proofs.md` to guide typed, bounded,
  redacted decision evidence for route policy, cache admission,
  load-balancer selection, admin mutation, config promotion, and future Wasm
  host calls.

### Changed

- Bump workspace, RPM, release notes, and image documentation to `1.6.0`.
- Update README wording so the 1.5 load-balancer line is closed and future
  load-balancer health-check work is no longer described as a later 1.5.x
  item.
- Refresh `ROADMAP.md` so `1.6.x` is consistently documented as the
  Pingora-exit line, shared Wasm extensibility is moved to `1.7`, and HTTP/3
  remains after the runtime boundary is stable.
- Harden `scripts/validate-pingora-dependency-policy.sh` so documented
  Pingora removal targets are enforced against the current Fluxheim version
  instead of acting as a set-membership inventory only.
- Tighten release-gate scripts by requiring modularity exceptions to be listed
  as structured table rows and by giving the UDP smoke negative assertion a
  longer observation window.

## 1.5.23 - 2026-06-14

### Added

- Add cache origin-protection configuration with per-vhost or per-route
  `max_concurrent_fills` budgets for Fluxheim-owned origin fill paths. The
  first protected path is range slice fill: when the budget is saturated,
  Fluxheim refuses the protected fill with `503` instead of falling through to
  origin.
- Expose cache origin-protection rollout through admin cache status and
  low-cardinality metrics:
  `fluxheim_cache_origin_protection_enabled_policies`,
  `fluxheim_cache_origin_protection_max_concurrent_fills`, and bounded
  `origin_protected` cache policy activity.
- Extend `fluxheim cache-key` and `fluxheim cache-lookup` previews with
  origin-protection policy state and expectation flags for release gates.

### Changed

- Consolidate slice-fill, peer-fill, and origin-fill cache concurrency permits
  into one shared limiter implementation so future hardening of the DoS budget
  primitive applies uniformly.

## 1.5.22 - 2026-06-14

### Changed

- Start the next cache/load-balancer crate-boundary pass by moving
  load-balancer persistence key extraction behind a Fluxheim-owned request
  view trait. The Pingora `RequestHeader` adapter remains at the
  load-balancer API boundary, so routing, persistence, managed-cookie, header,
  cookie, URI, and source-IP selection behavior is unchanged.
- Add persistence-module tests that exercise managed-cookie validation through
  the Fluxheim request view directly, reducing Pingora coupling in unit-level
  load-balancer coverage.
- Harden `fluxheim-web` filesystem tests that exercise symlink detection by
  using repository-local, component-validated test paths instead of raw
  `temp_dir()`-derived paths, resolving CodeQL path-expression alerts without
  changing runtime web behavior.
- Move cleartext TCP health checks to a Fluxheim-owned Tokio connect probe.
  TLS TCP health checks still use the existing Pingora transport connector for
  SNI/TLS handshake compatibility until the larger `1.6.x` connector-removal
  work.
- Move cache request bypass, client revalidation, and range-selection
  decisions behind a Fluxheim-owned cache request view. The root proxy cache
  module now adapts Pingora request headers into that view, keeping runtime
  behavior unchanged while shrinking the Pingora-facing cache surface.
- Move cache response admission policy for status, content type, response
  no-store headers, Vary handling, and range responses into the cache crate,
  leaving the root proxy cache module as the Pingora response adapter.
- Move cache storage interface result enums for purge type and miss completion
  into the cache crate, keeping Pingora conversions in the root adapter layer.
- Move range/slice cache-key component construction into the cache crate so
  the proxy cache module only adapts the Pingora cache-key container.
- Harden UDP beta passive health so local downstream drop conditions
  (`response_rate_limited` and oversized upstream responses) do not count as
  upstream failures, and rate-limit passive-ejection warning logs.

## 1.5.21 - 2026-06-13

### Added

- Added UDP beta per-source pressure controls with
  `max_sessions_per_source`, released when each datagram session completes.
- Added UDP beta per-source response-rate limiting with
  `max_responses_per_source_per_second` for request/response UDP routes.
- Added UDP Prometheus metrics for accepted/sent/error datagrams, drops, and
  active route sessions.
- Added `GET /_fluxheim/udp/status` for admin-visible UDP route configuration,
  listener exposure warnings, and configured UDP limits.
- Added UDP beta passive upstream health: consecutive request/response
  failures can temporarily eject a member from route selection, and successful
  exchanges clear the ejection state.

### Changed

- UDP `dns-load-balance` routes now emit a security warning when configured on
  non-loopback listeners during the beta period.
- Updated UDP beta documentation and smoke coverage for the new production
  readiness guardrails.
- Extended UDP smoke coverage to verify exact-cap responses are accepted and
  oversized downstream datagrams are dropped before reaching the upstream.
- Added optional stable-gate UDP beta smoke via `FLUXHEIM_GATE_UDP=1`, with
  `FLUXHEIM_UDP_SMOKE_ITERATIONS` for longer local soak runs.
- Hardened UDP beta hot paths by removing per-response full-map scans from
  source response-rate limiting and bounding passive-health fallback selection
  by upstream count instead of total configured weight.

## 1.5.20 - 2026-06-13

### Changed

- Start the `fluxheim-cache` crate boundary by moving shared cache-header
  request/response directive parsing into `crates/fluxheim-cache`. The root
  crate keeps `crate::cache_headers` as a compatibility re-export, so runtime
  behavior and call sites are unchanged.
- Move pure cache admin request/result/preview DTOs into
  `crates/fluxheim-cache::api`, with root `crate::cache_api` and
  `crate::proxy` re-exports kept for compatibility. Pure runtime totals and
  activity-reset DTOs also moved.
- Move cache object metadata, activity stats, tier stats, object lookup, and
  vhost/route runtime stats into `crates/fluxheim-cache::api`. Root
  `crate::cache` and `crate::cache_api` keep compatibility re-exports so admin,
  CLI, metrics, and proxy call sites are unchanged.
- Move cache storage-plan DTOs into `crates/fluxheim-cache::plan`, keeping
  root `crate::cache` re-exports while the Pingora storage adapters remain in
  the root cache runtime.
- Move cached object DTOs and `CacheStoreError` into
  `crates/fluxheim-cache::object`, keeping root `crate::cache` re-exports for
  memory-cache and test call sites.
- Move cache request/key DTOs into `crates/fluxheim-cache::request`, with root
  `crate::cache` re-exports and root cache-key builders preserving the existing
  behavior.
- Move cache range/slice request DTOs, single-range parsing, client range
  parsing, client-range resolution, and required-slice planning into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  Pingora request-header and cache-key adapter.
- Move Content-Range parsing into `crates/fluxheim-cache::request`, so
  range-cache admission and slice-object reconstruction share one pure parser.
- Move pure cache freshness helpers for remaining TTL and synthesized
  Cache-Control freshness directives into `crates/fluxheim-cache::headers`.
- Move Vary header parsing and configured request-header variance policy into
  `crates/fluxheim-cache::headers`, keeping root `crate::proxy_cache` focused
  on Pingora request hashing and adapter logic.
- Move Vary request hash material framing into
  `crates/fluxheim-cache::headers`; root `crate::proxy_cache` now only adapts
  Pingora request headers and calls the Pingora hash function.
- Move cacheable response Content-Type matching into
  `crates/fluxheim-cache::headers`, leaving root cache admission as the
  status/header adapter.
- Move cache-bypass cookie and query-string matching, including percent-decoded
  query comparisons, into `crates/fluxheim-cache::headers`.
- Move cache stale-serving event and status/error allow policy into
  `crates/fluxheim-cache::headers`, keeping Pingora error classification in
  root `crate::proxy_cache`.
- Move response `Age` and `Cache-Control` max-age/s-maxage parsers into
  `crates/fluxheim-cache::headers`, leaving root response helpers as thin
  Pingora header adapters.
- Move Cache-Control directive merge/replacement into
  `crates/fluxheim-cache::headers`, leaving root response mutation as a
  Pingora header adapter.
- Move range response `Content-Range` and `Content-Length` validation into
  `crates/fluxheim-cache::request`, leaving root range-cache admission as the
  Pingora status/header adapter.
- Move cache-key component formatting and the temporary HEAD cache bypass
  predicate into `crates/fluxheim-cache::request`, keeping root compatibility
  wrappers for existing proxy callers.
- Move multipart slice range policy sizing into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  config adapter.
- Move cache Prometheus label classifiers into `crates/fluxheim-cache`,
  keeping root `crate::metrics` as recorder wiring.
- Move cache purge-index state, purge-entry DTOs, storage-local purge result
  counters, and cache-key path matching helpers into
  `crates/fluxheim-cache::purge_index`. Root `crate::cache` keeps the existing
  compatibility type names while the Pingora storage implementations remain in
  the root runtime adapter.
- Start the `fluxheim-web` crate boundary by moving static directory-listing
  data/rendering helpers into `crates/fluxheim-web`. The root `crate::web`
  module re-exports the same types and renderer while keeping Pingora response
  serving in the root adapter.
- Move static byte-range parsing into `crates/fluxheim-web`, keeping
  `crate::web` compatibility re-exports for the existing static response
  planner and tests.
- Move static response planning, conditional request evaluation, weak ETag
  construction, and range response plan DTOs into `crates/fluxheim-web`.
  `crate::web` keeps the existing `StaticRequestConditions` compatibility
  adapter so proxy call sites and cache-refresh semantics are unchanged.
- Move safe relative path and directory-listing path helpers into
  `crates/fluxheim-web`, leaving root static serving responsible for filesystem
  canonicalization and symlink checks.
- Move configured web-root symlink detection into `crates/fluxheim-web`, keeping
  root `StaticFileServer` construction as the filesystem adapter.
- Move static cache identity formatting into `crates/fluxheim-web`, keeping
  root `StaticFile` as the filesystem metadata adapter.
- Start the `fluxheim-php-fpm` crate boundary by moving PHP-FPM timeout
  classification and bounded error-outcome helpers into
  `crates/fluxheim-php-fpm`, with the root PHP-FPM module re-exporting the same
  names for existing runtime and test code.
- Move managed PHP-FPM restart-backoff and sanitized `PATH` fallback helpers
  into `crates/fluxheim-php-fpm`, again keeping the root module as the
  compatibility surface for existing code.
- Move managed PHP-FPM config rendering and its config-value validators into
  `crates/fluxheim-php-fpm`, leaving root PHP-FPM process supervision as the
  compatibility adapter.
- Move PHP-FPM effective timeout calculation, retry attempt/deadline policy,
  retryable status matching, and retryable error classification into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` retaining the
  `StatusCode` compatibility adapter.
- Move PHP-FPM endpoint selection and endpoint DTOs into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` keeping compatibility
  re-exports for the proxy runtime and tests.
- Move PHP-FPM response-header name/value safety guards into
  `crates/fluxheim-php-fpm`, keeping root response parsing as the Pingora
  header adapter.
- Move PHP-FPM response split, `Status` parsing, ASCII trimming, and header
  colon splitting into `crates/fluxheim-php-fpm`, leaving root response parsing
  as the Pingora response-header adapter.
- Move managed PHP-FPM instance-name generation and metric-pool sanitization
  into `crates/fluxheim-php-fpm`, leaving root process supervision as the Unix
  runtime adapter.
- Start the `fluxheim-geoip` crate boundary by moving `GeoContext` and the
  optional local MMDB runtime into `crates/fluxheim-geoip`, with root
  `crate::geo_context` and `crate::geoip` compatibility re-exports.
- Start the `fluxheim-compression` crate boundary by moving response
  compression encoder lifecycle and output-limit accounting into
  `crates/fluxheim-compression`, while keeping Pingora header selection and
  response mutation in the root adapter.
- Move Accept-Encoding token and qvalue parsing into
  `crates/fluxheim-compression`, keeping root response-header selection as the
  Pingora adapter.
- Move compression response policy string matching for Cache-Control directives
  and Content-Type eligibility into `crates/fluxheim-compression`, leaving root
  response-header iteration as the adapter.
- Move active Content-Encoding classification and compression input-size bounds
  into `crates/fluxheim-compression`, keeping root response headers/config as
  adapters.
- Start the `fluxheim-observability` crate boundary by moving W3C Trace Context
  parsing, generation, and traceparent normalization into
  `crates/fluxheim-observability`, with root `crate::trace_context` kept as a
  compatibility re-export.
- Move the shared OTLP HTTP agent and symlink-safe custom CA bundle loader into
  `crates/fluxheim-observability` behind its `otlp-http` feature, while keeping
  the root `crate::otlp_http` module as the metrics/tracing adapter.
- Move OTLP HTTP endpoint parsing into `crates/fluxheim-observability`, keeping
  the Prometheus metrics payload conversion in the root metrics adapter.
- Move the Prometheus-to-OTLP metrics payload builder into
  `crates/fluxheim-observability` behind its `otlp-metrics` feature, leaving
  root metrics OTLP as exporter lifecycle and HTTP post wiring.
- Move access-log helper logic for request-id validation/generation,
  shared low-cardinality status classes, response byte counting, and Unix
  nanosecond timestamps into `crates/fluxheim-observability`, while the root
  access-log module keeps Pingora request-header integration and JSON event
  assembly and Prometheus metrics reuses the shared status-class helper.
- Move shared JSON string escaping for access logs and runtime JSON logs into
  `crates/fluxheim-observability`, keeping both root log schemas unchanged.
- Move proxy metrics outcome, method, and status-class label bucketing into
  `crates/fluxheim-observability`, keeping root `crate::metrics` as the
  Prometheus registry/recorder adapter.
- Move general Prometheus label classifiers for host-routing, admin-auth,
  compression, edge-policy, load-balancer event/queue/upstream, stream, ACME,
  PHP/PHP-FPM, and metrics-OTLP exporter events into `crates/fluxheim-observability`,
  further narrowing root `crate::metrics` to recorder wiring.
- Move Prometheus numeric helper logic for bounded ratios and saturating gauge
  conversions into `crates/fluxheim-observability`, leaving root metrics as the
  registry/recorder adapter.
- Move `LoadBalanceSelection` metric-label mapping into `fluxheim-config`,
  keeping root `crate::metrics` as a compatibility wrapper.
- Move config-derived cache and load-balancer metrics summary aggregation into
  `fluxheim-config`, leaving root metrics to only publish the Prometheus
  gauges.
- Move the OTLP trace exporter and trace-span payload builder into
  `crates/fluxheim-observability` behind its `otlp-trace` feature, with root
  `crate::otel_otlp` kept as a compatibility re-export.
- Start the `fluxheim-protocol` crate boundary by moving PROXY protocol v1/v2
  upstream header framing into `crates/fluxheim-protocol`, while the root
  `crate::proxy_protocol` module keeps the Pingora L4 connector adapter.
- Move route method matching and prefix-boundary helpers into
  `crates/fluxheim-protocol`, keeping root `crate::route_policy` as the config,
  regex-capture, and Pingora request adapter.
- Start the `fluxheim-snapshot` crate boundary by moving the durable config
  snapshot store, metadata validation, rollback pointer handling, and
  symlink-safe filesystem writes into `crates/fluxheim-snapshot`, with root
  `crate::snapshot` kept as a compatibility re-export.
- Move reload-impact classification into `crates/fluxheim-config`, with root
  `crate::reload` kept as a compatibility re-export for admin and CLI reload
  reporting.
- Move load-balancer runtime/member weight parser helpers into
  `crates/fluxheim-load-balancer`, leaving root admin as the HTTP/query
  endpoint adapter.
- Move cache admin summary math helpers into `crates/fluxheim-cache::api`,
  leaving root admin JSON assembly as the response adapter.
- Move runtime cache-purger `usize` metric saturation into
  `crates/fluxheim-observability`, keeping root runtime as the background-task
  adapter.
- Move downstream PROXY-protocol trusted-source parsing into
  `crates/fluxheim-protocol`, leaving root runtime as the Pingora listener
  adapter.
- Move HTTP Upgrade token grammar validation into `crates/fluxheim-protocol`,
  leaving root proxy as the Pingora request-header adapter.
- Move Fluxheim `Via` header value formatting into `crates/fluxheim-protocol`,
  leaving root proxy as the Pingora header mutation adapter.
- Move multipart cache Content-Type sanitization into
  `crates/fluxheim-cache::headers`, leaving root proxy as the slice response
  assembly adapter.
- Move cache slice metadata first-header extraction into
  `crates/fluxheim-cache::headers`, leaving root proxy as the slice identity
  adapter.
- Move hop-by-hop `Connection` option token validation onto the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
- Move response header rewrite prefix authority-boundary matching into
  `crates/fluxheim-protocol`, leaving root header policy as the mutation
  adapter.
- Move cache CLI header-name validation onto the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
- Move config HTTP token validation onto the shared `crates/fluxheim-protocol`
  grammar while preserving method-specific uppercase checks.
- Move cache object lookup summary formatting into `crates/fluxheim-cache`,
  leaving the CLI as the command/output adapter.
- Move cache-warm count summaries and bounded status labels into
  `crates/fluxheim-cache`, leaving the CLI to print the prepared summaries.
- Use the shared `crates/fluxheim-cache` storage-tier helper directly from
  admin cache status JSON.

### Fixed

- Harden the vendored HTTP/1 request parser to reject requests that carry both
  `Transfer-Encoding` and `Content-Length`, matching Fluxheim's raw
  request-framing release smoke and avoiding ambiguous downstream body
  framing.
- Document the shared protocol HTTP token grammar as case-permissive and warn
  when accepted IPv6 trusted-proxy CIDR entries are broader than `/32`.
- Fix cache-only builds after shared cache stats moved purge-index and activity
  fields into the always-present cache API shape.
- Allow real provider IPv6 trusted-proxy ranges such as Cloudflare's
  `2a06:98c0::/29`. The `1.5.19` config-crate split preserved runtime IPv6
  CIDR support but made config validation too strict by rejecting trusted proxy
  IPv6 prefixes broader than `/32`.

## 1.5.19 - 2026-06-12

### Security

- Fix fallback proxy cache auth ordering so cache fallback handling cannot run
  before the configured authorization decision.
- Reject ambiguous dot-segment proxy request paths before route selection,
  route-local policy checks, cache keying, or upstream forwarding.
- Treat incoming method casing as equivalent for route method filters so
  lowercase HTTP/1 method tokens cannot miss method-scoped route policy.
- Restrict accepted inbound request IDs to an identifier-safe alphabet so
  URL-like or email-like values are regenerated before reaching logs, traces,
  templates, or upstream headers.
- Release response-compression output buffers after each emitted chunk while
  preserving the cumulative `max_output_bytes` cap.
- Make route prefix matching and prefix stripping path-segment aware so sibling
  paths such as `/repoadmin` cannot enter a `/repo` route or rewrite to
  unintended upstream paths.
- Percent-encode URI-special bytes in route regex capture substitutions before
  applying rewrite templates, preserving slash-spanning captures while removing
  raw matrix/userinfo/list delimiters from rewritten upstream paths.
- Normalize `Set-Cookie` `Domain` and `Path` attribute values before response
  rewrites, covering leading-dot domains, quoted attribute values, and trailing
  ASCII whitespace so alternate cookie syntax cannot bypass configured rewrite
  rules.
- Harden range slice-cache origin fill so dynamic-only upstream discovery
  cannot fall back to the default loopback upstream, unsafe dot-segment origin
  paths are rejected, and multipart range requests are bounded by range count
  and response-wrapper overhead.
- Resolve exact local-static purge identities through the same route rewrite
  logic used by static serving, including `rewrite_prefix`.
- Apply decoded route matching to edge policy checks, closing mismatches between
  encoded request paths and policy enforcement.
- Preserve private cache-control directives for status-specific TTL handling so
  restrictive origin cache headers are not weakened by cache policy.
- Harden PHP-FPM path handling by denying scripts after resolved-path
  normalization and covering directory-index resolution under denied PHP path
  prefixes.
- Fix proxy-only route decode feature wiring so shared path safety remains
  available in proxy builds without cache.
- Isolate upstream CA bundle material in peer reuse keys to avoid reusing
  upstream TLS peers across distinct trust material.
- Add a default stream proxy connection cap to avoid unbounded accepted TCP
  stream connections.
- Detach self-healing probes from public proxy traffic paths.
- Preserve restrictive PHP cache headers when PHP-FPM responses are converted
  into Fluxheim responses.
- Reject PHP-FPM `PHP_VALUE` and `PHP_ADMIN_VALUE` style ini-control parameters
  so configured PHP params cannot rewrite php-fpm runtime policy.
- Clean pending PHP request-body spool files on retry/error paths.
- Add `php.max_in_flight`, defaulting to `8`, to cap concurrent PHP-FPM requests
  before request body buffering and FastCGI dispatch.
- Add `proxy.load_balance.passive_health.min_healthy_backends`, defaulting to
  `1`, so passive outlier ejection cannot fail-closed an entire load-balanced
  pool by default. Operators can set it to `0` to retain strict fail-closed
  passive-health behavior.
- Harden managed-cookie load-balancer persistence so invalid affinity cookies
  no longer create server-side persistence-table entries, while newly issued
  signed cookies immediately record one bounded table entry for the selected
  backend so the next request remains pinned.
- Reject verified HTTP proxy upstream TLS configs that target an IP-addressed
  upstream without explicit `upstream_sni`, preventing the Pingora connector
  from falling into empty-SNI certificate-verification bypass behavior.
- Harden HTTP load-balancer discovery so private, loopback, link-local,
  metadata, multicast, reserved, and documentation IP-literal backends are
  rejected by default unless the operator explicitly enables
  `proxy.upstreams_http_allow_private_backends`.
- Add `proxy.downstream_read_timeout_secs`, defaulting to 60 seconds, and wire
  it into vendored Pingora HTTP/2 downstream request-body reads so slow-body
  clients cannot hold proxy forwarding tasks indefinitely while withholding
  DATA frames or END_STREAM.
- Apply the downstream read timeout before PHP-FPM request-body collection and
  drain paths, covering PHP routes that read the body before FastCGI execution
  begins.
- Revalidate managed PHP-FPM binary paths immediately before spawning child
  processes and reject symlinked binaries at config validation so local path
  swaps cannot replace the supervised executable between reload and spawn.
- Harden downstream HTTP/2 flow-control defaults by capping per-stream send
  buffering at 256 KiB, keeping DATA frames at 16 KiB, fixing the receive
  window at 64 KiB, and reducing pending-accept reset-stream pressure.
- Remove encrypted filesystem disk-cache fill heap amplification for the local
  provider by committing streamed cache bodies through bounded AEAD chunks, and
  bound the OpenBao Transit whole-object fallback heap budget.
- Harden DNS-refreshed upstream discovery against DNS rebinding pivots by
  rejecting private, loopback, link-local, multicast, reserved, documentation,
  metadata, and unspecified resolved addresses unless
  `proxy.upstream_dns_allow_private_backends = true` is set.
- Harden HTTP and DNS discovery backend filtering by applying the IPv4 private
  address policy to IPv4-mapped and IPv4-compatible IPv6 literals before they
  can be accepted as upstream addresses.
- Harden split-config trusted-proxy handling by extending
  `server.trusted_proxies` fragments instead of replacing the main list, and by
  rejecting catch-all or near-global trusted-proxy ranges such as `0.0.0.0/0`
  and `::/0`.
- Harden split-config proxy handling by applying field-level `[proxy]`
  fragment merges so a later timeout-only proxy fragment cannot silently clear
  upstream TLS verification, auth request, mirror, or load-balancer policy.
- Complete recursive split-config merges for `[proxy.auth_request]`,
  `[proxy.mirror]`, and `[proxy.load_balance]` so partial nested fragments
  cannot reset established auth, shadow-traffic, persistence, health-check,
  retry, or load-balancer selection policy back to defaults.
- Harden split-config handling for `[compression]`, `[cache]`,
  `[cache_purger]`, `[web]`, and `[stream]` so partial fragments cannot
  silently drop previously configured compression limits, cache encryption,
  static-file safety policy, or stream routes.
- Harden split-config admin handling by applying field-level `[admin]`
  fragment merges so a later ops-socket or health-only admin fragment cannot
  silently disable the admin API or clear token and snapshot-store settings.
- Harden cache peer-fill request construction so peer lookups use the selected
  vhost's canonical `Host`, while client-controlled `Host` headers and
  absolute-form URI authorities cannot pivot peer requests to another vhost.
- Add an inbound peer-fill recursion guard so requests marked with
  `X-Fluxheim-Peer-Fill: 1` cannot launch another outbound peer-fill fetch in
  cyclic peer topologies.
- Decode percent-encoded cache bypass query names and values before comparing
  `bypass_query_params` and `bypass_query_values`, closing encoded preview or
  private-mode cache bypass evasion.
- Align configured cache Vary request headers with the 16-field runtime Vary
  cap and reject effective origin-plus-configured Vary overflows at cache
  admission instead of dropping variance.
- Harden auth-request response header handling so allowed auth response
  headers cannot override Fluxheim's upstream request header policy on name
  collisions.
- Harden auth-request forwarded context handling so allow-listed
  `X-Original-URI`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and
  `X-Forwarded-Proto` values are synthesized from Fluxheim's trusted request
  context instead of copied from spoofable client headers.
- Match auth-request split `Cookie` handling to the origin request path by
  joining repeated `Cookie` fields with `; ` instead of `, ` before sending the
  authorization subrequest.
- Harden Unix admin-token and file-log opening by using rustix
  architecture-correct `NOFOLLOW` flags instead of hand-coded constants.
- Harden trusted-proxy `X-Forwarded-For` parsing so any malformed hop rejects
  the forwarded chain and falls back to the direct peer IP instead of silently
  attributing traffic to a trusted proxy hop.
- Normalize IPv4-mapped IPv6 client addresses before trusted-proxy,
  access-policy, rate-limit, and GeoIP decisions so IPv4 CIDR policy also
  applies on dual-stack listeners that report IPv4 peers as `::ffff:...`.
- Restrict WebSocket-enabled proxy routes to the `websocket` upgrade token so
  valid but unrelated protocol upgrades such as `h2c` are not forwarded to
  upstreams.
- Strip HTTP/1 `Connection` and `Upgrade` request headers when
  `proxy.websocket = false`, preventing normal proxy routes from tunneling
  upgraded protocols by accident.
- Remove vendored Pingora upstream TLS underscore-to-hyphen hostname
  verification rewriting so certificates are checked against the exact
  configured SNI or alternative name.
- Strip client-controlled hop-by-hop request headers before forwarding to
  upstreams, including `Connection`-listed extension headers and non-WebSocket
  `Upgrade` values.
- Harden response `Location` and `Refresh` prefix rewrites so absolute URL
  prefixes only match the intended authority boundary and cannot rewrite
  userinfo-style URLs such as `http://origin@evil.example/`.
- Reject redirect templates that place `{query}` inside the URL authority so
  attacker-controlled query strings cannot turn operator redirect rules into
  authority-changing redirects.
- Harden Host and authority normalization by rejecting percent signs,
  consecutive dots, leading/trailing label hyphens, overlong labels, and
  numeric-only final labels in DNS hostnames.
- Harden OpenBao Transit cache encryption calls by disabling HTTP redirects
  and reading Transit JSON responses through a bounded buffer before parsing.
- Harden PHP-FPM path handling by rejecting protocol-relative directory-slash
  redirects and decoded control characters in path-derived FastCGI params.
- Harden PHP-FPM TCP endpoint validation by rejecting unsafe IP literals and
  requiring `allow_private_tcp_upstreams = true` for loopback,
  private/link-local IPs.
- Reject stream routes that enable upstream TLS certificate verification for
  IP-addressed upstreams without an explicit `upstream_sni`, matching the HTTP
  proxy validation rule and avoiding runtime hostname-verification skips.
- Harden traffic mirroring by rejecting unsafe mirrored paths/queries before
  outbound URL construction and suppressing recursive mirror requests marked
  with `X-Fluxheim-Mirror`.
- Add stream route `allow_sources` and `deny_sources` IP/CIDR policies so raw
  TCP stream listeners can reject unauthorized sources before connecting
  upstream.
- Harden stream hostname upstreams against DNS-rebinding pivots by rejecting
  private or reserved DNS answers unless the route explicitly sets
  `upstream_dns_allow_private_addresses = true`.
- Reject horizontal tabs in configured static header values so operator header
  policies cannot pass HTTP/1.x-only whitespace into HTTP/2 upstream requests
  or responses.
- Rewrite quoted `Refresh` response URLs for configured prefix rewrite rules,
  covering both single-quoted and double-quoted URL forms.
- Harden runtime file-log opening by rejecting symlinked log path components
  immediately before creating or appending the log file.
- Harden `Accept-Encoding` qvalue parsing so non-finite or malformed values
  such as `NaN` and `Infinity` cannot influence compression negotiation.
- Add `admin.ops_socket.require_bearer_token` so local Unix ops-socket status
  endpoints can require the same bearer token as the TCP admin control plane.
- Require bearer-token authentication for `GET /_fluxheim/snapshots` on the
  Unix ops socket even when other read-only status endpoints are local-only.

### Changed

- Move the Fluxheim-owned load-balancer core into the internal
  `crates/fluxheim-load-balancer` workspace crate.
- Keep the root `crate::load_balancer` compatibility shim so admin, proxy,
  runtime, config, release profiles, and operator-facing behavior remain
  unchanged.
- Move load-balancer backend snapshots, discovery adapters, health checks,
  selection algorithms, runtime policy overrides, persistence, queue policy,
  state files, background task glue, and tests together under the new crate.
- Add narrow root-to-crate hooks for metrics event recording and compliance
  HMAC signing without making the load-balancer crate depend on proxy, admin,
  cache, web, or PHP internals.
- Keep `pingora-load-balancing` and Pingora health-check adapter removal as
  later 1.5.x work; this release is an ownership/boundary extraction only.

## 1.5.18 - 2026-06-12

### Changed

- Move the Fluxheim configuration schema, parsing, validation, config-source
  loading, and config tests into the internal `crates/fluxheim-config`
  workspace crate.
- Keep the root `crate::config` and `crate::config_*` compatibility shims so
  runtime modules, release profiles, config tester behavior, and operator config
  syntax remain unchanged.
- Add a config-crate `test-support` feature so root integration tests retain
  repository-local process paths without changing production defaults.

### Security

- Harden downstream HTTP/2 response handling against the HTTP/2 Bomb
  window-stall half by adding an absolute
  `proxy.downstream_total_response_timeout_secs` response-write lifetime bound.
- Clarify and test that `server.limits.max_request_headers` counts duplicate
  request header values, including split HTTP/2 `Cookie` crumbs, before routing.

## 1.5.17 - 2026-06-11

### Changed

- Start the workspace and shared-crate foundation line.
- Convert the repository into a Cargo workspace with `crates/fluxheim-common`
  as the first internal shared crate.
- Move the Fluxheim-owned `FluxError`/`FluxResult` boundary into
  `fluxheim-common` while keeping the root `crate::flux_error` adapter for
  existing runtime code.
- Move shared forward-path safety validation into `fluxheim-common` while
  keeping the root `crate::path_safety` adapter for existing proxy/cache code.
- Move repository-local test path helpers behind the `fluxheim-common`
  `test-support` feature while keeping the root `crate::test_support` adapter
  for existing tests.
- Update `regex` from `1.12.3` to `1.12.4`.
- Add a release-gate freshness check for compatible non-Pingora crate updates
  and strengthen release metadata validation for release notes, README,
  build/container docs, and RPM version alignment.
- Copy workspace crates into all container build stages so release images build
  correctly after the workspace split.
- Make `scripts/stable_release_gate.sh release` require the root image smoke
  plus representative Debian and Alpine variant image smokes before tagging.
- Fix the OpenSSL FIPS support build-script hex literal grouping so Rust 1.96
  clippy accepts the vendored support crate under `-D warnings`.
- Keep all feature profiles, binaries, release scripts, RPM/container behavior,
  config syntax, and runtime behavior unchanged in this first workspace slice.

## 1.5.16 - 2026-06-10

### Changed

- Start the UDP/GSLB exploration line with a separate `[udp]` beta
  configuration namespace and runtime service instead of extending TCP stream
  routes with UDP semantics.
- Add the `udp-proxy` feature gate and bounded UDP route schema for explicitly
  scoped future modes: `dns-load-balance`, `syslog-forward`,
  `quic-pass-through`, and `game-proxy`.
- Add beta UDP listener/runtime support for DNS-style request/response
  forwarding and syslog-style one-way forwarding.
- Validate UDP route names, listeners, upstreams, upstream weights, upstream
  aliases, idle/session timeouts, datagram caps, and session caps before any
  datagram forwarding starts.
- Add `response_timeout_secs` for UDP routes, defaulting to `3`, so unanswered
  DNS-style request/response datagrams do not hold route slots for the full
  idle timeout.
- Remove the unused beta `max_session_secs` UDP field before release; current
  beta modes process one datagram at a time and use `response_timeout_secs` for
  upstream waits.
- Drop oversized upstream UDP responses instead of forwarding truncated
  datagrams, and rate-limit high-volume UDP drop warnings.
- Default UDP route `max_sessions` to `4096`; `0` remains an explicit
  unlimited setting.
- Add `scripts/smoke_udp_proxy.sh` to prove the beta UDP runtime through the
  Fluxheim binary with local UDP backends.
- Refresh low-risk dependency and workflow pins: `base64-ng` 1.0.8, `http`
  1.4.2, manifest `log` 0.4.32, and exact current GitHub Action tags for
  checkout and Docker image workflows.
- Keep `udp-proxy` out of the normal full/proxy/load-balancer feature profiles
  until a reviewed runtime exists. Configs with `udp.enabled = true` fail
  clearly unless built with the beta feature.
- Keep QUIC pass-through, game-server UDP proxying, generic UDP proxying,
  authoritative DNS/GSLB, WAF, VPN/firewall appliance behavior, HTTP/3 ingress,
  and Wasm/iRules/Lua scripting outside this stop line.
- Document that `dns-load-balance` remains beta and must not be exposed as an
  open public DNS reflector without network ingress filtering and future
  response-rate-limit work.

## 1.5.15 - 2026-06-10

### Changed

- Start the database/protocol-aware health-check line with bounded Redis
  `PING`, MySQL/MariaDB handshake, and PostgreSQL SSLRequest active health
  checks for load-balancer pools.
- Add `protocol = "redis"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, sends one fixed RESP
  `PING` frame, and requires a simple-string `+PONG` response.
- Read Redis health-check responses until CRLF within the existing 64-byte cap
  so fragmented `+PONG\r\n` responses do not falsely mark healthy Redis
  backends down.
- Add `protocol = "mysql"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, reads one MySQL
  server greeting packet, and requires a protocol-10 handshake without sending
  a login packet or SQL query.
- Add `protocol = "postgres"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, sends PostgreSQL's
  pre-auth SSLRequest, and requires a one-byte `S` or `N` response without
  sending a StartupMessage or SQL query.
- Reject HTTP/gRPC response matchers, request headers, host overrides,
  connection reuse, port overrides, and parallel checking on Redis, MySQL, and
  PostgreSQL probes so database checks remain health probes rather than a
  command/query engine.
- Add `examples/load-balancer-redis-health.toml`,
  `examples/load-balancer-mysql-health.toml`,
  `examples/load-balancer-postgres-health.toml`, and include them in the local
  example config validation gate.
- Add `scripts/smoke_redis_health_check.sh` to prove Redis health checks
  against Valkey in Podman, including observed Redis `PING` commandstats and
  unhealthy transition after the backend stops.
- Add `scripts/smoke_mysql_health_check.sh` to prove MySQL health checks
  against MariaDB in Podman, including observed unauthenticated handshake
  accounting and unhealthy transition after the backend stops.
- Add `scripts/smoke_postgres_health_check.sh` to prove PostgreSQL health
  checks against PostgreSQL in Podman, including observed pre-auth connection
  logging and unhealthy transition after the backend stops.
- Document that repeated idle MySQL/MariaDB pre-auth handshake probes can count
  toward non-loopback server host-cache error budgets (`max_connect_errors`);
  operators should raise that limit, tune probe intervals, or use an
  authenticated `exec` check such as `mysqladmin ping` where needed.
- Log ACME managed-certificate install recovery failures instead of silently
  discarding cleanup or backup-restore errors, making cert/key mismatch recovery
  failures visible to operators.
- Harden two defensive panic surfaces: delay-mode rate limiting now rejects
  impossible non-finite/non-positive local rates before computing a wait
  duration, and load-balancer persistence warning text no longer depends on an
  `unreachable!()` branch.
- Keep Redis TLS, MySQL TLS/authenticated readiness, PostgreSQL TLS/authenticated
  readiness, SMTP/LDAP send-expect, authenticated agent checks, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, and Wasm/iRules/Lua scripting as
  future-version work.

## 1.5.14 - 2026-06-09

### Changed

- Start the local exec health-check line. The stop line is opt-in, bounded
  command probes for health checks that cannot be represented by TCP/TLS,
  HTTP, gRPC, JSON, or later database protocol probes.
- Add `protocol = "exec"` for load-balancer active health checks with an
  absolute `exec_command`, exact `exec_allowed_commands` allow-list,
  bounded literal argv through `exec_args`, and `exec_timeout_secs`.
- Reject `.` and `..` components in exec health-check command paths so the
  allow-list reflects the binary path being reviewed.
- Reject parallel exec checks and unrelated network/HTTP health-check fields on
  exec checks, keeping process execution serial per pool in this release.
- Run exec health checks without a shell, with a cleared inherited
  environment, null stdio, and explicit backend context variables:
  `FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST`, and
  `FLUXHEIM_HEALTH_BACKEND_PORT`.
- Expose the active health-check protocol in load-balancer runtime status for
  operator visibility without exposing exec command paths or arguments.
- Keep exec health-check backend summaries to `via exec`, avoiding command
  path exposure in log-facing health-check strings.
- Add `examples/load-balancer-exec-health.toml` and include it in the local
  example config validation gate.
- Reject HTTP/gRPC response matchers and request-header fields on exec checks
  so local command probes remain a separate monitor type rather than a
  scripting or response-inspection subsystem.
- Keep authenticated agent checks, database protocol probes, arbitrary
  scripting/Wasm, runtime backend mutation, UDP/GSLB, WAF, and VPN/firewall
  appliance behavior as future-version work.

## 1.5.13 - 2026-06-09

### Changed

- Start the Fluxheim-owned cache interface line. The stop line is the cache
  interface boundary only: existing memory, disk, encrypted disk, storage-bin,
  tiered, purge, stale, cache-lock, range/slice, and predictor behavior remains
  unchanged.
- Add `FluxCacheStorage`, `FluxHandleHit`, and `FluxHandleMiss` as
  Fluxheim-owned cache traits so cache implementations no longer implement
  Pingora's session-bound `Storage`, `HandleHit`, and `HandleMiss` traits
  directly.
- Add narrow Pingora cache adapters for the current HTTP proxy path. Pingora
  remains the HTTP session/cache caller for now, but the implementation side now
  has a Fluxheim-owned boundary for future crate extraction.
- Move cache unit coverage that exercises storage behavior onto the Fluxheim
  cache interface while preserving the Pingora adapter for proxy integration.
- Harden slice-cache multipart range responses by replacing deterministic
  length-derived MIME boundaries with per-response random boundaries and by
  stripping CR/LF from cached upstream `Content-Type` values before writing
  MIME part headers.
- Fix cache-only test imports so cache feature CI builds do not depend on
  proxy-gated Flux cache trait names unless the proxy feature is enabled.
- Keep `privacy-cache` as an explicit future design only. Normal cache remains
  incompatible with `privacy-mode`; a future public-asset cache must enforce no
  client-IP keys, no `Cookie`/`Authorization` admission, no per-user variants,
  no private/no-store/Set-Cookie storage, strict query defaults, and bounded
  memory or encrypted short-TTL disk storage.

## 1.5.12 - 2026-06-08

### Changed

- Start the Fluxheim-native background task registry line. The stop line is
  Fluxheim-owned background work only: cache runtime metrics, stale cache
  purging, ACME renewal scheduling, admin self-healing watchdog work,
  load-balancer refresh loops, and future discovery workers.
- Add `src/background.rs` as a Fluxheim-owned background task adapter with a
  Tokio watch-based shutdown handle and one-shot readiness callback, so
  background task implementations no longer depend directly on Pingora's
  generic `GenBackgroundService` helper, raw `ShutdownWatch` handling, or
  `ServiceReadyNotifier`.
- Move cache metrics, stale cache purging, ACME renewal, and the admin
  self-healing watchdog to the new `FluxBackgroundTask` interface while
  preserving their previous startup and shutdown behavior.
- Move load-balancer discovery/health refresh services through the shared
  Fluxheim background adapter while preserving the existing readiness ordering:
  the service marks ready only after its first discovery update has run.
- Add regression coverage for the Fluxheim background adapter shutdown/ready
  behavior and load-balancer background-service readiness ordering.
- Keep Pingora's service trait boundary only as the server registration adapter
  for this release. HTTP proxy request handling, stream listener ownership,
  cache interfaces, UDP/GSLB, WAF, VPN/firewall appliance behavior, and
  Wasm/iRules/Lua scripting remain future-version work.

## 1.5.11 - 2026-06-08

### Changed

- Start the service-discovery and control-plane integration line. The stop line
  is one or more bounded discovery adapters such as Kubernetes, Consul, or xDS
  after local DNS/file discovery and runtime backend mutation are stable, with
  authentication/trust boundaries, churn limits, safe fallback, status,
  audit/metrics, and reload behavior.
- Update Fluxheim and the vendored `pingora-core` metrics dependency from
  Prometheus 0.13 to 0.14, which moves the transitive protobuf dependency from
  vulnerable 2.x to 3.7.2.
- Remove the obsolete `RUSTSEC-2024-0437` protobuf suppression and its release
  metadata review gate now that the Prometheus/protobuf dependency path is
  fixed.
- Keep Pingora pinned at `=0.8.0` so routine dependency refreshes cannot bypass
  Fluxheim's patched vendored Pingora core.
- Harden downstream HTTP/2 defaults against the HTTP/2 Bomb class by installing
  bounded H2 handshake options and defaulting downstream write timeout to 30
  seconds.
- Add bounded pull-based HTTP upstream discovery for load-balancer pools through
  `proxy.upstreams_http_url`, with optional bearer-token authentication, 64 KiB
  response limits, 2-64 unique authority validation, and 1-300 second refresh
  intervals.
- Report each load-balancer pool's discovery mode and refresh status in runtime
  status, including update frequency, success/failure counters, last
  success/failure timestamps, and a bounded last-error field.
- Emit bounded `fluxheim_load_balancer_events_total` events for background
  discovery refresh successes and failures using the existing vhost/route pool
  labels.
- Harden reload classification for load-balancer discovery services: static
  pool membership, route-local pools, file/DNS/HTTP discovery sources, refresh
  intervals, and HTTP discovery bearer-token files now all require the
  process-upgrade path because their refresh loops are registered at startup.
- Harden HTTP upstream discovery by sending `Accept: application/json` and
  `Cache-Control: no-store`, rejecting non-JSON response `Content-Type` values
  when present, and rejecting empty or whitespace-bearing bearer-token files
  before sending authorization headers.
- Add `examples/load-balancer-http-discovery.toml` as a minimal
  control-plane-backed load-balancer example.
- Refresh load-balancer migration boundary documentation so runtime
  add/remove/update behavior, local runtime-state persistence, and HTTP
  discovery limits match the current `1.5.x` implementation.
- Harden HTTP discovery bearer-token handling by zeroizing Fluxheim's formatted
  Authorization header copy after request construction, and check the
  discovered-upstream cap before allocating the rejected entry.

## 1.5.10 - 2026-06-07

### Changed

- Start the runtime backend-set mutation line. The stop line is authenticated
  add, remove, and update operations for configured load-balancer pool members
  through atomic backend-set swaps.
- Keep the explicit boundary for this release: runtime mutations must include
  validation, audit events, status and metrics visibility, drain behavior, and
  clear selector limitations for hash, ring, Maglev, and power-of-two policies.
  This release does not add xDS/Kubernetes/Consul discovery, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
- Add authenticated admin endpoints for static load-balancer pools:
  `POST /_fluxheim/load-balancer/member-add`,
  `POST /_fluxheim/load-balancer/member-remove`, and
  `POST /_fluxheim/load-balancer/member-update`.
- Publish backend-set and readiness changes as one atomic runtime snapshot, and
  reject runtime backend-set mutations for DNS/file-discovery pools and Maglev
  selectors in this release.
- Require in-flight requests to drain before removing a member or retargeting it
  to a new address.
- Harden privacy-mode load-balancer mutation output so response/log member
  fields use configured aliases or `redacted`, and metrics keep alias-only
  member labels.
- Document that runtime-added or retargeted members carry address and
  configured weight only; aliases, tags, backup/locality/priority metadata, and
  per-upstream caps remain static-config fields.
- Clear per-backend runtime overrides and passive-health state when an admin
  explicitly removes or retargets a runtime backend member, so re-adding the
  same address starts from clean runtime state.
- Start retargeted backend addresses with fresh readiness state instead of
  carrying the previous address's health-check state across the key change.
- Move the "at least one backend remains" remove guard under the runtime
  backend-set mutation lock and cap runtime backend sets at 256 members.
- Save new backend-set mutations through the background runtime-state save path
  and warn if a narrow post-check race leaves a request completing against a
  removed or retargeted address.
- Normalize backend-set mutation `member` fields to the resolved backend
  address while keeping configured aliases in the separate `alias` field.

## 1.5.9 - 2026-06-07

### Changed

- Start the restart-persistent load-balancer state line. The stop line is
  versioned, size-limited, atomically written, auditable local persistence for
  selected runtime member overrides and bounded persistence tables after the
  Fluxheim-native backend model stabilized in the `1.5.7` and `1.5.8` lines.
- Keep the explicit boundary for this release: corrupt or incompatible
  persisted state must be ignored and rebuilt, not poison a pool; this release
  does not add cross-node state sync, runtime add/remove-member, dynamic
  discovery control planes, UDP/GSLB, or Wasm/iRules/Lua scripting.
- Add a versioned load-balancer runtime state snapshot API for runtime member
  overrides and local persistence tables. Snapshot restore validates version,
  entry limits, duplicate keys, override states, runtime weights, persistence
  key size, TTLs, and live backend membership before replacing current state.
- Add optional `proxy.load_balance.runtime_state_file` for local
  restart-persistent load-balancer state. The file is loaded best-effort,
  ignored on corrupt/incompatible input, and written atomically after runtime
  member-state, runtime weight, persistence-table, and persistence-clear
  changes.
- Report `persistent: true` from load-balancer admin mutation responses when a
  pool has `proxy.load_balance.runtime_state_file` configured, and keep
  `persistent: false` for in-memory-only pools.

### Security

- Move request-path persistence state-file writes to the blocking worker pool
  with serialized snapshot writes, while keeping admin mutation saves
  synchronous and ordered.
- Harden runtime state files with fd-based permission setting, temp-file
  cleanup on failed writes, and all-or-nothing restore validation for mixed
  policy/persistence state.
- Document and warn when raw header or cookie persistence writes client affinity
  identifiers to `proxy.load_balance.runtime_state_file`; prefer
  `managed-cookie` or encrypted, access-restricted storage for session-bearing
  identifiers.

## 1.5.8 - 2026-06-07

### Added

- Add bounded custom request headers for HTTP active health checks. Operators
  can now check authenticated or tenant-scoped health endpoints with
  `proxy.load_balance.health_check.request_headers`.
- Add standard gRPC active health checks with optional
  `proxy.load_balance.health_check.grpc_service`.
- Add bounded `expected_body_json` scalar matching for JSON HTTP health
  responses.
- Add health-derived degraded backend weights through `X-Health-Weight`, exposed
  as `health_weight_percent` in runtime status and kept separate from
  configured/admin runtime weights.

### Security

- Validate HTTP health-check request headers at config load time: headers are
  HTTP/gRPC-only, capped at 16 entries and 1024 bytes per value, duplicate
  names are rejected case-insensitively, `Host` stays controlled by the
  existing `host` setting, and hop-by-hop/proxy-control headers are rejected.
- Keep configured health-check request header values out of metrics labels and
  runtime status surfaces.
- Keep gRPC health checks strict: Fluxheim sends the standard HTTP/2 request and
  rejects conflicting HTTP status/header/body matcher config for gRPC protocol
  checks.
- Evaluate load-balancer selection and runtime status from one loaded
  backend/health snapshot per operation, removing the remaining conservative
  mismatch window between backend membership and readiness reads.

## 1.5.7 - 2026-06-06

### Changed

- Start the Fluxheim-native load-balancer core line. The stop line remains
  replacing the `pingora-load-balancing` substrate while preserving current
  config, admin API, status shape, metrics, privacy-mode behavior,
  managed-cookie behavior, and selector results as far as possible.
- Add a Fluxheim-owned backend/backend-set model and route static, file, and
  DNS upstream discovery through it.
- Move load-balancer key, passive-health, slow-start, connection-counter,
  latency, and backend-policy helpers onto a Fluxheim-owned backend identity
  abstraction so those subsystems no longer require Pingora's concrete backend
  type.
- Build Maglev lookup tables from Fluxheim backend identities instead of
  adapting static upstreams to Pingora backend values during table
  construction.
- Move file-refreshed and DNS-refreshed backend discovery behind a
  Fluxheim-owned discovery trait.
- Route runtime backend stats, bounded-load weight accounting, and disabled
  upstream parsing through the same backend identity/adapter layer.
- Move slow-start state regression coverage onto Fluxheim backend identities,
  keeping Pingora backend construction only in runtime-selection tests.
- Replace Pingora's FNV weighted-hash selector for source, URI, header, and
  cookie hash modes with Fluxheim-owned weighted-first FNV selection over the
  current backend container.
- Seed Fluxheim-owned FNV and consistent-hash selectors with per-boot routing
  secrets so clients cannot precompute keys that target a chosen backend.
- Replace Pingora's random selector dependency for power-of-two choices with a
  Fluxheim-owned weighted random first pick and unique backend fallback scan.
- Replace Pingora's consistent-hash selector dependency with Fluxheim-owned
  rendezvous candidate ordering for consistent and bounded-load consistent
  hash modes, while preserving dynamic discovery support through the Fluxheim
  runtime backend container. This is a valid consistent-hash algorithm change
  and can remap existing consistent-hash affinity keys once during the 1.5.7
  upgrade.
- Collapse the load-balancer factory, stats, and priority-check helpers onto a
  concrete readiness container now that Fluxheim owns all shipped selection
  algorithms, removing the remaining generic Pingora selector trait plumbing.
- Centralize runtime backend container operations behind Fluxheim-owned
  adapter helpers so readiness, backend enumeration, and health-check metadata
  have one migration boundary.
- Route static upstream pools through the same Fluxheim-owned discovery
  adapter as file-refreshed and DNS-refreshed pools, removing Pingora's static
  discovery wrapper from load-balancer construction.
- Replace Pingora's generic `GenBackgroundService` wrapper for load-balancer
  pools with a Fluxheim-owned `ServiceWithDependents` implementation while
  preserving the current update and health-check loop.
- Introduce a Fluxheim backend-container trait and move selection/stat modules
  onto that trait instead of the concrete Pingora `LoadBalancer<RoundRobin>`
  type.
- Centralize the remaining concrete runtime backend value type behind the
  backend adapter module so orchestration and discovery use Fluxheim's adapter
  alias while the final value-type replacement remains isolated.
- Wrap load-balanced pools in a Fluxheim runtime type before handing them to
  selection, status, and background-service code.
- Return Fluxheim runtime-wrapped load-balancer pools from discovery so
  selection-mode construction no longer repeats Pingora container wrapping.
- Keep the selector-facing backend-container trait implemented only by the
  Fluxheim runtime wrapper.
- Replace Pingora's load-balancer `Backends` container, discovery adapter, and
  background update loop with Fluxheim-owned backend storage, readiness state,
  discovery refresh, health-check scheduling, and shutdown handling. Existing
  Pingora health-check implementations remain adapted for this slice.
- Move load-balancer health checks behind a Fluxheim-owned health-check trait,
  keeping Pingora TCP/HTTP health-check connector code only inside the
  adapter layer while runtime readiness depends on Fluxheim's trait.
- Hide the remaining runtime backend value type behind the load-balancer
  backend adapter so selector and health-check modules import Fluxheim's
  boundary type instead of `pingora::lb::Backend` directly.
- Serialize per-backend load-balancer health state updates so enable/disable
  changes and active health observations cannot overwrite each other under
  concurrent health checks.
- Store refreshed backend sets before refreshed health maps and use checked
  wake-time arithmetic in the load-balancer background loop.
- Clarify stream upstream TLS warnings for mixed hostname and IP upstream
  routes where only IP connections skip hostname verification without
  `upstream_sni`.

## 1.5.6 - 2026-06-06

### Changed

- Start the Fluxheim-native stream-proxy runtime line. The stop line is stream
  connect/copy/shutdown ownership and error-boundary cleanup while preserving
  existing TCP stream route config, route-local PROXY protocol behavior,
  weighted upstream selection, byte/lifetime/idle limits, metrics, and release
  profiles.
- Move stream connect, copy, shutdown, upstream resolution, upstream PROXY
  header writes, byte-limit enforcement, and lifetime/idle timeout helpers onto
  `FluxResult` while keeping `io::Error` adaptation only at legacy runtime
  boundaries.
- Make the stream copy/proxy data path generic over Tokio
  `AsyncRead + AsyncWrite` streams instead of requiring Pingora's stream wrapper
  in the internal helper signatures.
- Replace the stream proxy's Pingora `ServerApp` / listening-service entrypoint
  with a Fluxheim-owned Tokio listener loop registered as a service in the
  existing process supervisor.
- Add Fluxheim-owned bounded downstream PROXY protocol v1/v2 receive parsing
  and trusted-source matching for stream routes.
- Move stream data-path tests off Pingora's stream wrapper and add regression
  coverage for downstream PROXY parser and trusted CIDR matching.
- Replace the stream upstream connection return type with a Fluxheim-owned
  async IO boundary so plain TCP upstreams stay as Tokio `TcpStream` values
  instead of being wrapped in Pingora's L4 stream type. TLS upstreams are
  adapted behind the same boundary.
- Split stream upstream TLS connector wiring into a dedicated `stream_tls`
  adapter module. The stream proxy orchestration file no longer owns Pingora
  `TransportConnector` / `HttpPeer` setup directly.
- Replace the stream upstream TLS connector adapter with Fluxheim-native
  `tokio-rustls` / `tokio-openssl` connectors. Stream upstream TLS now uses
  Fluxheim-owned TCP connect, TLS handshake, trust-root loading, SNI derivation,
  hostname/certificate verification policy, and upstream mTLS client material
  while preserving the existing route configuration.
- Extend the local stream smoke to exercise a route-local rustls upstream TLS
  connection with generated server certificate, explicit SNI, and custom trust
  root validation.
- Clarify stream upstream TLS hostname verification semantics, warn when a
  verified stream TLS route contains any IP-address upstream without explicit
  `upstream_sni`, and document rustls parsed private-key DER zeroing limits.
- Accept HAProxy PROXY protocol v1 `UNKNOWN` lines with optional trailing
  address fields.
- Remove the nested stream TLS handshake timeout so the route connect timeout
  consistently covers DNS lookup, TCP connect, and TLS handshake.

## 1.5.5 - 2026-06-05

### Changed

- Start the Fluxheim-native HTTP/error type boundary line while preserving
  Pingora runtime adapters.
- Add internal `http_types` aliases for standard `http` crate values and
  explicit Pingora request/response adapter names.
- Add a direct `thiserror` dependency plus `FluxError` / `FluxResult` for
  internal error propagation.
- Convert the upstream PROXY-protocol connector to use the typed internal error
  surface and convert back to Pingora errors only at the connector boundary.
- Extend HTTP boundary aliases into load-balancer health/persistence and static
  web response helpers, and route selected compression/cache errors through
  `FluxError` before Pingora adaptation.
- Move load-balancer tests, access-log tests, and the cache-key CLI request
  builder through explicit HTTP adapter aliases.
- Fix proxy HTTP adapter feature gates so the macOS developer CI matrix can
  check static-site, reverse-proxy, full, and development profiles consistently.
- Move header policy request/response signatures and tests through the explicit
  Pingora HTTP adapter aliases.
- Route load-balancer HTTP health-check response/header/body validation through
  the internal `FluxError` surface before adapting back to Pingora health-check
  errors.
- Route load-balancer HTTP health-check response body size-limit failures
  through the same internal error adapter.
- Route load-balancer file/DNS discovery helper failures through the internal
  `FluxError` surface before adapting back to Pingora `ServiceDiscovery`
  errors.
- Split cache range/slice key construction into internal `FluxResult` helpers
  with Pingora adaptation kept at the proxy cache boundary.
- Move static-file body read/open validation onto `FluxResult` while keeping
  Pingora adaptation at static serving and proxy cache call sites.
- Move response compression encoder initialization and chunk emission onto
  `FluxResult`, with Pingora adaptation kept at compression setup and proxy body
  filter boundaries.
- Move route regex matcher construction onto `FluxResult`, with conversion back
  to `io::Error` kept at the legacy vhost route-construction boundary.
- Move auth subrequest fetch failures and response body-limit enforcement onto
  `FluxResult`, with Pingora adaptation kept at the proxy authorization
  boundary.
- Move traffic mirror dispatch failures and response body-limit enforcement
  onto `FluxResult` inside the fire-and-forget mirror task.
- Move trusted-proxy parsing and runtime access-policy construction onto
  `FluxResult`, with conversion back to `io::Error` kept at proxy runtime
  construction boundaries.
- Move Maglev table construction validation onto `FluxResult`, with conversion
  back to `io::Error` kept at the load-balancer discovery factory boundary.
- Move static load-balancer backend construction onto `FluxResult`, with
  conversion back to `io::Error` kept at load-balancer discovery setup.
- Move stream downstream PROXY trusted-source parsing onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service construction.
- Move stream route app construction validation onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service registration.
- Move stream downstream PROXY protocol listener setup onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service registration.
- Move proxy static-file server construction context wrapping onto
  `FluxResult`, with conversion back to `io::Error` kept at proxy runtime
  construction.
- Move HTTP health-check request-header setup onto `FluxResult`, with
  conversion back to `io::Error` kept at the health-check factory boundary.
- Move cache peer-fill and origin-slice request validation plus blocking fetch
  helper failures onto `FluxResult`.
- Move PHP `X-Accel-Expires` response header mutation failures onto
  `FluxResult`, with Pingora adaptation kept at the PHP response boundary.
- Move PHP FastCGI response-header construction failures onto `FluxResult`,
  with conversion back to `io::Error` kept at the PHP response parser boundary.
- Route PHP FastCGI response split/status parsing through `FluxError` while
  preserving `InvalidData` at the parser boundary.
- Replace the PROXY-protocol connector's string-matched write-error
  classification with a typed `FluxError::WriteProxyHeader` variant.
- Use each `FluxError`'s display message as the primary Pingora error
  description at adapter boundaries.
- Tighten `http_types` exports to active boundary items and move proxy/cache
  tests off direct `pingora::http` request/response header imports.

## 1.5.4 - 2026-06-04

### Changed

- Remove incomplete `tls-boringssl` and `tls-s2n` backend support from the
  supported feature/config matrix.
- Keep rustls as the default/recommended TLS backend and OpenSSL as the
  supported alternative for non-FIPS and FIPS/ISO evidence paths.
- Reject removed TLS backend config values and update tests around the reduced
  backend enum.
- Simplify TLS backend validation tooling and release documentation around the
  rustls/OpenSSL-only support matrix.

## 1.5.3 - 2026-06-04

### Changed

- Start the managed affinity-cookie and HA persistence release line. The stop
  line is signed/opaque load-balancer cookie insertion, cookie rotation,
  privacy-mode constraints, cache/compression/header-policy interaction,
  cookie-mirroring design for active-active HA, and focused smoke coverage.
- Number the remaining `1.5.x` roadmap stops through UDP/GSLB exploration so
  the load-balancer line does not spill into the `1.6` Wasm line.
- Add `proxy.load_balance.persistence.mode = "managed-cookie"` for
  signed/opaque, process-local load-balancer affinity cookies. Fresh 2xx/3xx
  backend responses receive `Set-Cookie`, and later requests with a valid
  managed cookie reuse the selected backend while it remains selectable.
- Rotate local managed-cookie signing keys daily and verify against the current
  or previous key generation so normal key rotation does not immediately break
  in-flight affinity cookies.
- Add managed-cookie validation for path/domain/max-age/SameSite attributes
  and keep persistence rejected in `privacy-mode` builds.
- Add `docs/load-balancer-ha.md` to pin the future active-active
  cookie-mirroring and persistence-state replication design boundaries.
- Harden managed-cookie pentest findings: enforce ASCII-only cookie
  domain/path attributes, bind the HMAC tag to the configured cookie name,
  zeroize retired signing keys on rotation/drop, and label HMAC abort logs by
  caller context.

## 1.5.2 - 2026-06-04

### Changed

- Start the runtime load-balancer weight-control release line. The stop line is
  authenticated runtime weight overrides for configured members, audit/status
  visibility, migration documentation, and focused smoke coverage. Managed
  affinity-cookie insertion, cross-node state synchronization, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, and iRules/Lua/Wasm scripting remain later
  roadmap tracks.
- Add authenticated runtime load-balancer member weight mutation through
  `POST /_fluxheim/load-balancer/member-weight` for configured members in
  `round-robin`, `least-connections`, `least-sessions`, and `least-time` pools.
- Report configured weight, effective weight, runtime weight override, and
  runtime weight transition timestamp in load-balancer backend status.
- Count successful, invalid, and not-found runtime member-weight operations as
  bounded load-balancer events.
- Omit backend addresses from member-state and member-weight mutation responses
  and structured mutation logs in `privacy-mode`, and label successful mutation
  metrics only by configured upstream alias.
- Bound retained runtime load-balancer override state and preserve runtime
  weight overrides across dynamic backend churn while the same backend is
  explicitly disabled or forced down.
- Emit successful runtime member-state and member-weight mutations to the
  `fluxheim::audit` log target in addition to operational load-balancer logs.
- Restore backend metric attribution for unaliased member mutations in
  non-privacy builds, while keeping privacy-mode alias-only behavior.
- Reject configured load-balancer upstream pools whose backend identity keys
  collide.

## 1.5.1 - 2026-06-03

### Changed

- Start the enterprise load-balancer stabilization release after the `1.5.0`
  control-plane launch. The stop line is load-balancer correctness,
  documentation, migration polish, and release-profile fixes; new large feature
  surfaces stay in later `1.5.x` milestones.
- Keep load-balancer persistence-clear metrics distinct from member-state
  mutation metrics for clearer admin audit dashboards.
- Prune stale transient load-balancer drain overrides when dynamic discovery
  removes backends, while preserving explicit runtime `disabled` and
  `forced_down` operator decisions until an authenticated admin clears them.
- Prune persistence-table entries that point at removed dynamic-discovery
  backends from the periodic backend-state cleanup path, while keeping normal
  selection and status persistence counts read-only.
- Clarify the current `1.5.x` load-balancer boundaries in README, config,
  migration, and container documentation so local persistence/runtime overrides
  are not mistaken for managed affinity cookies, restart-persistent HA state,
  runtime weight mutation, runtime member add/remove, or cross-node
  synchronization.
- Extend the local load-balancer smoke to exercise route-scoped header
  persistence, authenticated persistence-table clear, and the
  `persistence_clear` metrics event.
- Add a focused `packaging/container/load-balancer.toml` template and wire the
  load-balancer image/profile validation to that config instead of the generic
  proxy container template.

## 1.5.0 - 2026-06-01

### Changed

- Start the enterprise load-balancer/control-plane development release.
- Promote the `profile-load-balancer-edge` image line from prepared/manual
  testing to the planned `1.5` release artifact set.
- Add the focused Linux `load-balancer` runtime archive to the release asset
  builder and release documentation.
- Expand the `1.5` roadmap around F5/HAProxy/Envoy-class load-balancer
  operations: runtime pool/member mutation, persistence, priority groups,
  slow-start, adaptive health, circuit breaking, locality/failure-domain
  policy, richer selection algorithms, and migration fixtures.
- Make `least-connections` weight-aware so heterogeneous pools respect
  configured `upstream_weights` while still using in-flight request permits.
- Accept `weighted-least-connections` and `ratio-least-connections` as
  migration-friendly aliases for the weighted least-connections selector.
- Add `least-sessions` load-balancer selection backed by the bounded
  persistence table for sticky-session-aware distribution.
- Add `least-time` selection using weighted EWMA upstream latency plus
  in-flight request counts for latency-sensitive application pools.
- Make the `power-of-two` / `weighted-random-two-choice` selector compare
  weighted in-flight pressure after Pingora's weighted random sampling.
- Add bounded-load consistent-hash selections
  (`bounded-load-consistent-source-hash`,
  `bounded-load-consistent-uri-hash`,
  `bounded-load-consistent-header-hash`, and
  `bounded-load-consistent-cookie-hash`) so hash-persistent pools can skip an
  overloaded hash target before falling back to normal consistent selection.
- Add static `upstream_priority_groups` for F5-style preferred/fallback
  selection across configured static upstream pools.
- Add `upstream_priority_group_min_active` so lower priority groups activate
  when preferred groups fall below a selectable-member threshold.
- Add static `upstream_localities` and `preferred_upstream_localities` for
  locality/failure-domain preferred selection with automatic fallback when no
  preferred backend is selectable.
- Add static per-upstream `upstream_tags` metadata for load-balancer runtime
  status grouping and migration notes without affecting selection.
- Add static per-upstream `upstream_max_in_flight` caps so saturated members
  are skipped consistently across load-balancing selectors.
- Add opt-in bounded load-balancer queue policy so saturated pools can wait
  briefly for capacity before returning the configured all-down status.
- Count load-balancer queue wait, full, and timeout outcomes in
  `fluxheim_load_balancer_events_total` when metrics are compiled.
- Add `fluxheim_load_balancer_queue_wait_seconds` to observe bounded
  load-balancer queue wait and timeout duration by configured vhost/route.
- Add `GET /_fluxheim/load-balancer/status` so operators can retrieve
  load-balancer runtime pool state without parsing the full admin status body;
  the same read-only view is available on the local ops socket.
- Add `fluxheim_load_balancer_pools` to report configured load-balancer pool
  counts by scope and bounded selection algorithm.
- Add low-cardinality OTLP trace attributes for load-balanced requests:
  configured upstream alias and retry count only, with raw upstream URLs
  rejected from trace payloads.
- Add static `disabled_upstreams` so configured members can be kept in the pool
  definition while being administratively removed from selection and reported
  distinctly from drained members; disabled members also show as not ready in
  load-balancer runtime status.
- Extend HTTP active health checks with configurable request methods and exact
  expected response header validation.
- Add HTTP active health-check `expected_status_ranges` for inclusive status
  range monitors such as `200..=399`.
- Add HTTP active health-check `expected_body_contains` substring validation
  with a bounded 64 KiB probe-body read ceiling.
- Add active health-check `connect_timeout_secs` and `read_timeout_secs`
  overrides so probes can be tuned independently from normal upstream traffic.
- Add `proxy.load_balance.all_down_status` for explicit 5xx responses when a
  configured load-balanced pool has no selectable backend.
- Add read-only load-balancer runtime status to `GET /_fluxheim/status`,
  including pool/backend readiness, configured policy metadata, in-flight
  counts, passive ejection, slow-start, and least-time latency state.
- Expand load-balancer runtime status with pool-level selection, iteration,
  all-down, health-check frequency/parallel mode, passive-health, and
  slow-start policy metadata.
- Include load-balancer retry policy metadata in runtime status, including
  safe methods, status/status-range retry rules, and retry budget settings.
- Include ready and policy-available backend counts in load-balancer runtime
  status so pool capacity is visible without client-side backend inference.
- Include primary/backup availability counts plus drain, disabled, passive
  ejection, and saturation summary counts in load-balancer runtime status.
- Include explicit runtime member override state and runtime override summary
  counts in load-balancer runtime status.
- Include per-backend runtime member-state transition timestamps in
  load-balancer runtime status while a manual override remains active.
- Add authenticated in-memory load-balancer member-state operations through
  `POST /_fluxheim/load-balancer/member-state` for existing configured
  members: normal, drain, disable, forced-down, and manual-resume by configured
  address or alias.
- Add runtime `manual_resume` for load-balancer members to clear passive-health
  failure/ejection state and restart slow-start ramp without a config reload.
- Return explicit `scope` and `persistent = false` metadata from load-balancer
  runtime member-state operations.
- Emit load-balancer audit logs for successful and rejected runtime
  member-state operations.
- Count successful, invalid, and not-found load-balancer member-state
  operations in `fluxheim_load_balancer_events_total` when metrics are
  compiled.
- Add active TCP health-check transition coverage proving configured failure
  and recovery thresholds flip backend readiness.
- Add bounded local source-IP load-balancer persistence with TTL, table-size
  limits, admin status entry counts, and automatic fallback when the stored
  backend is no longer selectable.
- Add bounded local request-header load-balancer persistence with explicit
  header-name validation and the same TTL/table limits as source-IP
  persistence.
- Add bounded local request-cookie load-balancer persistence for explicitly
  named application or upstream cookies.
- Add authenticated runtime clearing for vhost or route load-balancer
  persistence tables through
  `POST /_fluxheim/load-balancer/persistence/clear`.
- Report per-backend persistence-entry counts in load-balancer runtime status
  so operators can spot sticky-session skew.
- Count load-balancer persistence hits, misses, and fallbacks in
  `fluxheim_load_balancer_events_total` when metrics are compiled.
- Add a validated `examples/load-balancer-enterprise.toml` migration fixture
  for HAProxy/F5-style weighted pools, priority groups, health policy,
  persistence, retry budgets, and all-down behavior.
- Add `docs/load-balancer-migration.md` with nginx, HAProxy, and F5 LTM pool
  mappings plus explicit boundaries for UDP, GSLB, WAF, VPN, and scripting
  roadmap items.
- Document the `1.5.0` load-balancer boundaries clearly: no managed affinity
  cookie insertion, no restart-persistent LB runtime state, no runtime weight
  changes or add/remove-member operations, and no cross-instance state sync yet.
- Extend the local load-balancer smoke to use temporary process paths and verify
  configured all-down status after all checked origins are unavailable.
- Extend the local load-balancer smoke to exercise authenticated runtime
  member disable/normal operations through the 1.5 admin control plane.
- Expose passive-health ejection as per-backend `circuit_state` plus a
  pool-level `circuit_open_backend_count` in load-balancer runtime status.
- Make slow-start admission vary per selection attempt instead of using only
  the backend identity hash, so warming members receive a bounded traffic
  sample rather than a fixed backend-key class during the ramp window.
- Prune stale passive-health backend state during periodic load-balancer state
  cleanup while preserving active ejections until their deadline.
- Extract HTTP/TCP load-balancer health-check construction, validation, and
  response-body handling into `src/load_balancer/health.rs` so monitor logic is
  reviewable without navigating the full load-balancer orchestration module.
- Split load-balancer backend state, persistence, selection, backend policy,
  and discovery/factory code into focused `src/load_balancer/*` modules while
  keeping `crate::load_balancer::*` stable for callers.
- Align read-only slow-start status with the sampled admission mechanism instead
  of the old backend-key-only gate.
- Include passive-health ejection remaining time in load-balancer runtime
  status so temporary ejections are explainable through the admin plane.
- Include per-backend passive-health consecutive failure counts in
  load-balancer runtime status.
- Add `proxy.load_balance.passive_health.failure_status_ranges` for bounded
  passive outlier detection on inclusive 5xx status ranges.
- Add `proxy.load_balance.retry.statuses` for bounded safe-method redispatch
  on explicitly configured upstream HTTP 5xx responses before response
  streaming starts.
- Add `proxy.load_balance.retry.status_ranges` for bounded safe-method
  redispatch on inclusive upstream HTTP 5xx status ranges.
- Accept `power-of-two-choices`, `two-choice`, `weighted-two-choice`, and
  `weighted-random-two-choice` as aliases for `power-of-two` selection.
- Add bounded static-pool Maglev hashing selections (`maglev`,
  `maglev-uri-hash`, `maglev-header-hash`, and `maglev-cookie-hash`) with a
  fixed 65,537-slot lookup table and policy-aware fallback probing. Dynamic
  file/DNS-refreshed pools reject Maglev until table rebuild semantics are
  promoted in a later control-plane slice.
- Harden load-balancer state handling after SAST review by capping
  client-derived persistence keys, secret-salting Maglev route lookup,
  consolidating runtime member-state overrides behind one mutex, pruning stale
  per-backend runtime maps periodically, using stable backend identity hashes,
  and applying the 64 KiB health-check body cap to drain-only probes.

## 1.4.7 - 2026-05-31

### Changed

- Start the TCP stream hardening development release.
- Add true per-read stream idle timeout and make `max_connection_secs` an
  optional lifetime cap instead of the default stream timeout.
- Add stream upstream TLS controls and upstream mTLS material loading for
  rustls, OpenSSL, and BoringSSL builds. s2n remains fail-closed for custom
  stream upstream trust/client files.
- Add stream-local transport-neutral upstream policy: weighted selection,
  aliases, drained upstream exclusion, and backup upstream connect fallback.
- Add a localhost stream smoke script covering raw TCP forwarding,
  drained/backup fallback, upstream PROXY protocol v1 send, and downstream
  PROXY protocol v1 receive from trusted sources.
- Add stream unit coverage for wall-clock lifetime caps and upstream PROXY
  protocol v2 framing.
- Bound stream upstream TLS DNS resolution under `connect_timeout_secs`, add
  stream write/shutdown deadlines, avoid derived IP-literal SNI, and zeroize
  temporary upstream mTLS private-key buffers after parsing.

## 1.4.6 - 2026-05-30

### Changed

- Release the TCP stream proxy foundation.
- Add route-local downstream PROXY protocol receive for TCP stream routes with
  mandatory route-local `trusted_proxies`; HTTP `server.proxy_protocol` no
  longer applies to stream listeners.
- Rename stream `idle_timeout_secs` to `max_connection_secs` to reflect the
  wall-clock connection lifetime cap, and add optional
  `max_connection_bytes` per-direction byte caps.
- Track the transitive `RUSTSEC-2024-0388` `derivative` advisory with an
  explicit review deadline while Pingora still pulls the unmaintained crate.

## 1.4.5 - 2026-05-29

### Changed

- Start the bounded GeoIP/Geo-Context development release.
- Add the optional `geoip` feature with provider-agnostic local MMDB loading for
  MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets.
- Add vhost and route access-policy Geo-Context rules:
  `allow_countries`, `deny_countries`, `allow_asns`, and `deny_asns`.
- Add optional `geo_country` and `geo_asn` fields to structured access logs
  when `geoip` is compiled and a lookup succeeds.
- Raise the pinned Rust toolchain and minimum supported Rust version from
  1.95 to 1.96.
- Track a future `fluxheim-sdk` Rust companion crate for application-side
  health/drain, trusted request context, tracing, cache-control, and purge
  helpers.
- Align GeoIP deny-only access policy with the documented contract: unresolved
  Geo-Context now defaults to allow unless an allow list is configured.

## 1.4.4 - 2026-05-28

### Changed

- Start the Apple Silicon macOS Level 1 developer-support release. Scope is
  local build/check/smoke coverage and Mac-safe development runtime paths, not
  production macOS packaging, FIPS evidence, notarized binaries, Homebrew
  distribution, or launchd service support.

## 1.4.3 - 2026-05-27

### Changed

- Harden path forwarding safety against triple-encoded traversal segments,
  zeroize copied auth-request forwarded header values, and rename the private
  admin empty-path validator to avoid confusion with full path-safety checks.
- Harden admin auth throttling so a full per-source table evicts the stalest
  tracked source instead of immediately promoting a new source to global
  lockout, and route cache purge path validation through the shared path-safety
  decoder.
- Start the config module split and maintenance architecture release. This
  release is intentionally scoped to behavior-preserving extraction of the
  large `config.rs` surface into focused loading, validation, and domain slices
  before adding GeoIP or other advanced policy features.
- Move the remaining `1.4.x` plan so `1.4.3` is the config split, `1.4.4` is
  Apple Silicon macOS Level 1 developer support, `1.4.5` is GeoIP/Geo-Context,
  and `1.4.6` is TCP stream proxying.
- Extract path-safe TOML source discovery and bounded config-file loading into
  `config_loader`, preserving the existing `crate::config::*` public API.
- Move config load errors and the shared `ByteSize` parser/serializer into
  focused config support modules while keeping their existing
  `crate::config::*` re-export paths stable.
- Move file-refreshed proxy upstream pool loading into `config_loader`, keeping
  the existing `crate::config::read_proxy_upstreams_file` internal path stable.
- Extract host normalization and upstream/trusted-proxy authority validation
  helpers into `config_net`, preserving the public `crate::config::normalize_*`
  API used by runtime modules.
- Extract HTTP/OTLP endpoint URL validation and local FIPS endpoint exception
  helpers into `config_http`, with shared HTTP authority parsing in
  `config_net`.
- Extract generic config path inspection, symlink checks, parent-permission
  checks, and process path validation into `config_path`.
- Extract header mutation, dynamic header-template, TLS identity append, and
  response/cookie rewrite validation helpers into `config_header`.
- Extract access allow/deny and client-certificate SHA-256 list validation into
  `config_access`.
- Extract route path, regex matcher, method, rewrite-template, and redirect
  target validation helpers into `config_route`.
- Extract PHP custom parameter validation and protected FastCGI parameter guards
  into `config_php`, preserving `crate::config::protected_php_param_name` for
  PHP-FPM runtime code.
- Move PHP-FPM retry method/status validation and PHP intercepted-error status
  validation into `config_php`.
- Move PHP index, allowed-extension, denied-prefix, stderr failure-pattern, and
  hidden-response-header validation into `config_php`.
- Move managed PHP-FPM process-manager, identity, timeout, socket-directory,
  and generated pool-file safety validation into `config_php`.
- Move OTLP CA certificate path and service-name validation into
  `config_http`.
- Move `CompressionConfig`, compression defaults, and compression policy
  validation into `config_compression` while re-exporting
  `crate::config::CompressionConfig`.
- Move load-balancer selection, health-check, passive-health, slow-start, and
  retry policy config into `config_load_balance` while preserving the existing
  `crate::config::*` type paths.
- Move logging and access-log config into `config_logging`, including file-log
  path validation and request-id header validation.
- Move metrics and tracing config into `config_observability`, keeping OTLP
  endpoint validation routed through the shared HTTP config helpers.
- Move static web serving config into `config_web`, including index-file,
  cache-control, expires, root path, and directory-listing validation.
- Move admin API config into `config_admin`, including auth source, ops socket,
  client-certificate header, health, throttle, and self-healing validation.
- Move server listener, downstream PROXY protocol, HTTPS redirect, host-routing,
  server limits, and process runtime path config into `config_server`.
- Start the cache config split by moving cache purger config and validation
  into `config_cache`.
- Move cache policy, range/slice, storage tier, peer fill, and disk encryption
  config into `config_cache`, keeping existing `crate::config::*` type paths
  stable.
- Move the large config unit-test module into `config_tests.rs` so
  `config.rs` contains only production orchestration and shared error types.
- Move ACME issuer, renewal, automation, challenge, and external-account-binding
  config into `config_acme`.
- Move listener TLS policy, TLS compliance mode, client-auth config, TLS cipher
  and curve policy, and static certificate path validation into `config_tls`.
- Move header policy config structs, overlay merge logic, HSTS defaults, and
  response rewrite policy types into `config_header`.
- Move access policy, rate limit, and concurrency limit config into
  `config_access`.
- Move vhost TLS and vhost ACME challenge config into the existing TLS/ACME
  config modules.
- Move PHP and managed PHP-FPM config types, defaults, and path validation into
  `config_php`.
- Move route, gRPC route, route redirect, and vhost redirect config into
  `config_route`.
- Move proxy upstream, auth-request, traffic-mirror, and proxy error-page
  config into `config_proxy`.

## 1.4.2 - 2026-05-27

### Changed

- Start the proxy module split and maintenance architecture release. This
  release is intentionally scoped to behavior-preserving extraction of the large
  proxy runtime into focused domains before adding more large proxy features.
- Extract structured access-log formatting, request-id generation, status-class
  labeling, and response-body byte accounting from `proxy.rs` into a focused
  `access_log` module.
- Extract response compression negotiation, encoder lifecycle, output bounding,
  and `Vary: Accept-Encoding` mutation from `proxy.rs` into a focused
  `compression` module while preserving the existing vhost and route policy
  behavior.
- Extract `auth_request` input construction and outbound decision fetching from
  `proxy.rs` into a focused `auth_request` module.
- Extract traffic-mirror request construction, sampling, in-flight limits, and
  outbound shadow delivery from `proxy.rs` into a focused `traffic_mirror`
  module.
- Extract trusted-proxy parsing, access policy checks, rate limiting, and
  request concurrency admission into a focused `edge_policy` module.
- Extract route matcher construction, method checks, regex capture extraction,
  and path rewrite rendering into a focused `route_policy` module.
- Extract managed PHP-FPM process lifecycle, watchdog/cleanup handling,
  generated pool configuration, and PHP request-body spool file handling into a
  focused `php_fpm` module.
- Extract PHP-FPM endpoint construction, keepalive pool transport,
  timeout/retry classification, FastCGI response buffering, and CGI response
  header parsing into `php_fpm`. The remaining PHP code in `proxy.rs` is the
  Pingora session integration layer that resolves requests, builds CGI params,
  applies response policy, and coordinates static offload.
- Start the proxy-cache split with a focused `proxy_cache` module for
  request-side cache policy helpers: request identity conversion,
  bypass/revalidation checks, and header/cookie/query matching.
- Move response-side cache admission and `Vary` policy helpers into
  `proxy_cache`, including content-type admission, no-store checks, configured
  response-header rejection, range-response admission, and variance hashing.
- Move range-cache request selection, bounded `Range` parsing, range cache-key
  derivation, and partial-response admission checks into `proxy_cache`; the
  remaining cache code in `proxy.rs` is storage, slice assembly, and Pingora
  request/session orchestration.
- Move fixed-slice range parsing, slice-bound planning, slice policy admission,
  and slice cache-key derivation into `proxy_cache`. The remaining slice code
  in `proxy.rs` is object lookup/fill/composition tied to Pingora storage and
  response streaming.
- Move stateless cache freshness, status-header, stale-serving, and
  response-header mutation policy into `proxy_cache`. Stateful min-use/pass
  counters remain in `proxy.rs` until their optional-cache dependencies are
  split behind a cleaner cache-runtime boundary.
- Move cache admin/API request and result DTOs into `cache_api`, while
  preserving the existing `crate::proxy::*` public re-export paths for current
  callers.
- Extract outbound PROXY protocol v1/v2 frame construction and the L4 connector
  that writes those frames before upstream traffic into a focused
  `proxy_protocol` module.
- Extract traversal-safe forwarded path validation into `path_safety`, giving
  peer-fill, route rewrites, and future forwarding code one shared security
  helper outside the proxy orchestration layer.
- Extract upstream TLS trust-root and client-certificate material loading into
  `upstream_tls`, keeping O_NOFOLLOW, regular-file, and size-limit checks out
  of the proxy orchestration layer.
- Document the source-boundary rule for future work: new feature domains should
  start in focused modules once they have their own validation, tests, metrics,
  dependencies, or security boundary. The same audit tracks future split
  candidates in `config.rs`, `cache.rs`, `admin.rs`, and `cli.rs`.

### Fixed

- Harden traffic-mirror sampling with a process-local random salt so request
  paths cannot be precomputed into predictable mirror include/exclude buckets.
- Keep ACME certificate installation portable across Linux and macOS by using
  platform-specific `rustix` file mode conversion without tripping Linux
  Clippy's useless-conversion lint.

## 1.4.1 - 2026-05-26

### Added

- Added opt-in regex route matching through `server.regex_enabled = true` and
  route-level `path_regex`. Regex routes are validated with Rust's bounded
  regex engine at config load time and are selected after exact and longest
  prefix routes, before fallback routes.
- Added bounded regex route capture variables for request-header templates:
  `{route.regex.0}`, numbered captures through `{route.regex.15}`, and named
  captures such as `{route.regex.version}`.
- Added bounded regex-route `rewrite_template` support for path-only upstream
  URI rewriting with capture variables. Rendered paths keep the original query
  string and pass the same traversal/encoded-separator safety checks as
  `strip_prefix`.
- Added route-level `methods = ["GET", "HEAD"]` matching. Method lists are
  optional, bounded, uppercase HTTP tokens and let one path route to different
  actions or upstreams by request method.
- Added explicit HTTP/1.1 upgrade proxying with `proxy.websocket = true`.
  Upgrade requests preserve the required `Connection: upgrade` and `Upgrade`
  token upstream, require `upstream_http_version = "http1"`, and bypass proxy
  cache policy for long-lived websocket-style connections.
- Added `[proxy.auth_request]` external authorization for proxy actions. The
  first slice sends bounded `GET` subrequests, forwards only configured request
  headers, copies allow-listed auth response headers into the upstream request
  on 2xx, and constrains FIPS/ISO-required deployments to numeric local
  `http://` auth sidecars.
- Added opt-in `[proxy.mirror]` traffic shadowing behind the `traffic-mirror`
  feature. The first slice mirrors safe bodyless methods only, uses
  deterministic per-mille sampling, copies only allow-listed headers, drains a
  bounded mirror response, caps per-vhost/route in-flight mirror worker tasks,
  records low-cardinality mirror outcomes through edge policy metrics when
  metrics are enabled, and never changes the primary response.
- Added `[admin.ops_socket]`, a Unix-only read-only local operational socket
  for status, cache status, snapshots, and health checks. The socket is
  owner/group permission constrained and does not route mutating admin
  operations.
- Added richer structured access-log fields for load-balanced proxy requests:
  `upstream_alias` and `upstream_retries`. The alias follows
  `logging.access.include_upstream` so operators can still suppress backend
  identity from logs.
- Added file-refreshed upstream pools for load-balancer builds with
  `upstreams_file` and bounded refresh intervals. The first format is one
  authority per line with safe file handling and no weights/aliases yet.
- Added DNS-refreshed upstream pools for load-balancer builds with
  `upstream_dns_refresh_secs`, intended for container/service-name targets.
  The first slice keeps dynamic DNS separate from weights, aliases, backups,
  and drains.
- Added low-cardinality `auth_request` allow/deny/error outcomes to
  `fluxheim_edge_policy_events_total`.

### Fixed

- Moved file-refreshed and DNS-refreshed upstream discovery off blocking Tokio
  executor paths.

### Deferred

- Keep broader typed operator hook points, advanced policy composition,
  stick-table tracking, runtime backend mutation, GeoIP policy, response body
  substitution, TCP stream proxying, and arbitrary Wasm/Lua execution outside
  `1.4.1`.
- Reserve `1.4.2` for proxy runtime module extraction before the next large
  proxy feature. GeoIP/Geo-Context and TCP stream proxying move to later
  `1.4.x` stops.
- Clarify the later GeoIP/Geo-Context plan: the target should use a
  provider-agnostic local MMDB layer for MaxMind GeoIP2/GeoLite2 and CIRCL Geo
  Open datasets, normalized typed country/ASN context, and ordered local
  fallback without built-in remote lookup or database downloading.
- Add an Apple Silicon macOS developer-support stop for local
  `aarch64-apple-darwin` build/check/smoke coverage, Mac-safe dev runtime
  paths, and explicit deferral of production macOS packaging/security support
  while Pingora macOS support remains experimental.

## 1.4.0 - 2026-05-25

### Added

- Added the first production proxy parity edge-policy primitive:
  trusted-proxy-aware IP ACLs through `[vhosts.access]` and
  `[vhosts.routes.access]`, with exact IP/CIDR `allow` and `deny` lists.
- Added opt-in local token-bucket request limiting through
  `[vhosts.rate_limit]` and `[vhosts.routes.rate_limit]`, keyed by the
  trusted-proxy-aware client IP.
- Added opt-in local in-flight request limits through `[vhosts.concurrency]`
  and `[vhosts.routes.concurrency]`.
- Added opt-in gzip response compression behind the `compression-gzip` feature,
  with conservative MIME, size, cookie/auth, range, `no-transform`, and
  `Vary: Accept-Encoding` handling.
- Added `proxy.upstream_weights` for weighted round-robin upstream selection in
  `load-balancer` builds.
- Added `proxy.load_balance.selection` for least-connections, power-of-two,
  weighted source, URI, header, cookie, and consistent-hash upstream selection in
  `load-balancer` builds.
- Added opt-in `proxy.load_balance.passive_health` outlier detection for
  load-balanced upstreams, with bounded consecutive-failure ejection for proxy
  failures and selected 5xx response statuses.
- Added opt-in passive latency ejection with
  `proxy.load_balance.passive_health.max_latency_ms`.
- Added opt-in `proxy.load_balance.retry` redispatch for load-balanced
  connection failures before request forwarding, bounded by retry count and
  safe HTTP method policy.
- Added optional load-balanced retry budgets with `budget_per_window` and
  `budget_window_secs` so redispatch cannot amplify an upstream outage without
  an operator-set cap.
- Extended load-balanced upstream selection, passive health, and retry policy
  to route-level proxy pools, not only vhost-level proxy pools.
- Added load-balanced upstream `backup_upstreams` and `drain_upstreams`
  policies so operators can keep standby origins out of normal rotation and
  stop new traffic to draining origins without removing them from the pool.
- Added opt-in `proxy.load_balance.slow_start` so newly seen or passively
  recovered load-balanced backends can warm up gradually instead of immediately
  receiving their full selection share.
- Added active HTTP load-balancer health checks with path, host,
  expected-status, connection reuse, and port override controls alongside the
  existing TCP/TLS health check mode.
- Added `fluxheim_load_balancer_events_total` to count load-balanced
  selections, unavailable pools, retries, and success/failure outcomes with
  bounded vhost/route labels.
- Extended load-balancer metrics to count passive-health ejection transitions
  without labeling raw upstream addresses.
- Added `proxy.upstream_aliases` as optional safe low-cardinality backend labels
  for load-balancer metrics without exposing raw upstream addresses.
- Added opt-in `compression-zstd` and `compression-brotli` codec features
  alongside gzip, with bounded levels and negotiation preference `br`, `zstd`,
  then `gzip`.
- Added vhost-level compression overrides so operators can keep compression
  disabled globally and enable it only for selected sites.
- Added route-level compression overrides so path prefixes such as
  `/wp-content/uploads/` can opt into or out of compression independently from
  the rest of the vhost.
- Added response `Location` and `Refresh` prefix rewrite rules under
  `headers.response.rewrite` for common `proxy_redirect` /
  `ProxyPassReverse` migrations.
- Added response `Set-Cookie` `Domain=` and `Path=` rewrite rules under
  `headers.response.rewrite.cookie_domain` and
  `headers.response.rewrite.cookie_path`.
- Added route `rewrite_prefix` so a stripped public path prefix can be mapped
  onto a safe upstream path prefix before proxy forwarding.
- Added trusted-proxy-aware client IP, effective cache phase, resolved route
  name, and selected upstream address to structured access log events, with
  `logging.access.include_client_ip`, `logging.access.include_cache_phase`,
  `logging.access.include_route`, and `logging.access.include_upstream`
  controls for redaction-sensitive deployments.
- OTLP trace spans now report the resolved route name instead of a synthetic
  route index label.
- Access logs and OTLP trace spans now report the Fluxheim-applied response
  compression encoding when gzip, zstd, or brotli compression is used.
- Added `fluxheim_response_compressions_total` to count Fluxheim-applied
  response compression by vhost, route scope, and bounded encoding.
- Added `fluxheim_edge_policy_events_total` to count ACL denials, rate-limit
  delays/rejections, and concurrency-limit rejections with bounded labels.
- Added `compression.max_output_bytes` so encoded responses stay bounded even
  when a compressible input is within `max_input_bytes`.
- Added rate-limit delay mode with a bounded `max_delay_ms` budget so vhost and
  route token buckets can smooth short bursts without creating an unbounded
  request queue.
- Added `queue_timeout_ms` to vhost and route concurrency limits so saturated
  policies can wait briefly for an in-flight permit before returning their
  configured rejection status.
- Added listener-level downstream client certificate authentication through
  `[tls.client_auth]` with `off`, `optional`, and `required` modes plus a safe
  CA bundle path. The first implementation wires rustls and OpenSSL/BoringSSL
  listeners and fails closed for s2n until its CA loader can be exposed without
  panic-prone helpers.
- Added downstream TLS/client-certificate request header template variables,
  including `{tls.version}`, `{tls.cipher}`, `{tls.client_cert_sha256}`,
  `{tls.client_cert_serial}`, and `{tls.client_cert_organization}`, so verified
  mTLS identity can be forwarded explicitly to trusted origins.
- Added the same downstream TLS/client-certificate identity values to structured
  access logs as `tls_version`, `tls_cipher`, `tls_client_cert_sha256`,
  `tls_client_cert_serial`, and `tls_client_cert_organization`.
- Added vhost and route access-policy controls for verified downstream client
  certificate fingerprints through `require_client_cert`,
  `allow_client_cert_sha256`, and `deny_client_cert_sha256`.
- Added admin control-plane client-certificate fingerprint hardening for trusted
  TLS/mTLS terminators through `[admin.client_certificate]`.
- Added upstream TLS verification controls for proxy origins:
  `upstream_verify_cert`, `upstream_verify_hostname`, and
  `upstream_alternative_cn`, while keeping certificate and hostname validation
  enabled by default.
- Added proxy upstream custom trust roots and upstream mTLS client certificate
  loading through `upstream_ca_path`, `upstream_client_cert_path`, and
  `upstream_client_key_path`. Rustls, OpenSSL, and BoringSSL are wired; s2n
  fails closed until its upstream PEM loaders can be exposed without
  panic-prone helpers.
- Added opt-in upstream HAProxy PROXY protocol v1 send support through
  `proxy.upstream_proxy_protocol = "v1"`, using the trusted-proxy-aware client
  identity when available and falling back to `PROXY UNKNOWN` when a safe
  TCP4/TCP6 line cannot be formed.
- Added binary PROXY protocol v2 upstream send support through
  `proxy.upstream_proxy_protocol = "v2"`, emitting TCP4/TCP6 frames when Fluxheim
  has same-family source and destination addresses and an empty PROXY/UNSPEC
  frame otherwise.
- Added opt-in listener-side HAProxy PROXY protocol v1 receive support through
  `server.proxy_protocol = "v1"`. It requires `server.trusted_proxies`, rejects
  untrusted direct peers before parsing the header, and restores the PROXY
  source address before downstream TLS and HTTP handling.
- Added listener-side binary PROXY protocol v2 receive support through
  `server.proxy_protocol = "v2"`, with the same trusted-direct-peer gate as v1
  plus bounded TCP4/TCP6 parsing and LOCAL/UNSPEC handling.
- Added upstream HTTP version selection through `proxy.upstream_http_version`
  with `http1`, `http2`, and `http1-and-http2`, plus bounded HTTP/2 stream and
  ping controls for gRPC-capable origins.
- Added route-scoped `[vhosts.routes.grpc]` pass-through policy that requires
  HTTP/2-capable proxy origins and rejects obvious non-gRPC requests before
  forwarding.
- Added upstream connection establishment and keepalive-pool tuning through
  `proxy.upstream_total_connection_timeout_secs` and
  `proxy.upstream_idle_timeout_secs`.
- Added upstream TCP socket tuning for proxy origins, including TCP keepalive,
  Linux user timeout, receive-buffer size, DSCP, and TCP Fast Open controls.
- Added bounded `max_queue` waiters for vhost and route concurrency limits,
  replacing the previous short sleep/retry loop with semaphore-backed wakeups.
- Replaced Fluxheim's direct `rustls-pemfile` usage with
  `rustls-pki-types::pem::PemObject`; the remaining `RUSTSEC-2025-0134`
  warning is transitive through Pingora's rustls stack and documented in
  `SECURITY.md`.

### Security

- Hardened route path rewriting against double-encoded traversal and decoded
  control-byte segments before forwarding to upstreams.
- Rejected request-header append policies that use TLS identity templates so
  spoofed inbound identity headers cannot be forwarded before Fluxheim's
  verified TLS-derived value.
- Switched admin and route/vhost client-certificate fingerprint list checks to
  full-list constant-time-oriented comparisons.
- Added `reject_indeterminate` to vhost and route rate-limit policies so
  operators can reject requests when no trusted-proxy-aware client IP can be
  determined instead of using the shared anonymous bucket.
- Bounded process-global slice-cache fill concurrency keys and abort on a
  poisoned slice-fill lock so high-cardinality cache misses cannot grow that
  map indefinitely.
- Removed the process ID from generated snapshot IDs; uniqueness now comes from
  timestamp plus a process-local sequence without disclosing PID information
  through the authenticated admin API.
- Documented the anonymous shared rate-limit bucket used when no effective
  client IP is available, and warn when admin client-certificate header gates
  are configured on loopback listeners without an enforced terminator boundary.

### Planned

- Move the remaining proxy-operations work into `1.4.1`: dynamic upstream
  discovery, file-watched upstream lists, traffic mirroring, richer structured
  logs, regex/template rewrite policy, local operational sockets, and typed
  hook points.

## 1.3.7 - Production PHP-FPM Completion

Released: 2026-05-23

### Added

- Added managed php-fpm process supervision under the existing `php-fpm`
  feature. External php-fpm remains the default. Managed pools now include a
  watchdog that respawns the php-fpm master after post-start crashes with
  bounded backoff.
- Added a small audited `[vhosts.php.fpm] mode = "managed"` config surface for
  Fluxheim-owned private php-fpm pools, generated pool config, private Unix
  socket paths, bounded worker counts, static/dynamic/ondemand process manager
  modes, max-request recycling, request lifecycle controls, slowlog support,
  output/env toggles, session/upload temp paths, and clear startup/runtime
  diagnostics.
- Extended the local WordPress PHP-FPM smoke test so the same install, login,
  redirect, cookie, and admin-dashboard flow can run against external,
  managed-static, managed-dynamic, managed-ondemand, managed-respawn, all
  managed, or all external plus managed PHP-FPM modes.
- Added a self-contained Wolfi PHP image path that installs `php-8.5-fpm`,
  uses the managed php-fpm container config, and has a smoke test proving
  `/index.php` executes through the Fluxheim-supervised pool.
- Dropped the reserved pure-Rust PHP/phprs track. Managed php-fpm is the
  supported zero-admin PHP direction for the 1.3 line.

### Changed

- Managed php-fpm now starts with a cleared inherited environment and a
  sanitized `PATH`, generates private pool state, and keeps external php-fpm as
  the default deployment mode.
- Managed php-fpm teardown now sends SIGTERM before SIGKILL, detaches blocking
  child cleanup from Tokio worker threads, observes shutdown during respawn
  socket waits, and tracks stable restart windows from the actual successful
  php-fpm socket-ready timestamp.
- The `1.4` roadmap is now the compact production proxy parity line covering
  edge policy/compression, upstream resilience, TLS/protocol parity, and
  discovery/mirroring/operator hooks.

## 1.3.6 - FIPS/ISO Internal Crypto Closure

Released: 2026-05-23

### Added

- Added FIPS/ISO-required internal-crypto guards that fail closed for
  security-sensitive non-TLS cryptography that is not yet routed through the
  selected validated module or externally evidenced service.
- Added validation tests proving FIPS/ISO-required mode rejects managed ACME
  for the intended provider-boundary reason, accepts provider-backed admin
  auth, and rejects local disk-cache encryption, while allowing OpenBao Transit
  cache encryption as an external evidence boundary.
- Added a compliance evidence package template covering release artifacts,
  SBOMs, build commands, cryptographic module evidence, runtime diagnostics,
  scanner output, and Common Criteria-aligned evidence records.
- Added compliance evidence sections to `scripts/release_evidence.sh`,
  including candidate TOE boundary, Security Target-style draft,
  operational-environment assumptions, validation-script identifiers, and
  vulnerability-analysis records.
- Added hot-reload reuse for runtime Pingora cache storage, cache locks, tiered
  storage, and cache predictors so identical cache plans do not allocate a new
  leaked `'static` backend on every authenticated reload.
- Added a release-metadata guard for the `RUSTSEC-2024-0437` suppression so the
  protobuf advisory has to be reviewed when Pingora moves off Prometheus
  `0.13.4`.
- Added a documented numeric-local-loopback-only OTLP exception for
  FIPS/ISO-required mode so operators can export metrics/traces to a local
  collector without making outbound TLS part of Fluxheim's approved
  cryptographic boundary.
- Extended the OpenSSL and rustls FIPS validation scripts with provider-backed
  admin-auth fixtures plus fail-closed fixtures for managed ACME and local
  cache encryption. The managed ACME fixture now checks the specific ACME
  rejection text instead of treating any config-tester failure as evidence.

### Changed

- FIPS/ISO-required mode now prefers externally issued static certificates and
  rejects `[tls.acme] enabled = true` until ACME account key generation, JWS
  account signing, EAB, outbound ACME HTTPS transport, and TLS-ALPN certificate
  generation are routed through validated cryptography or separately evidenced.
- FIPS/ISO-required mode now allows `admin.enabled = true` in
  `tls-openssl-fips` and `tls-rustls-fips` builds because bearer-token HMAC is
  routed through OpenSSL FIPS or AWS-LC FIPS respectively. Non-FIPS builds still
  reject admin in FIPS/ISO-required configs.
- FIPS/ISO-required mode now rejects local cache encryption and requires either
  no cache encryption or `provider = "openbao-transit"` with operator evidence
  for the external OpenBao crypto boundary.
- Added `tls.fips.require_disk_cache_encryption` and
  `tls.iso19790.require_disk_cache_encryption` so operators can promote the
  unencrypted disk-cache warning to a hard config error in stricter
  data-at-rest deployments.
- The compliance evidence package is folded into `1.3.6` so regulated
  operators get the fail-closed gates and the evidence workflow in the same
  release.
- Admin runtime/auth-throttle mutex poisoning now aborts instead of recovering
  potentially inconsistent management state, matching release-mode fail-closed
  behavior in debug/test builds.
- Dynamic admin API JSON responses now serialize through `serde_json::to_vec`
  instead of hand-written `format!` response bodies, preserving the existing
  response schemas while reducing future JSON escaping risk.
- Admin bearer-token authorization now avoids length-check short-circuiting,
  zeroizes the temporary candidate copy used for comparison, and aborts on
  impossible system-clock failures instead of falling back to epoch timestamps.
- Snapshot ID generation now aborts on system-clock failure rather than
  generating `s0-...` identifiers.
- Peer-fill concurrency permit accounting now uses checked arithmetic and
  refuses permits if the counter saturates.
- The `security` feature runtime marker was renamed to
  `security::feature_compiled_in()` so it is not mistaken for an enforcement
  gate.
- The `RUSTSEC-2024-0437` release metadata guard now fails after the scheduled
  manual review date if the advisory exception is still present.

## 1.3.5 - rustls/AWS-LC FIPS Candidate

Released: 2026-05-22

### Added

- Added the rustls/AWS-LC FIPS-capable candidate backend feature:
  `tls-rustls-fips`, with `tls-rustls-iso19790`, `profile-fips-rustls`, and
  `profile-iso19790-rustls` validation/terminology aliases.
- Added provider-aware rustls TLS setup so default rustls builds keep using
  ring while FIPS rustls builds use `rustls::crypto::default_fips_provider()`.
- Added rustls FIPS diagnostics to `fluxheim crypto` and
  `fluxheim-config-tester --crypto`.
- Added `examples/fips-rustls.toml`, `examples/iso19790-rustls.toml`, and
  `scripts/validate-fips-rustls.sh` for local/manual AWS-LC FIPS candidate
  validation.

### Changed

- Split the internal rustls backend feature from the public `tls-rustls`
  provider selection so `tls-rustls` and `tls-rustls-fips` remain mutually
  exclusive public choices.
- Documented that rustls/AWS-LC FIPS candidate builds require the
  `aws-lc-fips-sys` build toolchain, including CMake, Go, and a C compiler.

## 1.3.4 - OpenSSL FIPS-Capable TLS

Released: 2026-05-21

### Added

- Added a standalone FIPS-capable deployment plan covering NIST/CMVP
  references, compliance boundaries, backend-specific OpenSSL and rustls/AWS-LC
  paths, internal crypto blockers, and the post-`1.3.4` roadmap for rustls and
  broader internal-crypto closure.
- Added the `tls.fips.required` fail-closed OpenSSL guard,
  `fluxheim crypto`, and `fluxheim-config-tester --crypto` diagnostics for the
  `1.3.4` OpenSSL FIPS-capable TLS line.
- Added an opt-in `tls-openssl-fips` feature that accepts
  `tls.fips.required` only with `backend = "openssl"` and verifies that the
  OpenSSL FIPS provider can be loaded, queried with `fips=yes`, and selected
  through OpenSSL default properties at runtime.
- Added a small local OpenSSL FIPS support crate that wraps OpenSSL 3 default
  property APIs outside Fluxheim's `#![forbid(unsafe_code)]` crate boundary.
- FIPS-required OpenSSL startup now enables and verifies
  `EVP_default_properties_enable_fips` / `EVP_default_properties_is_fips_enabled`
  before Pingora TLS services are built, and rejects startup if non-FIPS
  algorithms remain available through the default fetch path.
- Patched the vendored `pingora-openssl` compatibility crate to stop forcing
  `openssl/vendored`, allowing OpenSSL builds to link against the operator's
  system OpenSSL provider.
- Added FIPS-capable release evidence instructions for OpenSSL provider
  diagnostics, `tls.fips.required` config-tester checks, and operator evidence
  capture.
- Extended crypto diagnostics to report the OpenSSL configuration and module
  environment visible to the Fluxheim process without hardcoding distro paths.
- Added `profile-fips-openssl` as a narrow proxy/security/OpenSSL-FIPS build
  alias for local and release validation.
- Added `examples/fips-openssl.toml` and a matching
  `fluxheim-config-tester --profile fips-openssl` validation mode.
- Added `scripts/validate-fips-openssl.sh` to build/check the FIPS-capable
  OpenSSL profile, capture provider diagnostics, validate the fixture, and
  optionally require a working provider with `FLUXHEIM_REQUIRE_FIPS_PROVIDER=1`.
- Added fail-closed backend-mismatch and non-FIPS TLS-policy fixtures to the
  OpenSSL FIPS-capable validation script.
- Wired OpenSSL FIPS-capable validation into the optional stable release gate
  with `FLUXHEIM_GATE_FIPS_OPENSSL=1`.
- Added OpenSSL FIPS-capable evidence capture to `scripts/release_evidence.sh`,
  with `--skip-fips` for release lines where it is not relevant.
- Added the OpenSSL FIPS-capable profile to CI and local check coverage so the
  feature alias, config tester fixture, provider diagnostics, and fail-closed
  behavior are exercised before release.
- Documented the `1.3.4` OpenSSL FIPS boundary: Fluxheim proves provider
  availability, enables OpenSSL default FIPS properties for the process-default
  library context, and records the operator evidence still needed for the
  selected module Security Policy.
- Added a mapped OWASP Top 10 2025 baseline document and validation script that
  checks Fluxheim-owned controls for the categories that can be tested in-repo.
- Wired the OWASP Top 10 2025 baseline into stable release gates and release
  evidence capture.

### Changed

- Updated the release runbook for the `1.3.4` release line, corrected the
  local formatting preflight command, and documented explicit OWASP baseline
  evidence capture.

## 1.3.3 - PHP-FPM Hardening And Compatibility

Released: 2026-05-20

### Added

- Started the `1.3.3` PHP-FPM hardening line with opt-in FastCGI
  keep-connection pooling under `[vhosts.php.fpm]`: `keepalive`,
  `pool_max_idle`, and `idle_timeout_secs`.
- Added `[vhosts.php.params]` and `[vhosts.routes.php.params]` for safe custom
  FastCGI parameter injection without allowing overrides of Fluxheim-managed
  CGI variables or inbound `HTTP_*` request-header parameters. Custom parameter
  tables are capped at 128 entries.
- Added `php.fpm_root` for split Fluxheim/php-fpm filesystem layouts so
  Fluxheim can validate scripts under `php.root` while sending php-fpm paths
  under the runtime container root.
- Added `php.resolve_root_symlink` for opt-in final `php.root` symlink
  resolution in current-release/Caddy-style deploy layouts while keeping
  symlinked parent directories rejected.
- Added `php.try_files` with `front-controller`, `wordpress`, and `strict`
  modes for typed PHP front-controller and `try_files $uri =404` behavior.
- Added `php.preset = "wordpress"` to combine WordPress front-controller
  behavior with PHP execution denial for common upload/file directories.
- Added `php.path_info = "split"` as the clear spelling for safe explicit
  `PATH_INFO` splitting, while keeping `strict` as a compatibility alias.
- Added canonical slash redirects for PHP directory indexes so `/dir` redirects
  to `/dir/` before executing `/dir/index.php`.
- Added `php.pass_request_headers` and `php.pass_request_body` switches for
  advanced FastCGI migration control.
- Added `php.stderr_log` and `php.stderr_max_bytes` controls for bounded,
  sanitized php-fpm STDERR logging.
- Added `php.stderr_log_level` so php-fpm STDERR can be logged as `error`,
  `warn`, `info`, or `debug` instead of always using warning severity.
- Added `php.stderr_failure_patterns` for opt-in literal STDERR matching that
  marks a php-fpm response invalid for safe-method retry/failover when
  `php.fpm.retry_invalid_response` is enabled; matching STDERR is logged before
  invalidation when STDERR logging is enabled. Pattern lists are bounded to 32
  entries, with each pattern capped at 512 bytes.
- Added `php.hide_response_headers` for removing selected php-fpm response
  headers before they reach clients; the list is now bounded and rejects
  duplicate header names case-insensitively.
- Stripped hop-by-hop php-fpm response headers, including `Connection`-named
  headers and `Transfer-Encoding`, before Fluxheim frames the client response.
- Added `php.intercept_error_statuses` for opt-in
  `fastcgi_intercept_errors`-style replacement of selected PHP 4xx/5xx
  responses with Fluxheim-generated errors. Intercept status lists are capped
  at the valid 400-599 error-status range.
- Added `[[vhosts.php.error_pages]]` and route-level PHP error pages for
  serving internal static fallback pages when selected PHP statuses are
  intercepted. PHP error-page lists are capped at 64 entries.
- Added `php.deny_path_prefixes` to block php-fpm script execution under
  configured URI prefixes such as WordPress upload directories. PHP execution
  deny prefixes are capped at 128 entries, and `php.allowed_extensions` is
  capped at 16 entries with case-insensitive duplicate rejection.
- Added `php.max_response_header_bytes` to make the php-fpm CGI response
  header cap configurable while keeping the `64KiB` default. Added
  `php.server_port` for explicit CGI `SERVER_PORT` overrides on non-standard
  PHP listener deployments.
- Capped configurable buffered PHP responses at `64MiB` while keeping the
  default `php.max_response_bytes = "64MiB"`; php-fpm STDOUT/STDERR is now
  collected through the configured cap instead of after unbounded buffering.
- Added PHP-specific Prometheus request totals and duration histograms with
  bounded labels through `fluxheim_php_requests_total` and
  `fluxheim_php_request_duration_seconds`, and
  `fluxheim_php_stderr_events_total`, and retry-attempt counts through
  `fluxheim_php_fpm_retries_total`, plus pool visibility through
  `fluxheim_php_fpm_pool_idle_connections` and
  `fluxheim_php_fpm_pool_events_total`; multi-upstream keepalive pools use
  stable indexed pool labels. Added low-cardinality OTLP trace
  attributes for PHP runtime and PHP outcome so Jaeger can distinguish PHP
  handling without script-path labels. PHP request outcomes now distinguish
  connect timeouts, request timeouts, connection errors, configuration errors,
  invalid responses, and intercepted PHP statuses.
- Added cache bypass primitives for path prefixes, exact paths, any non-empty
  query string, and cookie-name prefixes, plus `cache.preset = "wordpress"`
  for common WordPress shared-cache bypasses, including admin, login,
  XML-RPC, cron, app/mail/register, index, and sitemap endpoints. Cache
  bypass, header, status, vary, content-type, extension, and method lists are
  capped to bounded sizes.
- Added `php.ignore_origin_cache_headers` for NGINX-style migrations that need
  Fluxheim to drop PHP-generated `Cache-Control`, `Expires`, and `Pragma`
  before applying response policy.
- Added `php.fpm.tcp_upstreams` for multiple TCP php-fpm backends with
  round-robin selection and safe-method failover on connection failures and
  connect timeouts. Upstream lists are capped at 64 entries and reject
  duplicate authorities.
- Added opt-in php-fpm retry controls with `php.fpm.max_retries`,
  `php.fpm.retry_timeout_secs`, and `php.fpm.retry_methods` for connection
  failures and connect timeouts before
  php-fpm returns a response; request timeouts are not retried. Retry method
  lists are capped at 16 safe methods and now reject non-idempotent methods such
  as `POST`, `PUT`, `PATCH`, and `DELETE`.
- Added opt-in php-fpm retry controls for malformed FastCGI responses and
  selected PHP 5xx responses through `php.fpm.retry_invalid_response` and
  `php.fpm.retry_statuses`, using the same safe-method and retry-window policy.
  Retry status lists are capped at the valid 500-599 server-error range.
- Wired `php.fpm.connect_timeout_secs`, `php.fpm.read_timeout_secs`, and
  `php.fpm.write_timeout_secs` as stricter caps on php-fpm connect and buffered
  FastCGI request phases alongside `php.request_timeout_secs`.
- Added opt-in PHP request-body disk spooling with
  `php.request_body_spool_threshold_bytes` and `php.request_body_spool_dir` so
  large uploads can be replayed to php-fpm and retried without cloning the
  entire request body in memory. Both spool settings are now required together.
  When `php.max_request_body_bytes` is set on the same PHP action, the spool
  threshold must be lower than that body limit. Existing spool directories must
  be directories and must not be group/world writable, and runtime spool
  creation rechecks permissions before writing upload bodies. Runtime spool
  filenames now include CSPRNG entropy to avoid predictable local pre-creation.
- Added PHP-assisted static offload for `X-Accel-Redirect` and `X-Sendfile`.
  Offload targets must resolve under `php.root`, `X-Sendfile` paths are mapped
  from `php.fpm_root` when configured, and Fluxheim refuses to offload files
  with configured PHP script extensions.
- Added PHP `X-Accel-Expires` handling: Fluxheim consumes the internal
  backend header, maps valid TTLs to normal `Cache-Control` and `Expires`
  headers, treats zero or past expiries as `no-store`, and avoids public cache
  directives on responses that set cookies.
- Capped proxy upstream lists, ACME challenge upstream lists, and proxy
  error-page lists at 64 entries, with duplicate upstream rejection.
- Capped configured request/response header mutation lists and maps so
  remove/unset, set/add, and append policies remain bounded.
- Capped listener lists, trusted proxy lists, total vhosts, vhost host aliases,
  and per-vhost route counts so config validation and reload planning stay
  bounded.
- Capped TLS policy allow-lists, global static certificate lists, ACME issuer
  lists, and explicit vhost ACME domain lists so certificate planning remains
  bounded.
- Capped static web `index_files` lists so global, vhost, and route static
  index probing remains bounded.
- Capped `cache.key_parts` to the four supported cache-key fields before
  duplicate and required-path validation.
- Capped configured vhost and route names at 128 bytes so log labels, admin
  responses, and metric dimensions remain bounded.

### Changed

- Added RFC 9110 hardening for proxy and static responses: ACME HTTP-01 405
  responses now include `Allow`, proxied requests and responses append Fluxheim
  `Via`, chunked requests without `Content-Length` are accepted for streaming
  body limits, satisfiable multi-range static requests are served as full
  responses, and Fluxheim-generated text error bodies include `Content-Type`.
- Admin authentication throttling now fails closed with a global lockout when
  the per-source table is full instead of evicting tracked source state.
- Fixed `fluxheim-config-tester --no-runtime-paths` so it skips `server.process`
  runtime path inspection before config loading fails on inaccessible
  `/run/fluxheim` mounts, while still validating non-path process settings.
  Updated the container and production docs to show when to use the tester
  versus full `fluxheim --validate-config` preflight, and refreshed container
  and RPM examples to the current `1.3.3` release line.
- Documented the explicit FastCGI protocol scope for php-fpm: Fluxheim
  supports the one-request-at-a-time `FCGI_RESPONDER` web-serving subset and
  does not support FastCGI multiplexing, authorizer, filter, or management
  roles in `1.3.x`.
- Added PHP application recipes for WordPress, WordPress Multisite, Laravel,
  Symfony, Flarum, MediaWiki, phpBB, XenForo, MyBB, and Discourse-as-proxy,
  clarifying that the reviewed PHP apps fit Fluxheim's generic PHP-FPM
  primitives while flat-root apps still need careful static path exposure until
  generic static deny/allow policy exists.
- Updated the PHP-FPM example to use `php.preset = "wordpress"` and show the
  optional `cache.preset = "wordpress"` shared-cache migration block.
- Removed `php-turbine` from the PHP runtime plan because Turbine-style app
  servers are better handled as reverse-proxy upstreams. The later pure-Rust
  PHP/phprs track has also been dropped from the `1.3.x` plan in favor of
  managed php-fpm.
- Added managed php-fpm process supervision to the future `1.3.x` PHP plan as
  a runtime config mode inside the existing `php-fpm` feature, while keeping
  external php-fpm as the default and rejecting persistent `php-cli` workers as
  the production path for normal PHP applications.
- Hardened PHP-FPM and observability follow-ups from pentest review: bounded
  joined FastCGI header params, added runtime custom-param guards, added a
  default PHP request-body fallback cap, tightened X-Sendfile root checks,
  restricted PHP response header values to ASCII-safe bytes, created PHP spool
  files relative to a verified directory fd on Unix, and added HTTPS-capable
  OTLP/HTTP export with strict 2xx status handling.
- Added private-PKI CA bundle support for OTLP metrics and tracing exporters,
  warn on plaintext OTLP endpoints outside loopback, create PHP body spool
  directories with private Unix permissions, canonicalize existing `php.fpm_root`
  paths while preserving separate-container path mapping, and raise the
  `PHP_ADMIN_VALUE disable_functions` warning to error level.
- Updated the optional `base64-ng` dependency to `1.0.0` for ACME EAB key
  decoding and OpenBao Transit cache encryption encoding.

## 1.3.2 - ACME Operations And Config Tester

Released: 2026-05-18

### Added

- Started the `1.3.2` operational follow-up with a dedicated
  `fluxheim-config-tester` binary for validating mounted configs without
  starting the gateway.
- Added config tester profile validation for `full`, `cache`, `proxy`,
  `web-php`, `development`, and future `load-balancer` release profiles.
- Added config tester modes for runtime-path validation, TLS storage checks,
  ACME target preview, upstream DNS resolution, and explain output.
- Added the dedicated `fluxheim-acme` companion binary with `renew` and
  `targets` commands backed by the existing ACME engine.
- Added a local Unix-domain certificate reload socket so `fluxheim-acme renew`
  can activate renewed certificate handles in the running gateway.
- Added `fluxheim-acme status` and `fluxheim-acme renew --vhost <name>` for
  safer single-target first issuance and renewal operations.
- Added `fluxheim-acme reload` for explicit service-manager or manual
  certificate-handle reload requests.
- Added bounded ACME lifecycle metrics through
  `fluxheim_acme_events_total{event}` for pending, renewed, failed, and reload
  outcomes without exposing domains, certificate paths, or challenge tokens.

### Changed

- Release evidence now builds one unified config-tester artifact instead of
  installing the tester into normal RPMs or runtime images.
- RPMs and runtime images now include `fluxheim-acme` for external ACME
  service/timer and container companion workflows.
- Hardened `fluxheim-acme` certificate reload responses with a bounded socket
  read.
- Kept ACME and cache secret-file intermediates in zeroizing buffers and capped
  ACME secret input files.
- Capped Admin API JSON response and error-message sizes as a defense-in-depth
  guard for authenticated control-plane responses.
- Hardened the certificate reload control socket with private bind/listen
  sequencing and read timeouts.
- Extended Unix `O_NOFOLLOW` coverage across config, snapshot, web,
  runtime-log, ACME, and admin-token path opens.
- Bounded trace-context random ID generation so CSPRNG failures disable tracing
  for the request instead of spinning indefinitely.
- Switched in-memory admin token digests from bare SHA-256 to per-process
  HMAC-SHA256, redacted internal Admin API 500 responses, and made
  indeterminate admin sources count only toward the global throttle budget.

## 1.3.1 - PHP-FPM Runtime Support

Released: 2026-05-16

### Added

- Added the `php-fpm` compile-time module for Fluxheim `1.3.1`, including
  typed `[vhosts.php]` and `[vhosts.routes.php]` config, strict PHP script
  resolution, WordPress-style front-controller dispatch, bounded FastCGI
  request/response handling, and malformed PHP response-header rejection.
- Added PHP runtime feature-policy checks so only one PHP runtime feature can
  be selected in a binary.
- Added `examples/php-fpm.toml` and PHP-FPM build/config documentation.
- Added a hardened browser WordPress login probe for reproducing real browser
  login/admin cookie behavior during gateway testing.

### Changed

- Updated the release line to use `base64-ng 0.8.0`, `aws-lc-rs 1.17.0`,
  `aws-lc-sys 0.41.0`, and `winnow 1.0.3`; `prometheus` remains pinned for
  Pingora compatibility.
- Hardened cache `Vary` request hashing with length-prefixed components instead
  of sentinel delimiters.

### Fixed

- Normalized split `Cookie` headers before proxying upstream and before
  generating PHP-FPM `HTTP_COOKIE`, fixing WordPress browser login flows over
  HTTP/2 and intermediaries that split cookies.
- Cleaned up test/runtime error propagation reported by the final pentest pass.

## 1.3.0 - Shared Ingress And TLS Feature Split

Released: 2026-05-14

### Changed

- Documented the release-artifact ACME default: official RPMs, container
  images, and release tarballs include `acme-client` for full, cache, and proxy
  builds, while raw Cargo profile aliases remain ACME-optional for custom
  offline/static-certificate builds.

### Added

- Started the shared ingress/TLS feature-graph split so TLS backends can be
  compiled without implicitly enabling the full proxy module.
- Added focused profile aliases for the next packaging line:
  `profile-full`, `profile-web-server`, `profile-cache-edge`,
  `profile-proxy-edge`, and `profile-load-balancer-edge`.
- Added CI feature-policy, check, and clippy coverage for the focused
  profiles.
- Added runtime validation that rejects web or cache configuration when the
  corresponding compile-time module is absent.

### Changed

- Container image builds now use focused feature profiles for `full`, `cache`,
  and `proxy` images. The load-balancer image profile remains prepared but is
  gated until the `1.5` load-balancer line unless manually requested.
- Updated the roadmap so `1.3.1+` owns PHP support, `1.4` owns advanced proxy
  parity, `1.5` owns enterprise load-balancer parity, and `1.6` owns shared
  Wasm extensibility.

## 1.2.6 - Slice Cache Range Composition Follow-Up

Released: in progress

### Added

- Added opt-in `[cache.range.slice]`, `[vhosts.cache.range.slice]`, and
  route-scoped slice-cache policy for Varnish-style fixed-slice range
  composition.
- Added normalized slice cache keys so arbitrary client ranges can be served
  from compatible fixed-size cached slices without colliding with complete
  objects or exact `1.2.5` range entries.
- Added bounded missing-slice fill from origin. Fluxheim fetches only normalized
  single-slice `Range` requests, validates `206`, `Content-Range`,
  `Content-Length`, `ETag`/`Last-Modified`, total length, and content type, and
  collapses concurrent fills for the same slice key.
- Added composed responses for bounded ranges, open-ended ranges, suffix
  ranges, and multipart multi-range requests when all required slices are
  fresh and validator-compatible.
- Added end-to-end proxy-cache smoke coverage for slice fill, slice hit,
  open-ended range, suffix range, multipart range composition, and cached
  slice `If-Range` matches.

### Changed

- `range.max_bytes` may exceed `cache.max_object_bytes` when
  `range.slice.enabled = true`; individual `range.slice.size_bytes` values
  remain bounded by `cache.max_object_bytes`.
- Exact admin purges now also remove slice entries for the same indexed path
  when slice caching is enabled.

## 1.2.5 - Bounded Range Cache Follow-Up

Released: in progress

### Added

- Added opt-in `[cache.range]`, `[vhosts.cache.range]`, and route-scoped
  cache range policy for safe bounded single `Range: bytes=start-end` proxy
  requests.
- Added range-specific proxy cache keys so repeated partial downloads can be
  served from cache without colliding with complete-object entries.
- Added range-cache admission checks that only store upstream `206 Partial
  Content` responses when `Content-Range` and `Content-Length` match the
  requested byte window.

### Changed

- Upstream `206 Partial Content` responses are now rejected from normal
  full-object cache admission unless the request is participating in the
  opt-in range-cache path.
- Documented the `1.2.5` large-file cache behavior in the README, config
  reference, cache backend notes, production-readiness notes, and versioning
  plan.

## 1.2.4 - Distributed Cache Peer-Fill Follow-Up

Released: in progress

### Added

- Started the `1.2.4` distributed cache line with `[cache.peer_fill]` policy
  configuration, bounded peer lists, explicit timeouts, fail-open behavior, and
  safe peer-origin validation for future peer-fill runtime support.
- Added a focused `examples/cache-peer-fill.toml` fixture and CI validation for
  the peer-fill configuration shape.
- Added aggregate Prometheus gauges for peer-fill enabled policies, configured
  peers, and maximum configured peer-fill concurrency.
- Added `cache-key` and `cache-lookup` preview fields and fail-closed
  expectation flags for selected peer-fill policy shape.
- Added peer-fill policy coverage to protected admin cache-status JSON.
- Added the first peer-safe runtime primitive for distributed cache fill:
  proxy-cache requests carrying `Cache-Control: only-if-cached` are now served
  from a fresh local cached object or receive `504` without contacting origin.
- Added outbound peer-fill on proxy-cache misses. Fluxheim now asks configured
  peers for `only-if-cached` hits before going to origin, stores valid peer
  hits locally, and respects `fail_open` when no peer can satisfy the request.
- Added bounded policy-level cache activity events for peer-fill hit, miss,
  error, fallback, and fail-closed outcomes.
- Added `scripts/smoke_peer_fill_cache.sh` and wired it into CI/release gates
  to prove node-to-node peer fill, local store after peer hit, and peer-fill
  activity metrics before release. The smoke also verifies fail-closed peer
  misses return `504` without contacting origin and fail-open peer misses fall
  back to origin.
- Enforced `peer_fill.max_concurrent_requests` at runtime per vhost/route cache
  policy so configured peer-fill limits now bound active outbound peer fetches.
- Preserved peer response `Age` during peer-fill admission so a peer hit stores
  only its remaining freshness instead of extending the origin TTL.
- Stored peer-fill hits under the correct `Vary` variance key so subsequent
  local hits preserve negotiated variants.

## 1.2.3 - Optional Cache Encryption Follow-Up

Released: 2026-05-13

### Added

- Started the `1.2.3` optional cache encryption-at-rest line with
  `[cache.disk.encryption]` policy configuration. Encryption remains disabled
  by default and normal deployments do not need OpenBao.
- Added local-key AES-256-GCM encryption for disk cache objects. Local keys can
  be loaded from a safe file path or a systemd/container credential, and
  encrypted cache objects authenticate the configured key id plus combined cache
  key as associated data.
- Added OpenBao Transit runtime encryption for disk cache objects. Fluxheim can
  call OpenBao Transit over HTTPS, load the token from a safe file or
  systemd/container credential, and store only the Transit ciphertext in the
  filesystem or storage-bin cache backend.
- Added optional Podman/OpenBao developer validation with a dev-mode OpenBao
  compose file and an end-to-end smoke script that verifies Transit-backed
  encrypted proxy-cache storage.
- Added focused local-key and OpenBao Transit encrypted cache example configs
  and CI validation for both.
- Added release-gate smoke coverage for local-key encrypted storage-bin cache
  traffic.
- Added `fluxheim cache-keygen` for generating local AES-256-GCM cache
  encryption keys.
- Added cache-encryption operations documentation covering local-key setup,
  OpenBao policy, rotation behavior, and smoke-test commands.

## 1.2.2 - Storage-Bin Disk Cache Follow-Up

Released: 2026-05-13

### Added

- Started the `1.2.2` storage-bin cache line with an explicit
  `cache.disk.backend` selector. The current filesystem backend remains the
  default and `storage-bin` is recognized as the focused slab/bin backend.
- Added the isolated storage-bin cache storage prototype with manifest/bin
  files, durable object index recovery, free-range reuse, LRU eviction parity,
  purge-index synchronization, Pingora `Storage` trait support, and runtime
  backend selection.
- Added storage-bin management parity for runtime stats, activity reset, cache
  inspection, exact purge, indexed hard/soft purge, and stale-object purge so
  the backend has the same operational hooks needed by the filesystem tier.
- Debounced storage-bin index writes after insert, eviction, and purge bursts
  so high-cardinality cache fills do not rewrite the full durable index once per
  object.
- Added storage-bin storage-pressure reporting for allocated bin bytes, reusable
  free bytes, free range count, largest free range, and bin file count in admin
  cache stats and aggregate Prometheus gauges.
- Fixed same-key storage-bin rewrites so revalidation or replacement can reuse
  the previous object's range instead of refusing an otherwise admissible write.
- Added a best-effort storage-bin index flush on clean storage teardown so the
  debounce path reduces write amplification without dropping fresh cache entries
  during normal shutdown.
- Added conservative storage-bin tail reclamation so eviction and purge can
  remove fully-free highest-numbered bin files without moving live objects.
- Added a focused `examples/cache-storage-bin.toml` fixture and CI validation
  for the storage-bin cache backend.

## 1.2.1 - Local Static Cache Follow-Up

Released: 2026-05-12

### Added

- Added the `1.2.1` focused local/static vhost cache follow-up with an explicit
  `local_static` cache-policy opt-in, local cache `MISS`/`HIT`/`Age` headers,
  and cache-key/lookup/exact-purge support for local static objects.

## 1.2.0 - Operations And Cache Completion Pack

Released: 2026-05-12

### Added

- Metrics builds now publish aggregate cache configuration gauges for vhost,
  route, policy, and storage-tier coverage.
- Metrics builds now publish aggregate memory and disk cache storage-pressure
  gauges, including object counts, byte usage, configured budgets, fill ratios,
  and purge-index entry counts.
- Metrics builds now publish bounded cache activity counters for memory and disk
  hits, misses, stores, store refusals, evictions, and purges.
- The local observability smoke now verifies Prometheus cache operation
  histograms plus memory and disk storage-pressure gauges while also checking
  local Prometheus OTLP metrics and Jaeger OTLP traces when available.
- The release smoke suite now verifies proxy cache HIT behavior, cached-hit
  `Age`, conditional `304`, and byte-range `206` behavior end to end.
- Proxy cache revalidation now preserves changed `Last-Modified` metadata from
  origin `304 Not Modified` responses and refuses metadata updates when a
  revalidation response changes `Vary`, keeping existing variant metadata
  intact until full re-keying support is added.
- Disk cache writes now use a v5 object header that records the combined cache
  key, primary key, user tag, cache tags, and path-index metadata, allowing
  Fluxheim to rebuild disk purge indexes after a process restart while
  retaining read compatibility with older v1-v4 objects.
- Cache policies can now set `pass_uncacheable_after` to temporarily bypass the
  cache path for repeated uncacheable responses with the same cache key.
- Cache debug headers now report pass-cache policy bypasses as `BYPASS` with
  reason `cache-pass` when `status_reason_header` is enabled.
- Prometheus cache activity metrics now include bounded policy pass decisions
  as `fluxheim_cache_activity_total{tier="policy",event="pass"}`.
- Prometheus now exposes configured vhost and route cache activity through
  `fluxheim_cache_activity_scope_total{scope,vhost,route,tier,event}`.
- Indexed cache purge endpoints now accept bounded `batches` /
  `x-fluxheim-cache-batches` for incremental large-scope invalidation.
- Stale cache purges now rotate scanned fresh entries on truncated non-dry-run
  batches, allowing bounded background cleanup to reach expired entries behind
  fresh front pages.
- Cache policies can now opt into Pingora's cacheability predictor with
  `[cache.predictor]`, `[vhosts.cache.predictor]`, and
  `[vhosts.routes.cache.predictor]`.
- `fluxheim cache-key` and `fluxheim cache-lookup` now report selected
  cacheability predictor state and can assert it with
  `--expect-cache-predictor-enabled`.
- The proxy cache smoke now enables and asserts vhost/route cacheability
  predictor policy.
- Route-scoped cache runtime stats now appear in the protected admin cache
  status endpoint and activity-reset response.
- `fluxheim cache-lookup` can now assert exact stored response header values
  with `--expect-header "Name: value"`, allowing release smoke tests to prove
  validator changes after proxy cache revalidation.
- Cache activity JSON now includes `miss_ratio_per_mille` alongside
  `hit_ratio_per_mille`.
- Cache activity JSON now includes `store_ratio_per_mille` alongside
  `store_refusal_ratio_per_mille`.
- Cache activity reset responses now include route and vhost cache coverage
  ratios.
- Cache status JSON now includes route and vhost cache coverage ratios.
- Cache status JSON now includes aggregate memory and disk cache tier counts.
- Cache status JSON now includes per-vhost and per-route `storage_tiers`
  counters.
- Cache status and activity-reset JSON now distinguish all configured routes
  from routes with explicit cache policy, including a cache-route coverage
  ratio.
- Cache policies can now emit an optional status response header, such as
  `X-Cache-Status`, for requests that participate in the proxy cache.
- Cache policies can now hide selected upstream response headers before cache
  admission and downstream delivery, enabling tightly scoped static-asset routes
  to strip headers such as `Set-Cookie`.
- Cache policies can now refuse shared cache storage when configured origin
  response headers are present, while still delivering the response normally.
- Cache policies can now refuse shared cache storage when configured origin
  response header values such as `x-app-cache = "private"` are present.
- Cache policies can now bypass lookup and storage when configured request
  headers such as `Cookie` or `Authorization` are present.
- Cache policies can now bypass lookup and storage when configured request
  header values such as `x-preview-mode = "1"` are present.
- Cache policies can now bypass lookup and storage when configured cookie names
  such as `sessionid` or `wordpress_logged_in` are present.
- Cache policies can now bypass lookup and storage when configured cookie
  values such as `preview = "1"` are present.
- Cache policies can now bypass lookup and storage when configured raw query
  parameter names such as `preview` or `token` are present.
- Cache policies can now bypass lookup and storage when configured raw query
  parameter values such as `mode = "private"` are present.
- Cache policies can now add safe request headers such as `Accept-Encoding` to
  the cache variance key when an origin does not emit the needed `Vary` header.
- Cache policies can now set an operator-controlled `key_namespace` to isolate
  new cached objects from older route-cache contents without changing URLs.
- Cache policies can now set `key_parts` to safely customize primary cache keys
  from `method`, `host`, `path`, and `query` without arbitrary interpolation.
- Cache policies can now set `min_uses` to delay shared cache storage until a
  cache key has produced repeated cacheable origin responses.
- Cache policies can now define positive response TTLs by HTTP status, which
  normalizes matching cache-participating origin responses before admission.
- Cache policies can now set `default_status_ttl_secs` as an explicit fallback
  TTL for cache-participating origin statuses not listed in `status_ttls`.
- Configured cache status TTLs now also opt matching non-200 origin responses
  into proxy cache admission; statuses without an explicit or fallback TTL
  remain rejected.
- Cache policies now support `content_types` plus an `extensions` alias for
  `image_extensions`, so route-scoped proxy cache can safely target common
  static assets such as CSS, JavaScript, WebAssembly, fonts, and images.
- Cache policies now support `include_query = false` for tightly matched static
  routes where query parameters should not vary the cache key.
- Cache policies can now explicitly ignore origin `Cache-Control` and `Expires`
  headers before proxy cache admission for tightly scoped static routes.
- Cache request-collapsing locks are now configurable per cache policy through
  `[cache.lock]`, while preserving the previous 30 second defaults.
- Protected cache purge endpoints can now target named route-scoped cache
  policies through `route` or `x-fluxheim-cache-route`.
- Protected cache purge responses now echo the normalized purge identity
  (`host`, `method`, `path`, and optional query) for easier bulk-operation
  auditing.
- Protected single cache purge responses and per-item bulk purge results now
  include aggregate and per-tier `not_purged` booleans.
- Protected bulk cache purge responses now include `purged_ratio_per_mille` so
  operators can quickly see how much of a requested purge batch matched.
- Protected bulk cache purge responses now include `not_purged`, avoiding
  manual subtraction when checking purge misses.
- Protected bulk cache purge responses now also echo the selected `route` and
  cache `scope`, matching single and indexed purge responses.
- Protected bulk cache purge responses now include memory and disk purged
  counts plus per-tier purge ratios.
- Protected indexed cache purge responses now include per-tier
  `memory_purged_ratio_per_mille` and `disk_purged_ratio_per_mille` fields.
- Protected indexed cache purge responses now include aggregate and per-tier
  `not_purged` counts for entries that matched the index but were not removed.
- Protected bulk and indexed cache purge responses now include aggregate and
  per-tier `not_purged_ratio_per_mille` fields for easier dashboarding.
- `server.default_vhost` validation now hints at `include_conf_d = true` or
  directory-based config loading when the named vhost is not loaded.
- Cache policies can now set `stale_if_error_secs` to permit serving stale
  cached objects during upstream errors after normal freshness expires.
- Stale-on-error serving now requires an explicit `stale_if_error_secs` policy
  window instead of serving stale for every upstream error.
- Cache policies can now narrow stale-on-error serving with
  `stale_if_error_on`, covering upstream error classes such as `connect`,
  `timeout`, `read`, `write`, `connection-closed`, `http-status`, `protocol`,
  and `tls`.
- Cache policies can now narrow HTTP-status stale-on-error serving with
  `stale_if_error_statuses`, for example to serve stale only on `500`, `502`,
  `503`, and `504` origin responses.
- Cache policies can now set `stale_while_revalidate_secs` to permit serving
  stale cached objects while Fluxheim revalidates them in the background.
- ACME HTTP-01 client failures now include published challenge URLs after
  challenge material has been written, making failed authorization checks easier
  to debug from production logs.

## 1.1.0 - TLS Policy And Certificate Operations

Released: pending

### Added

- ACME-managed vhost certificate sources now derive safe on-disk certificate
  paths and can satisfy the TLS listener fallback certificate requirement when
  configured on `server.default_vhost`.
- HTTP-01 challenge requests for ACME-managed vhosts can be served locally from
  the managed ACME storage directory when `tls.acme.challenge = "http-01"`.
- TLS-ALPN-01 challenge certificates can now be generated and served by the
  rustls downstream listener when `tls.acme.challenge = "tls-alpn-01"`.
- ACME EAB secret sources can now be loaded through a bounded, redacted,
  zeroized helper for the runtime issuer client.
- ACME-managed certificate files can now be installed through a guarded helper
  that validates PEM shape, writes temporary files, rejects symlinked targets,
  and preserves previous files on validation or staging failures.
- ACME HTTP-01 challenge files can now be installed and removed through the
  managed challenge store with token/value validation and symlink checks.
- ACME account credentials are now stored under safe issuer-derived paths with
  bounded JSON loading, owner-only writes on Unix, and symlink rejection.
- `acme-client` adds live `instant-acme` account bootstrap plus HTTP-01 and
  rustls TLS-ALPN-01 order/finalize support behind an explicit feature gate.
- Google Trust Services production and staging are now built-in ACME issuers,
  with separate default EAB environment variables for each environment.
- Managed ACME certificate expiry is now observed from bounded, symlink-safe PEM
  reads so Fluxheim can distinguish missing, due, and not-yet-due certificates.
- `fluxheim acme-renew` runs due-only renewal once, while
  `fluxheim acme-renew --force-renew` forces every configured ACME vhost.
  The old `--all` alias still works but now prints a deprecation warning.
- Builds with `acme-client` now register a background ACME renewal service for
  configured ACME vhosts. It renews missing or due certificates on the
  configured check interval and refreshes reloadable downstream SNI certificate
  objects after successful renewal.
- Downstream TLS listeners now have explicit policy config for named profiles,
  minimum protocol version, ALPN selection, curve preferences, and cipher suite
  allow-lists. `modern` now means TLS 1.3-only, while the default
  `intermediate` profile preserves the 1.0 TLS 1.2+ / HTTP/1.1+HTTP/2
  compatibility baseline with explicit AEAD ECDHE cipher policy.
- Response HSTS can now be configured as structured policy with `max_age_secs`,
  `include_subdomains`, and `preload` instead of requiring a raw header string.

### Changed

- `1.1.0` is now scoped as TLS policy and ACME certificate operations so normal
  production deployments can avoid external certificate copy scripts.
- Advanced provider-specific and zero-downtime certificate automation moved to
  a later certificate milestone.

## 1.0.0 - Gateway Foundation

Released: 2026-05-08

### Added

- `1.0` gateway migration fixtures and smoke coverage for representative
  multi-site configs, including canonical redirects, app proxy vhosts, custom
  error pages, static aliases, challenge exceptions, and multi-subdomain
  route/proxy layouts.
- Route-level exact, prefix, and fallback matching with proxy, static, and
  redirect actions.
- Route prefix stripping, per-route request body limits, and route-local
  upstream connect/read/send timeout policy.
- Websocket-safe upgrade proxying coverage for `/chat/`-style routes.
- Vhost ACME challenge helper for standard cleartext challenge paths while
  preserving HTTPS redirects for normal traffic.
- Vhost canonical redirect helper for apex/secondary-host redirects that preserve
  the request URI safely.
- Custom upstream error pages with internal static serving.
- Static alias routes with secure optional directory listing and local-time
  timestamp rendering.
- Safe dynamic request-header templates for common proxy migrations.
- SNI certificate selection for the default rustls downstream TLS backend and
  callback-capable downstream TLS backends.
- Native systemd deployment files, sysusers/tmpfiles packaging, and manual
  server preparation helper for compiled binaries.
- Zeroizing admin-token buffers and `subtle`-backed constant-time admin bearer
  token verification.
- SBOM generation and local reproducible-build checks in the stable release
  gate and CI supply-chain evidence.

## 0.5.0 - Basic Sites Preview

Released: 2026-05-06

### Added

- GitHub CI, Dependabot, CodeQL, dependency policy, and release-check scripts.
- Feature preflight validation for mutually exclusive TLS backends and
  zero-retention privacy-mode incompatibilities.
- `profile-*` Cargo feature aliases for common build profiles.
- Dedicated `1.0` core build matrix validation for default, profile, web-only,
  and proxy-only builds.
- Stable release security gate script for local release validation.
- Deep stable-release gate wrapper for release-candidate validation.
- Release-gate report capture helper for local release-note artifacts.
- Stable release-notes template covering gate results, reviewed advisories, and
  container image metadata.
- Production-readiness checklist separating the `1.0` stable-core promise from
  incubator and future modules.
- Vhost config guide explaining TOML `[[vhosts]]` ownership and the recommended
  one-vhost-per-file layout.
- User-friendly header mutation aliases: `remove`/`add` and nested
  `[headers.*.operations]` tables, while keeping `unset`/`set` compatible.
- Config validation rejects ambiguous header additions where the same header is
  defined in more than one `set`, `add`, or `operations.add` table.
- Config validation rejects proxy blocks that define both the compatibility
  `upstream` field and the preferred `upstreams` list.
- Optional `hey` based `1.0` local load-smoke script.
- Raw-socket request-framing smoke for malformed HTTP rejection before release.
- Initial `cargo-fuzz` targets for Host normalization and cache-header parsing.
- Fuzz target compile validation helper for release gates.
- Local `testssl.sh` TLS scan wrapper for scanner-backed release validation.
- `1.0` localhost smoke coverage for HTTP static hosting, HTTP proxying, static
  certificate storage validation, HTTPS static hosting, HTTPS proxying, and
  optional cleartext-to-HTTPS redirect.
- Global `[server.https_redirect]` option with safe Host validation and
  restricted redirect statuses.
- Wolfi, Alpine, SUSE Micro, and Debian runtime Containerfiles.
- Container image publish workflow for GitHub Container Registry and Docker Hub.
- Self-contained packaged default site and config so fresh containers/RPMs
  serve `/srv/fluxheim/index.html` on port `8080` without external assets.
- RPM packaging spec for RHEL/openSUSE-style builds from vendored Cargo
  dependencies.
- Runtime UID/GID build args for container images, defaulting to non-root
  `65532:65532` while allowing deliberate root-runtime images.
- Zero-retention privacy example config for `profile-privacy` builds.

### Changed

- Removed the advanced CodeQL workflow so GitHub CodeQL default setup can own
  code scanning without duplicate SARIF upload failures.
- Updated the optional OpenSSL TLS backend lockfile path to `openssl 0.10.79`
  and `openssl-sys 0.9.115`.
- Centralized temporary test path creation so CodeQL does not treat descriptive
  test labels as filesystem-controlled path input.
- The default build is `proxy`, `web`, `cache`, `tls-rustls`, and `security`.
- Container builds can select both feature set and packaged config.
- CI now separates the stable `1.0` core matrix from incubator-module feature
  checks.
- Container publishing uses variant-suffixed tags such as `v1.0.0-wolfi` and
  `latest-alpine`.
- Roadmap now tracks a future declarative redirect and rewrite engine with
  match-action routing, loop detection, and safe URL handling.
- Release ladder now focuses `1.1` on TLS policy and ACME certificate
  operations before operational and load-balancing modules graduate.
- Process runtime paths now default to `/run/fluxheim` instead of predictable
  files directly under `/tmp`.
- Examples now prefer `upstreams = [...]`; the single `upstream` field remains
  supported for compatibility.

### Security

- Path and header handling are treated as release-gated areas with tests and
  CodeQL scanning.
- Static file serving now rejects same-size file replacement between resolution
  and body read on Unix by checking the opened file handle identity.
- Process PID, upgrade-socket, and process error-log paths are rejected on Unix
  when their nearest existing parent directory is world-writable.
- File logging paths are rejected on Unix when their nearest existing parent
  directory is world-writable.
- Disk cache roots are rejected on Unix when their nearest existing parent
  directory is world-writable.
- Admin token files, configured snapshot stores, and direct snapshot store roots
  are rejected on Unix when they would use a world-writable directory.
- TLS certificate paths, ACME storage paths, and ACME EAB secret file paths are
  rejected on Unix when their nearest existing parent directory is
  world-writable, including in the dedicated TLS storage checker.
- `privacy-mode` rejects access logging and cannot be combined with `cache` or
  `metrics`.
- CodeQL uses the supported Rust `build-mode: none` setup.

### Notes

- This is a preview release for normal static HTML websites and simple
  whole-vhost proxying with static TLS certificates. It is not the `1.0.0`
  gateway release.
- At the `0.5.0` tag, known `1.0.0` gaps included multi-certificate SNI,
  route-level proxy/static/redirect behavior, websocket-safe proxying,
  per-route limits and timeouts, custom upstream error pages, and secure static
  alias/directory listing behavior.

## 0.1.0 - Repository Baseline

### Added

- Initial Fluxheim Rust/Pingora project baseline.
- Modular static web, reverse proxy, cache, TLS, ACME planning, admin snapshot,
  load-balancer, metrics, logging, and privacy-mode foundations.
- EUPL-1.2 license, GitHub-ready README, roadmap, architecture docs, examples,
  and rootless Podman packaging.
- `deny.toml` and audit policy for license/advisory checks.

### Notes

- This is not a production `1.0` release. The stable `1.0` target remains
  static hosting, reverse proxying, vhosts, rustls TLS, secure defaults, and
  local/rootless Podman operation.
