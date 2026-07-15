# Fluxheim 1.7.12 Release Notes

Fluxheim 1.7.12 adds standards-based response metadata generated from native
runtime outcomes and final response bytes. It also adds reproducible,
CI-only proof environments for both FIPS-capable TLS backend profiles.

All new response metadata remains opt-in. Existing configurations and response
headers are unchanged unless an operator enables the new metadata policy.

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
- Cache-header tests cover cumulative byte/directive ceilings and quoted-comma
  parsing.
- Shared path-safety and live redirect tests cover invalid UTF-8, overlong
  slash encodings, encoded Unicode controls, and valid encoded Unicode.
- Static-web tests cover missing children below valid and broken symlinked
  parents plus hidden non-UTF-8 Unix filenames.
