# Fluxheim 1.7.8 Release Notes

Fluxheim 1.7.8 starts the optional WASI Preview 1 capability boundary for
non-request-body policy plugins. This is a narrow access-decision preview, not
general-purpose WASI application hosting.

## Added

- Propagate the `wasm-wasi` feature through the root, config, server, and
  `fluxheim-wasm` crates.
- Add the `wasi-preview` ABI and host-call namespace pair.
- Add `[wasm.plugins.wasi]` with independent `clocks` and `randomness` grants,
  both disabled by default.
- Add `wasm.max_total_preview_concurrent_executions`, defaulting to and capped
  at `32`, for both WASI and proxy-ABI preview access hooks.
- Add real WASI modules proving explicit randomness and clock grants work under
  the normal Fluxheim sandbox.
- Add live native HTTP/1 coverage proving a granted WASI policy continues into
  normal route handling while an ungranted import fails closed before origin
  dispatch.
- Add a checked-in WASI randomness policy/config example and include it in the
  standalone Wasm smoke.
- Restore native-request GeoIP context lookup using the trusted-proxy-aware
  client address for HTTP/1 and HTTP/2 policy evaluation.
- Decode CIRCL Geo Open combined Country and ASN databases, including their
  provider-specific string ASN field.
- Add an opt-in, checksum-pinned CIRCL real-database smoke proving country and
  ASN policy on static, direct-proxy, and load-balanced request paths.

## Security

- Normalize IPv4-mapped and IPv4-compatible IPv6 DNS results before stream
  rebinding checks, closing access to embedded loopback, private, link-local,
  metadata, carrier-grade NAT, benchmark, and other reserved IPv4 addresses.
- Keep both stream copy directions in persistent pinned futures and drive one
  shared idle deadline from their latest successful transfer. Partial writes
  can no longer be cancelled and silently discarded when reverse traffic wins
  the dispatcher race.
- Clear each successfully forwarded plaintext prefix and clear complete stream
  copy buffers on drop through `sanitization`.
- Reject zero, oversized, or overflowing weighted-stream totals inside
  `StreamUpstreamSelector`, preserving the config limits at the public runtime
  construction boundary.
- Make configuration snapshots transactional and recoverable with mutation-wide
  private locking, explicit parent/generation history, create-new publication,
  temporary/orphan cleanup, retryable rollback, persisted self-healing state,
  redacted invalid-ID diagnostics, and typed clock errors.
- Add optional HMAC-SHA-256 manifests backed by an external bounded key file.
  Config and metadata are verified before rollback parsing; legacy stores are
  reported as unverified rather than silently authenticated.
- Persist an authenticated generation high-water mark and per-manifest
  generation witnesses so pruning cannot reuse audit generations and freshness
  scans remain bounded without rereading complete snapshot configurations.
- Preserve authenticated manifests created before generation witnesses. A
  fully verified all-legacy store with no generation counter bootstraps from
  its highest generation, persists authenticated state first, migrates its
  manifests, and publishes the next snapshot at `max + 1`. Missing state still
  fails closed for V2 and mixed stores.
- Route snapshot SHA-256 and HMAC-SHA-256 through the selected Ring,
  OpenSSL-FIPS, or AWS-LC-FIPS provider, returning provider failures to the
  administrative caller instead of aborting the data plane.
- Require owner-only snapshot state and integrity-key files, keep integrity
  keys outside the snapshot store, and authenticate intentional pruning
  boundaries.
- Add resilient listing plus snapshot `show`, `diff`, `verify`, `doctor`, and
  protected `prune` operations. Snapshot TOML remains plaintext and needs
  encrypted storage or backups when confidentiality is required.
- Enforce OpenSSL cipher allow-lists across protocol families. A policy with
  only TLS 1.3 suites disables TLS 1.2, and a policy with only TLS 1.2 suites
  disables TLS 1.3, preventing inherited acceptor defaults from negotiating an
  unconfigured suite. Move to OpenSSL's Mozilla v5 acceptor baseline so the
  legacy v4 template cannot suppress configured TLS 1.3 listeners.
- Replace synchronous rustls TLS-ALPN challenge loading on ClientHello with a
  bounded, atomically replaced in-memory SNI certificate table. Remote
  handshakes perform lookup only and cannot trigger file parsing or loader
  logging.
- Limit certificate chains to 1 MiB and 16 certificates, private-key files to
  64 KiB, and client-auth CA bundles to 8 MiB and 4096 certificates in both
  downstream TLS providers.
- Keep transient rustls private-key PEM and decoded DER bytes in
  `sanitization::SecretVec` until provider parsing completes. Read key files
  directly into protected storage so partial I/O and concurrent-growth errors
  also wipe initialized key bytes.
- Decode Rustls private-key PEM payloads through base64-ng's staged
  constant-time-oriented decoder and report only the redacted decode-error
  class, never an offending secret-adjacent byte or input index.
- Disable default provider features for rustls and tokio-rustls. Normal Ring
  builds no longer include AWS-LC; AWS-LC remains explicitly selected by the
  rustls FIPS profile.
- Keep `base64-ng` out of default and OpenSSL-only `fluxheim-tls` dependency
  graphs; it is now activated only by the Rustls key-parsing boundary.
- Validate each declared `wasi_snapshot_preview1` import before instantiation.
  Clock imports require `clocks = true`; `random_get` requires
  `randomness = true`.
- Keep environment, arguments, inherited stdio, filesystem, sockets/network,
  polling, and process-exit imports unavailable in this preview, regardless of
  capabilities granted for clocks or randomness.
- Build a fresh WASI context per execution without inherited process state.
- Cap each granted `random_get` call at 4096 bytes so guest-selected host work
  cannot request the full memory budget in one operation.
- Restrict `wasi-preview` to `access-decision`, require explicit preview-ABI
  allowance, require pinned module digests for that security phase, and retain
  fail-closed composition.
- Include WASI grants in compiled-module identity equality so differently
  authorized modules cannot share an identity.
- Isolate preview hooks from native policy hooks with separate process-wide
  admission and 32-slot blocking-work pools, preventing preview saturation
  from consuming native `fluxheim-policy-v1` capacity.
- Apply one absolute PHP-FPM request deadline to request transmission and full
  FastCGI response collection, discarding timed-out pooled connections.
- Open managed PHP-FPM executables without following symlinks, validate the
  opened file and every ancestor for trusted ownership and modes, and execute
  through the retained descriptor to close path-replacement races.
- Run each managed PHP-FPM pool in a dedicated process group and terminate the
  complete group on shutdown, failed status checks, and watchdog restarts.
- Unlink request-body spool files immediately after secure creation while
  retaining a descriptor for retry replay. Give every reader an independent
  logical offset backed by bounded positional reads so overlapping readers
  cannot corrupt each other's request body stream.
- Hold PHP memory bodies and bounded spool-read buffers in
  `sanitization::SecretVec`, clear consumed spool buffers immediately, and
  clear full buffer capacity on cancellation, error, or drop.
- Read each verified GeoIP database into an exact admitted-length buffer and
  probe growth with a separate stack byte, preventing a one-byte in-place
  append from triggering large `Vec` capacity growth before rejection.
- Validate public `GeoContext` construction, canonicalize accepted two-letter
  ASCII countries to uppercase, and reject ASN zero before policy consumers can
  observe malformed security state.
- Replace inherited managed PHP-FPM `PATH` handling with a fixed allowlisted
  search path after clearing the child environment.
- Render unavailable directory-listing timestamps as `-` after checked epoch
  and year-9999 bounds, preventing attacker-influenced file metadata from
  reaching panic-prone timestamp formatters in release builds.
- Replace unchecked `SafeRelativePath` component insertion with a validating
  single-normal-component API so the public type preserves its traversal-safety
  invariant for current and future static-serving callers.
- Enforce crate-level hard ceilings for Wasm module, memory, table, fuel,
  execution-timeout, and compile-timeout limits, with matching config rejection
  and checked `Instant` deadline arithmetic.
- Reject Wasm admission values above Tokio's semaphore capacity before
  constructing a semaphore, and create compilation workers through the fallible
  named thread builder instead of the panicking convenience API.
- Check the absolute execution deadline before and after every synchronous host
  callback so late callback results fail as timeouts. Keep blocking callbacks
  prohibited until a killable subprocess runner exists.
- Require in-process native Wasm callbacks to be panic-free and total for every
  guest integer, and property-test all current guest-ID decoders over arbitrary
  `i32` inputs. Keep panic-prone or third-party native callbacks behind the
  future subprocess-isolation boundary.

## Validation

```bash
cargo test --locked -p fluxheim-wasm --features wasi
cargo test --locked -p fluxheim-config --features wasm-wasi wasm_wasi
cargo test --locked -p fluxheim-server --features wasm-wasi native_wasm_wasi
cargo test --locked -p fluxheim-stream
cargo test --locked -p fluxheim-snapshot
cargo test --locked -p fluxheim-tls --no-default-features --features tls-rustls,acme
cargo test --locked -p fluxheim-tls --no-default-features --features tls-openssl,acme
scripts/smoke_wasm_sandbox.sh
cargo test --locked -p fluxheim-php-fpm
scripts/smoke_wordpress_php_fpm.sh
scripts/smoke_fluxheim_php_wolfi.sh
scripts/smoke_geoip_circl.sh
scripts/smoke_admin_listener.sh
```

## Operator Notes

- Build with `wasm-wasi`; the feature remains absent from default images and
  incompatible with `privacy-mode`.
- Set `[wasm].allow_preview_abi = true`, then declare both
  `abi = "wasi-preview"` and `host_call_namespace = "wasi-preview"`.
- Grant only the capability the module imports. Unsupported imports are config
  or execution errors and security-decision hooks fail closed.
- This release does not grant request bodies, environment, filesystem, network,
  stdio, arguments, or process-control access.
- The clock grant exposes the full-resolution host clock. Avoid granting it to
  untrusted multi-tenant plugins colocated with secret-dependent computation.
- Document the rootless Podman ownership mapping required for trusted read-only
  config mounts, including explicit `podman unshare chown`, an opt-in `:U`
  alternative, and an in-container verification command.
- Existing authenticated snapshot stores created before generation witnesses
  upgrade automatically on their next locked snapshot creation only when every
  retained legacy manifest verifies. See `docs/config-snapshots.md` for the
  fail-closed mixed-store and external anti-rollback requirements.
- CIRCL Geo Open users should follow `docs/geoip.md` for dataset attribution,
  trusted installation, pinned checksums, schema details, and the opt-in live
  database proof. The large network download remains outside normal CI gates.
