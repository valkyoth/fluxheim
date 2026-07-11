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

## Validation

```bash
cargo test --locked -p fluxheim-wasm --features wasi
cargo test --locked -p fluxheim-config --features wasm-wasi wasm_wasi
cargo test --locked -p fluxheim-server --features wasm-wasi native_wasm_wasi
scripts/smoke_wasm_sandbox.sh
cargo test --locked -p fluxheim-php-fpm
scripts/smoke_wordpress_php_fpm.sh
scripts/smoke_fluxheim_php_wolfi.sh
scripts/smoke_geoip_circl.sh
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
- CIRCL Geo Open users should follow `docs/geoip.md` for dataset attribution,
  trusted installation, pinned checksums, schema details, and the opt-in live
  database proof. The large network download remains outside normal CI gates.
