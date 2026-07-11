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

## Validation

```bash
cargo test --locked -p fluxheim-wasm --features wasi
cargo test --locked -p fluxheim-config --features wasm-wasi wasm_wasi
cargo test --locked -p fluxheim-server --features wasm-wasi native_wasm_wasi
scripts/smoke_wasm_sandbox.sh
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
