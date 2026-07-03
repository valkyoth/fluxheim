# Fluxheim 1.7.0 Release Notes

Fluxheim 1.7.0 starts the WebAssembly extensibility line after the Pingora-free
runtime and crate-boundary cleanup work in `1.6.x`.

This release does not yet expose production request/response policy hooks. It
adds the first sandbox foundation: safe plugin file loading, bounded Wasmtime
execution, compile-time feature gates, and real smoke evidence for executing
and trapping Wasm modules.

## Highlights

- Add the optional `fluxheim-wasm` workspace crate.
- Add `wasm`, `wasm-proxy-abi`, and `wasm-wasi` feature switches. The Wasm
  feature family remains off by default and incompatible with `privacy-mode`.
- Load Wasm plugin files only from approved absolute roots, rejecting relative
  paths, `.`/`..` components, symlinked files or parents, non-regular files,
  and files over the configured module-size limit.
- Record the SHA-256 hash of loaded plugin bytes for future admin/status and
  audit surfaces.
- Add a Wasmtime runtime foundation with bounded fuel, memory, instance/table
  limits, and a wall-time watchdog.
- Add unit tests for plugin path safety, oversized modules, real Wasm
  execution, fuel exhaustion, and memory-limit rejection.
- Add `scripts/smoke_wasm_sandbox.sh` as a real Wasm smoke test that runs a
  successful module and verifies an infinite-loop module traps under limits.
- Add the Wasm smoke to `scripts/test_starter.py`; the deep release gate now
  enables it by default through `FLUXHEIM_GATE_WASM=1`.

## Operator Notes

- Wasm is not compiled into default builds.
- `privacy-mode` rejects Wasm feature combinations because Wasm policy hooks
  are an extension and observability surface.
- The first `1.7.0` runtime only supports a small internal `i32` no-argument
  execution proof. Request/response header hooks, access decisions, cache
  policy hooks, proxy-ABI compatibility, and WASI capabilities remain staged for
  later `1.7.x` releases.
