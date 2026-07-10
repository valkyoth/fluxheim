# Fluxheim 1.7.7 Release Notes

Fluxheim 1.7.7 adds the first opt-in `wasm-proxy-abi` compatibility preview
boundary. This release does not claim that existing arbitrary proxy-wasm
plugins run unchanged. It establishes the safe shape for that work: explicit
ABI and host-call namespace validation, feature-gated config acceptance, and
deterministic unsupported-call rejection.

## Added

- Add `wasm-proxy-abi` feature propagation through the root, config, server,
  and `fluxheim-wasm` crates.
- Add `host_call_namespace = "proxy-wasm-preview"` support for
  `[[wasm.plugins]]` entries when paired with `abi = "proxy-wasm-preview"`.
- Add manifest validation that rejects mismatched ABI and host-call namespace
  combinations.
- Add native HTTP/1 proxy-ABI preview host-call stubs that reject unsupported
  calls deterministically instead of silently binding to Fluxheim's native
  policy namespace.
- Reject module imports that are not explicitly bound for the selected
  host-call namespace before Wasm instantiation, with a stable import-specific
  error.
- Add a live native HTTP/1 compatibility fixture using the canonical
  proxy-wasm `env.proxy_log(i32, i32, i32) -> i32` import and prove that the
  unsupported call fails closed with `503` before the upstream is reached.

## Security

- `proxy-wasm-preview` host calls remain disabled unless the binary is compiled
  with `wasm-proxy-abi` and config explicitly sets `allow_preview_abi = true`.
- Compiled WebAssembly module identities now include the host-call namespace,
  so future compile-cache reuse cannot cross from `fluxheim-policy-v1` to
  `proxy-wasm-preview`.
- Restrict proxy-ABI preview manifests to `access-decision`, and independently
  prevent native request-header, route, and cache host functions from being
  linked into the preview namespace.

## Changed

- Update `base64-ng` to 1.3.6, `bytes` to 1.12.1, `regex` to 1.13.0,
  `sanitization` to 1.2.4, and test-only `wat` to 1.253.0.
- Update the workspace MSRV, pinned toolchain, and container builders to Rust
  1.97.0.
- Exercise current MariaDB 12.3 LTS, PostgreSQL 18, and Valkey 9.1 container
  lines in the database and health-check smoke defaults.
- Restore the standalone cargo-fuzz workspace and remove its obsolete Pingora
  dependency patch so the checked-in fuzz targets build against their current
  owning crates again. The fuzz validation gate now compiles every target.

## Operator Notes

- Existing `wasm` configs using `fluxheim-policy-v1` continue unchanged.
- To test the preview namespace, build with `--features wasm-proxy-abi`, set
  `allow_preview_abi = true`, and declare both:

```toml
[wasm]
enabled = true
allow_preview_abi = true

[[wasm.plugins]]
name = "proxy_preview"
path = "/etc/fluxheim/plugins/proxy-preview.wasm"
abi = "proxy-wasm-preview"
host_call_namespace = "proxy-wasm-preview"
phases = ["access-decision"]
```

- The preview namespace is intentionally narrow in this release. Unsupported
  calls fail closed through the plugin fail mode.
