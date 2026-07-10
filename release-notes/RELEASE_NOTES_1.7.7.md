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
