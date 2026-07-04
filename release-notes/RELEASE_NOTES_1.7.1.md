# Fluxheim 1.7.1 Release Notes

Fluxheim 1.7.1 continues the WebAssembly extensibility line with config-level
integration for the typed plugin registry. Runtime request-path hooks remain
staged for later `1.7.x` releases.

## Highlights

- Add `[wasm]` config validation for plugin roots, default sandbox limits,
  default execution admission budgets, plugin declarations, and plugin
  attachments.
- Add `[[wasm.plugins]]` declarations with plugin name, path, optional expected
  SHA-256 digest, ABI, host-call namespace, phases, fail mode, per-plugin
  sandbox limits, and per-plugin admission budgets.
- Add `[[wasm.attachments]]` declarations that attach a known plugin to a
  configured vhost and optional route, with optional phase narrowing and
  per-attachment admission budgets.
- Reject unknown plugin references, attachment phases not declared by the
  plugin, duplicate same-target attachments, preview ABIs without explicit
  allowance, unsafe `fail_open` security-decision plugins, invalid plugin
  names, invalid plugin paths, invalid SHA-256 digests, and invalid sandbox or
  admission budgets.
- Keep the new config integration validation-only. No request/response,
  routing, cache, or load-balancer hook execution is enabled by this release.

## Operator Notes

- `wasm.enabled = true` is required before plugin roots, plugin declarations,
  or attachments are accepted.
- Binaries built without the `wasm` feature reject non-empty `[wasm]` config
  during validation instead of accepting a registry that cannot run.
- Plugin paths and plugin roots must be absolute and must not contain `.` or
  `..` components. Runtime file existence and symlink checks are still handled
  by the `fluxheim-wasm` loader when hook execution is wired later.
- Attachments use root-scoped target fields:

```toml
[[wasm.attachments]]
plugin = "security_headers"
vhost = "example"
route = "static"
phases = ["response-headers"]
```
