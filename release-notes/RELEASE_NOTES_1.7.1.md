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
- Add a typed config-to-loader manifest bridge so validated `[[wasm.plugins]]`
  entries become `fluxheim-wasm` manifests with inherited sandbox limits and
  optional expected SHA-256 digests.
- Add authenticated `/_fluxheim/status` visibility for the validation-only
  WASM registry: enabled state, plugin/attachment counts, plugin names, phases,
  fail modes, and expected SHA-256 digests.
- Add accepted and rejected WASM config-registry fixtures and wire them into
  `scripts/validate-wasm-config-registry.sh`.
- Reject unknown plugin references, attachment phases not declared by the
  plugin, duplicate same-target attachments, preview ABIs without explicit
  allowance, unsafe `fail_open` security-decision plugins, invalid plugin
  names, invalid plugin paths, invalid SHA-256 digests, and invalid sandbox or
  admission budgets.
- Enforce the registry allowlist at config validation time: each plugin path
  must live under one of the configured `wasm.plugin_roots`, and roots must be
  scoped deployment directories rather than filesystem-root or top-level system
  directories.
- Require `sha256` for plugins that declare security-decision phases
  (`access-decision`, `route-decision`, or `cache-store`).
- Preserve explicit WASM default resets from later `conf.d` fragments by using
  fragment-aware merge semantics for default sandbox limits and admission
  budgets.
- Keep the new config integration validation-only. No request/response,
  routing, cache, or load-balancer hook execution is enabled by this release.

## Operator Notes

- `wasm.enabled = true` is required before plugin roots, plugin declarations,
  or attachments are accepted.
- Binaries built without the `wasm` feature reject non-empty `[wasm]` config
  during validation instead of accepting a registry that cannot run.
- `sha256` on `[[wasm.plugins]]` is enforced by the plugin loader when a plugin
  file is loaded, not just checked as a syntactically valid digest. It is
  mandatory for security-decision phases.
- Plugin paths and plugin roots must be absolute and must not contain `.` or
  `..` components. Plugin paths must be under `wasm.plugin_roots`, and plugin
  roots must be scoped directories such as `/srv/fluxheim/plugins`, not broad
  roots such as `/` or `/etc`. Runtime file existence and symlink checks are
  still handled by the `fluxheim-wasm` loader when hook execution is wired
  later.
- Attachments use root-scoped target fields:

```toml
[[wasm.attachments]]
plugin = "security_headers"
vhost = "example"
route = "static"
phases = ["response-headers"]
```
