# Fluxheim 1.7.1 Release Notes

Fluxheim 1.7.1 continues the WebAssembly extensibility line with config-level
plugin registry integration, deterministic hook-chain contracts, and the first
live request-path hook family: native HTTP/1 access decisions. Request-header
mutation remains staged until the typed host-call ABI can safely pass and
mutate header state.

## Highlights

- Add `[wasm]` config validation for plugin roots, default sandbox limits,
  default execution admission budgets, process-wide execution admission,
  plugin declarations, and plugin attachments.
- Add `[[wasm.plugins]]` declarations with plugin name, path, optional expected
  SHA-256 digest, ABI, host-call namespace, phases, fail mode, per-plugin
  sandbox limits, and per-plugin admission budgets.
- Add `[[wasm.attachments]]` declarations that attach a known plugin to a
  configured vhost and optional route, with optional phase narrowing,
  deterministic `priority`, and per-attachment admission budgets.
- Add a typed config-to-loader manifest bridge so validated `[[wasm.plugins]]`
  entries become `fluxheim-wasm` manifests with inherited sandbox limits and
  optional expected SHA-256 digests.
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
- Add `wasm.max_total_concurrent_executions`, a process-wide ceiling for total
  concurrent Wasm plugin executions.
- Add a canonical ordered attachment view in config so all hook families use
  the same priority/declaration-order rules.
- Add reusable `fluxheim-wasm` access-decision and admission primitives,
  including process-wide, per-plugin, and per-attachment execution ceilings
  plus `first-deny-wins` composition.
- Wire live native HTTP/1 `access-decision` hooks for vhost and route
  attachments. Built-in ACLs remain non-overridable; Wasm access hooks can only
  add an allow/continue or deny decision after built-in access policy passes.
- Compile Wasm modules once when the native hook registry is built, then
  instantiate a fresh store/instance per request. This keeps request execution
  isolated without spending the global compile-slot budget on every request.
- Add live listener tests that load real Wasm modules and prove deny behavior,
  priority-ordered `first-deny-wins`, percent-decoded route policy selection,
  non-overridable built-in route ACLs,
  process-wide/plugin/attachment admission rejection, and fail-closed behavior
  for invalid output, traps, and execution timeouts.
- Classify any `[wasm]` runtime, plugin, attachment, limit, or admission change
  as `wasm-runtime-changed` and require a process upgrade until the atomic
  compiled-module reload path is implemented and tested.
- Expose the process-wide Wasm execution ceiling and attachment priorities in
  authenticated `/_fluxheim/status`.
- Add low-cardinality Wasm metrics for plugin executions, execution duration,
  and admission rejections. Native hook execution installs Prometheus recorders
  when metrics are enabled.
- Preserve explicit WASM default resets from later `conf.d` fragments by using
  fragment-aware merge semantics for default sandbox limits and admission
  budgets.
- Refresh release tooling pins: Docker GitHub Actions move to current v4/v7
  patch tags, Prometheus observability smoke coverage uses `v3.13.0`, and the
  non-Pingora crate freshness gate remains clean.
- Update `base64-ng` to `1.3.5` across the root, ACME, server, and
  load-balancer crates.

## Operator Notes

- `wasm.enabled = true` is required before plugin roots, plugin declarations,
  or attachments are accepted.
- Binaries built without the `wasm` feature reject non-empty `[wasm]` config
  during validation instead of accepting a registry that cannot run.
- The default process-wide Wasm execution ceiling is `256`.
- The default attachment priority is `1000`.
- `access-decision` hooks use the exported
  `fluxheim_access_decision() -> i32` preview ABI in this release: `0`
  continues the chain, `1` allows/continues, and `2` denies with `403`.
- Plugin paths and plugin roots must be absolute and must not contain `.` or
  `..` components. Plugin paths must be under `wasm.plugin_roots`, and plugin
  roots must be scoped directories such as `/srv/fluxheim/plugins`, not broad
  roots such as `/` or `/etc`.
- Runtime loaded plugin hashes remain staged for a later `1.7.x` status slice.
  Configured expected hashes remain visible in admin status.

Example attachment:

```toml
[[wasm.attachments]]
plugin = "security_headers"
vhost = "example"
route = "static"
priority = 100
phases = ["response-headers"]
```
