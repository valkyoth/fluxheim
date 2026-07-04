# Fluxheim 1.7.2 Release Notes

Fluxheim 1.7.2 starts the live WebAssembly hook execution contract and wires
the first request-path hook family: access decisions. Request-header mutation
remains staged until the typed host-call ABI can safely pass and mutate header
state.

## Highlights

- Add `wasm.max_total_concurrent_executions`, a process-wide ceiling for total
  concurrent Wasm plugin executions. Per-plugin and per-attachment admission
  budgets remain in force inside this global ceiling.
- Add `[[wasm.attachments]].priority` for deterministic plugin chain ordering.
  Lower priorities run first; equal priorities retain declaration order.
- Add a canonical ordered attachment view in config so future hook families use
  the same priority/declaration-order rules.
- Add a reusable `fluxheim-wasm` access-decision combiner with
  `first-deny-wins` behavior.
- Add a reusable `fluxheim-wasm` process-wide admission controller that rejects
  excess concurrent executions until active permits are dropped.
- Wire live native HTTP/1 `access-decision` hooks for vhost and route
  attachments. Built-in ACLs remain non-overridable; Wasm access hooks can only
  add an allow/continue or deny decision after built-in access policy passes.
- Add live listener tests that load real Wasm modules, prove deny behavior,
  prove priority-ordered `first-deny-wins`, and prove percent-decoded route
  policy selection still applies to Wasm access decisions.
- Install native Wasm metrics recorders when Prometheus metrics are enabled so
  live hook executions and admission rejections feed the low-cardinality Wasm
  metric instruments.
- Classify any `[wasm]` runtime, plugin, attachment, limit, or admission change
  as `wasm-runtime-changed` and require a process upgrade until the compiled
  module cache and atomic reload path are implemented and tested.
- Expose the process-wide Wasm execution ceiling and attachment priorities in
  authenticated `/_fluxheim/status`.
- Add low-cardinality Wasm metrics for plugin executions, execution duration,
  and admission rejections. Unknown plugin/phase/outcome/scope values collapse
  to bounded labels.

## Operator Notes

- The default process-wide Wasm execution ceiling is `256`.
- The default attachment priority is `1000`.
- `access-decision` hooks use the exported
  `fluxheim_access_decision() -> i32` preview ABI in this release: `0`
  continues the chain, `1` allows/continues, and `2` denies with `403`.
- Runtime loaded plugin hashes remain staged for a later `1.7.x` status slice.
  Configured expected hashes remain visible in admin status.
