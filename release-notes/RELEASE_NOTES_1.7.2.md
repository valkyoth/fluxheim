# Fluxheim 1.7.2 Release Notes

Fluxheim 1.7.2 starts the live WebAssembly hook execution contract. This
release slice keeps request-path execution staged, but adds the deterministic
ordering, global admission, reload, and admin-status foundations needed before
access-control hooks can safely affect traffic.

## Highlights

- Add `wasm.max_total_concurrent_executions`, a process-wide ceiling for total
  concurrent Wasm plugin executions. Per-plugin and per-attachment admission
  budgets remain in force inside this global ceiling.
- Add `[[wasm.attachments]].priority` for deterministic plugin chain ordering.
  Lower priorities run first; equal priorities retain declaration order.
- Add a canonical ordered attachment view in config so future hook families use
  the same priority/declaration-order rules.
- Classify any `[wasm]` runtime, plugin, attachment, limit, or admission change
  as `wasm-runtime-changed` and require a process upgrade until the compiled
  module cache and atomic reload path are implemented and tested.
- Expose the process-wide Wasm execution ceiling and attachment priorities in
  authenticated `/_fluxheim/status`.
- Add low-cardinality Wasm metrics scaffolding for plugin executions,
  execution duration, and admission rejections. The recorders are ready for
  live hook wiring and collapse unknown plugin/phase/outcome/scope values to
  bounded labels.

## Operator Notes

- The default process-wide Wasm execution ceiling is `256`.
- The default attachment priority is `1000`.
- `access-decision` hooks will use `first-deny-wins` when live request-path
  execution is enabled, so stacked authorization plugins must be ordered
  deliberately.
- Runtime loaded plugin hashes remain staged for a later `1.7.x` slice. This
  release establishes the config, reload, and metrics contract they will report
  against.
