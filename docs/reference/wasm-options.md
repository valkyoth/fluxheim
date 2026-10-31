# Wasm Configuration Reference

Use the [deployment guide](../guides/wasm-extensibility.md) for installation,
complete attachment examples, failure policy and preview boundaries. Values
below describe the current configuration types, not proposed future APIs.

## Global Registry

All fields are inside `[wasm]`.

| Field | Default | Meaning / accepted values |
| --- | --- | --- |
| `enabled` | `false` | Activate plugin registry; requires compiled Wasm support |
| `allow_preview_abi` | `false` | Permit explicitly compiled preview namespaces; does not grant WASI capabilities |
| `plugin_roots` | `[]` | Up to 32 scoped absolute directories; at least three normal path components per root; plugins must be beneath an approved root |
| `default_limits` | Table below | Parent sandbox settings for omitted plugin limit fields |
| `default_admission` | 64 active, 0 queued | Default plugin and attachment admission budgets |
| `max_total_concurrent_executions` | `256` | Native non-cache admission; 1..256 |
| `max_total_preview_concurrent_executions` | `32` | Shared preview admission; 1..32 |
| `max_total_cache_concurrent_executions` | `256` | Cache-hook admission; 1..256 |
| `plugins` | `[]` | Up to 128 `[[wasm.plugins]]` declarations |
| `attachments` | `[]` | Up to 64 `[[wasm.attachments]]` declarations |

Use absolute paths in deployment examples. The file-based configuration loader
can resolve relative configured paths before validation; direct programmatic
configuration must supply the resolved paths. This does not grant access outside
approved roots. Keep the roots and config under trusted ownership/ACLs.

## Plugin Declaration

| Field in `[[wasm.plugins]]` | Default | Meaning / constraints |
| --- | --- | --- |
| `name` | Required | Unique registry name, 1..64 bytes; ASCII letters, digits, `-`, `_`, `.` |
| `path` | Required | Compiled module under an approved root, not a WAT source file |
| `sha256` | Absent | Exactly 64 hexadecimal characters when supplied; required for access-decision, route-decision and cache-store; recommended for every module |
| `abi` | `fluxheim-policy-v1` | Native policy, `proxy-wasm-preview` or `wasi-preview` |
| `host_call_namespace` | `fluxheim-policy-v1` | Must match the selected ABI; this TOML value is not the native import module's underscore spelling |
| `wasi` | Both grants false | Explicit preview capabilities below; grants rejected on other ABIs |
| `phases` | `[]` (invalid for a plugin) | Nonempty, distinct list: request-headers, response-headers, access-decision, route-decision, cache-lookup, cache-store; maximum configured list length 16 |
| `fail_mode` | `fail-closed` | `fail-closed` or `fail-open`; access-decision, route-decision and cache-store cannot be fail-open |
| `limits` | Absent | Omitted fields inherit global limits; explicit values replace their corresponding fields |
| `admission` | Absent | Omitted fields inherit global admission; explicit values replace their corresponding fields |

Both preview namespaces require `allow_preview_abi`, their corresponding Cargo
feature and only the access-decision phase. A registry entry without an
attachment is still loaded/compiled during runtime construction.

## Attachment Declaration

| Field in `[[wasm.attachments]]` | Default | Meaning / constraints |
| --- | --- | --- |
| `plugin` | Required | Name of an existing plugin |
| `vhost` | Required | Configured vhost name, not its Host-header alias |
| `route` | Absent | Optional existing route name within that vhost; absent selects vhost scope |
| `phases` | `[]` | Empty uses the plugin's declared phases; nonempty must be a subset |
| `priority` | `1000` | 0..1,000,000; ascending execution order, declaration order for ties |
| `admission` | Absent | Defaults from global admission, independently of plugin override |

Duplicate `(plugin, vhost, route)` attachments are rejected even if their phase
lists differ. Put the intended phase subset in a single attachment.

WebSocket-enabled proxy scopes support access-decision, not route-decision or
request/response-header hooks. Configuration rejects the latter phases even
with header `fail-open`. Empty `phases` still inherits every plugin phase, so
use an explicit supported subset when appropriate. A vhost attachment affects
all of its routes; a named-route attachment affects that route. Cache hooks do
not run on upgrade/tunnel traffic. See the [protocol contract](wasm-policy-abi.md).

## Sandbox Tables

The same fields apply to `[wasm.default_limits]` and `[wasm.plugins.limits]`.
Every limit must be positive. Byte limits accept integer byte counts or size
strings such as `"1MiB"`.

| Field | Stock default | Hard maximum | Scope |
| --- | --- | --- | --- |
| `max_module_bytes` | 1 MiB | 16 MiB | Loaded module bytes |
| `max_compiled_artifact_bytes` | 32 MiB | 256 MiB | Serialized compiled artifact, checked after compilation |
| `max_memory_bytes` | 16 MiB | 256 MiB | Linear memory per store, not total process memory |
| `max_table_elements` | 10,000 | 100,000 | Guest table elements |
| `fuel` | 5,000,000 | 100,000,000 | Per-execution Wasmtime fuel, not elapsed time |
| `timeout_ms` | 50 | 5,000 | Execution deadline; native callbacks are not forcibly preemptible |
| `compile_timeout_ms` | 500 | 10,000 | Synchronous compilation result deadline, not a kill timeout |

The runtime additionally limits instances/memories/tables; those are not extra
TOML options. Startup compilation and engine overhead need service-level CPU
and memory limits as well. Do not multiply linear-memory caps and call the
result a guaranteed process RSS ceiling.

## Admission Tables

Apply to `[wasm.default_admission]`, `[wasm.plugins.admission]` and
`[wasm.attachments.admission]`.

| Field | Stock default | Accepted values |
| --- | --- | --- |
| `max_concurrent_executions` | `64` | 1..256 active executions |
| `queue_limit` | `0` | 0..256 waiting slots; zero disables waiting capacity |

Narrower admission and process-wide admission both apply; a plugin override
does not disable global limits. Preview and cache families have their own
global pools. Admission rejection follows the plugin failure policy.

### Field Inheritance: the documented limitation

Plugin limits, plugin admission and attachment admission retain field presence.
Absent or empty override tables inherit every field. A partial table overrides
only supplied fields, including explicit zero queue capacity or stock-value
resets. Attachment admission inherits the global defaults independently of
plugin admission; both resulting admission controllers still apply.

With global concurrency 1, a plugin table containing only `queue_limit = 2`
keeps concurrency 1. With global fuel 1000, a timeout-only override keeps fuel
1000. Effective settings are validated before building the runtime/controller;
zero execution/fuel limits and values above hard ceilings remain errors.

Included default-limit/admission tables also merge by field into earlier
defaults; an empty fragment table changes nothing. All plugin and attachment
overrides resolve against the final merged globals. Explicit changes require
process upgrade, including changes to field presence.

For Rust callers, `WasmSandboxLimitsOverride` and `WasmAdmissionBudgetOverride`
use optional fields. `Default::default()` inherits all fields. Converting a
concrete `WasmSandboxLimitsConfig` or `WasmAdmissionBudgetConfig` with `.into()`
sets every field explicitly, preserving existing full-policy construction.
Use the plugin/attachment `effective_*` methods for validated resolved values;
the lower-level `resolve` method only merges fields, it does not validate them.
Admin custom-limit/admission indicators describe the presence of configured
tables, not whether every resolved value differs from the global defaults.

[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
corrects the prior whole-table behavior. Native qualification, pentest and CI
acceptance remain open; older binaries need full explicit overrides as a workaround.

## WASI Capability Table

`[wasm.plugins.wasi]` is meaningful only for `wasi-preview`.

| Field | Default | Grant |
| --- | --- | --- |
| `clocks` | `false` | `clock_res_get`, `clock_time_get`; full-resolution host clocks |
| `randomness` | `false` | `random_get`; at most 4096 bytes per invocation |

There are no settings for filesystem, sockets, stdio, environment, arguments,
polling or process-exit access. Unsupported imports fail rather than inheriting
the Fluxheim process capabilities.

## Implementation And Qualification

- [Configuration/defaults/validation](../../crates/fluxheim-config/src/config_wasm.rs)
- [Override characterization tests](../../crates/fluxheim-config/src/config_tests_wasm_contract.rs)
- [Manifest and digest validation](../../crates/fluxheim-wasm/src/manifest.rs)
- [Bounded loader](../../crates/fluxheim-wasm/src/file.rs)
- [Engine/admission](../../crates/fluxheim-wasm/src/runtime.rs)
- [Native hook wiring](../../crates/fluxheim-server/src/native_http1_route_wasm.rs)
- [Coverage and remaining work](documentation-coverage.md)
