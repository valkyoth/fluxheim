# Wasm Policy Plugins

Wasm plugins run small, operator-supplied policy modules inside Fluxheim.
Use them for the supported access, header, route and proxy-cache decisions.
They are not a general scripting environment: existing Tcl iRules, Lua,
VCL and arbitrary proxy-wasm programs do not run unchanged.

Start with the [checked-in examples](../../examples/wasm/README.md).
The [options reference](../reference/wasm-options.md) lists every configuration
field, default and hard ceiling. The [configuration reference](../reference/config-reference.md)
also describes the current symbolic host-call interface.

Plugin authors should use the [exact ABI and ordering reference](../reference/wasm-policy-abi.md)
for every host-call ID, chain precedence and protocol boundary.

**Current limitation:** configuration now rejects route-decision
and request/response-header hooks attached to a WebSocket-enabled proxy scope.
Access-decision remains supported. Put header/routing hooks on an HTTP-only
route, or disable `websocket` for that scope. A vhost-wide attachment also
applies to its WebSocket routes, so move it to an HTTP-only named route when
separating the two. The runtime also rejects unsupported upgrades from
programmatically constructed configurations. This is an explicit restriction,
not implementation of those hooks during upgrades. The
[WebSocket guide](websocket.md) lists the separate upgrade-path blockers.

For example, keep the header-policy example on its HTTP-only route:

```toml
# Within the vhost containing the "gold" route:
[vhosts.routes.proxy]
upstreams = ["127.0.0.1:3000"]
websocket = false

[[wasm.attachments]]
plugin = "openresty_header_policy"
vhost = "example"
route = "gold"
phases = ["request-headers", "response-headers"]
```

This is a fragment of the [complete header example](../../examples/wasm/openresty-header-policy.toml).
For a separate WebSocket route, attach only an access-decision policy if needed;
do not attach the header policy at vhost scope. Access decisions cannot replace
the header or route transformations of an HTTP-only policy.

**Current limitation:** access hooks now cover the original
dispatch route, decoded-path policy route and any Wasm-selected route together
with vhost hooks. Shared attachments run once in configured priority order;
an allow does not override another attachment's denial or fail-closed error.
This corrects the earlier selection gap. Older binaries still need independent
origin authorization or equivalent native ACLs where affected.
[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
was implemented early at the owner's request; native qualification, pentest and
GitHub acceptance remain gates. See the
[ABI reference](../reference/wasm-policy-abi.md#decoded-route-gap-doc-wasm-004)
for the regression coverage and its scope. The upgrade restriction above is
the separate the local follow-up correction; native qualification and acceptance remain pending.

## Choose A Build

| Build option | Available functionality |
| --- | --- |
| Default build | No Wasm runtime; enabled Wasm configuration is rejected |
| Cargo feature `wasm` | Native `fluxheim-policy-v1` modules |
| `wasm-proxy-abi` | Native runtime plus the explicitly limited proxy compatibility preview |
| `wasm-wasi` | Native runtime plus the limited WASI Preview 1 capability preview |
| `profile-wasm` | Packaged server profile including native Wasm and both preview features |

Enabling a compiled feature does not enable plugins in configuration. Both
preview namespaces additionally require `allow_preview_abi = true`; leave it
false when using only native policy modules.

The privacy profile cannot be combined with Wasm. See the
[feature compatibility rules](../reference/features.md) before assembling a
custom build.

To build and exercise the shipped examples from a source checkout:

```sh
cargo build --locked --no-default-features --features profile-wasm --bin fluxheim
scripts/build_wasm_policy_examples.sh
scripts/smoke_wasm_policy_examples_binary.sh
```

The build script produces modules and `SHA256SUMS` in
`target/wasm-policy-examples/`. The standalone smoke launches a real Fluxheim
binary and loopback origins with generated configuration and exact module
digests. It does not deploy to your running service. Its Linux HTTP checks are
not proof of every protocol or native platform.

## Install A Module

1. Review the module and the permissions it needs. Start with a native example.
2. Build its WAT source using the example builder, or compile your own module
   against the actual bounded ABI.
3. Install the resulting binary beneath a dedicated plugin directory, for
   example `/etc/fluxheim/plugins`. The service must be able to read it.
4. Calculate its SHA-256 and put that exact digest in the plugin declaration.
5. Add an attachment to the intended vhost or named route.
6. Validate the deployment configuration, start a candidate process and test
   both allowed and denied traffic before replacing the service.

Do not use a broad plugin root such as `/` or `/etc`. Roots must be absolute,
scoped directories with at least three normal path components. Paths cannot
contain parent traversal components. Runtime loading checks path components
for links/reparse points, opens a regular file and bounds the bytes read.
Use real directories rather than symlink-based release pointers.

These path checks are not a substitute for ownership and ACL controls.
Keep the module directory and configuration non-writable by untrusted users
and preferably by the service identity. Pin **every** module. A digest checks
the loaded bytes against configuration; it does not authenticate whoever
supplied that configuration or prove the module's policy is correct.

**Current limitation:** Unix plugin opens now use nonblocking
mode together with no-follow protection, then verify that the opened handle is
a regular file. A FIFO is rejected without waiting for a writer, including when
the leaf changes after path checks. Normal reads, byte bounds and digest checks
are unchanged. [the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
was implemented early and still needs its acceptance gates. This is not a total
filesystem I/O deadline or atomic parent traversal. Deploy verified regular
artifacts in trusted directories and retain an external service startup timeout.

### Access-Denial Example

This is a configuration template, not a ready-to-run installation. Install
`irules-access-policy.wasm` from the example output and replace the all-`a`
digest below with its actual SHA-256. Provide an application at the configured
upstream address and merge the vhost into your normal listener configuration.

```toml
[wasm]
enabled = true
plugin_roots = ["/etc/fluxheim/plugins"]
max_total_concurrent_executions = 32

[wasm.default_admission]
max_concurrent_executions = 8
queue_limit = 0

[[wasm.plugins]]
name = "admin_policy"
path = "/etc/fluxheim/plugins/irules-access-policy.wasm"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
abi = "fluxheim-policy-v1"
host_call_namespace = "fluxheim-policy-v1"
phases = ["access-decision"]
fail_mode = "fail-closed"

[[wasm.attachments]]
plugin = "admin_policy"
vhost = "app"
route = "admin"
priority = 1000

[[vhosts]]
name = "app"
hosts = ["app.example"]

[vhosts.proxy]
upstreams = ["127.0.0.1:9000"]

[[vhosts.routes]]
name = "admin"
path_prefix = "/admin/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9000"]
```

The example module always denies where attached. `/admin/test` should return
403 without reaching the origin; an ordinary request outside this route should
reach the application. This is an attachment demonstration, not a login system.
The `/admin/` prefix does not mean every possible spelling of an administrative
URL is protected. Use the [routing guide](routing.md) and test the real
application's entry points.

`vhost` means the configured vhost **name**, not a client-controlled Host
header. `route` names an existing route within that vhost; omit it for a
vhost-scoped attachment. Omitted attachment `phases` uses the plugin's declared
phases; a supplied list must be a subset. Lower priorities run first; equal
priorities retain declaration order. Duplicate plugin/vhost/route attachments
are rejected.

## What A Plugin Can Decide

Each export below takes no arguments and returns an `i32`. The native import
module is `fluxheim_policy_v1` (underscores); the TOML ABI/namespace spelling is
`fluxheim-policy-v1` (hyphens). Do not interchange them.

| Phase / export | Successful decisions | Example |
| --- | --- | --- |
| `access-decision` / `fluxheim_access_decision` | 0 continue; 1 allow/continue; 2 deny with 403 | [Access policy](../../examples/wasm/irules-access-policy.wat) |
| `request-headers` / `fluxheim_request_headers` | 0 after bounded symbolic mutations | [Header policy](../../examples/wasm/openresty-header-policy.wat) |
| `response-headers` / `fluxheim_response_headers` | 0 after bounded symbolic mutations | Same header example |
| `route-decision` / `fluxheim_route_decision` | 0 continue; 1 select canary; 2 deny; 3 select mirror | [Routing policy](../../examples/wasm/haproxy-spoe-routing-policy.wat) |
| `cache-lookup` / `fluxheim_cache_lookup` | 0 normal; 1 pass without cache; 2 bypass cache; 3 deny | [Lookup policy](../../examples/wasm/cache-lookup-policy.wat) |
| `cache-store` / `fluxheim_cache_store` | 0 store normally; 1 skip storage; 2 deny | [Store policy](../../examples/wasm/cache-store-policy.wat) |

Unknown return values, traps, missing exports, timeouts and rejected admission
are failures, not additional decisions. Header exports must return **0**;
the access hook's allow value is not a universal success value.

Access allow means continue the chain, not override a later denial or native
access policy. Route decisions select existing matching routes named
`canary` or `mirror`; they cannot supply a backend address, arbitrary URL,
pool name or persistence key. Missing/nonmatching branches fail closed.
A mirror branch is a route selection, not direct permission to make an outbound
shadow request: normal configured [mirroring](traffic-mirroring.md) applies.

The shipped header example can set `x-policy-tier`, remove `x-powered-by`
and set `x-fluxheim-policy-branch`, using fixed integer IDs and fixed values.
It cannot inspect arbitrary header strings or construct arbitrary headers.

Cache hooks apply to the native **proxy cache**, not a general PHP/FastCGI
cache. The lookup example splits mobile/desktop variants using a bounded
symbolic device class. The store example chooses fixed TTL/tag/header values.
A stored `x-fluxheim-cache-policy` mutation appears on later cache hits, not
automatically on the original MISS response. A skip-storage result does not
hide a later deny in the store chain.

Signals such as `x-canary`, `x-mirror` and `X-Device-Class` are request
metadata, not credentials. Do not use those signals as proof of identity.

There is no guest API for arbitrary bodies, secret headers, cache objects,
filesystem/network/process access, admin operations, arbitrary synthetic
responses, streaming body mutation or arbitrary policy logs. Deny/error bodies
are generated by Fluxheim. Review the individual integration before assuming a
hook covers WebSocket upgrades, every early error or every protocol.

## Limits And Admission

All declared modules are loaded and compiled when the runtime registry is
constructed, even if a module has no attachment. Bad digests and failed
compilation prevent successful registry construction; request-time `fail-open`
is not a way to ignore those deployment failures. Phase-specific import linking
and export checks occur when a hook executes. A module can compile successfully
but fail on its first request, so validate actual traffic as well as startup.

Compiled modules are reused, but execution gets a fresh Wasmtime store and
instance. Memory, tables, fuel, execution time and admission are bounded.
The native, cache and preview families have separate process-wide admission
budgets. Plugin and attachment budgets add narrower limits; queues are bounded
and default to no waiting slots. These are execution budgets, not a promise of
a fixed total process RSS.

**Current limitation:** overrides now merge field by field.
Omitted fields inherit from the configured global defaults; an empty table is
equivalent to omitting all its fields. Explicit values always win, even if they
equal stock defaults. Plugin and attachment admission each inherit directly
from `wasm.default_admission`; attachment defaults do not come from the plugin.
Both budgets still apply independently, along with the process-wide ceilings.

[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
was implemented early and awaits its acceptance gates. Older binaries used
whole-table replacement, so repeat all intended values when configuring those.
Full explicit policies remain supported in the corrected version:

```toml
# Place directly after the relevant [[wasm.plugins]] declaration.
[wasm.plugins.limits]
max_module_bytes = "1MiB"
max_compiled_artifact_bytes = "32MiB"
max_memory_bytes = "1MiB"
max_table_elements = 1000
fuel = 1000
timeout_ms = 10
compile_timeout_ms = 500

[wasm.plugins.admission]
max_concurrent_executions = 2
queue_limit = 0

# Place directly after the relevant [[wasm.attachments]] declaration.
[wasm.attachments.admission]
max_concurrent_executions = 1
queue_limit = 0
```

For a partial override, place these tables after the relevant plugin declaration:

```toml
[wasm.plugins.limits]
timeout_ms = 10

[wasm.plugins.admission]
queue_limit = 2
```

With global fuel 1000, memory 1 MiB and concurrency 1, this changes only the
execution timeout and queue capacity; it keeps those three global restrictions.
Setting `fuel = 5000000` explicitly would instead reset fuel to that value.

Included fragments also merge supplied default-limit/admission fields into
the preceding defaults. An empty default table changes nothing. Plugin
overrides resolve against the final merged defaults, not the values present
when a plugin's fragment was first read. These changes still require process
upgrade; they are not live-reloaded into an existing compiled runtime.

Tune limits with your real module: very small fuel or memory limits may reject
legitimate work. Effective settings are validated against the hard ceilings.

`compile_timeout_ms` is a **result deadline**, not hard cancellation.
Compilation is synchronous; an over-deadline compile finishes and is rejected.
Serialized compiled-artifact size is checked after compilation and is not an
engine heap-allocation limit. Use OS/container CPU and memory limits as well.

Native host callbacks cannot be forcibly preempted while executing Rust.
The runtime checks deadlines before and after callbacks, but a callback that
never returns cannot be made safe by an in-process timeout. New blocking or
third-party callbacks require a separately reviewed, killable worker design.
Wasm is not a process boundary against a compromised engine or host callback.

## Failure Policy

`access-decision`, `route-decision` and `cache-store` require both
`sha256` and `fail_mode = "fail-closed"`. Header hooks and cache lookup
permit fail-open configuration; use it only when missing the policy is
acceptable. If a lookup hook is used to deny access, fail-open is inappropriate
even though configuration permits it.

In fail-closed mode a policy denial produces 403 and operational failures may
produce a fixed error response such as 503. Do not make applications depend on
arbitrary guest exception text. Test trap, overload and timeout paths as well
as the intended successful response.

## Compatibility Previews

### Proxy ABI

Requires feature `wasm-proxy-abi`, `allow_preview_abi = true`, and both ABI
and namespace set to `proxy-wasm-preview`. Only `access-decision` is allowed,
with its digest and fail-closed requirements.

This is **not general proxy-wasm compatibility**. The fixture's
`env.proxy_log(i32, i32, i32) -> i32` import has the expected shape but invocation
is deliberately rejected as unsupported. Native policy host functions are not
available to preview plugins.

### WASI

Requires feature `wasm-wasi`, `allow_preview_abi = true`, and both ABI and
namespace set to `wasi-preview`. Only access decisions are supported.
See the [complete source example](../../examples/wasm/wasi-random-policy.toml);
replace its digest and install its compiled module before use.

```toml
# In [wasm]:
allow_preview_abi = true
# In the plugin declaration:
abi = "wasi-preview"
host_call_namespace = "wasi-preview"
phases = ["access-decision"]
# Immediately after that declaration:
[wasm.plugins.wasi]
clocks = false
randomness = true
```

The default capability set is empty. `clocks` permits only `clock_res_get`
and `clock_time_get`; `randomness` permits only `random_get`, capped at
4096 bytes per call. Imports for arguments, environment, stdio, paths,
filesystem descriptors, sockets, polling and process exit are rejected.
The fresh context does not inherit the Fluxheim process environment.

Clock access exposes full-resolution wall/monotonic time. Do not enable it for
untrusted multi-tenant plugins beside secret-dependent work merely because it
sounds harmless. Both previews share a separate bounded admission pool;
neither gains the native header, routing or cache host calls.

## Deploying In Containers

Use a Wasm-capable image/profile. Mount the plugin directory read-only at the
same absolute path declared in configuration, and keep configuration read-only
too. For Podman on SELinux, a dedicated mount might be:

```yaml
volumes:
  - /srv/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z
```

Do not relabel a directory shared by other unrelated containers without
planning its SELinux policy. A read-only mount protects against container
writes, **not host-side replacement**. The host directory must remain trusted.
An attacker able to edit both the module and its configured digest can replace
the policy despite pinning.

Alternatively, bake reviewed modules and non-secret configuration into a
derivative image. Pin the base image and deployed image by digest, retain the
non-root service identity and use a read-only root filesystem where possible.
Keep keys, tokens and ACME credentials outside the image. Image digests and
module checksums complement deployment trust; they are not plugin correctness
or independent provenance proofs.

## Updating Plugins And Observing Them

A change to the Wasm configuration is classified as **process-upgrade**, not
live plugin hot swap. Stage the new file and digest together, validate the
candidate, restart/upgrade the process through your deployment mechanism and
run acceptance requests. Do not expect an unchanged config plus an edited
module file to trigger a reload or replace an already compiled module.

With Wasm compiled, authenticated `GET /_fluxheim/status` reports configured
registry information: names, paths, `expected_sha256`, phases, ABI/namespace,
budgets and attachment scopes. It does **not** attest the loaded runtime hash
or report a new hot-reloaded generation. Use the control-token requirements in
the [admin reference](../reference/config-reference.md#admin); the observer-only
operational-status endpoint is not interchangeable with this route.

With metrics wired in the server build, the Wasm families are:
- `fluxheim_wasm_plugin_executions_total`
- `fluxheim_wasm_plugin_execution_seconds`
- `fluxheim_wasm_plugin_admission_rejections_total`

See [metrics and observability](observability.md) for listener/export setup.
Do not assume planned compile-cache or generation metrics exist.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Wasm configuration rejected by the binary | Use a Wasm-enabled build, then enable `[wasm]` |
| Root/path rejected | Scoped absolute directory, no links or traversal, file readable by service |
| Digest mismatch | Hash the deployed binary, not WAT source; update configuration and file together |
| Import/export failure | Exact namespace, phase-specific imports, export name and function signature |
| Policy never applies | Enabled registry, correct vhost name/route, matching path/method and attachment phases |
| Unexpected 503 or rejected execution | Invalid decision, trap, fuel/deadline, admission capacity or missing route branch |
| Limits differ from the global table | Check explicit override fields; older binaries have the documented limitation whole-table behavior |
| Edited module still runs old policy | Existing compiled registry; perform the required process upgrade |
| Header absent on MISS but present on HIT | Cache-store header mutation changes the cached object only |

For local qualification run `scripts/smoke_wasm_sandbox.sh` for engine limits
and `scripts/smoke_wasm_policy_examples_binary.sh` for real policy traffic.
The [coverage ledger](../reference/documentation-coverage.md) records which
checks were actually rerun and what remains to audit. Historical
[example evidence](../evidence/wasm-policy-example-parity.md) is not a fresh
cross-platform release gate.
