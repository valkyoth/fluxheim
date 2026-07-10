# WASM Extensibility

Status: active `1.7` optional module family after the `1.6` Pingora-free
runtime line. Fluxheim `1.7.0` shipped the first sandbox foundation:
compile-time feature gates, strict plugin-file loading, bounded Wasmtime
execution, and real Wasm smoke coverage. Fluxheim `1.7.1` starts live
request-path execution with native HTTP/1 access-decision hooks. Fluxheim
`1.7.2` adds bounded native HTTP/1 request-header and response-header hooks.
Fluxheim `1.7.3` starts bounded native HTTP/1 route-decision hooks with
configured canary and mirror branch selection, including selected native
load-balanced and persistent routes. Fluxheim `1.7.4` starts bounded
cache-policy hooks with cache-lookup decisions that can continue, pass, bypass,
or deny before cache lookup and storage, plus cache-store decisions that can
continue, skip storage, or deny after origin response and before cache write.
Fluxheim `1.7.5` adds the first bounded symbolic cache-key component hook for
low-cardinality cache variants plus fixed-ID cache-store TTL/tag/header
metadata. Fluxheim `1.7.6` starts the mature-runtime hardening pass by giving
compiled modules explicit cache identities scoped by plugin SHA-256 digest, ABI
version, native feature surface, and Fluxheim version. Fluxheim `1.7.7` adds
the opt-in `wasm-proxy-abi` compatibility preview boundary with explicit
host-call namespace validation and deterministic unsupported-call rejection.
Direct backend choice, plugin-provided persistence keys, dynamic mirror/shadow
target choice, richer store policy hooks, broader Proxy-ABI compatibility, and
WASI capabilities remain staged for later `1.7.x` releases.

Cargo features:

- `wasm`
- `wasm-proxy-abi`
- `wasm-wasi`

Latest crate candidates checked on 2026-07-10:

- `wasmtime 46.0.1`
- `wasmtime-wasi 46.0.1`
- `proxy-wasm 0.2.4`
- `wat 1.253.0`

WASM extensibility gives Fluxheim a sandboxed way to run operator-provided
logic without compiling that logic into the Fluxheim binary. It should be
treated as a major extension boundary, not as a small scripting feature. The
same runtime should cover the operational jobs commonly solved with F5 iRules,
nginx Lua/OpenResty, HAProxy Lua/SPOE, and VCL-like cache policy hooks, instead
of creating separate partial extension systems. This is capability parity, not
syntax compatibility: Fluxheim should expose typed, versioned host calls and
bounded decisions rather than embedding Tcl, Lua, or an unrestricted scripting
language.

The end-of-line example and test requirements for F5 iRules-style policy,
nginx Lua/OpenResty-style header policy, HAProxy Lua/SPOE-style routing and
load-balancer policy, and VCL-like cache policy are tracked in
[Wasm Policy Example Parity](wasm-policy-example-parity.md).

## Proxy-ABI Compatibility Preview

Fluxheim `1.7.7` reserves a separate `proxy-wasm-preview` ABI and host-call
namespace for compatibility work. This path is intentionally opt-in:

- the binary must be built with `wasm-proxy-abi`;
- config must set `[wasm].allow_preview_abi = true`;
- the plugin must declare `abi = "proxy-wasm-preview"`;
- the plugin must declare `host_call_namespace = "proxy-wasm-preview"`.
- the plugin may currently declare only the `access-decision` phase.

The preview namespace does not mean arbitrary existing proxy-wasm plugins run
unchanged. Unsupported preview host calls are rejected deterministically through
the plugin fail mode, and security-decision plugins still fail closed. Fluxheim
keeps this namespace separate from `fluxheim-policy-v1` so native policy hooks
cannot accidentally bind to a future proxy-oriented compatibility surface.
The `1.7.7` compatibility fixture imports the canonical proxy-wasm
`env.proxy_log(i32, i32, i32) -> i32` function and verifies that invoking it is
rejected before the origin is reached. This deliberately tests a real ABI shape
without claiming logging or guest-memory access semantics that are not yet
implemented.
Imports that are not explicitly bound for the selected namespace are rejected
before module instantiation. A plugin therefore cannot obtain a host capability
by declaring an unexpected module or function name.
Fluxheim also scopes phase-specific native host functions by namespace in the
server. Preview plugins never receive `fluxheim_policy_v1` request-header,
routing, or cache capabilities, even if a future construction path bypasses
configuration validation.

## Design Goals

- Keep WASM runtime code out of default builds.
- Use a reviewed standard ABI where practical.
- Start with request/response header hooks, access-control hooks, and bounded
  cache-policy hooks.
- Cover the safe subset of iRules/Lua-style jobs over time: conditional
  routing, pool selection, persistence-key choice, synthetic deny/error
  responses, header mutation, logging/redaction, mirror/shadow selection, and
  cache policy.
- Make all host calls explicit, small, and auditable.
- Keep plugin execution bounded by memory, fuel, wall-time, and output limits.
- Prevent plugins from seeing secrets, bodies, filesystem, network, or admin
  APIs unless explicitly granted by policy.
- Make plugin failures isolated from the process and from unrelated requests.

## Stage 1: Header, Access-Control, And Cache Policy Hooks

The first implementation slice is the sandbox foundation: `fluxheim-wasm`
loads plugin files from approved roots, rejects symlinked plugin paths and
oversized modules, records SHA-256 module hashes, and executes real Wasm under
fuel, memory, table-element, table/instance, compile-timeout, and wall-time
limits. It also defines a typed plugin manifest boundary for plugin name, path,
ABI, phase, fail-mode, and per-plugin sandbox limits. The manifest-backed
loader validates the manifest and then loads the exact approved plugin path
with the validated limits; production hook execution still starts later in the
`1.7` line.

Compiled modules carry a stable identity that includes the loaded plugin digest,
the manifest ABI version, the host-call namespace, the native hook feature
surface used to compile it, and the Fluxheim crate version. Any future compile
cache must use that full identity as the cache key so module reuse cannot cross
ABI, namespace, feature, or release boundaries.

The first useful policy-hook scope should cover the common extension cases
without exposing request bodies or arbitrary I/O.

The first live request-path hook is `access-decision`. Multiple plugins may
attach to the same phase and vhost/route, so attachments use explicit
`priority`; lower priorities run first and equal priorities keep declaration
order. Security decisions use a safe default: `access-decision` is
`first-deny-wins`. Built-in Fluxheim access policy runs before Wasm and cannot
be overridden by a plugin.

The `1.7.1` preview access ABI calls an exported
`fluxheim_access_decision() -> i32` function:

- `0`: continue to the next plugin;
- `1`: allow/continue;
- `2`: deny with `403`.

Any other value, trap, timeout, compile error, or admission rejection is treated
as a plugin failure. Security-decision plugins are validated as `fail-closed`,
so failures deny instead of silently allowing traffic.

Fluxheim `1.7.2` adds the first header hook ABI. Plugins attached to
`request-headers` export `fluxheim_request_headers() -> i32`; plugins attached
to `response-headers` export `fluxheim_response_headers() -> i32`. The current
`fluxheim_policy_v1` host calls are deliberately symbolic:

- `context(kind, unused) -> i32` returns bounded request context such as a path
  class;
- `set_request_header(name_id, value_id) -> i32` sets only allow-listed
  synthetic request headers;
- `set_response_header(name_id, value_id) -> i32` sets only allow-listed
  synthetic response headers;
- `remove_response_header(name_id, unused) -> i32` removes only allow-listed
  response headers.

The preview IDs currently cover the nginx-Lua/OpenResty-style example tracked
for `v1.7.2`: add `x-policy-tier`, remove upstream `x-powered-by`, and add
`x-fluxheim-policy-branch`. Raw header values, `Authorization`, `Cookie`,
`Set-Cookie`, request/response bodies, filesystem, network, process, private
key, and admin API access are not exposed.

Fluxheim `1.7.3` adds the first routing hook ABI. Plugins attached to
`route-decision` export `fluxheim_route_decision() -> i32`. The current preview
return values are deliberately narrow:

- `0`: continue with normal route selection;
- `1`: select the configured matching route named `canary`;
- `2`: deny with `403`;
- `3`: select the configured matching route named `mirror`.

The route decision host-call surface reuses `context(kind, unused) -> i32` for
bounded symbolic inputs. The first routing example exposes only the path class,
whether the request carried `x-canary: 1`, and whether the request carried
`x-mirror: 1`. A selected branch is accepted
only when it maps to an existing configured route that still matches the
current request method and path. Unknown or unavailable branches fail closed
with `503`.

The `mirror` branch does not let Wasm create a shadow destination. It only
selects an already configured matching route named `mirror`; the route's normal
`[proxy.mirror]` policy still controls target URL, method allow-list, sampling,
timeouts, in-flight limits, and recursion protection.

The selected route may use the normal native load-balancer pipeline. Wasm does
not receive backend addresses or choose individual upstream members in this
preview; it selects a configured matching route, and Fluxheim's existing
load-balancer policy chooses the backend.

Configured persistence on a selected route also remains Fluxheim-owned. The
`1.7.3` coverage proves managed-cookie persistence still pins the selected
backend after a Wasm route decision. Plugins do not provide arbitrary
persistence keys in this preview.

Route decisions run only after the built-in vhost ACL, vhost rate-limit, vhost
concurrency, and preselected/decoded-route ACL gates. If the plugin selects a
different configured route, that selected route's ACL and route-specific
rate/concurrency limits are checked before Fluxheim proceeds.

Fluxheim `1.7.4` adds the first cache-policy hook ABIs. Plugins attached to
`cache-lookup` export `fluxheim_cache_lookup() -> i32`:

- `0`: continue normal cache lookup and storage;
- `1`: pass through origin without cache lookup or storage;
- `2`: bypass cache lookup and storage;
- `3`: deny with `403`.

The cache lookup host-call surface deliberately reuses only bounded symbolic
request context. Fluxheim `1.7.5` adds the first bounded cache-key mutation
host call:

- `context(5, 0)` returns a symbolic device class derived from
  `X-Device-Class`: `0` for unset/unknown, `5` for `mobile`, and `6` for
  `desktop`;
- `set_cache_key_component(1, 5)` adds the low-cardinality
  `wasm-device-class=mobile` cache-key component;
- `set_cache_key_component(1, 6)` adds the low-cardinality
  `wasm-device-class=desktop` cache-key component.

Any other cache-key component ID, value ID, duplicate component, or component
count above the hard cap fails the hook through the plugin fail mode. Plugins
still cannot emit arbitrary cache-key bytes or raw request headers. The lookup
hook runs before native proxy-cache slice lookup, normal lookup, peer-fill,
request collapsing, origin-fill protection, and store admission, but after
Fluxheim's built-in access, route, rate-limit, concurrency, and header policy
gates. Wasm-selected cache-key components are part of the complete-object,
single-range, and fixed-slice range-cache keys, so a bounded variant selected
by a plugin cannot share slice objects with another variant for the same URL.

Plugins attached to `cache-store` export `fluxheim_cache_store() -> i32`:

- `0`: continue normal cache storage;
- `1`: serve the origin response but skip storage;
- `2`: deny with `403`.

The cache store host-call surface exposes only the path class, response status,
symbolic response content-type class, fixed TTL IDs, fixed tag IDs, and one
fixed stored response-header family.
Plugins can call `set_cache_ttl(1, 0)` for a short bounded TTL,
`set_cache_ttl(2, 0)` for a medium bounded TTL, `add_cache_tag(1, 0)` for
`wasm-policy`, `add_cache_tag(2, 0)` for `wasm-gold`,
`set_cache_store_header(1, 1)` for `x-fluxheim-cache-policy: wasm`, or
`set_cache_store_header(1, 2)` for `x-fluxheim-cache-policy: gold`. Duplicate
TTL overrides, unknown TTL/tag/header IDs, duplicate stored-header mutations,
and mutation counts above the hard caps fail through the plugin fail mode. It
runs after an origin response and before memory/disk cache writes. Raw headers,
request bodies, arbitrary cache-key bytes, arbitrary TTLs, arbitrary tag
strings, arbitrary stored response headers, cached objects, and response-store
body mutation are not exposed in `1.7.5`.

Cache-store response-header inspection is also symbolic. `context(6, 0)`
returns `0` for unset/other, `7` for image media types, `8` for HTML, `9` for
JSON, and `10` for text media types. Plugins cannot read raw response header
names or values through this cache-store surface.

Cache-store chains use the same restrictive aggregation model as other hook
families: every hook runs unless a hook returns `deny`; an earlier `skip` does
not mask a later `deny`. Cache-key components are also aggregated across the
full chain with duplicate-label rejection and a hard total component cap; one
plugin cannot silently overwrite or multiply another plugin's cache-key
variant. Cache-store tag and stored-header caps are scoped to their own
metadata families so exhausting one family cannot drop the other.

`examples/wasm/cache-lookup-policy.wat` and
`examples/wasm/cache-store-policy.wat` show the shipped `1.7.5` cache-policy
subset as concrete Wasm Text modules, and `examples/wasm/cache-policy.toml`
shows the matching plugin/attachment config shape. The example is test-backed
by a live native HTTP/1 listener test that compiles the checked-in sources and
verifies mobile/desktop cache variants, image-only store metadata, short TTL
expiry, and fixed stored response headers.

Allowed hooks:

- request headers before upstream selection;
- response headers before sending to the client;
- access-control decision: allow, deny with status, or continue;
- route decision: continue, deny, or select a configured matching symbolic
  route branch;
- cache lookup/admission decision: bypass, pass, continue, or deny;
- bounded cache-key component decision with typed inputs and low-cardinality
  output limits;
- cache store-admission decision for TTL override, tag assignment, and safe
  response-header mutation;
- synthetic response with small bounded body for deny/error cases.

Non-goals for the first stage:

- streaming body mutation;
- filesystem access;
- outbound network access;
- spawning processes;
- direct raw cache object access;
- admin/control API access.

## Stage 2: Proxy ABI Compatibility

Fluxheim should evaluate a proxy-oriented WASM ABI rather than inventing a
large custom API.

Compatibility goals:

- map Fluxheim request/response lifecycle into a stable plugin contract;
- expose only the subset of ABI calls Fluxheim can implement safely;
- reject unsupported ABI calls with deterministic errors;
- version the host ABI and require plugin compatibility checks at startup;
- support per-vhost and per-route plugin attachment.

Compatibility does not mean every existing plugin should run unchanged. The
security boundary and host-call behavior must stay explicit.

## Stage 3: WASI And Policy Plugins

WASI should be separate from header/access-control plugins.

Potential use cases:

- media policy decisions;
- custom auth decision transforms;
- custom log redaction;
- specialized request classification;
- feature-specific plugins that do not need direct filesystem or network
  access.

WASI capabilities must be disabled by default and granted explicitly:

- no filesystem by default;
- no network by default;
- no clocks beyond coarse time unless needed;
- no randomness beyond host-provided safe APIs;
- no environment variables by default;
- no inherited process state.

## Resource Limits

Required limits:

- maximum module size;
- maximum compiled artifact size;
- maximum linear memory;
- maximum table elements;
- maximum fuel/instruction budget;
- maximum compile time;
- maximum concurrent compile workers;
- maximum wall-time;
- maximum log bytes emitted by plugin;
- maximum header mutations;
- maximum synthetic response size;
- maximum per-vhost concurrent plugin executions.
- maximum process-wide concurrent plugin executions;
- maximum process-wide Wasm memory or instance budget where Wasmtime exposes a
  reliable enforcement point.

Fluxheim `1.7.1` compiles each live hook module when the native WASM hook
registry is built and reuses that compiled module on the request path. Each
request still receives a fresh Wasmtime store and instance for isolation.
Future cross-generation module caches must remain isolated by module hash, ABI
version, feature set, and Fluxheim version.

Per-plugin and per-attachment admission budgets are not enough by themselves.
Fluxheim must also enforce a top-level admission ceiling such as
`wasm.max_total_concurrent_executions` before any live hook release. Otherwise
many individually-safe plugins can multiply into unsafe process-wide memory or
instance pressure.

Cache-policy hooks are isolated from the security-decision admission pool with
their own process-wide ceiling, `wasm.max_total_cache_concurrent_executions`.
This keeps a hot cacheable route with `cache-lookup` or `cache-store` hooks
from starving access-decision, route-decision, and header hooks on unrelated
vhosts.

## Security Requirements

- Disabled by default at compile time and runtime.
- Plugin files must be regular files below approved directories. Config
  validation rejects plugin declarations unless every plugin path is under one
  of the configured `wasm.plugin_roots`.
- Plugin roots must be scoped directories, not `/` or top-level system
  directories such as `/etc`; use deployment-specific roots such as
  `/etc/fluxheim/plugins` or `/srv/fluxheim/plugins`.
- Plugin paths must reject symlinks and symlinked parents.
- Plugin modules must be hashed and recorded in admin status.
- Plugins attached to security-decision phases (`access-decision`,
  `route-decision`, or `cache-store`) must pin `sha256` in config before they
  are accepted.
- Host calls must never expose admin tokens, ACME/EAB secrets, private keys,
  authorization headers, cookies, raw request bodies, or filesystem paths unless
  explicitly allowed and redacted.
- Plugins must not control routing destinations or upstream TLS verification
  directly. Cache-key influence is allowed only through constrained typed hook
  outputs that Fluxheim validates, bounds, and records.
- Plugin panics, traps, timeout, or fuel exhaustion must produce configured
  fail behavior and must not crash Fluxheim.
- `privacy-mode` should reject WASM features by default.
- WASM engine dependencies require license, advisory, and supply-chain review.

## Configuration Sketch

```toml
[wasm]
enabled = true
plugin_roots = ["/etc/fluxheim/plugins"]
max_total_concurrent_executions = 256
max_total_cache_concurrent_executions = 256

[[wasm.plugins]]
name = "security_headers"
path = "/etc/fluxheim/plugins/security_headers.wasm"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
abi = "fluxheim-policy-v1"
host_call_namespace = "fluxheim-policy-v1"
phases = ["response-headers"]
fail_mode = "fail-closed"

[wasm.plugins.limits]
max_module_bytes = "1MiB"
max_memory_bytes = "16MiB"
max_table_elements = 10000
fuel = 5000000
timeout_ms = 50
compile_timeout_ms = 500

[[wasm.attachments]]
plugin = "security_headers"
vhost = "example"
priority = 100
phases = ["response-headers"]

[[vhosts]]
name = "example"
hosts = ["example.com"]

[[vhosts.routes]]
name = "static"
path_prefix = "/static/"

[vhosts.routes.web]
root = "/srv/example/static"
```

`wasm.enabled = true` is accepted only by binaries built with Fluxheim's `wasm`
feature. Default and privacy-oriented builds reject non-empty `[wasm]` config
during validation so a plugin registry cannot be configured without a runtime
that can eventually enforce it.

The config crate converts validated plugin declarations into
`fluxheim-wasm` loader manifests. Per-plugin sandbox limits override
`[wasm.default_limits]`; omitted limits inherit the defaults. If `sha256` is
set on a plugin, the loader rejects a plugin file whose actual SHA-256 digest
does not match.

`wasm.max_total_concurrent_executions` caps total concurrent plugin executions
across the whole process. Per-plugin and per-attachment admission budgets are
still enforced inside that global ceiling. Fluxheim acquires attachment,
plugin, optional cache-vhost, and finally process-wide permits, so requests
waiting on a narrow policy cannot reserve broader process capacity. Admission
is implemented with Tokio semaphores and is complete before work is submitted
to Tokio's blocking pool. `queue_limit = 0` rejects immediately at the
configured concurrency limit; a positive value permits only that many async
waiters and never enlarges the blocking-work queue. Active and queued budgets
are each hard-capped at `256`. Immediately before blocking submission, Wasm
also acquires Fluxheim's shared request-driven blocking-work budget. Wasm has a
`96`-execution class ceiling beneath the `224` non-critical and `256` total
ceilings, so it cannot starve external auth, disk-cache work, traffic mirrors,
or the `32` slots reserved for critical ACME work. Runtime wall-time enforcement
uses one process-wide shared epoch ticker rather than one OS watchdog thread per
invocation.

`wasm.max_total_cache_concurrent_executions` caps total concurrent
`cache-lookup` and `cache-store` plugin executions across the whole process.
The cache-specific ceiling is intentionally separate from
`wasm.max_total_concurrent_executions` so cache-policy load cannot exhaust the
admission pool used by security and routing hooks.

`[[wasm.attachments]].priority` controls chain order for plugins attached to
the same phase and vhost/route. Lower numeric priorities run first; ties use
the declaration order in the loaded config. Access decisions use
`first-deny-wins` and are active for native HTTP/1 route proxy traffic in
`1.7.1`.

Config fragments preserve explicit resets to stock WASM defaults. A later
`conf.d` fragment can set `[wasm.default_limits]` or
`[wasm.default_admission]` back to the documented defaults and the loader will
apply that reset instead of treating it as an omitted section.

Authenticated `/_fluxheim/status` responses include a WASM registry summary
when Fluxheim is built with `wasm`: enabled state, plugin/attachment counts,
plugin names, phases, fail modes, and expected SHA-256 digests. Runtime loaded
plugin hash exposure remains staged for a later status slice.

`1.7.1` validates the registry and attachment declarations and enables the
first native HTTP/1 access-decision request-path hook. `1.7.2` adds bounded
request-header and response-header mutation. `1.7.3` adds the first bounded
route-decision hook with configured `canary` and `mirror` branch selection,
including live coverage for selected native load-balanced and managed-cookie
persistent routes. `1.7.4` adds bounded cache-lookup decisions before cache
lookup/storage and bounded cache-store skip/deny decisions before cache writes.
`1.7.5` adds bounded symbolic cache-key components with low-cardinality live
variant coverage plus fixed-ID TTL/tag/header store metadata. `1.7.6` adds
compiled-module identities and a derived per-vhost cache-hook admission layer
under `wasm.max_total_cache_concurrent_executions`, so one vhost cannot consume
the whole cache-hook process budget. Direct backend pool/member choice,
plugin-provided persistence-key choice, dynamic mirror/shadow target choice,
and richer store policy hooks remain staged for later `1.7.x` releases.

## Reload Semantics

WASM configuration must stay explicit in reload-impact classification. Changes
to plugin path, expected hash, ABI, feature flags, sandbox limits, admission
budgets, attachment order, or attachment targets must not fall through to a
generic snapshot classification by accident.

The default policy for the first live hook release should be conservative:
validate the new registry, build a new module/cache generation, and atomically
swap only after all affected modules are loadable under the new limits. Any
change that cannot be proven reload-safe must require restart or be rejected by
the reload path with a clear diagnostic.

## Observability

WASM hooks need first-class operator visibility from the first live hook
release. Metrics and traces must use low-cardinality labels such as plugin
name, phase, vhost/route scope, ABI, and outcome. They must not include raw
request paths, headers, secrets, or plugin-returned arbitrary strings.

Required metrics include:

- plugin invocations and completed decisions;
- execution duration;
- traps, panics, timeouts, compile timeouts, and fuel exhaustion;
- global, cache-global, cache-vhost, per-plugin, and per-attachment admission
  rejections;
- fail-open and fail-closed outcomes;
- loaded module count and module-cache generation/hash changes;
- reload validation, load, swap, and rejection outcomes.

## Test Plan

- Run `scripts/smoke_wasm_sandbox.sh` to execute a real Wasm decision module
  and verify that an infinite-loop module traps under sandbox limits and table
  growth past the configured cap is denied. The smoke also validates an
  accepted manifest and rejects unsafe `fail_open` security-decision manifests.
- Reject missing, symlinked, oversized, and invalid plugin files.
- Reject symlinked approved plugin roots.
- Verify Unix plugin opens use `O_NOFOLLOW` where available and reject file
  identity changes between validation and read.
- Reject unsupported ABI versions.
- Verify request header mutation within limits.
- Verify response header mutation within limits.
- Verify deny decisions and synthetic responses.
- Verify two plugins attached to the same phase and target execute in
  deterministic order.
- Verify `access-decision` composition is `first-deny-wins`.
- Verify native HTTP/1 live access hooks load real Wasm modules and deny
  traffic before upstream forwarding.
- Verify process-wide admission rejects excess concurrent plugin executions
  even when each plugin's individual budget has not been exhausted.
- Verify cache-hook admission applies a process-wide ceiling and a per-vhost
  fair-share ceiling so one vhost cannot starve another vhost's cache hooks.
- Verify WASM registry changes are classified by reload impact and do not fall
  through to the generic snapshot bucket.
- Verify per-plugin metrics are emitted for success, deny, timeout, trap, fuel
  exhaustion, admission rejection, and fail-mode behavior.
- Verify plugins cannot access bodies, filesystem, network, env, or admin APIs
  without capability grants.
- Verify fuel exhaustion, timeout, compile timeout, table-element limit, trap,
  and panic behavior.
- Verify unrelated engine epoch ticks cannot prematurely interrupt an
  invocation before its own deadline.
- Verify fail-open and fail-closed policy behavior.
- Verify sensitive field redaction.
- Verify plugin execution is isolated per request.
- Verify WASM code is absent from default and privacy builds.
