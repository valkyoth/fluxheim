# WASM Extensibility

Status: active `1.7` optional module family after the `1.6` Pingora-free
runtime line. Fluxheim `1.7.0` ships the first sandbox foundation:
compile-time feature gates, strict plugin-file loading, bounded Wasmtime
execution, and real Wasm smoke coverage. Request/response policy hooks,
proxy-ABI compatibility, and WASI capabilities remain staged for later `1.7.x`
releases.

Cargo features:

- `wasm`
- `wasm-proxy-abi`
- `wasm-wasi`

Latest crate candidates checked on 2026-07-03:

- `wasmtime 46.0.1`
- `wasmtime-wasi 46.0.1`
- `proxy-wasm 0.2.4`
- `wat 1.252.0`

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

The first useful policy-hook scope should cover the common extension cases
without exposing request bodies or arbitrary I/O.

Allowed hooks:

- request headers before upstream selection;
- response headers before sending to the client;
- access-control decision: allow, deny with status, or continue;
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

Compiled modules should be cached only with strong isolation by module hash,
ABI version, feature set, and Fluxheim version.

## Security Requirements

- Disabled by default at compile time and runtime.
- Plugin files must be regular files below approved directories.
- Plugin paths must reject symlinks and symlinked parents.
- Plugin modules must be hashed and recorded in admin status.
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
[wasm.plugins.security_headers]
path = "/etc/fluxheim/plugins/security_headers.wasm"
abi = "proxy"
max_memory = "32MiB"
fuel = 5000000
timeout = "5ms"
fail_mode = "fail_closed"

[[vhosts]]
name = "example"
hosts = ["example.com"]

[[vhosts.wasm]]
plugin = "security_headers"
phase = "response_headers"
paths = ["/*"]
```

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
