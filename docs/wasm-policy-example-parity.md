# Wasm Policy Example Parity

Status: acceptance plan for the `1.7` Wasm line. These examples are not all
implemented in `1.7.0`; they are required outcomes before the `1.7` line is
considered complete.

Fluxheim is not trying to embed Tcl, Lua, SPOE, or VCL interpreters. The goal is
capability parity through a small typed Wasm ABI with explicit resource limits,
redaction, and deterministic failure behavior.

## Required Example Families

Every family below must have:

- a documented operator-facing example;
- a real Wasm plugin fixture checked into the repository;
- a Fluxheim config fixture that attaches the plugin to a vhost or route;
- a live smoke script that starts Fluxheim, sends real HTTP traffic, and
  validates the observable result;
- unit tests for ABI encoding/decoding and rejection paths;
- release-gate coverage through `scripts/test_starter.py`.

### F5 iRules-Style Policy

Capability target:

- conditional allow, deny, or continue decisions;
- bounded synthetic deny/error response;
- simple route classification from host, path, method, trusted client IP, TLS
  facts, and selected runtime facts;
- no direct upstream address control and no direct TLS verification control.

Representative example:

```text
If the request path starts with /admin and the restored client IP is outside
the allowed CIDR set, return 403 with a small synthetic response. Otherwise
continue to the configured route.
```

Required live test:

- allowed client receives the origin response;
- denied client receives the plugin's 403 response;
- plugin timeout/trap follows the configured fail mode;
- the plugin cannot read request bodies, filesystem paths, admin tokens, or
  upstream TLS secrets.

Target release: `v1.7.1`.

### nginx Lua/OpenResty-Style Header Policy

Capability target:

- request header mutation before upstream selection;
- response header mutation before the response is sent;
- bounded header count, name, and value lengths;
- explicit redaction rules for sensitive headers.

Representative example:

```text
Add x-policy-tier based on the request path, remove x-powered-by from the
response, and attach a short response header that identifies the selected
policy branch.
```

Required live test:

- origin observes the plugin-added request header;
- client observes the plugin-added response header;
- oversized or forbidden header mutations are rejected;
- Authorization, Cookie, Set-Cookie, private keys, and admin credentials are
  not exposed to the plugin unless a future explicit capability allows it.

Target release: `v1.7.2`.

Status: implemented in `v1.7.2` for the bounded preview ABI. The live listener
coverage is in
`crates/fluxheim-server/src/native_http1_route_proxy_tests/wasm.rs` and proves
`x-policy-tier` request mutation, `x-fluxheim-policy-branch` response mutation,
`x-powered-by` response removal, and fail-closed rejection of forbidden header
mutation IDs. The ABI remains symbolic and does not expose raw sensitive
headers or bodies.

### HAProxy Lua/SPOE-Style Routing And Load-Balancer Policy

Capability target:

- bounded typed decisions for pool choice, persistence-key choice,
  mirror/shadow enablement, and deny/pass/continue outcomes;
- no arbitrary network I/O from the plugin;
- all decisions constrained to configured routes, pools, and mirrors.

Representative example:

```text
Choose a canary pool for requests carrying x-canary: 1, derive a persistence
key from a bounded request header, and mirror only safe GET requests to a
configured shadow route.
```

Required live test:

- two local origins prove the selected pool is honored;
- persistence key keeps repeated requests pinned as configured;
- mirror/shadow decisions never recurse and only target configured mirrors;
- a plugin trying to choose an unknown pool is rejected deterministically.

Target release: `v1.7.3`.

Status: first subset implemented in `v1.7.3` for native HTTP/1
`route-decision` hooks. The current live test uses two local origins and a
configured `canary` route branch selected by a bounded `x-canary: 1` signal.
The hook can continue, deny, or select a configured matching branch; arbitrary
pool names, persistence keys, and mirror/shadow target decisions remain staged
for later `1.7.x` slices.

### VCL-Like Cache Policy

Capability target:

- lookup/admission decision: bypass, pass, continue, or deny;
- bounded cache-key component output with low-cardinality enforcement;
- store-admission decision for TTL override, cache tags, safe response-header
  mutation, and rejection of unsafe responses;
- no raw cache-object access.

Representative example:

```text
Bypass cache for preview=true, add a bounded device-class key component,
override TTL for image responses up to the configured maximum, and tag objects
with a small plugin-provided cache tag.
```

Required live test:

- preview requests bypass cache;
- normal requests produce MISS then HIT;
- device-class key component changes the cache key only within configured
  cardinality bounds;
- plugin TTL override is clamped to route/vhost cache limits;
- plugin cache tags are visible to purge/status tooling;
- unsafe Set-Cookie or private responses remain uncacheable.

Target release: `v1.7.4`.

## Stabilization Requirements

Before `1.7` is complete:

- all four example families must be runnable from `scripts/test_starter.py`;
- the stable or deep release gate must run the applicable Wasm smokes;
- docs must state that Fluxheim provides capability parity, not syntax
  compatibility with F5 iRules, Lua/OpenResty, HAProxy SPOE, or VCL;
- unsupported host calls, unknown ABI versions, unsupported plugin phases, and
  invalid config combinations must fail deterministically at config load or
  plugin-load time;
- every example must have a matching negative test that proves the sandbox does
  not expose filesystem, network, env, admin APIs, secrets, request bodies, or
  raw cache objects without explicit future capabilities.
