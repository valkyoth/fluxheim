# Wasm Policy ABI And Hook Ordering

This is the current native `fluxheim-policy-v1` contract, not a generic
proxy-wasm SDK. Start with [deployment and configuration](../guides/wasm-extensibility.md)
and the [options reference](wasm-options.md). The checked-in
[WAT examples](../../examples/wasm/README.md) show complete modules.

## Function Signatures

Native imports use module **`fluxheim_policy_v1`**, with underscores. Every
native host function below has type `(i32, i32) -> i32`. A successful mutation
returns zero. Invalid IDs or disallowed operations raise a host error, causing
execution failure; they are not negative status codes for the guest to ignore.
Use zero for unused parameters; the current host ignores those parameters.

Exports take no arguments and return `i32`:

| Phase | Required export | Valid return values |
| --- | --- | --- |
| access-decision | `fluxheim_access_decision` | 0 continue; 1 allow/continue; 2 deny (403) |
| request-headers | `fluxheim_request_headers` | 0 success |
| response-headers | `fluxheim_response_headers` | 0 success |
| route-decision | `fluxheim_route_decision` | 0 continue; 1 canary route; 2 deny (403); 3 mirror route |
| cache-lookup | `fluxheim_cache_lookup` | 0 normal; 1 pass; 2 bypass; 3 deny (403) |
| cache-store | `fluxheim_cache_store` | 0 normal; 1 skip store; 2 deny (403) |

All other values fail through the configured failure policy. Missing or
wrongly typed exports also fail. A header hook returning 1 is **not** success.
Access/route/store phases must fail closed. A native access module receives no
host imports; use Fluxheim route/ACL configuration to scope its decisions.

Compilation alone does not validate phase-specific imports and exports. Those
checks run during invocation, before successful guest execution. The runtime
test `runtime_rejects_unbound_host_import_before_instantiation` deliberately
compiles an unbound import successfully and then rejects its invocation.

## Context IDs

`context(kind, 0)` exposes only the following bounded values, and only in the
listed phases. Unknown or out-of-phase kinds fail.

| Kind | Meaning | Results | Phases |
| --- | --- | --- | --- |
| 1 | Path class | 0 other; 1 API; 2 static; 3 gold | Header, route, cache lookup, cache store |
| 2 | Canary signal | 1 if any `x-canary` value trims to `1`, otherwise 0 | Route |
| 3 | Mirror signal | 1 if any `x-mirror` value trims to `1`, otherwise 0 | Route |
| 4 | Response status | Numeric HTTP status | Cache store |
| 5 | Device class | 0 unset/unknown; 5 mobile; 6 desktop | Cache lookup |
| 6 | Response content type | 0 other/unset; 7 image; 8 HTML; 9 JSON; 10 text | Cache store |

Path classification is deliberately fixed and case-sensitive: `/api` and
`/api/...`, `/static` and `/static/...`, `/gold` and `/gold/...`. It is not a
route-name lookup. `/apiary`, `/Gold` and `/%67old` are not those literal
classes. The classifier itself does not percent-decode. Access route matching
has separate decoded-path defenses; do not substitute these context IDs for
those controls.

Route/header hooks on an explicit route use the pre-rewrite path. Cache
context is built from the request passed into proxy dispatch, after applicable
route rewrites. A path rewritten from `/gold/item` to `/api/item` can therefore
have different header-hook and cache-hook classes.

Device class uses the **first** `X-Device-Class` field, trimmed and compared
case-insensitively. An unrecognized first field yields 0 even if a later one
says mobile. Canary/mirror use any matching field. These are client-supplied
diagnostic/routing signals, **not authentication evidence**.

Content type uses the first Content-Type field, ignores parameters after `;`
and compares lowercased media types. `image/*` is image; `text/html` and
`application/xhtml+xml` are HTML; `application/json` or a type ending `+json`
is JSON; remaining `text/*` is text. This is classification of the origin's
header, not validation of its response body.

## Header Mutations

| Host call | Accepted IDs | Effect |
| --- | --- | --- |
| `set_request_header(name, value)` | name 1; value 1 standard, 2 api, 3 static, 4 gold | Set `x-policy-tier` |
| `set_response_header(name, value)` | name 2; same value IDs 1..4 | Set `x-fluxheim-policy-branch` |
| `remove_response_header(name, 0)` | name 3 | Remove `x-powered-by` |

Both header phases bind this function set so one module can export request and
response hooks. Calling a response mutation during the request phase, or a
request mutation during the response phase, fails. No arbitrary names, values
or raw header reads are available.

At most **16 combined set/remove operations per invocation** are accepted.
Repeated legal sets are allowed and still consume slots. This is not a
16-operation cap across all attachments. Mutations are buffered until that
invocation succeeds; failed-invocation mutations are discarded. Earlier
successful hooks are not rolled back when a later fail-open hook fails.
Sets replace existing instances of the same header; later successful hooks
can replace earlier values. These headers must not become authorization inputs.

## Cache Mutations

| Host call | Accepted IDs | Effect |
| --- | --- | --- |
| `set_cache_key_component(label, value)` | label 1; value 5 mobile or 6 desktop | Append fixed `wasm-device-class` cache-key component |
| `set_cache_ttl(ttl, 0)` | 1 or 2 | Select 1 second or 300 seconds |
| `add_cache_tag(tag, 0)` | 1 or 2 | Add `wasm-policy` or `wasm-gold` |
| `set_cache_store_header(name, value)` | name 1; value 1 wasm or 2 gold | Set stored `x-fluxheim-cache-policy` |

Only lookup binds the key-component call. Only store binds TTL/tag/stored-header
calls. Keep modules with different import needs separate: all imports in a
module must resolve for each invocation, even if the selected export does not
call them. The separate lookup/store examples follow this rule.

Key components are capped at four per invocation and across the chain.
Duplicate labels, including the same label/value from two hooks, fail rather
than overwrite. The current ABI only exposes one label, so four is a ceiling,
not four distinct configurable labels. Do not append a component for device
class 0; no value-0 mapping exists.

Within one store invocation, a second TTL or duplicate stored-header name
fails. Tags are deduplicated. Tags and stored headers each have separate caps
of four; the current ABI exposes two tags and one header family.

Across successful store hooks, the **first TTL wins**, not the shortest TTL.
The first value for each stored-header name wins; tags are merged without
duplicates. The bounded merge retains only values fitting each family cap.
For example, a 300-second choice at priority 100 remains selected even if a
later hook chooses 1 second. Order overlapping policies deliberately.

These mutations are input to ordinary proxy-cache policy, not permission to
store an otherwise forbidden response. Stored headers affect the cached object,
not the immediate origin MISS response. Hooks do not receive cache bodies or
arbitrary keys/tags/TTLs. See [cache behavior](../guides/cache.md) for remaining
cache-specific contracts and limitations.

## Attachment Chains

Vhost-scoped attachments also match named routes in that vhost. Route-scoped
attachments match only that named route. Both participate in ascending
priority order; ties preserve declaration order, not a special vhost-first rule.

| Chain | Aggregation |
| --- | --- |
| Access | Continue/allow proceeds; first deny stops; allow cannot erase a later deny |
| Route | First branch selection retained, but later hooks still run and may deny |
| Headers | Successful mutations applied in order; failure follows fail mode |
| Cache lookup | First pass/bypass retained; later hooks still run and may deny; components merge with duplicate rejection |
| Cache store | Skip prevents storage but does not mask a later deny; metadata from continue results merges with first-value precedence |

Canary/mirror selection must resolve to an existing matching route, including
method/path constraints. It does not rerun route selection indefinitely or let
the guest invent a target. Normal backend selection/persistence remains native.

## Integration Order And Coverage

For the ordinary routed HTTP handler, the main sequence is:

1. Parse path, select ordinary/decoded policy routes, enforce native ACLs.
2. Apply vhost concurrency/rate admission, then Wasm route decision.
3. Apply selected-route ACL/admission and Wasm access decision.
4. Handle HTTPS redirects, CORS preflight and route-local early rejections.
5. Rewrite the route request, check body bounds, apply native request headers,
   then Wasm request-header hooks.
6. Execute the selected action. Proxy-cache hooks surround its cache work.
7. Run Wasm response-header hooks for responses returning from the action,
   then apply the route's final digest metadata.

This is not a universal response middleware. Early ACL, admission, redirect,
preflight, rewrite, body-limit and other early rejection responses can return
without the header hooks. Normal native response policy may run within the
action before the Wasm response hook. Do not assume all configured response
headers are applied after Wasm.

PHP/static fallback and explicit actions have their own branches. A fallback
static response does not run the same request-header hook path as proxy dispatch.
Cache hooks are for proxy caching, not PHP execution. HTTP/2's route adapter
calls this ordinary handler, but shared source is not full native HTTP/2 or
gRPC qualification. Extended-CONNECT WebSockets are not supported here.

### Decoded Route Gap: the documented limitation

Native ACLs check both the raw-path dispatch route and the decoded-path policy
route. Previously Wasm access chose only one route's hooks. The corrected
handler combines vhost, original dispatch, decoded-policy and Wasm-selected
route access hooks before serving the action. Takeover combines the vhost,
dispatch and decoded-policy hooks. No routing or rewrite semantics change.

Attachments retain their registry identity and priority order across route
sets. Shared attachments execute once; separate attachments of the same plugin
remain separate. An allow continues the chain and cannot mask a later failure.
Access-decision plugins still cannot configure fail-open mode.

Real TCP tests use a public exact `/route` redirect and a protected `/` proxy
route with an access-deny module:

The original characterization, before correction, was:

| Request / policy | HTTP/1 and HTTP/2 result before correction | Origin calls |
| --- | --- | --- |
| `/private`, deny on protected route | 403 | None |
| `/route`, no public-route deny | 302 | None |
| `/%72oute`, deny on protected route | 200, protected origin body | One |
| `/%72oute`, same deny moved to decoded route | 403 | None |
| `/%72oute`, native ACL deny on protected route | 403 | None |

This is a request-triggered access-policy bypass for configurations with
different matching raw/decoded routes, not just a logging discrepancy. The
HTTP/2 proof uses a cleartext prior-knowledge loopback connection to the real
adapter, not a TLS/ALPN or packaged-binary qualification. The origin receives
the original encoded path. The test does not require origin path normalization.

The updated regression now requires 403 and no origin call for the encoded
request, while removing the policy still permits the origin response. Additional
tests cover shared-hook ordering/deduplication, errors after or before allows,
canary selection retaining original/decoded/selected restrictions, and an
encoded WebSocket request denied before takeover. the documented limitation is handled by
the separate upgrade restriction below, not by the access-chain correction.

[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
was implemented early at the owner's request. Native platform qualification,
packaged/TLS smokes and acceptance remain required; local TCP tests alone do
not close those gates. Use independent origin authorization or equivalent
native ACLs when deploying older binaries without this correction.

### WebSocket Restriction: the documented limitation

HTTP/1.1 WebSocket takeover runs native ACL and Wasm **access-decision** checks.
Wasm **route-decision, request-headers and response-headers** are unsupported
for upgrades. Configuration now rejects these attachments on a WebSocket-enabled
proxy scope. A vhost attachment covers its fallback proxy and every named route;
a named-route attachment is checked against that route. An HTTP-only named route
can retain these hooks even when a different route enables WebSocket.
Empty attachment phases inherit the plugin's phases; an explicit supported
subset is allowed. Header `fail-open` does not relax this restriction.
The takeover path also has different admission ordering: Wasm access runs
before its HTTP rate/concurrency checks.

The runtime repeats the restriction for programmatic configurations: applicable
vhost, raw-route and decoded-route hook sets are checked before origin contact
or 101. Unsupported sets return 503, even if the module would return success.
Real TCP tests cover both scopes, encoded paths, header fail modes and unchanged
ordinary HTTP behavior. Access allow still permits 101; denial returns 403 and
execution errors return 503. Cache hooks remain outside upgrade/tunnel traffic.

[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
implements explicit rejection, not full upgrade hook execution. Native platform
qualification, pentest and CI acceptance remain pending. Older binaries require
WebSocket to remain disabled where these hooks are required, or independent
origin enforcement. An access-decision
module can deny the entire attachment scope but has no arbitrary request
inspection capability and does not replace routing/header behavior. See the
[WebSocket guide](../guides/websocket.md) for the separate authorization,
handshake and tunnel-admission findings, which this correction does not close.

## Loader And Execution Trust Boundaries

The loader checks path components for links, canonicalizes the path and roots,
checks containment, opens the leaf without following a leaf link/reparse point,
verifies a regular handle and reads bounded bytes. The bytes read are hashed
and compared to the configured digest before module use. Keeping the file
handle protects reads against subsequent pathname replacement.

Those steps are not an atomic handle-relative traversal of every parent. They
also do not enforce owner/ACL confidentiality or reject every hard-link alias.
Protect the entire plugin path and configuration against untrusted mutation;
do not treat an approved root as a sandbox for a concurrently hostile local
writer. Pin all modules, including optional-pin header/lookup modules. A pin
does not authenticate config.

**Current limitation:** the earlier Unix FIFO startup stall is corrected by opening
with `O_NONBLOCK | O_NOFOLLOW` before inspecting the retained handle. The loader
rejects the FIFO without a writer and still rejects a leaf symlink. A bounded
child test exercises both public loader/path-validation APIs, deterministic
leaf replacement at the open helper, and recovery to a regular file with the
expected bytes and digest. It does not claim a probabilistic parent-race test.

The standalone binary smoke also checks prompt nonzero startup failure, restores
the original module, and then runs the normal policy tests. This does not add
a total filesystem I/O deadline: kernel/device/network-filesystem stalls and
atomic parent-path traversal are outside this narrow change. Retain the trusted
directory requirement and external service startup timeout.
[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
was implemented early; native qualification, pentest and CI acceptance remain
required. Windows open behavior is unchanged by the Unix-specific flag change.

Fuel/deadline/linear-memory limits do not bound every host-side allocation.
Compilation deadlines report a late synchronous result rather than kill it.
Admission queue capacity is bounded, but `timeout_ms` starts with execution,
not the entire wait through all admission scopes. A cancelled async caller
cannot forcibly stop already-running blocking engine work; its owned permits
remain with that work until it returns. Use service resource limits as well.

Native callbacks must remain finite, nonblocking and panic-free. This ABI has
no raw guest-memory reader, arbitrary log call, secret API or native I/O grant.
WASI's explicitly granted clock/random functions and unsupported proxy
`env.proxy_log` preview remain separate; see the deployment guide. There is no
complete Proxy-Wasm or WASI application compatibility claim.

## Test And Source Map

- [Host-call decoding, chain rules and registry](../../crates/fluxheim-server/src/native_http1_route_wasm.rs)
- [ID/precedence assertions](../../crates/fluxheim-server/src/native_wasm_abi_contract_tests.rs)
- [Actual upgrade/ordinary HTTP comparisons](../../crates/fluxheim-server/src/native_http1_route_proxy_tests/wasm_upgrade_contract.rs)
- [Ordinary and takeover handlers](../../crates/fluxheim-server/src/native_http1_route_proxy_handler.rs)
- [File loader](../../crates/fluxheim-wasm/src/file.rs), [engine and admission](../../crates/fluxheim-wasm/src/runtime.rs)
- [Bounded Unix FIFO characterization](../../crates/fluxheim-wasm/src/file_contract_tests.rs)
- [Current qualification limits](documentation-coverage.md)
