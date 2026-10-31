# Request Forwarding and Header Templates

Request policy changes what Fluxheim sends to an application. It can replace
spoofable forwarding fields, remove application-specific identity headers, add
static values and render a limited set of templates. It does not authenticate
the values a client supplied. Response policy and [CORS](cors.md) are separate.

The `[headers]` policy groups the `request`, `response` and `cors` subtables.
This guide describes `[headers.request]`; use the linked guides for the other two.

Use the [complete local recipe](../../examples/headers/request.toml) for direct
clients. It keeps trusted proxies empty, replaces client-IP fields and removes
one example application identity field. It also demonstrates a regex route
whose rewritten path and capture are forwarded as diagnostic headers.

**Current trust limitation:** behind an HTTP proxy, the default stripping path
can lose the restored client address after ACL evaluation, forwarding the proxy's
address instead. Do not make origin authorization decisions from
these generated IP headers until the corrected path is qualified. Disabling
stripping is not a general security workaround: it retains other spoofable fields.

## Direct-Client Configuration

```toml
[server]
trusted_proxies = []

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true
forwarded = true
remove = ["x-internal-user"]
```

This fragment belongs in a complete configuration with a listener and action.
For direct HTTP clients, a forged X-Forwarded-For is discarded and the upstream
gets the connection's peer IP. Generated host comes from the inbound Host;
generated scheme comes from the Fluxheim listener's TLS state, not a supplied
X-Forwarded-Proto. A TLS-terminating proxy connecting over HTTP therefore does
not automatically make `{scheme}` become `https`.

Only allow the application to receive traffic through the intended gateway, and
keep application authentication independent. Add your own trusted identity names
to `remove` if the upstream uses them. The built-in list cannot know every
application's authorization header.

For a name-by-name shortcut covering request, response and admin fields, use the
[HTTP header quick reference](../reference/supported-headers.md).

## Every Request Setting

These fields are accepted under `[headers.request]`, `[vhosts.headers.request]`
and `[vhosts.routes.headers.request]`. Unknown fields fail parsing. The defaults
below describe the ordinary build; privacy behavior is discussed separately.

| Field | Default | Behavior |
| --- | --- | --- |
| `enabled` | `true` | Apply forwarding and mutations. False skips both, including normal spoof stripping; it does not disable unrelated proxy transport filtering. |
| `strip_inbound_client_ip_headers` | `true` | Remove the built-in spoofable names before generating forwarding fields. Current trusted-client resolution order has the documented limitation. |
| `x_forwarded_for` | `replace` | `off`: remove X-Forwarded-For. `replace`: write one effective client IP. `append`: preserve an existing chain only for a trusted direct peer and when stripping has not removed it, then append the derived client IP. Current append repeats the client rather than representing the direct proxy hop; see the documented limitation. |
| `x_real_ip` | `true` | Replace X-Real-IP with the effective client IP, or remove it when unavailable. False stops generation; it does not remove an existing field when stripping is also false. |
| `x_forwarded_host` | `true` | Replace X-Forwarded-Host with Host captured before generic mutations. False with stripping off can preserve spoofed input. |
| `x_forwarded_proto` | `true` | Replace X-Forwarded-Proto with `http` or `https` from the downstream listener. False with stripping off can preserve spoofed input. |
| `forwarded` | `false` | Generate one Forwarded element with client IP, quoted host and listener protocol. Does not append an inbound Forwarded chain. False with stripping off leaves an inbound field untouched. |
| `unset` | `[]` | Legacy removal list. |
| `remove` | `[]` | Remove all current occurrences of each name before generic replacements. |
| `set` | empty map | Legacy replacement map. |
| `add` | empty map | Replace all current occurrences, render the value, then insert it if nonempty. This does not mean append. |
| `append` | empty map | One string or a list per name; render and append separate values. Existing inbound values remain unless explicitly removed. Never use for trusted identity assertions. |
| `operations` | empty | Nested `remove` list and `add` map aliases; no nested append option. |

Example static replacements and multi-valued metadata:

```toml
[headers.request.add]
x-gateway = "public-edge"

[headers.request.append]
x-edge-note = ["region-a", "gateway"]
```

Equivalent nested mutation spelling:

```toml
[headers.request.operations]
remove = ["x-internal-user"]
[headers.request.operations.add]
x-gateway = "public-edge"
```

Do not define the same field through multiple replacement aliases at one scope.
Use lowercase names consistently. Limits apply to effective collections: 128
removal names, 128 replacement names and 128 append names, with at most 32 values
per appended name. Static values must be nonempty after trimming and contain no
ASCII controls, including tab, CR, LF or DEL. These are not a separate total
rendered-byte or CPU budget. Keep templates and header values small.

## Trusted Proxies and Client Identity

`server.trusted_proxies` accepts IP/CIDR entries. Trust only actual controlled
proxies that sanitize incoming forwarding fields, never the entire Internet or
an unnecessarily broad shared container/LAN subnet. For example, after the
identity correction is qualified, an intended edge topology might declare:

```toml
[server]
trusted_proxies = ["192.0.2.10/32", "2001:db8::10/128"]
```

These are documentation addresses, not deployable allowlist values. Replace them
with the observed proxy peer addresses. This declaration expresses trust; it is
not a firewall rule and does not prevent other peers reaching the listener.

The client-IP helper examines X-Forwarded-For from right to left when the direct
peer is trusted. It skips trusted hops and stops at the first untrusted IP. A
malformed **examined** hop falls back to the direct peer. Entries to the left of
the selected untrusted hop are not all parsed; do not claim whole-chain validation.
No trust is derived from an inbound Forwarded, CF-Connecting-IP or similar name.
If a PROXY-protocol listener supplies an effective address, that context takes
precedence; see [PROXY protocol](proxy-protocol.md), including its current TLS gap.

Presently the ACL can resolve the original chain before forwarding runs, while
forwarding strips it before trying to resolve it again. The live fixture proves
an ACL accepting only `198.51.100.9` passes a request carrying that trusted chain,
yet its upstream receives `127.0.0.1`. This is a mismatch, not a supported identity
translation. Append with stripping off also produces a repeated client IP in the
chain. the local follow-up must resolve these consistently before trustworthy multi-hop
identity is claimed. There is no recommendation here to weaken stripping.

The built-in stripping list is:

```text
x-forwarded-for, x-real-ip, forwarded, x-forwarded-host, x-forwarded-proto,
cf-connecting-ip, true-client-ip, x-client-ip, client-ip, x-cluster-client-ip,
fastly-client-ip, x-envoy-external-address, x-original-forwarded-for,
x-azure-clientip, fly-client-ip, x-proxyuser-ip, x-forwarded-client-cert
```

It does not remove arbitrary names such as `x-internal-user`, Authorization,
Cookie or every possible custom client-address field. Define application policy
explicitly. A generic replacement can override a generated field, so configuration
authors can still create misleading identity assertions; validation is not an
authorization proof.

## Template Support in the Native Runtime

```toml
[headers.request.add]
x-public-host = "{host}"
x-request-target = "{uri}"
x-request-path = "{path}"
x-request-query = "{query}"
x-client-address = "{remote_addr}"
x-downstream-scheme = "{scheme}"
x-diagnostic-id = "{request_id}"
```

| Variable | Actual source / current limit |
| --- | --- |
| `{host}` | First nonempty current Host value. **Not an immutable original**: earlier mutations can change/remove it. Leave Host untouched when preserving it; do not set `host = "{host}"`. |
| `{remote_addr}` | Effective address if present, otherwise peer address; no port. Subject to trusted restoration mismatch; empty in privacy builds. |
| `{scheme}` | Downstream TLS boolean: `http` or `https`. Not forwarded proxy metadata. |
| `{uri}` | Current request target, after route rewriting. |
| `{path}` | Current target before its query delimiter. |
| `{query}` | Current query without `?`; empty when absent. |
| `{request_id}` | Current X-Request-Id header. Normal correlation handling can generate/replace it, but this renderer itself does not establish provenance. Custom correlation header settings and disabled correlation need separate review. Diagnostic only, never an authentication token. |
| `{http.upgrade}` | Current Upgrade header; not permission to establish a tunnel. Use the [WebSocket route controls](websocket.md). |
| `{http.<other-name>}` | Accepted by validation but **not resolved** by this native renderer. Existing ordinary headers already pass through unless policy/transport removes them. |
| `{tls.version}` | Listener-provided TLS protocol when available. Empty on plain HTTP or absent context. |
| `{tls.client_cert_sha256}` | Listener-provided client certificate fingerprint when available. Configure certificate verification/access policy independently. |
| `{tls.client_cert_serial}` | Listener-provided client certificate serial when available. Not a unique authorization principal by itself. |
| `{tls.cipher}` | Accepted but currently unresolved even with populated TLS cipher context. |
| `{tls.client_cert_organization}` | Accepted but currently unresolved even with populated organization context. |
| `{route.regex.<name>}` / `{route.regex.<number>}` | Selected route's captured values when supplied by its match context. Existing missing/oversized capture bounds remain tracked in the documented limitation; see [routing](routing.md). |

The recipe maps `/items/alpha?q=one` to `/internal/alpha?q=one`; `{path}` sees
`/internal/alpha`, `{query}` sees `q=one`, and `{route.regex.id}` sees `alpha`.
These headers do not preserve the original pre-rewrite URL automatically.

Missing variables become empty strings. If the whole rendered value is empty,
no field is inserted; otherwise literal surrounding text remains. For example,
`prefix-{http.user-agent}` currently becomes `prefix-`, not an error. Control
characters are filtered from substituted values, and the upstream serializer
also checks header validity. This is not general-purpose escaping or a safe
substitute for verifying a required identity value.

Unknown variables and malformed template syntax fail validation. There are no
conditionals, arbitrary functions or documented literal-brace escape mechanism.
Avoid repeatedly expanding large inputs; rendered values have no dedicated
template-specific allocation/admission budget in this implementation.

## Host and TLS Identity Examples

Normally leave Host untouched. Fluxheim's HTTP/1 upstream writer preserves it
when present and uses the upstream authority if it is missing. A fixed backend
virtual host can be selected deliberately:

```toml
[vhosts.routes.headers.request.add]
host = "backend.example.test"
```

This does not change the already selected Fluxheim route or the downstream TLS
identity. Configure [upstream TLS/SNI](upstream-tls.md) separately. The current
`host = "{host}"` bug removes Host before reading it, causing authority fallback;
other later `{host}` templates can also lose their value.

For verified client-certificate forwarding, use replacement, not append:

```toml
[vhosts.routes.headers.request.add]
x-client-cert-sha256 = "{tls.client_cert_sha256}"
x-client-cert-serial = "{tls.client_cert_serial}"
x-client-tls-version = "{tls.version}"
```

Pair this with [TLS client authentication and access rules](tls.md). Configure
the upstream to accept such assertions only from the gateway. A missing value
removes the inbound copy when using replacement; append would preserve a
potentially spoofed value, and configuration therefore rejects TLS templates
under request append. Plain HTTP must not acquire trusted client identity merely
because a client sent a similarly named header.

## Inheritance, Order and Privacy

Omitted child scalar fields inherit; explicit scalar values replace. Generic
mutations currently merge removal lists, replacement maps and append values.
The same the documented limitation defect as response policy applies: child removal does
not cancel inherited set/append, and replacement aliases can conflict across
scopes. The live request smoke reproduces inherited fields returning after a
child remove. the local follow-up owns that shared fix.

Runtime order is typed forwarding, generic removal, replacements, then appends.
Replacement names come from ordered maps, not TOML declaration order. Each
replacement removes its own destination **before** rendering against the mutable
request. Later templates therefore see earlier changes.
Do not build a chain of header copies that depends on alphabetical field names.

In a privacy build, typed client/host/protocol forwarding generation is compiled
out. Known spoofable identity fields are stripped even when request policy is
disabled; when enabled they are stripped after generic mutations too.
`{remote_addr}` is empty. This is not a universal anonymizer: unrelated custom
fields, request targets, diagnostic IDs and available TLS metadata can still
be forwarded. Only expose necessary metadata, and inspect the actual upstream
request in the intended build profile.

Transport rules also apply: HTTP/1 hop-by-hop fields and Connection-nominated
fields are filtered, framing is owned by the writer, and Via/internal peer-fill
fields have separate ownership. Disabling header policy does not disable those
transport rules. Do not use custom Connection/Upgrade fields as a substitute for
the supported WebSocket configuration. PHP FastCGI parameters and auth/mirror
subrequests have their own projection paths; this ordinary proxy guide does not
promise identical behavior for them.

## Verify and Troubleshoot

With the complete recipe and an HTTP origin on port 9001:

```bash
fluxheim --config examples/headers/request.toml --validate-config
fluxheim --config examples/headers/request.toml
curl -i 'http://127.0.0.1:8080/items/alpha?q=one' \
  -H 'Host: api.example.test' -H 'X-Forwarded-For: 198.51.100.90'
```

Inspect the **upstream request**, not just the downstream response. The automated
test creates a bounded loopback origin that returns its observed request fields:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_request_headers_examples.py
python3 scripts/smoke_request_headers.py
```

| Symptom | Check |
| --- | --- |
| Host becomes the backend address | Remove `host = "{host}"`; preserve Host by leaving it untouched, or use an intentional static backend Host. |
| A template header vanishes | Native support table, absent context, generic remove order, same-name replacement and an empty final value. |
| Rewritten URL appears in diagnostic fields | `{uri}`, `{path}`, `{query}` use the current target, not the original URL. |
| Different ACL and origin client IP | the documented limitation; do not weaken stripping or trust the wrong identity as a workaround. |
| Spoofed header survives | Disabled normal policy, stripping disabled, a custom name outside the built-in list or append retaining the original value. |
| Child removal fails | the documented limitation; own that field at one scope until corrected. |
| Proxy terminated HTTPS but scheme is HTTP | The downstream Fluxheim connection is HTTP; do not blindly trust a public forwarded-proto input. |

## Open Corrections

| Finding | Proof and disposition |
| --- | --- |
| the documented limitation | Live User-Agent copy becomes empty despite present input; native helper with populated TLS context loses cipher/organization. the local follow-up aligns supported template validation and native resolution. |
| the documented limitation | Live Host self-template causes backend-authority fallback and removes another Host-derived field. the local follow-up defines immutable source context and mutation ordering. |
| the documented limitation | Live ACL/restored-IP versus forwarded-IP mismatch, and duplicate-client append chain. the local follow-up is security-priority for origins authorizing on forwarded identity; requires consistent resolution before stripping. |
| the documented limitation | Live request-side inherited remove reversal confirms shared scope of the local follow-up. No duplicate correction commit added. |

[Coverage](../reference/documentation-coverage.md) records evidence separately:
Linux HTTP/1.1 actual-server tests and synthetic native TLS/privacy context tests
do not constitute new TLS handshake, HTTP/2, native Windows/macOS or container
qualification. No runtime fix is delivered by this guide.
