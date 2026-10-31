# External Authorization For Proxy Requests

An authorization service answers whether a request may reach your application.
Fluxheim calls it first and forwards the application request only after an
accepted response. The service must validate the credential/session; Fluxheim
does not turn a bearer string into a verified user by itself.

This is a proxy-action hook, not the admin API token system or a blanket policy
for static files, PHP, redirects or CORS preflights. Protect each action
explicitly. The binary's `proxy` feature includes native `auth-request` support;
custom server-library builds need that feature.

## Important Current Limits

Two open security-priority blockers affect deployments that trust this hook:

- **Current limitation:** WebSocket takeover skips authorization. A real TCP
  test receives 403 for ordinary GET and 101 for its upgrade counterpart without
  another auth call. Disable `websocket` or authenticate independently at the
  origin; do not assume this hook protects upgrades.
- **Current limitation:** `allow_response_headers` is an output allowlist,
  not an inbound identity scrubber. A client-supplied identity survives when a
  successful auth reply omits that header. The example below strips identity
  before authorization. The origin must also reject missing required identity.

These remain blockers, not accepted limitations merely because they are
documented. The [correction plan](../roadmap/observability-commit-plan.md#post-documentation-corrections)
requires runtime fixes and security/native qualification.

## Configure A Protected Application

Use the complete [auth recipe](../../examples/proxy/auth.toml). It listens on
loopback for `app.example.test`, forwards to port 9001 and asks a sidecar on
9002. Its essential fragment under an existing vhost is:

```toml
[[vhosts.routes]]
name = "protected"
path_prefix = "/"

[vhosts.routes.headers.request]
remove = ["x-auth-request-user"]

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
websocket = false

[vhosts.routes.proxy.auth_request]
enabled = true
url = "http://127.0.0.1:9002/check"
forward_headers = ["authorization", "cookie", "x-original-uri", "x-forwarded-host", "x-forwarded-proto"]
allow_response_headers = ["x-auth-request-user"]
connect_timeout_secs = 1
read_timeout_secs = 2
max_response_bytes = "1KiB"
max_in_flight = 8
```

The explicit route's header stage removes the untrusted identity before auth;
an accepted auth reply can then supply it. Strip **every** identity/role header
the application trusts. Moving removal to a later stage is not equivalent: it
could remove the newly authorized identity. Do not authenticate applications
using arbitrary client-supplied headers.

The sidecar receives GET `/check`, not the application method or body. The real
POST/body reaches the origin after authorization. Method/body-dependent
authorization therefore still belongs in the application; this hook has no
built-in method-context header synthesis. Route rewrites and route header
policy have already run, so `x-original-uri` can contain a rewritten target.
See [routing](routing.md). Ordinary requests authorize before proxy cache
lookup too; no auth-decision cache is provided.

## Interpret Responses

| Auth result | Fluxheim behavior |
| --- | --- |
| 2xx with bounded readable body | Allow; inject allowlisted response headers into the origin request |
| 4xx/5xx | Return that status and bounded body; no origin request |
| Other returned status, such as 302 | Return 500; redirects are not followed |
| Transport failure or oversized response | Return 502; no origin request |
| Admission capacity exhausted | Return 503 without unlimited queueing |

Successful bodies are consumed within the limit and discarded. Prefer a small
204 with required identity headers. Denial bodies are client-visible: do not
include secrets or internal diagnostics. `Location`, `WWW-Authenticate` and
cookies are not automatically forwarded to the browser. This is not a complete
browser login/session middleware.

Returned identity values replace existing headers with the same name; absent
values currently do not clear client input. Only allowlist
deliberate application metadata, not Host, Content-Length, Connection or other
protocol-control fields.

## Forward Only Required Context

No client headers go to auth by default. Repeated Cookie fields are joined with
`; `; other repeated values use comma joining. Allowlisted credentials remain
sensitive even when sent to an internal service.

| Allowlisted name | Current native source |
| --- | --- |
| `x-original-uri`, `x-forwarded-uri`, `x-auth-request-redirect` | Current target at the proxy hook, not an absolute login URL |
| `x-forwarded-host` | Current Host header |
| `x-forwarded-proto` | Actual downstream TLS flag, `http` or `https` |
| `x-forwarded-for`, `x-real-ip` | Direct socket peer outside privacy mode, not automatically the forwarded client chain |
| Other names | Matching request header values |

**Current limitation:** when synthesis is unavailable, the helper falls
back to inbound values. Tests reproduce missing peer metadata and IP synthesis
intentionally disabled in privacy mode. Do not allowlist client-IP context in
privacy mode or trust it as authenticated identity. This is proven at the
helper boundary; a full public-listener/privacy-path reproduction remains a
correction requirement.

## Options And Transport

Use `[proxy.auth_request]`, `[vhosts.proxy.auth_request]` or
`[vhosts.routes.proxy.auth_request]` for the intended proxy action. Do not assume
a vhost fallback proxy policy protects every explicit route.

| Field | Default | Meaning / limits |
| --- | --- | --- |
| `enabled` | false | Enable hook; requires URL |
| `url` | absent | Absolute HTTP(S) endpoint with path; no userinfo/query/fragment |
| `forward_headers` | empty | At most 32 distinct case-insensitive names sent to auth |
| `allow_response_headers` | empty | At most 32 distinct names copied from successful replies to the origin request |
| `connect_timeout_secs` | 2 | Positive seconds, at most 86400; combined-deadline caveat below |
| `read_timeout_secs` | 5 | Positive seconds, at most 86400; combined-deadline caveat below |
| `max_response_bytes` | 64 KiB | Body limit, 1 byte through 1 MiB; integer or size string |
| `max_in_flight` | 64 | Per-instance admission ceiling, 1 through 256 |

**Current limitation:** the timeout fields become a single global deadline
equal to their sum, not two enforced phase budgets. 1+5 and 5+1 seconds produce
identical runtime policy. The current deadline is finite; phase enforcement
requires a separate correction.

Per-instance admission is additionally constrained by the process-wide auth
ceiling (256) and shared blocking-work budgets (auth class 96). A configured
ceiling is not guaranteed available capacity. Blocking calls retain their
permits until completion even if the waiting request task is cancelled.

Auth HTTPS uses the separate outbound HTTP client. Main proxy CA, SNI and mTLS
fields do not configure it; this block has no custom CA/client-key equivalents.
Use verified HTTPS outside a trusted same-host sidecar. Configuration can accept
remote HTTP; it does not enforce that recommendation. FIPS/ISO-required mode
restricts the hook to numeric loopback HTTP sidecars; see [FIPS](fips.md).

**Current limitation:** the reference previously promised allow/deny/error
samples in `fluxheim_edge_policy_events_total`. The native hook does not call
that producer. An accepted `auth_request` label and helper test are not runtime
emission. Missing series do not prove zero auth failures; producer wiring and
live scrape proof are planned.

## Test The Integration

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls,traffic-mirror
python3 scripts/smoke_proxy_hooks.py
```

The harness starts synthetic auth, origin and mirror services on loopback and
uses the actual recipes. It proves allow/deny, non-followed redirects,
oversized-response rejection, body separation and pre-auth identity scrubbing.
Its `Bearer allow` string is a fixture command, not a production auth scheme.

For deployment, test valid/expired/missing/forged credentials, omitted identity,
slow/unavailable auth, cache hits and every enabled transport. The
[native contract tests](../../crates/fluxheim-server/src/native_http1_proxy_tests/auth_contract.rs)
document flaws to correct, not acceptable access-control behavior.
