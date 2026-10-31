# CORS: Browser Access to Another Origin

CORS lets a browser application read selected responses from a different
origin. For example, a page at `https://app.example.test` can call an API at
`https://api.example.test`. The allowed origin is the **page's** origin, not the
API hostname. Scheme and port matter. CORS is not login, authorization, CSRF
protection or a firewall: an ordinary request may reach the application even
when the browser cannot read its reply. Some browser requests first send an
OPTIONS preflight. See the [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).

Fluxheim has a dedicated request-aware CORS policy. Prefer it to manually adding
`Access-Control-*` strings. Explicit origin, method and header lists work;
three current inheritance/wildcard gaps are listed below and remain open.
This guide covers the native routed HTTP implementation, not WebSocket Origin
validation or an HTTP/3 implementation. CORS has no separate Cargo feature;
the selected action still needs its normal proxy, web or PHP build support.

## Start With an Explicit Allowlist

The complete [local recipe](../../examples/headers/cors.toml) listens only on
`127.0.0.1:8080` and proxies to a local HTTP origin on port 9001. Its policy is:

```toml
[headers.cors]
enabled = true
allow_origins = ["https://app.example.test"]
allow_methods = ["GET", "HEAD", "POST"]
allow_headers = ["authorization", "content-type", "x-request-id"]
expose_headers = ["x-request-id"]
allow_credentials = true
max_age_secs = 600
```

Use a real application's exact origin in deployment. Keep the backend's own
authentication and authorization. `allow_headers` permits the browser's
requested header names; it does not create an Authorization header, verify a
token or grant access. `expose_headers` makes named response metadata available
to browser JavaScript; it does not create those headers. This example assumes
the application already emits an appropriate request ID.

For a simple local exercise, serve a file from a throwaway directory:

```bash
python3 -m http.server 9001 --bind 127.0.0.1 --directory /path/to/public-fixture
```

In another terminal, with a proxy-capable binary:

```bash
fluxheim --config examples/headers/cors.toml --validate-config
fluxheim --config examples/headers/cors.toml
```

Use the same filesystem permissions and service identity as the real server.
This HTTP example is local only; use [HTTPS](tls.md) for deployed APIs. A static
Python fixture does not implement authenticated POST operations.

## Every Setting

All settings below are available at `[headers.cors]`, `[vhosts.headers.cors]`
and `[vhosts.routes.headers.cors]`. Unknown fields fail validation.

| Setting | Default at the global scope | Meaning and bounds |
| --- | --- | --- |
| `enabled` | `false` | Enable Fluxheim's local preflight handling and ownership of CORS response fields. Disabled means leave origin CORS fields alone, not forcibly remove them. Route preflight opt-out currently has the documented limitation. |
| `allow_origins` | `[]` | Up to 64 distinct HTTP/HTTPS origins, each at most 2048 bytes. Required when enabled. No path, trailing slash, query, fragment, credentials, opaque `null`, regex or subdomain pattern. `"*"` must be the only entry and cannot be combined with credentials. |
| `allow_methods` | `["GET", "HEAD", "POST"]` | Up to 32 unique uppercase HTTP tokens; nonempty when enabled. Lists actual request methods, not a requirement to add OPTIONS for preflight. Use explicit names, not `"*"`. This is not a route-method or application-method restriction. |
| `allow_headers` | `[]` | Up to 64 distinct valid header names, compared case-insensitively to names requested in preflight. Enumerate every required name. Empty permits a preflight with no requested headers. Do not use `"*"`. |
| `expose_headers` | `[]` | Up to 64 distinct valid response-header names, serialized into Access-Control-Expose-Headers. Use explicit names. It neither generates the fields nor exposes cookie values to JavaScript. |
| `allow_credentials` | `false` | Emit Access-Control-Allow-Credentials: true for an allowed origin/method. Requires specific origins, never wildcard origin. Does not set cookies or change their attributes. |
| `max_age_secs` | omitted | Optional integer 0 through 86400 sent on handled preflights. Omission emits no Max-Age; zero requests no preflight caching. Browsers can impose their own limits. This is not an HTTP response-cache TTL. |

Duplicate list entries are rejected case-insensitively. Configuration validation
also checks list limits and syntax when `enabled = false`. It checks the final
merged policy, so a child wildcard origin cannot inherit `allow_credentials = true`.
Origin matching compares the configured serialized string case-insensitively;
it does not resolve DNS or normalize optional default ports. Copy the origin
actually sent by the browser. Never derive an allowlist by blindly reflecting
an arbitrary inbound Origin value.

The Fetch specification gives `*` in exposed headers wildcard meaning only for
non-credentialed requests. Explicit names avoid that credential-dependent
interpretation. Browser cookie policy and CORS permission are separate checks;
`allow_credentials = true` cannot override the browser's cookie restrictions.
See [credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials).

## Global, Vhost and Route Policies

Omitted child fields inherit. A supplied list **replaces** the parent list;
it is not appended. The recipe's `/reports` route accepts POST and uses:

```toml
[vhosts.routes.headers.cors]
allow_origins = ["https://reports.example.test"]
allow_methods = ["POST"]
allow_headers = ["content-type"]
expose_headers = []
max_age_secs = 0
```

It inherits `enabled = true` and `allow_credentials = true`, removes inherited
exposed fields and does not allow the parent's application origin. Add this
table to an existing route with an action; it is not a complete route by itself.
To configure one vhost instead, use `[vhosts.headers.cors]` with the same fields.
TOML has no null value to remove an inherited optional Max-Age; use zero when
you need to disable caching of its preflight permission.

To keep Fluxheim out of CORS handling entirely:

```toml
[headers.cors]
enabled = false
```

Check that no vhost/route re-enables it and that the origin's own CORS policy is
appropriate. Do not treat a child `enabled = false` as a current preflight
opt-out under an enabled parent: see the documented limitation. Prefer enabling CORS only on
the scopes that need it rather than broadly enabling a parent and opting out.

## What Happens to a Request

1. Routing can use Access-Control-Request-Method to select a method-specific
   route with CORS enabled. In the recipe, OPTIONS for POST `/reports` reaches
   that route's CORS policy even though the route lists only POST.
2. Vhost/route access checks, concurrency/rate limits and applicable Wasm access
   checks run before local CORS handling. HTTPS redirection also precedes it.
   A redirect or early rejection is not a successful preflight.
3. A recognized OPTIONS request with one nonempty requested-method value checks
   its Origin, requested method and requested header names. Allowed preflights
   return 204 with an empty body; rejected ones return 403. Neither contacts the
   origin. Header names can span comma-separated lists and repeated lines;
   malformed/empty entries are rejected and names are deduplicated ignoring case.
4. Local preflight precedes the proxy's external authorization hook. It approves
   browser request mechanics, not the actual operation. The actual request
   must still pass application/route authorization.
5. Ordinary requests proceed normally. An allowed origin and allowed method
   receive CORS response fields. Other requests normally retain the action's
   status/body but receive no CORS permission from this policy. A disallowed
   Origin is **not** a general server-side 403 rule.

A bare OPTIONS request without Access-Control-Request-Method is not handled as
a preflight; the selected action receives it. Missing/duplicate requested-method
fields are not a general malformed-OPTIONS firewall. Origin validation rejects
multiple nonempty values, `null`, non-origin URLs and disallowed origins on
recognized preflights. Do not use these parser details as authentication.

## Header Ownership, Caching and Errors

When enabled and applied, CORS removes upstream or generic configured values of:

- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials
- Access-Control-Expose-Headers
- Access-Control-Allow-Methods
- Access-Control-Allow-Headers
- Access-Control-Max-Age
- Access-Control-Allow-Private-Network

It writes its own allow-origin, optional credentials and exposed-header fields
only for allowed actual requests. Handled preflights also receive configured
methods, allowed headers and optional Max-Age. There is no setting here to
grant private-network access. General response-header changes run first; CORS
then owns these fields even if `[headers.response].enabled = false`.

Explicit-origin actual responses merge `Origin` into Vary even when no CORS
permission is emitted. Successful preflights merge `Origin`,
`Access-Control-Request-Method` and `Access-Control-Request-Headers`. Existing
Vary values are retained; Vary `*` remains `*`. Wildcard-origin actual responses
currently have the gap below. Also, early access/rate/body-limit or protocol
rejections can return before the response-policy stage. Do not promise CORS
fields on every error or use those headers as proof an operation succeeded.

Vary is a cache-selection signal, not authorization or a cache purge. Verify
intermediaries and application cache policy separately; credentialed data must
not become shared public content merely because an origin is allowed. See
[cache policy](cache.md) and [compression](compression.md).

## Public Non-Credentialed Content

For truly public resources, the accepted configuration is:

```toml
[headers.cors]
enabled = true
allow_origins = ["*"]
allow_methods = ["GET", "HEAD"]
allow_headers = []
expose_headers = []
allow_credentials = false
```

Currently this changes the allow-origin field based on whether a valid Origin
was supplied, without adding Origin to Vary. Until the documented limitation is fixed, use
explicit origins where practical or ensure an independently tested cache policy
does not reuse the wrong variant. Do not use wildcard CORS for data protected
only by host/LAN access or assume it makes credentialed browser requests work.

## Test and Troubleshoot

```bash
curl -i -X OPTIONS http://127.0.0.1:8080/resource \
  -H 'Host: api.example.test' \
  -H 'Origin: https://app.example.test' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: authorization, content-type'

curl -i http://127.0.0.1:8080/ \
  -H 'Host: api.example.test' -H 'Origin: https://app.example.test'
```

The first should return 204 without involving the backend. The second should
return the backend response with one matching allow-origin value. Changing the
preflight's Origin to `https://denied.example.test` should return 403. curl does
not enforce browser CORS; inspect your browser's network panel as well.

| Symptom | Check |
| --- | --- |
| Preflight 403 | Exact origin/scheme/port, effective route list, requested method and every requested header. Use explicit names rather than wildcard header/method entries. |
| Preflight works, request fails | Application auth, body/method rules, backend failure and cookie policy. A preflight never proves the action will succeed. |
| Actual request is 200 but browser reports CORS failure | Response lacks permission for the actual origin/method, error bypassed policy, or an intermediary reused a response with different CORS metadata. |
| OPTIONS reaches the backend | CORS is disabled at the selected scope or the request is not recognized as a preflight. |
| Origin's CORS fields disappear | Enabled Fluxheim CORS intentionally replaces them. Choose one policy owner. |
| Header not readable in JavaScript | Expose the response-header name and ensure the application actually emits it. |
| Child list seems to lose values | Lists replace rather than merge. Repeat all required entries. |

Repository qualification with a locally built binary:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_cors_examples.py
python3 scripts/smoke_cors_examples.py
```

## Open Corrections

These are recorded behavior gaps, not fixes delivered by this guide:

| Finding | Current behavior | Planned correction |
| --- | --- | --- |
| the documented limitation | A CORS-disabled route can fall back to the enabled parent's local preflight handler, while its actual response has CORS disabled. Reproduced with a static route under a proxy vhost. | the local follow-up: use the selected effective scope consistently for preflight and actual response; preserve method-specific routing and auth boundaries. |
| the documented limitation | A wildcard-origin policy sends no allow-origin on a request without Origin, but sends `*` for an allowed request at the same URL; neither adds Vary: Origin. | the local follow-up: consistent cache-safe wildcard response semantics and intermediary/browser proof. |
| the documented limitation | `allow_headers = ["*"]` and `allow_methods = ["*"]` pass validation but are compared literally; ordinary non-credentialed preflights are rejected. | the local follow-up: explicit validation or correctly scoped wildcard semantics; do not silently expand credentialed access. |

The [Fetch cache discussion](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches)
explains why conditional CORS headers need matching cache variation.
[Coverage and evidence](../reference/documentation-coverage.md) distinguish
actual Linux HTTP/1.1 proof from still-required browser, HTTP/2, container,
Windows and macOS qualification. No browser security guarantee is inferred
from curl or a static review alone.
