# Response Headers and Browser Security

Response headers tell clients how to interpret a reply. Fluxheim can remove
origin banners, replace or append headers, publish browser policy, rewrite
redirect/cookie attributes and generate response metadata. These features do
not replace application authentication, escaping, CSRF defenses or TLS.

Start with the [complete local example](../../examples/headers/response.toml)
and [every-option reference](../reference/response-header-options.md). The
example is intentionally restrictive: it is for wire inspection, not a universal
WordPress or application policy. Test login, embedded pages, payment flows,
scripts and external assets before deploying it. Request forwarding is separate;
see the [request-header reference](../reference/config-reference.md#headers).
[CORS](cors.md) has its own request-aware policy.

For a name-by-name shortcut covering request, response and admin fields, use the
[HTTP header quick reference](../reference/supported-headers.md).

## Defaults and Scope

Without custom settings, response policy is enabled and sets:

| Header | Value |
| --- | --- |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY` |
| Referrer-Policy | `no-referrer` |

It removes X-Powered-By. It does **not** enable HSTS, CSP, permissions policy,
cross-origin isolation or digest/status metadata. Hardening profile defaults to
`off`; that does not disable the three default headers. The native proxy
preserves an origin Server banner unless you remove it.

Configure global `[headers.response]`, vhost `[vhosts.headers.response]`, or
route `[vhosts.routes.headers.response]`. Omitted child scalar fields inherit.
For example, inside an existing route:

```toml
[vhosts.routes.headers.response]
x_frame_options = "SAMEORIGIN"
referrer_policy = "same-origin"
```

This changes two fields without turning off other inherited policy. Mutation
collections have more complicated current inheritance; read the limitations
below before trying to remove a parent-added field.

## Choose a Hardening Profile

```toml
[headers.response.hardening]
profile = "baseline"
```

| Profile | Additional behavior |
| --- | --- |
| `off` | No profile-derived changes; ordinary configured/default fields still apply. |
| `baseline` | Remove Server; deny camera, geolocation, microphone, payment and USB through Permissions-Policy; set X-Permitted-Cross-Domain-Policies to `none`. |
| `cross-origin-isolated` | Baseline plus COOP `same-origin`, CORP `same-origin`, COEP `require-corp`. |

The isolation profile supplies headers, not proof that a browser considers the
page isolated. Opener/embedder policy can affect popups and cross-origin resources;
verify the complete deployment and browser behavior against the
[HTML policy model](https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies).
Do not enable it globally just to satisfy a header scanner.

Typed settings override profile-derived values, then explicit remove/add/set
operations override those. For example:

```toml
[headers.response]
cross_origin_opener_policy = "same-origin-allow-popups"
cross_origin_resource_policy = "same-site"
cross_origin_embedder_policy = "credentialless"
x_permitted_cross_domain_policies = "none"
```

These are selectable policies, not a recommended universal combination. All
accepted enum values and defaults are in the reference. Turning a profile off
does not erase an origin's corresponding headers or separately configured fields.

## HSTS: Start With a Short Policy

Once HTTPS and certificate renewal work reliably:

```toml
[vhosts.headers.response.hsts]
enabled = true
max_age_secs = 300
include_subdomains = false
preload = false
```

HSTS tells browsers to keep using HTTPS. It is learned from secure transport;
a header on ordinary HTTP does not establish it. `include_subdomains` extends
the requirement to subdomains, so check them first. A learned policy can be
withdrawn with `max-age=0` over HTTPS; merely stopping header emission does not
clear the browser's stored policy. See [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797.html).

Fluxheim's typed HSTS table defaults to **63072000 seconds (two years)** when
present, so explicitly set a short duration during rollout. Typed enabled HSTS
rejects zero. Use the raw alternative for withdrawal:

```toml
[vhosts.headers.response]
strict_transport_security = "max-age=0"
```

First remove the typed HSTS configuration at this and inherited scopes: raw and
typed forms cannot coexist in the effective policy, even with typed HSTS disabled.
`preload = true` only adds that word to the header; Fluxheim does not submit a
site to a browser preload service or verify its eligibility.

HSTS configuration does not enable TLS or HTTP-to-HTTPS redirects. The response
policy currently emits the field even on an HTTP listener. Configure the correct
[TLS/redirect policy](tls.md) separately. In the config-driven path,
`hsts.enabled = false` stops Fluxheim generating it but preserves an origin HSTS
field. Use `remove = ["strict-transport-security"]` to remove an origin or typed
field, subject to the inherited generic-mutation limitation below.

## CSP and Reporting

Start by observing a candidate policy rather than breaking a working site:

```toml
[headers.response]
content_security_policy_report_only = "default-src 'self'; object-src 'none'; base-uri 'self'; report-to csp"

[headers.response.reporting_endpoints]
csp = "https://reports.example.test/csp"
```

After inspecting reports and exercising the application, an enforced example is:

```toml
[headers.response]
content_security_policy = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
```

Report-only CSP observes policy violations without enforcing that policy. An
enforced CSP restricts page behavior; inline code, external assets and framing
may need application-specific rules. Multiple enforced CSP fields combine as
restrictions, not a last-writer replacement. See the [CSP specification](https://www.w3.org/TR/CSP3/).

Fluxheim checks header-safe syntax, not whether CSP directives express the
intended security policy. It does not generate per-response nonces, rewrite HTML
with nonces, collect reports or guarantee delivery. Supply a real HTTPS report
service; the example address is a placeholder. Do not place secrets in endpoint
URLs. Report-only and enforced fields can coexist for different policies.

Typed CSP replaces matching origin fields; generic `append` can create multiple
fields. Choose a deliberate policy owner. Appending is not a way to relax an
existing enforced policy. Raw response values are not expanded as request
templates; `{request_id}` is not a CSP nonce generator.

## Browser Permissions

```toml
[headers.response.permissions_policy]
enabled = true
profile = "deny-sensitive"
```

`deny-sensitive` denies camera, geolocation, microphone, payment and USB.
`deny-all` emits the larger fixed list in the reference; it does not automatically
cover every present or future browser capability. Permissions Policy controls
browser features, not server authorization. See the [Permissions Policy specification](https://www.w3.org/TR/permissions-policy/).

For an application-specific value, use a literal replacement:

```toml
[vhosts.headers.response.add]
permissions-policy = "camera=(self), microphone=(self), geolocation=()"
```

This overrides a profile/typed value, but avoid a same-name generic add in the
parent until the documented limitation is fixed. Unlike disabled typed HSTS, an explicitly
disabled permissions-policy table removes the field, including an origin value.

## Remove, Replace and Append

```toml
[headers.response]
remove = ["server", "x-origin-secret"]

[headers.response.add]
x-service = "public-edge"

[headers.response.append]
link = ['</style.css>; rel=preload; as=style', '</app.js>; rel=preload; as=script']
```

`add` means **replace all existing values** of that name, not append. `set` is
its older alias. `remove` and `unset` are removal aliases; the default global
`unset` list contains X-Powered-By. `append` accepts one string or a list and
adds separate field lines after replacement. Do not append singleton security
fields blindly. Keep framing headers such as Content-Length, Connection and
Transfer-Encoding out of custom policy; protocol adapters own wire framing.

The nested form is equivalent at a single scope:

```toml
[headers.response.operations]
remove = ["server"]
[headers.response.operations.add]
x-service = "public-edge"
```

Use one form per field. Duplicate names across add/set/operations.add can fail
validation. Header names are case-insensitive on the wire; use lowercase names
consistently in configuration. Do not rely on differently cased keys to override
an inherited value.

Current application order is:

1. Compile the hardening profile, typed settings, then explicit mutations.
2. Rewrite existing Location, Refresh and Set-Cookie values.
3. Remove fields, replace set/add fields, then append values.
4. Add applicable Cache-Status and Proxy-Status metadata.
5. Apply the separately enabled CORS policy. Compression and final digest stages
   may subsequently change encoding, validators and digest metadata.

An explicit replacement therefore wins over a rewritten origin field. It is
not subsequently passed through the rewrite rules.

## Redirect and Cookie Rewriting

When an origin advertises internal URLs, translate just its headers:

```toml
[[headers.response.rewrite.location]]
from = "http://origin.example.test/internal/"
to = "https://public.example.test/app/"
[[headers.response.rewrite.refresh]]
from = "http://origin.example.test/internal/"
to = "https://public.example.test/app/"
[[headers.response.rewrite.cookie_domain]]
from = "origin.example.test"
to = "public.example.test"
[[headers.response.rewrite.cookie_path]]
from = "/internal/"
to = "/app/"
```

Location matches the whole value's prefix. Refresh matches the URL after `url=`
and preserves the surrounding delay and matched quote style. Rules are
first-match, in configuration order; child rules append after parent rules.
Put narrow rules first at the owning scope. Inherited broad rules can shadow
child rules. Duplicate `from` values in an effective rule list fail validation.

Only an **authority-only** HTTP/HTTPS prefix gets the `/`, `?`, `#` or end-of-value
boundary check that prevents matching `http://origin.example.test@evil.test/`.
Path-containing and path-only prefixes are literal: `/internal` also matches
`/internalized`. Use trailing slashes to restrict the example to descendants;
that intentionally does not match the bare `/internal` value. This is not a
regex engine, URL normalization or an exact-path matcher.

Cookie Domain matching ignores case and a leading dot; it is an exact domain
match, not a subdomain wildcard. Cookie Path uses the literal prefix rule above.
Each Set-Cookie line stays separate. The cookie's initial name/value pair and
unrelated attributes are preserved. Rewriting does not add Secure, HttpOnly or
SameSite, nor rewrite response HTML/JavaScript URLs. It is not a cookie security
policy or authorization boundary.

## Status and Digest Metadata

```toml
[headers.response.metadata]
identifier = "edge-public"
cache_status = true
proxy_status = true
content_digest = true
repr_digest = true
```

All four switches default off. The public identifier is required for status
fields and is bounded to 64 bytes. Status metadata is added only when the
runtime has an applicable cache outcome or locally generated proxy failure;
turning a switch on does not guarantee a header on every response. Origin status
members can remain alongside Fluxheim's. Do not treat origin-provided metadata
as a trusted attestation. See the [field reference](../reference/response-header-options.md#metadata).

Content-Digest uses SHA-256 over the final message-content buffer; HEAD hashes
empty content. Repr-Digest is emitted only for a complete GET/200 representation
without Content-Range and with a consistent declared size. No full-representation
digest is guessed for HEAD, ranges or other incomplete replies. Digests are not
signatures. The local smoke independently hashes wire bodies and checks HEAD;
cache-status completeness, every error path and every protocol/platform are not
newly qualified by that smoke.

## Disable Policy and Inspect the Result

```toml
[vhosts.routes.headers.response]
enabled = false
```

This skips that effective response policy's defaults, rewriting, mutations and
metadata. It does not strip origin policy, disable TLS, disable CORS or undo
changes made by other runtime stages. For one typed field, prefer a targeted
remove rather than disabling every defense, and verify the resulting response.

```bash
fluxheim --config examples/headers/response.toml --validate-config
fluxheim --config examples/headers/response.toml
curl -i http://127.0.0.1:8080/ -H 'Host: api.example.test'
curl -I http://127.0.0.1:8080/child -H 'Host: api.example.test'
```

These commands need an HTTP origin on port 9001. The automated repository test
creates one, uses private configuration and closes only its own processes:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_response_headers_examples.py
python3 scripts/smoke_response_headers.py
```

Inspect successful, application-error and locally rejected requests. Test real
browser behavior separately: seeing a field in curl does not prove the browser
accepts it or that all application flows still work.

## Current Limits and Planned Corrections

| Finding | Current behavior and workaround | Planned correction |
| --- | --- | --- |
| the documented limitation | Child remove cannot cancel inherited generic set/append. Parent add plus child same-name replacement can fail merged validation. Prefer owning a field at one scope, use typed overrides when available, and verify the wire. | the local follow-up: canonical, case-insensitive scoped mutation semantics and explicit compatibility tests. |
| the documented limitation | Generic response values accept known request template variables but emit them literally; unknown variables or unmatched braces can be rejected even though values are not rendered. Use static values only. | the local follow-up: align validation and rendering with an explicit response-value contract. |
| the documented limitation | Early local rejections can bypass response policy. A route body-limit 413 lacks configured CSP/HSTS/nosniff while an origin 500 receives them. No all-response hardening guarantee exists today. | the local follow-up: define and test safe policy coverage for local errors without weakening rejection or authentication. |

These remain open in the [correction plan](../roadmap/observability-commit-plan.md).
The guide does not close them by documenting them. The wire evidence is Linux
HTTP/1.1, not a new browser, HTTP/2, container, Windows or macOS qualification.
