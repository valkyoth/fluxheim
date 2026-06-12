# External Authorization Request

Status: future optional module.

Planned Cargo feature: `auth-request`.

This module lets Fluxheim ask a configured authorization service whether a
client request should continue. It is designed for deployments that already
have a policy service, session service, identity gateway, or internal access
decision API and want Fluxheim to enforce the decision before proxying or
serving static content.

## Design Goals

- Keep the default binary free of external-authorization code.
- Make authorization per-vhost and per-route.
- Support global authorization zones that protect all routes by default unless
  a route is explicitly excluded.
- Keep request workers protected with strict timeouts and response-size limits.
- Never trust headers supplied by the client as authorization facts.
- Make every fail-open/fail-closed choice explicit in config.
- Prefer local JWT/OIDC verification when a request can be decided without a
  network call.
- Support low-latency authorization hooks over HTTPS, Unix domain sockets, and
  later gRPC.
- Support static web, reverse proxy, and load-balancer routes without turning
  Fluxheim into an application runtime.

## Decision Contract

Fluxheim sends a small authorization request to a configured internal endpoint.
The authorization endpoint decides whether the original request may continue.

Transport options should be explicit:

- `https`: simplest integration with existing policy services.
- `unix`: local sidecar/service integration without exposing a TCP port.
- `grpc`: future persistent typed authorization API for high-throughput
  deployments.

Decision handling:

- `2xx`: allow the original request.
- `401`: deny with `401`; pass through only configured challenge headers.
- `403`: deny with `403`.
- Any other status: treat as an authorization service error.

Error handling is configurable:

- `fail_closed`: return `503` or configured error status.
- `fail_open`: allow the request and emit a security event, only allowed when
  explicitly configured.

`fail_closed` should be the default.

## Request Shape

Fluxheim should not forward the full original request by default. The safe
baseline is a header-only authorization probe:

- method;
- scheme;
- host;
- normalized path;
- query presence or query value depending on policy;
- configured request headers;
- verified client IP only when not in `privacy-mode` and only after trusted
  proxy processing;
- TLS/SNI metadata where useful;
- vhost name and route name.

Request bodies are disabled by default. If an operator enables body forwarding,
Fluxheim must enforce:

- a small `max_body_bytes`;
- allowed content types;
- redaction rules;
- timeout budgets;
- no body forwarding for streaming uploads unless explicitly supported.

## Header Policy

The module must use allow-lists, not pass-through-by-default behavior.

Inbound headers stripped before auth:

- `Authorization` unless explicitly forwarded;
- cookies unless explicitly forwarded;
- any `X-User-*`, `X-Auth-*`, `X-Forwarded-*`, or configured identity headers
  that could be spoofed by the client.

When an operator explicitly allow-lists common request-context names,
Fluxheim-generated context wins over client-supplied values. `X-Original-URI`,
`X-Forwarded-URI`, `X-Auth-Request-Redirect`, `X-Forwarded-For`, `X-Real-IP`,
`X-Forwarded-Host`, and `X-Forwarded-Proto` are built from the current request
and trusted proxy chain before the auth subrequest is sent. Repeated `Cookie`
fields are joined with `; `, matching the normalized upstream origin request,
so the auth service and origin receive the same cookie structure when cookies
are explicitly forwarded.

Headers copied from the auth response to the original upstream request must
also be allow-listed. Recommended defaults:

- no copied headers;
- optional namespaced verified headers such as `X-Fluxheim-User`,
  `X-Fluxheim-Groups`, and `X-Fluxheim-Auth-Decision`;
- no raw token propagation unless explicitly configured.

For `401`, challenge headers such as `WWW-Authenticate` may be passed to the
client only from an allow-list.

## Identity Context And Claim Mapping

Fluxheim should store the verified identity decision in request context after
authorization. Later phases can then use the same typed identity object for
upstream header injection, routing, logging, and metrics without reparsing
tokens or trusting inbound headers.

Claim/header mapping must be explicit:

- strip inbound identity headers before verification;
- map only verified claims from the auth response or local JWT verifier;
- prefer namespaced headers such as `X-Fluxheim-User`,
  `X-Fluxheim-Groups`, and `X-Fluxheim-Tier`;
- never forward raw tokens unless the operator explicitly allow-lists them.

Example:

```toml
[auth_request.profiles.internal.claim_headers]
x-fluxheim-user = "user.id"
x-fluxheim-groups = "groups"
x-fluxheim-tier = "subscription.tier"
```

## Global Auth Zones

For protected deployments, authorization should be opt-out at the route level
rather than opt-in everywhere. A global auth zone can cover a vhost, with
explicit exclusions for public assets and health checks.

```toml
[vhosts.auth_request]
enabled = true
profile = "internal"
mode = "protect_all"
except = ["/public/*", "/favicon.ico", "/_health"]
```

Config validation must reject ambiguous policies where a route both requires
and excludes auth through conflicting inherited settings.

## Local JWT Verification

When the identity provider issues signed JWTs, Fluxheim should be able to verify
the token locally through the future `identity-oidc` module:

- OIDC discovery and JWKS cache;
- issuer and audience validation;
- expiry, not-before, and clock-skew validation;
- algorithm allow-listing;
- bounded token and key sizes;
- key rotation and stale-key behavior.

Local verification avoids an auth-service round trip for normal requests. Live
external authorization remains useful for session revocation, policy checks,
device posture, and other decisions that cannot be encoded safely in a token.

## Denial Responses

Denial behavior should be explicit and client-aware:

- browser requests may redirect to a configured login URL;
- redirects may include a safe return destination generated from the normalized
  original URL;
- API/AJAX requests can receive a JSON `401`/`403` response instead of a
  redirect;
- redirect destinations must be validated to avoid open redirects.

## Caching

Authorization decisions may be cached only when the operator enables it.

Cache key isolation must include:

- vhost;
- route;
- method;
- normalized path or configured path bucket;
- selected identity/session token fingerprint;
- auth policy version.

Negative and positive TTLs must be separate. Defaults should be conservative:

- positive cache disabled;
- negative cache disabled;
- max TTL bounded in config validation.

Never cache decisions that include raw credentials, request bodies, or
unbounded query strings.

## Security Requirements

- Auth backend URL must be explicit per vhost or inherited from a typed global
  profile.
- Auth backend TLS verification must be enabled by default.
- mTLS to the auth backend should be supported.
- Auth backend response headers and bodies must have strict size limits.
- Auth requests must have connect, read, and total timeouts.
- Redirect responses from the auth backend are errors unless explicitly
  allowed for a narrow use case.
- Auth loops must be impossible: auth endpoints cannot themselves require the
  same auth policy.
- Admin, metrics, ACME challenge, and internal control paths must be excluded
  unless explicitly allowed.
- Logs must record decision class, policy name, status, latency, and error
  class after redaction. They must not log raw tokens, cookies, or auth
  response bodies.
- `privacy-mode` should be incompatible with `auth-request` by default because
  external authorization intentionally sends request metadata to another
  service.

## Configuration Sketch

```toml
[auth_request.profiles.internal]
endpoint = "unix:///run/auth/check.sock"
timeout = "250ms"
fail_mode = "fail_closed"
forward_body = false
max_response_header_bytes = "16KiB"
max_response_body_bytes = "4KiB"

[auth_request.profiles.internal.request_headers]
allow = ["authorization", "cookie"]

[auth_request.profiles.internal.response_headers]
copy_to_upstream = ["x-fluxheim-user", "x-fluxheim-groups"]
copy_to_client_on_401 = ["www-authenticate"]

[auth_request.profiles.internal.denial]
browser_redirect = "https://auth.example.com/login"
return_parameter = "rd"
api_response = "json"

[[vhosts]]
name = "example"
hosts = ["example.com"]

[vhosts.auth_request]
enabled = true
profile = "internal"
mode = "protect_all"
except = ["/public/*", "/favicon.ico"]
```

## Test Plan

- Allow on `2xx`.
- Deny on `401` and `403`.
- Treat every other auth status as an error.
- Pass only allow-listed challenge headers on `401`.
- Strip spoofable identity headers before auth and before upstream forwarding.
- Enforce auth backend timeout and response-size limits.
- Reject recursive auth configuration.
- Verify `fail_closed` and explicit `fail_open` behavior.
- Verify positive/negative cache TTL boundaries when decision caching is
  enabled.
- Verify global auth zones protect routes by default and honor explicit
  exclusions.
- Verify UDS auth endpoints and later gRPC hooks enforce the same timeout and
  size limits as HTTPS endpoints.
- Verify local JWT issuer, audience, expiry, algorithm, and key rotation
  behavior.
- Verify claim mapping only injects values from verified identity context.
- Verify browser redirects preserve a safe return destination and API/AJAX
  requests can receive non-redirect denials.
- Verify `auth-request` is absent from default builds and rejected with
  `privacy-mode`.
