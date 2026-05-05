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
- Keep request workers protected with strict timeouts and response-size limits.
- Never trust headers supplied by the client as authorization facts.
- Make every fail-open/fail-closed choice explicit in config.
- Support static web, reverse proxy, and load-balancer routes without turning
  Fluxheim into an application runtime.

## Decision Contract

Fluxheim sends a small authorization request to a configured internal endpoint.
The authorization endpoint decides whether the original request may continue.

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

Headers copied from the auth response to the original upstream request must
also be allow-listed. Recommended defaults:

- no copied headers;
- optional namespaced verified headers such as `X-Fluxheim-User`,
  `X-Fluxheim-Groups`, and `X-Fluxheim-Auth-Decision`;
- no raw token propagation unless explicitly configured.

For `401`, challenge headers such as `WWW-Authenticate` may be passed to the
client only from an allow-list.

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
endpoint = "https://auth.internal.example/check"
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

[[vhosts]]
name = "example"
hosts = ["example.com"]

[vhosts.auth_request]
enabled = true
profile = "internal"
paths = ["/private/*", "/api/*"]
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
- Verify `auth-request` is absent from default builds and rejected with
  `privacy-mode`.
