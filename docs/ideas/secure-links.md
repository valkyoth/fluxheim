# Secure Links

Status: future optional module.

Planned Cargo features:

- `secure-links`: shared config, URL token parsing, expiry checks, and route
  enforcement.
- `secure-links-hmac`: symmetric HMAC signing.
- `secure-links-ed25519`: asymmetric public-key verification.
- `secure-links-replay`: optional replay and usage accounting when a state
  backend is available.

Secure links are signed URLs for downloads, static assets, media segments, or
temporary shared routes. They should be independent from external
authorization: auth modules answer "who is this requester?", while secure links
answer "is this specific URL grant valid for this request?".

## Goals

- Replace weak legacy signing patterns with modern, reviewable cryptography.
- Support stateless verification for high-volume static and media paths.
- Support asymmetric verification so Fluxheim can verify links without holding
  the private signing key.
- Treat URL tokens as claims with expiry, audience, path, method, and optional
  entitlement constraints.
- Add optional replay controls only when a suitable state backend exists.
- Avoid logging raw tokens, signatures, or entitlement claims.

## Cryptography

Stable cryptographic options should start with:

- HMAC-SHA-256 or HMAC-SHA-384 for symmetric deployments;
- Ed25519 for asymmetric deployments where application servers sign and
  Fluxheim verifies with public keys.

Future token formats may include compact JWT or PASETO-like claims, but the
module should not accept arbitrary algorithms. Config must define an algorithm
allow-list, key IDs, expiry requirements, maximum token size, and key rotation
behavior.

Do not use weak digest-only constructions. A signature must cover at least:

- normalized path;
- method when configured;
- expiry timestamp;
- key ID or policy ID;
- optional audience/tenant/route constraints.

## Claims

Secure-link claims should be typed and bounded:

- `exp`: required expiry timestamp;
- `nbf`: optional not-before timestamp;
- `path`: exact path or policy-approved path prefix;
- `method`: optional method allow-list;
- `aud`: optional vhost/route audience;
- `sub`: optional user or account identifier;
- `tier`: optional entitlement tier;
- `jti`: optional token ID for replay controls;
- `max_bytes`: optional transfer budget when accounting exists.

Fluxheim should validate claims against the vhost and route policy before
serving or proxying the request.

## Replay And Usage Controls

Replay prevention needs state. It should not be claimed in the stateless core.

Future replay controls can integrate with cache/admin/cluster state:

- one-time token IDs;
- max uses per token;
- max distinct client identities per token;
- max transferred bytes per token;
- short-lived Bloom-filter style duplicate detection for media segments.

All stateful replay controls must define consistency semantics. In a cluster,
operators must choose between local-only, eventual, or strict behavior.

## Client Binding

IP-only binding is fragile. If supported, it should be optional and tolerant:

- bind to an IP CIDR range rather than a single IP;
- use the verified restored client IP only after trusted-proxy validation;
- support future identity or device-posture claims when identity modules exist;
- avoid client binding entirely for privacy-mode deployments.

TLS/session binding is future research and must not be promised until the
selected Pingora/TLS backends expose enough safe metadata.

## Configuration Sketch

```toml
[secure_links.profiles.downloads]
algorithm = "ed25519"
public_key_file = "/etc/fluxheim/secure-links/downloads.ed25519.pub"
token_query = "sig"
max_token_bytes = "2KiB"
on_invalid = 403
on_expired = 410
clock_skew_secs = 30

[secure_links.profiles.downloads.claims]
require_path = true
require_expiry = true
allowed_methods = ["GET", "HEAD"]

[[vhosts.routes]]
name = "private-downloads"
match = { prefix = "/downloads/" }
action = "web"
secure_link = { enabled = true, profile = "downloads" }
```

## Privacy And Security

- Never log raw secure-link tokens, signatures, or decoded claims by default.
- Strip secure-link query parameters from access-log paths unless the operator
  explicitly disables redaction.
- Reject unsigned or expired links before static serving, proxying, cache
  lookup, or media transformation.
- Cache keys must not include raw tokens. Cache admission for protected content
  must be explicitly designed so one user's token does not create a personalized
  shared cache object.
- `privacy-mode` should reject replay/accounting features and may reject the
  whole module until token redaction and no-retention behavior are tested.

## Test Plan

- Valid signed URL allows access.
- Expired and not-yet-valid tokens deny access.
- Wrong path, method, audience, or route denies access.
- Malformed and oversized tokens are rejected safely.
- Unknown key ID and disallowed algorithm are rejected.
- Key rotation behavior is tested.
- Tokens are redacted from logs and error output.
- Cache and media routes cannot leak personalized protected content.
- Replay controls, when enabled, enforce max-use and state consistency rules.
- Default and privacy builds prove secure-link code is absent unless explicitly
  enabled.
