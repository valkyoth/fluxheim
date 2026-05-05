# Cloudflare Origin Support

Cloudflare support is a feasible future optional module, but it should be split
into phases. Fluxheim should first treat Cloudflare as a trusted proxy only
after the direct peer is verified. Certificate automation and Authenticated
Origin Pulls are valuable, but they involve credentials, TLS reload behavior,
and security-sensitive trust decisions.

No Cloudflare module should be compiled into the default binary.

## Goals

- Restore the real visitor IP only for verified Cloudflare-originated requests.
- Correlate access logs with Cloudflare Ray IDs.
- Support Cloudflare IP range refresh without downtime.
- Support Cloudflare Origin CA certificate issuance as an optional automation.
- Support Authenticated Origin Pulls as an optional mTLS hardening layer.
- Keep Cloudflare credentials out of config snapshots and logs.

## Non-Goals

- No dependency on Cloudflare in default builds.
- No blind trust in `CF-*` headers.
- No automatic mutation of Cloudflare zone settings in the MVP.
- No promise that Cloudflare global AOP proves the user's specific account.
- No replacement for normal ACME/own-certificate support.

## Feature Flags

Planned feature split:

```toml
cloudflare = ["dep:ipnet"]
cloudflare-api = ["cloudflare", "dep:cloudflare", "dep:arc-swap"]
cloudflare-origin-ca = ["cloudflare-api", "dep:rcgen"]
cloudflare-aop = ["cloudflare"]
```

Reviewed crate candidates as of 2026-05-05:

- `cloudflare 0.14.0`, BSD-3-Clause: Rust library for Cloudflare v4 API.
  Configure with `rustls-tls` if used so it follows Fluxheim's default TLS
  direction.
- `rcgen 0.14.7`, MIT/Apache-2.0: local CSR/private-key generation.
- `ipnet 2.12.0`, MIT/Apache-2.0: CIDR parsing and membership checks.
- `arc-swap 1.9.1`, MIT/Apache-2.0: atomic replacement of trusted IP range
  snapshots or certificate state.

## Trust Boundary

Cloudflare request headers are trusted only when at least one configured trust
condition succeeds:

- the direct peer socket IP is in the validated Cloudflare IP range set;
- Authenticated Origin Pulls mTLS verification succeeded;
- a future explicit trusted listener is configured for private Cloudflare
  tunnel traffic.

If none of those conditions succeeds, Fluxheim must treat `CF-Connecting-IP`,
`CF-Ray`, `CF-IPCountry`, and related headers as untrusted remote input.

The direct peer IP should remain available in logs as `peer_ip`. The restored
client IP should be stored separately as `client_ip` or `real_ip` so operators
can audit whether traffic is actually coming through Cloudflare.

## Header Handling

Accepted headers after trust validation:

- `CF-Connecting-IP`: visitor IP to use for logs, WAF/rate-limit decisions, and
  admin visibility.
- `CF-Ray`: request correlation ID for structured logs and optional response
  echoing.
- `CF-IPCountry`: coarse country signal for logs/metrics after cardinality
  controls.
- `CF-Visitor`: optional scheme metadata, parsed strictly as JSON if needed.
- `CF-Worker` and `CF-Device-Type`: optional context fields, never security
  authorities.

Security rules:

- Reject or ignore malformed IP values.
- Never let untrusted Cloudflare headers override socket-derived metadata.
- Never use `CF-IPCountry`, city, device, worker, or bot headers as
  authorization decisions.
- Keep metrics labels bounded. Country labels may be allowed only as fixed
  two-letter country codes plus `unknown`; never use free-form city names as
  labels.
- Redact or bound all header values in logs.

## IP Range Refresh

Startup:

- load a configured pinned Cloudflare IP range file;
- validate every CIDR;
- refuse startup if Cloudflare mode requires trusted ranges and none are
  usable.

Optional background refresh:

- fetch Cloudflare's official IP range API daily or on a configured interval;
- validate the complete response before swapping it in;
- keep the last known-good range set if refresh fails;
- record `last_success`, `last_failure`, and active range count in metrics and
  admin status;
- never block request workers while refreshing.

Use `ArcSwap` or equivalent atomic state so new requests see the fresh range set
without interrupting active requests.

## Origin CA Automation

Cloudflare Origin CA certificates are separate from Let's Encrypt/ACME
certificates. They are trusted by Cloudflare for edge-to-origin TLS, not by
normal browsers directly.

Planned flow:

1. Generate a private key locally with strict permissions.
2. Generate a CSR for configured hostnames.
3. Call the Cloudflare Origin CA create-certificate API.
4. Persist certificate and key through Fluxheim's atomic snapshot/storage
   pattern.
5. Validate certificate hostnames and expiry.
6. Reload TLS state without downtime through the existing cert reload model.
7. Optionally revoke superseded Origin CA certificates after a safe overlap
   period.

Guardrails:

- API token must be least-privilege and loaded from a secret path or
  environment, not committed into config snapshots.
- Token, CSR private key, and certificate private key must never be logged.
- Renewal should happen well before expiry and expose failures through
  admin/metrics/logging.
- The operator must be able to disable automation and use their own
  certificate files.

## Authenticated Origin Pulls

Authenticated Origin Pulls add mTLS client-certificate verification from
Cloudflare to the origin.

Modes:

- Global AOP: easiest setup, but the Cloudflare-provided client certificate is
  shared across Cloudflare accounts and proves only that the connection came
  from Cloudflare's network.
- Zone-level AOP: uses a user-uploaded certificate and is stricter.
- Per-hostname AOP: uses a user-uploaded certificate for specific hostnames and
  is preferred for mixed or high-security deployments.

Fluxheim should support:

- configured AOP CA bundle per listener/vhost;
- certificate verification during TLS handshake where the selected TLS backend
  supports it;
- certificate reload without dropping active requests;
- metrics/logs for AOP success/failure counts;
- clear validation warnings when a deployment relies only on global AOP.

## Config Shape

Initial target:

```toml
[cloudflare]
enabled = false
mode = "trusted_proxy"
trusted_ranges_file = "/etc/fluxheim/cloudflare-ips.toml"
refresh_ranges = true
refresh_interval_hours = 24
require_cloudflare_peer = true
restore_real_ip = true
use_cf_ray_as_trace = true
echo_cf_ray = false

[cloudflare.origin_ca]
enabled = false
hostnames = ["example.com", "*.example.com"]
requested_validity_days = 90
key_type = "ecdsa"
cert_path = "/var/lib/fluxheim/cloudflare/origin.pem"
key_path = "/var/lib/fluxheim/cloudflare/origin.key"
token_file = "/run/secrets/cloudflare-origin-ca-token"
renew_before_days = 21

[cloudflare.aop]
enabled = false
mode = "zone"
ca_bundle = "/etc/fluxheim/cloudflare/aop-ca.pem"
fail_closed = true
```

Per-vhost override target:

```toml
[vhosts.cloudflare]
enabled = true
require_cloudflare_peer = true
restore_real_ip = true
```

## Implementation Stages

1. Add feature guards and config validation.
2. Add trusted Cloudflare range loading from a local pinned file.
3. Restore real IP and Ray ID only after trust validation.
4. Add structured log fields and metrics.
5. Add background IP range refresh with last-known-good fallback.
6. Add Cloudflare Origin CA CSR and renewal workflow.
7. Add AOP/mTLS configuration and reload tests for the active TLS backend.
8. Add optional API calls for managing AOP only after credential and permission
   scope is reviewed.

## Tests

Required tests:

- Default build does not compile Cloudflare modules.
- Spoofed `CF-Connecting-IP` from a non-Cloudflare peer is ignored.
- Valid Cloudflare peer restores `CF-Connecting-IP`.
- Malformed `CF-Connecting-IP` is ignored or denied according to config.
- `CF-Ray` is logged only as a bounded correlation field.
- IP range refresh failure keeps the last known-good set.
- Empty or invalid trusted range config fails closed when required.
- API tokens are redacted from logs, admin status, and validation errors.
- Origin CA CSR includes only configured hostnames.
- Certificate reload does not interrupt active requests.
- AOP fail-closed denies requests without a valid client certificate.
