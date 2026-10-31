# ACME Option Reference

Use the [operator guide](../guides/acme.md) first. Tables list the public fields
in `config_acme.rs`, `config_acme_issuer.rs` and `config_acme_challenge.rs`.
Unknown fields are rejected. Optional fields are omitted, not written as TOML
`null`. Duration fields below are integer seconds, not strings such as `"1h"`.

## Global ACME

`[tls.acme]` also requires `[tls] enabled = true` for managed targets. TLS
listeners are separate `server.tls_listen` settings, not created by ACME.

| Field | Default | Meaning / constraint |
| --- | --- | --- |
| `enabled` | `false` | Enable managed ACME configuration |
| `storage` | Absent | Required when enabled; persistent, private directory; relative paths resolve against config base |
| `contact_email` | Absent | Required when enabled; operator contact, not an EAB identifier |
| `default_issuer` | `"letsencrypt"` | Exact configured issuer name |
| `challenge` | `"http-01"` | `http-01` or `tls-alpn-01`; latter validates with rustls/TLS listener but native challenge serving is incomplete  |
| `automation` | `"background"` | `background` or `external`; external stops the in-process renewal task, not challenge serving |
| `renewal` | Table below | Scheduling and reload settings |
| `issuers` | Five built-in entries | `[[tls.acme.issuers]]`; maximum 128, unique nonempty names; an explicit list replaces built-ins |

The [HTTP-01](../../examples/acme-http-01.toml) and
[external/EAB](../../examples/acme-actalis.toml) templates show both automation
modes. Do not paste a second `[tls.acme]` table to override the first.

## Renewal

`[tls.acme.renewal]`:

| Field | Default | Meaning / current limitation |
| --- | --- | --- |
| `enabled` | `true` | Permit renewal target generation; false also suppresses CLI forced targets |
| `renew_before_secs` | `2592000` | Local planner's pre-expiry window (30 days); positive when renewal enabled; ARI may influence actual execution |
| `renew_after` | Absent | TOML offset datetime, e.g. `2099-01-01T00:00:00Z`; planner lower bound, **Current limitation:** |
| `check_interval_secs` | `3600` | Positive background sleep after a renewal tick; work time is additional |
| `retry_initial_secs` | `300` | Positive, no greater than max; **Current limitation:** |
| `retry_max_secs` | `86400` | Positive maximum backoff setting; same runtime gap |
| `reload_after_renewal` | `true` | Companion reload and server reload-control service selection; **Current limitation:** |
| `zero_downtime_reload` | `true` | Accepted configuration, **Current limitation:** |

Scheduling validators do not currently impose a small maximum on the positive
duration values. Use practical intervals, not integer-limit values. Local
datetimes without offsets are rejected. To pause safely, use the workflow in
the operator guide rather than relying on the currently inconsistent hold.

## Per-Vhost Certificate

Inside each `[[vhosts]]`, enable `[vhosts.tls]`, then configure
`[vhosts.tls.acme]`:

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Use a managed certificate for this vhost |
| `issuer` | Absent | Override global default with an existing issuer name |
| `domains` | `[]` | Explicit concrete names (at most 64); otherwise derive from vhost hosts, excluding wildcard hosts |

```toml
[vhosts.tls]
enabled = true
[vhosts.tls.acme]
enabled = true
issuer = "letsencrypt-staging"
domains = ["site.example.test", "www.site.example.test"]
```

Names are validated and duplicates rejected. Wildcard routing is not wildcard
issuance; DNS-01 is unavailable. The server's `default_vhost` can provide a
fallback managed certificate when no global static default is configured.

## Issuer And Agreement

`[[tls.acme.issuers]]`:

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | Required | Nonempty unique identifier; referenced by vhosts/default |
| `directory_url` | Required | HTTPS ACME directory, not a certificate download URL |
| `terms_of_service_agreed` | `false` | Explicit acceptance for new-account registration |
| `terms_of_service_url` | Absent | Reviewed HTTPS terms URL; required when accepting |
| `allow_unadvertised_terms_of_service` | `false` | Explicit exception for an issuer that does not advertise terms; requires acceptance and URL; not permission to ignore mismatched advertised terms |
| `ca_bundle_file` | Absent | Optional trusted CA bundle for the issuer client; protected path, relative to config base |
| `eab` | Absent for custom entries | Optional external-account-binding table |

Built-in entries start with terms unaccepted. Their EAB environment mappings are:

| Issuer | Key-ID variable | HMAC-key variable |
| --- | --- | --- |
| Actalis | `FLUXHEIM_ACTALIS_EAB_KID` | `FLUXHEIM_ACTALIS_EAB_HMAC_KEY` |
| GTS | `FLUXHEIM_GTS_EAB_KID` | `FLUXHEIM_GTS_EAB_HMAC_KEY` |
| GTS staging | `FLUXHEIM_GTS_STAGING_EAB_KID` | `FLUXHEIM_GTS_STAGING_EAB_HMAC_KEY` |

Use explicit file/credential mappings when environment secrets are unsuitable.

## EAB Sources

`[tls.acme.issuers.eab]` has six optional fields, all absent by default for a
custom table. Choose exactly one key-ID source and one HMAC-key source:

| Key-ID field | HMAC field | Source |
| --- | --- | --- |
| `key_id_env` | `hmac_key_env` | Name of a process environment variable, not the secret value |
| `key_id_file` | `hmac_key_file` | Protected file path; relative paths resolve against config base |
| `key_id_credential` | `hmac_key_credential` | Valid systemd credential name under its credential directory |

Example alternatives to the guide's file mapping:

```toml
[tls.acme.issuers.eab]
key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
```

```toml
[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Use one table, not both. The HMAC key must have the issuer's expected base64url
representation. See [secret storage](../guides/certificate-renewal.md) for
bounded loading, permissions and systemd unit examples.

## External HTTP-01 Forwarding

`[vhosts.acme_challenge]` is independent of managed issuance. Enabling it
selects an external challenge route instead of the managed token handler:

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Forward `/.well-known/acme-challenge/`; exempt this route from HTTPS redirect |
| `upstream` | Absent | Single `host:port` authority; no URL path |
| `upstreams` | `[]` | Alternative list, maximum 64 unique authorities; mutually exclusive with `upstream` |
| `upstream_tls` | `false` | TLS to the upstream agent; normal proxy verification still applies |
| `connect_timeout_secs` | Absent | Optional positive connection timeout; otherwise proxy defaults |
| `read_timeout_secs` | Absent | Optional positive read timeout; otherwise proxy defaults |
| `send_timeout_secs` | Absent | Optional positive send timeout; otherwise proxy defaults |

```toml
[vhosts.acme_challenge]
enabled = true
upstreams = ["challenge-a.example.test:8443", "challenge-b.example.test:8443"]
upstream_tls = true
connect_timeout_secs = 5
read_timeout_secs = 10
send_timeout_secs = 10
```

The agents must share the needed challenge state and present verifiable TLS
identities. This example is a deployment template, not a live-tested HA setup.
For the ordinary local agent, prefer the single-loopback example in the guide.
