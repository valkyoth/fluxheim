# Downstream TLS Options

Use the [HTTPS and mTLS guide](../guides/tls.md) for workflows. These fields come
from `config_tls.rs`, `config_tls_policy.rs`, `config_tls_certificate.rs` and
`config_tls_client_auth.rs`. They do not configure upstream proxy TLS.
Unknown fields are rejected; optional values are omitted rather than TOML `null`.

## Listener And Policy

`server.tls_listen` binds TLS addresses; `[tls] enabled = true` alone does not
create a socket. `server.listen` is independent plaintext HTTP. A fallback
certificate source is required for a TLS listener.

| `[tls]` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Enable downstream TLS configuration |
| `backend` | `rustls` | `rustls` or `openssl`; must match compiled features |
| `profile` | `intermediate` | `modern`, `intermediate`, `compat` |
| `min_protocol` | Profile default | `tls1.2` or `tls1.3`; modern requires 1.3 |
| `alpn` | `http1-and-http2` | `http1`, `http2`, `http1-and-http2` |
| `curve_preferences` | Profile list | At most 16 entries; empty restores defaults |
| `cipher_suites` | Profile list | At most 32 entries; empty restores defaults |
| `certificates` | Empty | At most 1024 pairs; first global pair is fallback, not automatic SAN indexing of all entries |
| `client_auth` | Off | Listener-wide policy below |
| `acme` | Disabled | [ACME option reference](acme-options.md); native TLS-ALPN integration remains pending |
| `fips` | Not required | Compliance guard below |
| `iso19790` | Not required | Compliance guard below |

Protocol aliases: `TLS1.2`/`VersionTLS12` and `TLS1.3`/`VersionTLS13`.
Modern defaults to TLS 1.3; intermediate/compat default to TLS 1.2 plus 1.3.
There is no maximum-protocol field. An explicit cipher list without suites for
a protocol family prevents using that family.

## Curves And Cipher Suites

All three profiles default to `X25519`, `CurveP256`, `CurveP384`, in that order.
Accepted group names and aliases:

| Canonical name | Aliases | Availability |
| --- | --- | --- |
| `x25519` | `X25519` | Normal providers |
| `p256` | `P-256`, `CurveP256` | Normal/compliance-capable providers |
| `p384` | `P-384`, `CurveP384` | Normal/compliance-capable providers |
| `x25519-mlkem768` | `X25519MLKEM768`, `X25519-MLKEM768` | Default rustls/Ring rejects it; provider/build support is required |

Modern defaults to these TLS 1.3 suites:

```toml
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
]
```

Intermediate/compat add these TLS 1.2 suites to the same list:

```toml
cipher_suites = [
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]
```

These are the complete accepted cipher names. The second fragment alone is a
TLS-1.2-only list, not the full intermediate default. A TLS 1.3 minimum rejects
TLS 1.2 entries. Certificates and peer capabilities must match the chosen suites.

## Certificates And Client Authentication

Each `[[tls.certificates]]` pair and `[vhosts.tls.certificate]` requires
`cert_path` and `key_path`. Relative paths use the configuration base. Vhost
`enabled` defaults false, `certificate` defaults absent and `acme` defaults
disabled. Explicit vhost static pairs take selection precedence over its managed
ACME source. Do not configure both expecting automatic failover.

`[tls.client_auth]`:

| Field | Default | Meaning |
| --- | --- | --- |
| `mode` | `off` | `off`, `optional`, `required`; global TLS listener policy |
| `ca_path` | Absent | PEM client CA bundle, required for optional/required |
| `crl_path` | Absent | PEM CRL bundle; rejected with mode off |

Bounds: chain file 1 MiB / 16 certificates; private-key file 64 KiB; client CA
bundle 8 MiB / 4096 certificates; CRL bundle 8 MiB / 1..64 lists. Rustls supports
unencrypted PKCS#1 RSA, SEC1 EC and PKCS#8 private-key PEM sections. Validation
rejects symlinked paths and unsafe existing parents, but Unix runtime reads do
not yet preserve that trust boundary at open time (**Current limitation:**, the local follow-up).
Use restrictive ownership and permissions; do not interpret parse success as
proof of secret confidentiality. Windows uses confidential-key ACL checks.

## Compliance Guards

Both `[tls.fips]` and `[tls.iso19790]` have `required` and
`require_disk_cache_encryption` fields, both defaulting to `false`.
Required mode needs the matching
compliance-capable build/runtime provider and approved cipher/group choices.
Default X25519/ChaCha20 choices are not silently rewritten to approved choices.
Required client authentication in required compliance mode also needs a CRL.
The disk-cache guard promotes the relevant unencrypted-cache warning to a
configuration error. See [FIPS requirements and limitations](../guides/fips.md).
