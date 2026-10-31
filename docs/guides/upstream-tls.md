# Secure Connections To HTTPS Origins

An HTTPS browser connection ends at Fluxheim. To encrypt and authenticate the
next connection, from Fluxheim to your application, enable **upstream TLS** on
the proxy policy. Otherwise an HTTPS frontend can still forward plaintext to
its origin. These settings are independent of [downstream TLS](tls.md).

This guide covers the native HTTP proxy. TCP stream TLS, load-balancer health
probes, discovery downloads and OTLP collectors have their own configuration
and lifecycles; do not assume this policy configures those connections.

## Start With A Verified Origin

Use the complete [upstream HTTPS example](../../examples/tls/upstream.toml).
Its HTTP entry point is loopback-only for local testing. For public requests,
add a downstream HTTPS listener using the [TLS guide](tls.md).

The example connects to `127.0.0.1:9443`, but verifies the origin's certificate
as `origin.example.test`. Supply `origin-ca.pem` alongside the configuration
and run an origin whose certificate is issued by that CA and covers that name.

```toml
[vhosts.proxy]
upstreams = ["127.0.0.1:9443"]
upstream_tls = true
upstream_sni = "origin.example.test"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "origin-ca.pem"
upstream_http_version = "http1"
connect_timeout_secs = 3
upstream_total_connection_timeout_secs = 5
read_timeout_secs = 5
send_timeout_secs = 5
```

Place this table after the intended `[[vhosts]]` declaration, as in the complete
example. These fields also belong to root `[proxy]` or an explicit route's
`[vhosts.routes.proxy]` policy. Keep a route's intended destination and trust
settings together; do not rely on a different vhost's certificate configuration.
Origin addresses are `host:port` authorities, not `https://` URLs.

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
fluxheim --config /etc/fluxheim/fluxheim.toml
curl --fail --header 'Host: gateway.example.test' http://127.0.0.1:8080/
```

The curl command reaches the local HTTP frontend; Fluxheim verifies the separate
TLS hop. A successful config check is not proof of an origin handshake. Test a
request and deliberately test an untrusted/wrong-name origin before rollout.

For a public-PKI origin, omit `upstream_ca_path` to use the platform trust store:

```toml
[vhosts.proxy]
upstreams = ["origin.example.com:443"]
upstream_tls = true
upstream_sni = "origin.example.com"
upstream_verify_cert = true
upstream_verify_hostname = true
```

Use your actual origin name. The runtime/container must contain usable CA roots.
Rustls loads native roots; OpenSSL uses its default verification paths. A custom
`upstream_ca_path` **replaces**, rather than augments, those default roots for
this policy. A private bundle is not automatically also a public CA bundle.

## Understand The Three Names

| Value | Purpose | Example |
| --- | --- | --- |
| Upstream authority | Where Fluxheim connects | `127.0.0.1:9443` |
| `upstream_sni` | TLS server selection and normally certificate name verification | `origin.example.test` |
| HTTP Host / HTTP/2 authority | Application routing after the TLS handshake | `gateway.example.test` |

Choosing SNI does not rewrite the HTTP Host header. The live examples verify
that the original `gateway.example.test` Host reaches the origin while TLS
uses `origin.example.test`. Use a separate request-header policy if your origin
needs a different HTTP name; see the [header reference](../reference/config-reference.md#headers).

Without an explicit SNI, the native connector derives the name from the chosen
upstream authority. Verified IP-addressed origins require an explicit
`upstream_sni`; use a DNS name covered by the certificate for portable behavior.
Dynamic file/HTTP discovery also requires explicit SNI when TLS is enabled.
A shared SNI applies to the whole proxy policy, not a separate name per pool
member. See [load balancing](load-balancer.md) for pool/discovery boundaries.

When a TLS routing name intentionally differs from the certificate identity:

```toml
# Add to the same proxy table, keeping verification enabled and the CA bundle.
upstream_sni = "routing.example.test"
upstream_alternative_cn = "origin.example.test"
```

Despite its historical name, `upstream_alternative_cn` is a **replacement
verification name**, not a second acceptable name and not a request to bypass
SAN checking. Both native backends check this name instead of SNI. A certificate
matching only SNI fails if the replacement does not match. Wildcards are not
allowed in this setting; wildcard SAN interpretation remains the verifier's
job. Prefer the ordinary single-name configuration unless the origin requires
the split. Backend certificate-name rules still apply; issue correct SANs.

## Authenticate Fluxheim To The Origin

Use the complete [upstream mTLS example](../../examples/tls/upstream-mtls.toml).
Add a client certificate chain and matching unencrypted private key:

```toml
# Add to the same verified proxy policy.
upstream_client_cert_path = "gateway-client.pem"
upstream_client_key_path = "gateway-client-key.pem"
```

The origin must trust the issuer of `gateway-client.pem` and require/authorize
that identity. The chain file starts with the client leaf, followed by any
intermediates. It is distinct from `origin-ca.pem`, which tells Fluxheim whom
to trust as a server. Set both client paths together; one without the other
is rejected. TLS must be enabled to use CA or client-key settings.

This identity belongs to Fluxheim's origin connection. It is not automatic
forwarding of a browser's client certificate or private key. Every request
using this policy can use the configured gateway identity, so keep application
authorization and downstream access rules in place.

Protect the private key and all containing directories; use service-owned
private files (for example mode 0600 on Unix). A password callback for encrypted
client keys is not provided. Never mount private keys into an origin's public
document root, log them, or include them in support archives.

## Verification Controls

Keep both verification flags true for production:

| `upstream_verify_cert` | `upstream_verify_hostname` | Effect |
| --- | --- | --- |
| `true` | `true` | Verify chain/trust and expected server name |
| `true` | `false` | Verify trust without binding it to the intended name; another trusted server may impersonate the origin |
| `false` | `false` | No authenticated server identity; encryption alone does not prevent an active intermediary |
| `false` | `true` | Rejected as inconsistent |

A custom CA bundle with certificate verification disabled is rejected. Fix the
CA bundle, SAN/name or server chain instead of disabling verification to hide
an error. Rustls still constructs a root store even in its insecure mode; do
not depend on insecure mode as a workaround for a missing CA installation.

There is no upstream CRL-file, certificate-pin or custom OCSP policy setting
in this proxy schema. Do not transfer downstream `tls.client_auth.crl_path`
semantics to origin verification. Where immediate origin credential revocation
is required, manage CA trust and connection draining explicitly.

## HTTP Protocols And TLS Policy

`upstream_http_version` is independent of the browser's protocol:

- `http1` (default): HTTP/1.1 to the origin.
- `http2`: HTTP/2 to a compatible origin, including HTTP/2-based applications.
- `http1-and-http2`: offer HTTP/2 and allow HTTP/1.1 fallback.

TLS uses ALPN for this negotiation. `upstream_h2c_upgrade` is plaintext-only
and is rejected with upstream TLS. Downstream `tls.alpn` does not configure
origin ALPN. HTTP/1.1 WebSocket upgrade proxying requires `http1` upstream policy.
Use the [proxy reference](../reference/config-reference.md#proxy) for H2 stream
limits, ping intervals, timeouts and TCP controls.

Both native connectors establish a TLS 1.2-or-newer baseline. There is no
per-proxy minimum-version, cipher-list or group-list setting. In particular,
downstream `tls.profile = "modern"` does not force TLS 1.3 to the origin.
Enforce stricter origin requirements on the origin and test the actual build;
do not infer FIPS compliance from encryption or a downstream flag.

The upstream implementation is selected by compiled backend features: rustls
when present, otherwise the OpenSSL backend. A runtime downstream backend
setting is not a separate upstream backend selector. Use a supported build
profile with TLS rather than enabling every backend feature together.

`upstream_proxy_protocol = "v1"` or `"v2"` sends a PROXY header before the
TLS handshake. Enable it only if the origin explicitly expects that framing.
An ordinary HTTPS server does not. Leave it `off` otherwise.

## Files, Reloads And Current Limits

CA bundles, client chains and client keys are read when an upstream connector is
constructed, not watched for every request. Replacing bytes at the same pathname
does not itself update existing connectors or pooled TLS sessions. A downstream
certificate-only reload is not an upstream trust-refresh mechanism. Use a
controlled process replacement and drain old connections when you must ensure
the new trust/client identity is active; verify both accepted and rejected
connections afterward. Snapshot reload behavior needs its own qualification.

Each upstream TLS file is bounded to 1 MiB, with a bounded read to detect growth.
Windows uses the existing regular-file/confidential-key handle and ACL helpers.
Unix rejects a final-component symlink, but its reader canonicalizes the parent
and does not retain the configuration's parent ownership/permission policy.

**Current limitation:** Tests reproduce a parent symlink and group-writable parent drift
being rejected by fresh proxy validation yet accepted by the Unix upstream
reader. the local follow-up will enforce trusted handles and regular-file admission at
open time for CA, client-chain and key inputs. Until then, keep the whole path
stable and operator-controlled. This is not a demonstrated unauthenticated
network exploit, but documenting it is not a fix or a race-safety guarantee.
The downstream reader has a distinct issue tracked as the documented limitation / the local follow-up.

## TLS Option Reference

These fields apply to each proxy policy. Relative material paths are resolved
from the configuration base. No optional value is written as TOML `null`.

| Field | Default | Meaning |
| --- | --- | --- |
| `upstream_tls` | `false` | Encrypt/authenticate origin connections when enabled |
| `upstream_sni` | Absent | Explicit TLS name; otherwise derived from origin authority |
| `upstream_verify_cert` | `true` | Verify server certificate trust |
| `upstream_verify_hostname` | `true` | Verify expected identity; requires certificate verification |
| `upstream_alternative_cn` | Absent | Replace the verification name, without changing SNI |
| `upstream_ca_path` | Absent | Custom PEM roots instead of native roots |
| `upstream_client_cert_path` | Absent | PEM client chain; requires matching key path |
| `upstream_client_key_path` | Absent | PEM client key; requires matching chain path |
| `upstream_http_version` | `http1` | HTTP/ALPN policy: `http1`, `http2`, `http1-and-http2` |
| `upstream_proxy_protocol` | `off` | `off`, `v1`, `v2`; pre-TLS framing, not HTTP headers |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Proxy policy fails initialization | CA/key parsing, readable protected paths, matching client pair, available compiled TLS backend |
| 502 before origin receives HTTP | TLS trust/name, certificate validity, complete server chain, required client certificate, protocol mismatch |
| Direct curl works but proxy fails | Compare trust stores, SNI, SAN, client certificate and the unchanged HTTP Host; do not compare with `curl -k` |
| TLS works but origin returns the wrong site | HTTP Host routing is separate from TLS SNI |
| Certificate changes have no effect | Existing connector/pool generation; replace the process and drain when necessary |
| Plain HTTPS origin rejects the first bytes | Disable PROXY protocol unless explicitly supported by that origin |

The local example harness tests both accepted requests and handshake rejection
using disposable certificates. It is not public-PKI, platform-wide or container
qualification; the [coverage ledger](../reference/documentation-coverage.md)
records exactly which checks were run.
