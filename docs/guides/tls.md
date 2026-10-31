# HTTPS, Certificates And Client Authentication

TLS encrypts a connection and lets a client verify the server it reached.
Fluxheim has two separate TLS directions:

- **Downstream:** a browser or API client connects to Fluxheim. `[tls]` and
  `server.tls_listen` control this connection.
- **Upstream:** Fluxheim connects to an origin. Proxy TLS settings control that
  connection independently. Encrypting the browser connection does not encrypt
  a plaintext origin connection. See the [upstream TLS guide](upstream-tls.md).

This guide covers downstream HTTPS. Use [ACME](acme.md) for automatic certificates,
[TLS options](../reference/tls-options.md) for exact fields/defaults and
[FIPS-capable deployments](fips.md) for compliance-specific requirements.
HTTP/3 is not provided by these listeners.

## Start With One HTTPS Site

Use the complete [static HTTPS example](../../examples/tls/static.toml).
It serves `site/index.html` on loopback port 8443 and deliberately has no
plaintext listener. Supply `server.pem` and `server-key.pem` alongside the
configuration. The certificate must cover `site.example.test`, or replace the
example hostname with the real name covered by your certificate.

The essential TLS settings are:

```toml
[server]
listen = []
tls_listen = ["127.0.0.1:8443"]

[tls]
enabled = true
backend = "rustls"
profile = "intermediate"
alpn = "http1-and-http2"

[[tls.certificates]]
cert_path = "server.pem"
key_path = "server-key.pem"
```

This fragment needs the vhost/content settings in the complete example. Paths
are resolved relative to the configuration base; use absolute paths when that
makes deployment ownership clearer. Keep files in a service-owned protected
directory, not a shared temporary directory. For public service, deliberately
change the bind address/port and configure the firewall, DNS and container port
mapping. The example does not open port 443 automatically.

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
fluxheim --config /etc/fluxheim/fluxheim.toml
```

Validation checks configuration and paths; successful validation alone is not a
TLS handshake, certificate expiry check or proof that a browser trusts the chain.
Supply a PEM chain with the leaf certificate first, followed by intermediates,
and its matching unencrypted private key. A password prompt/secret field for
encrypted PEM keys is not provided. Do not publish private keys or include them
in diagnostic reports.

For a local test with your own CA, keep verification enabled:

```bash
curl --cacert /path/to/test-ca.pem \
  --resolve site.example.test:8443:127.0.0.1 \
  https://site.example.test:8443/
```

Use an ordinary verified HTTPS request for a publicly trusted certificate. Do
not make `-k` the deployment health check: it hides trust and hostname errors.

## Choose A TLS Policy

| Profile | Minimum | Intended use |
| --- | --- | --- |
| `intermediate` | TLS 1.2 | Default TLS 1.2/1.3 compatibility baseline |
| `modern` | TLS 1.3 | Clients known to support TLS 1.3 |
| `compat` | TLS 1.2 | Currently the same defaults as intermediate, not legacy TLS support |

For TLS 1.3 only, replace the existing `[tls]` policy fields:

```toml
[tls]
enabled = true
backend = "rustls"
profile = "modern"
min_protocol = "tls1.3"
alpn = "http1-and-http2"
```

Keep the certificate configuration. Modern rejects an explicit TLS 1.2 minimum.
TLS 1.0/1.1 and SSL are not supported configuration choices. Profiles supply
curve and cipher lists; empty lists mean profile defaults, not no encryption.
Explicit lists replace those defaults. Cipher choices must match both the
protocol family and certificate key type; an ECDSA-only TLS 1.2 list cannot use
an RSA certificate for that protocol. Prefer the defaults unless you have a
specific tested compatibility requirement.

The [modern](../../examples/tls-modern.toml) and
[intermediate](../../examples/tls-intermediate.toml) proxy examples show complete
explicit lists. Their origins on port 3000 and certificate paths must be supplied.
The option reference lists every accepted cipher/group name and aliases.

`alpn` controls the HTTP protocols offered over TLS:

- `http1`: HTTP/1.1; supports clients that do not send ALPN.
- `http2`: HTTP/2; clients must negotiate `h2` to receive HTTP service.
- `http1-and-http2`: offer both, preferring HTTP/2 when negotiated.

A successful TLS handshake is not alone proof that the selected HTTP protocol
can serve a request. The native dispatcher does not route an ALPN-less client
to HTTP/1.1 when HTTP/1.1 is disabled. WebSocket/gRPC protocol requirements still
apply independently of the encryption policy.

## Serve Multiple Names With SNI

SNI is the hostname a client sends during TLS negotiation, before the HTTP
request exists. The [SNI example](../../examples/tls/sni.toml) has a fallback
certificate and a separate API certificate:

```toml
[[vhosts]]
name = "api"
hosts = ["api.example.test", "*.api.example.test"]

[vhosts.tls]
enabled = true
[vhosts.tls.certificate]
cert_path = "api.pem"
key_path = "api-key.pem"
```

Add a root/proxy action for this vhost as in the full example. The certificate
must actually contain the corresponding SAN names. The `hosts` array selects a
certificate; it does not create SANs or make an unrelated certificate valid.

Exact names take precedence over wildcards. `*.api.example.test` matches
`one.api.example.test`, not `api.example.test` or `deep.one.api.example.test`.
Absent or unmatched SNI uses the fallback. A client still verifies that fallback
against the name it intended to reach; fallback is not a hostname-verification
bypass or an unknown-host rejection policy.

The first global `[[tls.certificates]]` entry is the fallback. Without one,
`server.default_vhost` must identify a TLS-enabled vhost with a certificate
source. Extra global entries do not automatically become a SAN-indexed store:
attach each additional identity explicitly to a vhost. This is also not automatic
RSA/ECDSA dual-certificate selection for one hostname.

For a static TLS-enabled vhost, declare its certificate pair explicitly, even
when reusing the global fallback paths, as the complete examples do. Merely
setting `[vhosts.tls] enabled = true` is not enough to supply that source.

HTTP Host/`:authority` routing happens after TLS. Do not treat SNI selection as
application authorization or tenant isolation. A TLS-enabled vhost flag chooses
certificate behavior; it does not by itself redirect plaintext traffic. Configure
HTTPS redirects separately, and use HTTPS-only listener exposure when required.

## Require Client Certificates (mTLS)

With mutual TLS, Fluxheim also verifies the connecting client's certificate.
Use the complete [mTLS example](../../examples/tls/mtls.toml):

```toml
[tls.client_auth]
mode = "required"
ca_path = "client-ca.pem"
# crl_path = "client-crls.pem"
```

`client-ca.pem` contains trusted issuing CA certificates, not the gateway's
private key. This policy applies globally to downstream TLS listeners, not to
one vhost, URL path or SNI name. Use a separate Fluxheim process/listener
deployment if services need incompatible client-auth policies.

**Do not expose the same protected content over plaintext HTTP.** TLS client
authentication does not protect `server.listen` sockets. The example uses
`listen = []`; an HTTP redirect is also not a substitute for protecting content
on every reachable listener.

| Mode | No client certificate | Certificate presented |
| --- | --- | --- |
| `off` | Accepted | No client-auth identity is required |
| `optional` | Accepted | Must validate against the configured trust policy |
| `required` | Rejected | Must validate against the configured trust policy |

`optional` is not “ignore bad certificates.” Valid TLS authentication is also
not a complete authorization policy: every client trusted by the configured
CA policy can reach the HTTP layer, subject to separate access rules.
See [IP and certificate authorization](access-control.md) for complete fingerprint
examples, combined policy and the difference between allowlists and deny-only rules.

Test both permitted and denied clients:

```bash
curl --cacert server-ca.pem --cert client.pem --key client-key.pem \
  --resolve site.example.test:8443:127.0.0.1 https://site.example.test:8443/
# Repeat without --cert/--key: a required-mTLS listener must not serve the page.
```

Verified client fingerprints can be forwarded using request-header `add`
templates such as `{tls.client_cert_sha256}`. Do not use append or trust a
client-supplied header of the same name. The [header reference](../reference/config-reference.md#headers)
describes replacement and validation. Rustls currently exposes fingerprint,
cipher and version; its native request context does not populate client serial
or organization. OpenSSL extracts those additional fields when available.
Missing metadata must not be interpreted as an authenticated identity.

## Revoke Clients With A CRL

Set `crl_path` to a PEM CRL bundle to enable revocation checks. With an
intermediate CA hierarchy, include the required issuer CRLs for the complete
presented chain, not just the leaf's issuer. Keep CRLs current before expiry.
Rustls rejects unknown revocation status and expired lists; OpenSSL uses full
chain CRL checks. Empty/malformed/oversized bundles fail construction. Without
this field, CA trust validation does not perform CRL revocation checking.

Client CA/CRL policy is constructed for the listener. Use a controlled process
replacement to refresh trust/revocation policy; do not assume changing a file
or running certificate-only reload refreshes it. Existing authenticated sessions
need a deliberate drain/isolation policy during an incident. The rustls
certificate resolver reloads server identities, not the client verifier.
Backend-specific reload details are not a portable CRL refresh contract.

## Replace Server Certificates Safely

For external certificates, prepare and verify the complete matching pair outside
active paths, preserve restrictive permissions and replace it during a controlled
maintenance/reload workflow. A pair is two files: independently overwriting them
while readers run can expose a mismatch. Managed ACME uses separate locks and
journals; see its [recovery limits](acme-recovery.md).

The rustls resolver constructs the replacement set before publishing it. An
invalid replacement leaves its previous in-memory generation available; existing
TLS connections are not renegotiated by a reload. Verify a new connection's
public certificate after activation. A changed certificate pathname or TLS
policy can require a process upgrade rather than certificate-only reload.

**Current limitation:** Unix downstream TLS reads do not currently enforce configuration
path trust at open time. Tests show that certificate reload follows replaced
leaf and parent symlinks and accepts a parent made group-writable, even though
fresh configuration validation rejects those paths. Windows uses distinct
handle-based trust checks; these Unix observations are not Windows results.
the local follow-up must fix the shared downstream reader used by rustls and OpenSSL.
Until then, keep the whole directory tree operator-controlled and stable; do
not rotate using symlinks or allow another account to modify the tree. This
warning does not close the defect or establish safety against concurrent swaps.

## Backend And Deployment Boundaries

The binary must include the chosen backend. Standard rustls builds use Ring;
OpenSSL requires its matching build feature and library. Select one backend,
not all TLS features at once. Compliance builds and post-quantum group support
have additional provider requirements; a configuration flag does not confer
certification. See [build features](../reference/features.md) and [FIPS](fips.md).

Mount certificates/trust bundles read-only where practical and keys privately.
An ACME writer needs a separate writable protected state directory. Avoid
container/user permission fixes that make private keys world-readable. Keep
the service clock accurate; client validation depends on certificate validity.

## Troubleshooting

| Symptom | First checks |
| --- | --- |
| Configuration validates but listener fails | PEM parse/key match, compiled backend, file access, supported cipher/group combination |
| Unknown CA or hostname mismatch | Full intermediate chain, intended SNI/SAN, client trust store; do not disable verification |
| Wrong certificate | Global fallback, `default_vhost`, exact/wildcard SNI mapping, new connection after reload |
| TLS succeeds but HTTP closes | Offered/selected ALPN and enabled HTTP protocol |
| Client rejected | Required client certificate/key, issuing CA, expiry, EKU, CRLs and complete chain |
| Revoked client still connected | Existing sessions, listener verifier generation and process replacement/drain |
| ACME TLS-ALPN issuance fails | Known missing native integration, the documented limitation; use the documented HTTP-01 workflow |

These examples are checked with local certificates and loopback listeners.
They are not a substitute for testing the actual published artifact, firewall,
public trust chain and supported clients on each deployment platform.
