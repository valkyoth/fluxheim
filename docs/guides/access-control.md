# IP and Client-Certificate Access Control

An access policy decides whether a request may proceed to a website, origin or
redirect. It can restrict the client IP, verified client certificate, country
and ASN. It is separate from application login, the admin API's credentials,
[external authorization](external-authorization.md), and
[rate/concurrency limits](rate-and-concurrency-limits.md).

Start with the [complete loopback IP recipe](../../examples/access/ip.toml) or
the [HTTPS certificate recipe](../../examples/access/mtls.toml). The first needs
an HTTP origin on port 9001; the second needs your certificate files and site.
Example documentation addresses are placeholders, not your actual office/VPN.

**Current limitation:** IPv4-mapped IPv6 CIDRs such as
`::ffff:192.0.2.10/128` validate but do not match normalized IPv4 clients.
In a denylist this leaves the client unblocked. Use `192.0.2.10/32` instead;
use native IPv6 CIDRs separately for native IPv6 clients. the local follow-up will align
validation and matching. An exact mapped literal without a prefix does match.

## Protect a Whole Site

Add this beneath an existing `[[vhosts]]` definition:

```toml
[vhosts.access]
enabled = true
allow = ["192.0.2.0/24", "2001:db8:1234::/48"]
deny = ["192.0.2.25", "2001:db8:1234::25"]
```

The client must match an allow entry and must not match any deny entry. Deny
wins even if another allow entry is more specific. These are not ordered
firewall statements: moving an allow line above a deny line changes nothing.

Use the actual addresses visible to Fluxheim. NAT can make multiple people
share one address; an IP is not a unique user identity. A firewall should also
prevent clients bypassing Fluxheim and reaching the origin directly.

An empty allowlist means no IP allow restriction. A deny-only policy is useful
for exclusions, not a default-deny perimeter:

```toml
[vhosts.access]
deny = ["192.0.2.25", "2001:db8:1234::25"]
```

To deliberately deny every IPv4 and native IPv6 client at a scope:

```toml
[vhosts.access]
deny = ["0.0.0.0/0", "::/0"]
```

Keep both address families. IPv4-mapped clients are normalized to IPv4; do not
assume an IPv6-only catch-all covers them. If the runtime has no client address
and either IP list is nonempty, it rejects the request rather than guessing.

## Protect a Route

```toml
[[vhosts.routes]]
name = "admin"
path_prefix = "/admin"
# Omit methods so all methods selecting this route receive the policy.
[vhosts.routes.access]
allow = ["192.0.2.10/32"]
[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
```

The vhost policy and selected route policy must **both** allow the request.
Route settings are an additional check, not a replacement for the vhost's
rules. `enabled = false` on a route disables only that route's check; it cannot
undo a vhost denial. The default `enabled = true` with empty lists adds no
restrictions.

Routes are not a nested policy tree. A more-specific `/admin/health` exact
route does not inherit the ACL of a separate `/admin` prefix route. Put rules
that must apply everywhere at the vhost, or repeat them on every affected route.
Likewise, `methods = ["GET"]` restricts route selection, not all traffic to that
path: POST might select a permissive fallback. The live test demonstrates both
cases; they are routing semantics, not a supported way to protect a whole subtree.

Paths are case-sensitive and prefixes are segment-aware: `/admin` covers
`/admin/secret`, not `/administrator`. Query strings do not select a route.
Normal request handling also checks the route found after one percent-decoding
pass, so `/%61dmin` receives the `/admin` ACL in the example. This is not a
promise to duplicate every application's URL decoder. See [routing](routing.md)
for selection, rewrites and rejected path forms; test the actual application.

## Every Access Option

The same fields are available under `[vhosts.access]` and
`[vhosts.routes.access]`; there is no global `[access]` table.

| Field | Default | Meaning and accepted values |
| --- | --- | --- |
| `enabled` | `true` | Whether this scope enforces its rules. Disabled does not skip syntax validation or disable another scope. |
| `allow` | `[]` | Exact numeric IPv4/IPv6 addresses or CIDRs. Nonempty requires a match. Maximum 256 entries. |
| `deny` | `[]` | Same syntax and cap; any match denies before allow. |
| `require_client_cert` | `false` | Require verified certificate fingerprint context; does not itself configure TLS client authentication. |
| `allow_client_cert_sha256` | `[]` | Nonempty requires a matching verified leaf-certificate SHA-256 fingerprint, even if require_client_cert is false. Maximum 256. |
| `deny_client_cert_sha256` | `[]` | Reject matching fingerprints; takes precedence over allow. Maximum 256. Alone, does not reject clients with no certificate. |
| `allow_countries` | `[]` | Nonempty requires a known matching two-letter uppercase country code. Maximum 512. |
| `deny_countries` | `[]` | Reject matching known countries. Same syntax/cap; absent country alone does not match deny. |
| `allow_asns` | `[]` | Nonempty requires a matching ASN, an integer from 1 through 4,294,967,295. Maximum 2,048 entries. |
| `deny_asns` | `[]` | Reject matching known ASNs; same bounds. |

Do not include hostnames, ports or surrounding whitespace in IP rules. CIDR
prefixes range from 0 to 32 for IPv4 and 0 to 128 for IPv6, subject to the mapped
CIDR limitation above. Duplicate textual entries fail validation; equivalent
network spellings are not a substitute for reviewing redundant rules.

Fingerprints are exactly 64 hexadecimal characters, case-insensitive, with no
colons, spaces or `SHA256:` prefix. Duplicate fingerprints differing only in case
fail validation. Country entries must be uppercase; validation checks two-letter
syntax, not membership in a current geopolitical registry. Duplicate country/ASN
entries fail. Unknown configuration fields are rejected.

All configured categories must pass: an allowed IP does not override a rejected
certificate, country or ASN. The lists are not alternative login methods.

## Choose the Correct Client Address

Without trusted proxy configuration, IP policy uses the directly observed peer
(or validated listener PROXY-protocol context when present). A client cannot
become allowed just by sending X-Forwarded-For, X-Real-IP or a certificate header.

When the direct peer is a configured `server.trusted_proxies` member, ordinary
builds can restore the client through X-Forwarded-For, examining hops from right
to left and stopping at the first untrusted IP. A malformed examined hop causes
fallback to the direct peer. Entries left of the selected address are not all
validated. Trust only controlled proxies that sanitize their inputs.

```toml
[server]
trusted_proxies = ["192.0.2.100/32"]
```

That is a trust declaration, not a firewall. Replace it with your actual proxy
address, and separately restrict network access. Never add broad trust merely
to make an allowlist start passing. In privacy builds, X-Forwarded-For restoration
is disabled; the direct peer or existing listener effective address is used.

Read [request forwarding](request-headers.md) before having the application
authorize using forwarded IPs: the documented limitation currently permits a mismatch
between the ACL-selected address and the address sent upstream. Read the
[PROXY protocol guide](proxy-protocol.md) before relying on that listener mode,
especially the existing HTTPS trust-policy blocker the documented limitation.

## Require and Pin a Client Certificate

TLS verifies the certificate first; HTTP access policy then decides whether
that verified client is permitted. These are separate steps:

```toml
[tls.client_auth]
mode = "required"
ca_path = "/etc/fluxheim/tls/client-ca.pem"

[vhosts.access]
require_client_cert = true
allow_client_cert_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
```

Replace the example fingerprint. It identifies the complete leaf certificate,
not its public key, issuer CA or account. A renewed certificate generally needs
a new entry. For controlled overlap, list old and new leaf fingerprints while
migrating clients, then remove the old one. Do not expose the same content on a
plaintext listener: configure `listen = []` as in the full certificate recipe.

Obtain the fingerprint from a locally verified client certificate file:

```bash
openssl x509 -in client.pem -noout -fingerprint -sha256
```

Copy only the hexadecimal digest into TOML, removing the display label and
colons. Do not hash the PEM text with a generic file checksum command: this
field uses the certificate's DER encoding.

| TLS mode / HTTP policy | No certificate | Trusted certificate not in nonempty allowlist | Trusted and allowed certificate |
| --- | --- | --- | --- |
| required / pinned | TLS handshake rejected | HTTP 403 | HTTP action proceeds |
| optional / pinned | HTTP 403 | HTTP 403 | HTTP action proceeds |
| optional / denylist only, require false | May proceed | May proceed unless denied | May proceed unless denied |

An untrusted presented certificate fails TLS verification; `optional` does not
mean invalid certificates are accepted. The full example uses optional TLS plus
a required/pinned HTTP policy so its missing-certificate behavior can be tested
as HTTP 403. A nonempty allowlist also rejects missing certificates by itself.

To explicitly block a certificate, add a deny entry:

```toml
[vhosts.access]
require_client_cert = true
deny_client_cert_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
```

This allows other TLS-verified clients; it does not restrict them to one identity.
Without require_client_cert, a denylist alone also permits missing certificates
when TLS authentication is optional. Use an allowlist when only named clients
should pass. HTTP fingerprints do not replace
CA trust, CRLs or application authorization. TLS policy is listener-wide, while
access rules can differ per vhost/route; see [TLS and revocation](tls.md).
Changing a file is not proof of live policy reload: use the documented validated
[configuration snapshot/reload workflow](config-snapshots.md) and test both old
and new clients after activation.

## Combine Geographic Rules

With GeoIP enabled and an appropriate database loaded:

```toml
[vhosts.access]
allow = ["192.0.2.0/24"]
allow_countries = ["SE", "NO"]
deny_countries = ["RU"]
allow_asns = [64512, 64513]
deny_asns = [64514]
```

These addresses/ASNs only illustrate syntax. IP, country and ASN allow conditions
are ANDed, and every deny list still applies. Unknown country/ASN fails its
nonempty allowlist; deny-only geographic rules do not deny absent data. GeoIP
rules require global GeoIP enablement even in a disabled access block. Consult
the [GeoIP guide](geoip.md) for provider fields, databases, accuracy limits and
complete runnable configurations. Geography is not proof of a person's identity.

## Verify Before Exposure

For the IP demo, supply a loopback HTTP origin on port 9001, then:

```bash
fluxheim --config examples/access/ip.toml --validate-config
fluxheim --config examples/access/ip.toml
curl -i -H 'Host: api.example.test' http://127.0.0.1:8080/
curl -i -H 'Host: api.example.test' http://127.0.0.1:8080/admin
curl -i -H 'Host: api.example.test' -H 'X-Forwarded-For: 192.0.2.10' \
  http://127.0.0.1:8080/admin
```

The latter two requests should be 403 with no origin request. Test every relevant
method, exact/prefix route, fallback, alternate encoding, address family and
reachable listener. An application returning 403 is not proof the gateway blocked
origin contact; inspect the origin or use the bounded test fixture:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_access_examples.py
python3 scripts/smoke_access_examples.py
```

This launches actual loopback Fluxheim processes and origins, plus short-lived
TLS identities. It verifies no origin contact for IP denials and real TLS/HTTP
outcomes for missing, untrusted, allowed and denied certificates. Private keys
are temporary. It is not a native Windows/macOS, HTTP/2 or release qualification.

Ordinary native ACL rejection is 403 and closes the HTTP/1 connection before
the selected action/redirect. The current early-error response-header limitation
the documented limitation still applies. Some requests with no route/action return 404
before ACL evaluation; TLS verification failures do not produce an HTTP status.

Do not assume `fluxheim_edge_policy_events_total` records each native ACL denial:
its helper currently has no production callers. Ordinary ACL rejection does
invoke the separate bounded operational security producer, but that is not a
durable audit guarantee or proof of the legacy counter. The shared native-policy
metrics correction is tracked under the local follow-up. Never infer authorization worked
solely from an empty metric or log stream.

| Symptom | Check |
| --- | --- |
| Everyone denied | Actual peer/restored IP, address family, required certificate, all allow categories, vhost plus selected route. |
| Some methods unexpectedly pass | Method-restricted protected route may leave another method to fallback. |
| A nested path unexpectedly passes | A more-specific route has independent ACLs; move common restrictions to the vhost. |
| Mapped IPv6 deny ignored | the documented limitation; use ordinary IPv4 CIDRs for IPv4 clients. |
| Certificate change causes 403 | Fingerprint belongs to old leaf, contains separators or identifies the CA instead of the leaf. |
| Missing certificate still accepted | Deny-only policy and optional TLS; require a certificate or use a nonempty allowlist. |
| Forged client IP appears allowed | Check trusted-proxy scope and the actual request peer; distinguish ACL admission from upstream header identity. |

[Coverage](../reference/documentation-coverage.md) records tests and remaining
platform boundaries. The mapped-CIDR fix and shared forwarding/metrics fixes
remain planned, not delivered by this documentation.
