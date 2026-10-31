# Cloudflare And CDN Origin Deployments

Fluxheim can serve an ordinary HTTPS origin behind a CDN. There is **no
Cloudflare-specific module**: `[cloudflare]`, `[vhosts.cloudflare]` and the
`cloudflare-*` Cargo features are not implemented. Configuration containing those
tables is rejected, even with `enabled = false`. The earlier module design is
preserved separately as an [unimplemented proposal](../ideas/cloudflare-origin-support.md).

This page explains the existing building blocks, not a qualified Cloudflare
integration. Review the linked guides' current limits before deployment.

## What Exists Today

| Need | Current Fluxheim capability | Boundary |
| --- | --- | --- |
| Encrypt CDN-to-origin traffic | [HTTPS with supplied PEM certificates](tls.md) | Configure DNS, origin selection, ports and CDN certificate verification outside Fluxheim |
| Obtain public certificates | [HTTP-01 ACME workflow](acme.md) | Cloudflare Origin CA issuance and DNS-01 automation are not provided |
| Authenticate a connecting TLS client | [Global downstream mTLS](tls.md#require-client-certificates-mtls) | Not a per-vhost AOP integration; external provisioning and testing are required |
| Interpret a forwarded client address | Explicit `server.trusted_proxies` and X-Forwarded-For handling | No automatic Cloudflare ranges or CF-Connecting-IP decoder; forwarding limitations below |
| Limit direct origin access | Deployment firewall/network controls, separate application access policy | A trusted-proxy list is not a connection allowlist |
| Cloudflare API, Origin CA renewal, range refresh or Ray-ID integration | Not implemented | Do not infer these capabilities from ordinary proxy, TLS or tracing support |

## Start With Verified Origin HTTPS

Use the complete [static HTTPS example](../../examples/tls/static.toml) and the
[TLS setup instructions](tls.md#start-with-one-https-site). Supply a matching PEM
certificate/key pair for your origin name. The example binds only loopback;
deliberately configure the reachable origin address, firewall and container port
mapping for a real deployment. Keep configuration and certificate directories
operator-controlled and private keys confidential.

There are two TLS connections: visitor to CDN, and CDN to Fluxheim. A successful
browser connection verifies the edge certificate, not necessarily the origin.
Cloudflare's Full (strict) mode verifies the origin certificate, including its
validity, hostname and trust. Configure that on Cloudflare, not in Fluxheim TOML.
[Cloudflare Full (strict) requirements](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).

An operator-provisioned Origin CA PEM certificate can use Fluxheim's ordinary
static certificate configuration; it is not managed by Fluxheim ACME. Cloudflare
Origin CA certificates are intended for edge-to-origin trust, not ordinary direct
browser trust. Review how direct-origin clients will validate the chain before
changing certificates. [Cloudflare Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/).

For a local CA fixture, preserve hostname and certificate verification:

```bash
fluxheim --config examples/tls/static.toml --validate-config
fluxheim --config examples/tls/static.toml
# In another terminal, with your test CA and matching site.example.test certificate:
curl --cacert /path/to/test-ca.pem \
  --resolve site.example.test:8443:127.0.0.1 \
  https://site.example.test:8443/
```

Use the [reverse-proxy guide](reverse-proxy.md) instead of the static handler when
Fluxheim forwards to an application. Upstream application TLS is another,
independently configured connection. Also check the
[request scheme behavior](request-headers.md): generated scheme headers describe
the connection to Fluxheim, not arbitrary inbound X-Forwarded-Proto metadata.

## Client Addresses And Origin Access

`server.trusted_proxies` defaults to empty. Configure only actual trusted direct
peers and intermediary hops, using current operator-reviewed ranges. Fluxheim
does not download or refresh provider ranges. Do not copy loopback trust from
tests, use a catch-all range, or assume that a CDN DNS record blocks direct access.

For a trusted direct peer, the generic address resolver walks X-Forwarded-For
right to left and stops at the first non-trusted hop. Without a trusted peer or
usable chain, it uses the peer address. CF-Connecting-IP, CF-IPCountry and CF-Ray
do not establish this trust or supply a native visitor identity.

Cloudflare's header and Worker/transform behavior depends on the request path
and configuration. Verify the actual headers reaching your origin; do not assume
every deployment has the same chain. [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

Keep these controls separate:

- Use the host/cloud firewall or an intentionally isolated network to restrict
  which peers can connect. `trusted_proxies` does not reject other connections.
- Use [application access rules](access-control.md) for the intended request
  identity. These can evaluate a restored visitor address, so they are not a
  substitute for a network rule admitting only the CDN's socket peers.
- Review [forwarding behavior and current limits](request-headers.md). Restored
  addresses used by access policy are not currently guaranteed to survive header
  stripping and regeneration unchanged. Do not promise end-to-end visitor-IP
  fidelity or disable stripping as a blanket workaround.
- Default request-header stripping removes known spoofable identity fields,
  including CF-Connecting-IP. It does not certify every remaining `CF-*` header
  or turn a Ray ID into an authorization credential or native trace identity.

## Client Certificates And AOP

The existing mTLS policy can require a valid client certificate from the CA
bundle you supply. Its scope is global across downstream TLS listeners, not
per vhost, and it does not protect a parallel plaintext listener. The complete
[mTLS example](../../examples/tls/mtls.toml) deliberately disables plaintext.

Cloudflare Authenticated Origin Pulls (AOP) is a separately configured
client-certificate mechanism. Its global certificate is shared rather than
exclusive to your account; accepting it does not identify your particular zone.
Consult [Cloudflare's AOP setup and trust limits](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/global/).

Fluxheim does not configure AOP, upload certificates, manage Cloudflare secrets
or rotate its trust bundle. Test the intended client chain, an absent certificate
and an unrelated certificate before enforcement. Follow the TLS guide's trust
policy restart/reload boundaries; certificate-only reload is not a general
client-CA refresh command. A local mTLS test is not proof of Cloudflare AOP
interoperability.

## Verify The Deployment

1. Validate the exact Fluxheim profile/configuration and test origin HTTPS with
   hostname and CA verification enabled.
2. Test through the CDN and separately check that unintended direct origin
   connections are blocked by the deployment's network policy.
3. Inspect a controlled application's effective client address and scheme. Test
   supplied forwarding headers from both trusted and untrusted peers; never use
   application credentials or real visitor data as test fixtures.
4. Exercise renewal and verify the certificate on a fresh connection. A successful
   file installation alone does not establish activation or edge trust.
5. If using HTTP-01, verify the public challenge route without a cached, redirected
   or otherwise substituted response. Use a staging CA before production issuance.

Repository loopback proxy and TLS tests qualify generic components only. A real
Cloudflare zone, edge-to-origin traffic, provider range changes and AOP have not
been qualified by this documentation pass. Provider controls remain external to
Fluxheim and must be tested in the actual deployment.
