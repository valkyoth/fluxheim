# Historical Pingora Patches

Starting in Fluxheim `1.6.34`, normal Fluxheim builds no longer compile
Pingora crates and `Cargo.toml` no longer carries Pingora patch overrides. This
document is retained as historical context for the `1.5.x` and earlier `1.6.x`
compatibility-runtime line and should not be read as an active dependency
policy for current release profiles.

Before Fluxheim `1.6.34`, Fluxheim vendored `pingora-core 0.8.0` for a small
set of narrow proxy/TLS compatibility fixes required by the old default
`tls-rustls` build and the `1.4` production proxy parity line.

## Rustls Listener Certificate Resolver

- `TlsSettings::with_cert_resolver(...)`
- an internal `cert_resolver` field used by the rustls listener when building
  `rustls::ServerConfig`

The patch keeps Pingora's existing single-certificate path unchanged. It only
allows Fluxheim to pass a rustls `ResolvesServerCert` implementation so
per-vhost certificates can be selected by SNI in the default build.

As of Fluxheim `1.6.20`, the resolver implementation itself moved to
`fluxheim-tls`: Fluxheim owns wildcard/exact SNI lookup, the reloadable
certificate table, PEM certificate/private-key parsing, and TLS-ALPN challenge
certificate loading. In the old compatibility runtime, the vendored Pingora
patch was only the temporary listener acceptor hook that let that resolver pass
into rustls. Normal `1.6.34` builds use the native downstream listener path
instead.

`fluxheim-tls` also owns the native rustls downstream `ServerConfig` builder.
That builder applies Fluxheim TLS policy and returns typed errors for protocol,
cipher, group, client-auth, and FIPS reporting failures.

For OpenSSL-only builds, `fluxheim-tls` owns the native downstream
`SslAcceptor` builder for the fallback-certificate listener path. It applies
certificate/key loading, ALPN, cipher, curve, minimum protocol, and client-auth
CA policy with typed errors. It also owns OpenSSL SNI certificate storage,
reload, pending managed-certificate handling, and certificate application. The
old compatibility runtime used a thin `TlsAccept` adapter before production
listener cutover.

`fluxheim-server` now has native rustls and OpenSSL HTTP listeners that accept
ready TLS server configuration, bound the TLS handshake, and then hand the
stream to the same native HTTP parser/handler path used by plain listeners.

## Rustls Upstream Verification Policy

Fluxheim also patches the rustls upstream connector so per-peer
`verify_cert = false` and `verify_hostname = false` policies apply even when no
other setting forced Pingora to clone the rustls client config. In Pingora 0.8,
the dangerous verifier path was only installed when a cloned config already
existed for ALPN or upstream mTLS. Fluxheim exposes explicit upstream TLS
verification controls, so the connector must clone the config and install the
custom verifier whenever verification is disabled or SNI is absent.

This was a temporary compatibility patch, not a long-term fork.

## Listener PROXY Protocol Receive

Fluxheim also patched Pingora listeners with an opt-in PROXY protocol receive
hook that ran after the TCP accept and before downstream TLS or HTTP parsing.
That patch added:

- `ProxyProtocolConfig::v1(...)`, `ProxyProtocolConfig::v2(...)`, and
  `ProxyProtocolTrustedSource`;
- `Service::set_proxy_protocol_v1(...)`, `Service::set_proxy_protocol_v2(...)`
  and matching `Listeners` helpers;
- bounded v1 line parsing with the HAProxy 108-byte limit and bounded v2
  payload parsing;
- mandatory direct-peer trust checks before parsing;
- socket-digest peer-address replacement only after a trusted, valid v1/v2
  header.

This was needed because Fluxheim must restore client identity before TLS and
HTTP handling when it sits behind a trusted load balancer that speaks PROXY
protocol. The native listener path now owns that behavior.

## Historical Removal Criteria

These criteria are satisfied for normal Fluxheim builds as of `1.6.34`:
`Cargo.toml` no longer carries Pingora patch overrides and official release
profiles no longer compile Pingora crates. The vendored source tree remains in
the repository only as historical source context until a later repository
cleanup removes it.

The old removal checklist was:

- `cargo check --no-default-features --features proxy,tls-rustls`
- `scripts/smoke_1_0_core.sh`
- the smoke assertion that `app.test` receives the `app.test` certificate via
  SNI
- a rustls upstream with `upstream_verify_cert = false` can connect to a
  self-signed or otherwise untrusted test origin without requiring unrelated
  ALPN or mTLS settings
- a rustls upstream with `upstream_ca_path` validates against that per-peer CA
  bundle rather than the process default root store
- listeners configured with `server.proxy_protocol = "v1"` or `"v2"` reject
  untrusted direct peers and restore the PROXY source address before TLS/HTTP
  handling

## Upstream Candidate

These patches are small enough to propose upstream. The cleaner upstream shape
would be:

- re-export the needed rustls server certificate resolver types from
  `pingora-rustls`, or add the direct rustls dependency in `pingora-core`;
- add `TlsSettings::with_cert_resolver(Arc<dyn ResolvesServerCert>)` for the
  rustls listener;
- preserve the existing `TlsSettings::intermediate(cert, key)` behavior for
  single-certificate listeners;
- keep ALPN handling through the existing `enable_h2` and `set_alpn` methods.
- in the rustls connector, compute per-peer verification mode independently and
  clone the client config when a custom verifier is needed.
- in the rustls connector, honor `PeerOptions.ca` when constructing the
  per-peer root store for both normal verification and custom verifier modes.
- expose a pre-TLS listener hook for PROXY protocol v1/v2 receive, or native
  listener support that can enforce trusted direct peers before overriding the
  socket digest client address, with bounded v2 TLV handling.

Fluxheim should keep the vendored patch narrow and avoid unrelated edits to
vendored Pingora source.

## Pingora OpenSSL Patch

Before `1.6.34`, Fluxheim also vendored `pingora-openssl 0.8.0` for one
dependency-policy change: the crates.io package forced
`openssl = { features = ["vendored"] }`. Fluxheim's `tls-openssl-fips` path
must be able to link against the operator-installed OpenSSL 3 FIPS provider, so
the local patch removed only the `vendored` feature from `pingora-openssl`'s
OpenSSL dependency.

This patch did not change Pingora's OpenSSL API or runtime behavior. It only
let normal Cargo/OpenSSL discovery use the system OpenSSL selected by the
operator.

## Proposed PR Steps

1. Fork the upstream Pingora repository and create a focused branch, for
   example `rustls-listener-cert-resolver`.
2. Apply only the rustls listener API change:
   - add a resolver field to the rustls listener `TlsSettings`;
   - add `TlsSettings::with_cert_resolver(...)` or use Fluxheim's native
     listener resolver directly once Pingora is removed;
   - make `build()` use the resolver when present and keep the existing
     `intermediate(cert, key)` single-certificate path unchanged.
3. Prefer the smallest public API surface the upstream maintainers will accept.
   If `pingora-rustls` can re-export the needed rustls resolver types, that is
   cleaner than adding a broad direct dependency.
4. Add or update an upstream test/example if the repository has a listener TLS
   test harness that can verify the resolver path without opening a real public
   socket.
5. Run the upstream formatting and test commands documented by Pingora.
6. Open the PR with a narrow description: rustls listeners need a server
   certificate resolver hook so applications can select certificates by SNI
   while keeping the existing single-certificate API.
7. Link Fluxheim's local patch as a real downstream use case, but do not include
   Fluxheim-specific config, docs, or behavior in the upstream PR.
