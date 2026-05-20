# Pingora Patches

Fluxheim vendors `pingora-core 0.8.0` only to expose one rustls listener hook
that is required for the default `tls-rustls` build:

- `TlsSettings::with_cert_resolver(...)`
- an internal `cert_resolver` field used by the rustls listener when building
  `rustls::ServerConfig`

The patch keeps Pingora's existing single-certificate path unchanged. It only
allows Fluxheim to pass a rustls `ResolvesServerCert` implementation so
per-vhost certificates can be selected by SNI in the default build.

This is a temporary compatibility patch, not a long-term fork. Keep it small,
easy to audit, and limited to the rustls certificate resolver gap.

## Removal Criteria

Remove `vendor/pingora-core` and the `[patch.crates-io]` entry in
`Cargo.toml` when an upstream Pingora release exposes equivalent rustls server
certificate resolver support.

Before removing the patch, verify:

- `cargo check --no-default-features --features proxy,tls-rustls`
- `scripts/smoke_1_0_core.sh`
- the smoke assertion that `app.test` receives the `app.test` certificate via
  SNI

## Upstream Candidate

This patch is small enough to propose upstream. The cleaner upstream shape would
be:

- re-export the needed rustls server certificate resolver types from
  `pingora-rustls`, or add the direct rustls dependency in `pingora-core`;
- add `TlsSettings::with_cert_resolver(Arc<dyn ResolvesServerCert>)` for the
  rustls listener;
- preserve the existing `TlsSettings::intermediate(cert, key)` behavior for
  single-certificate listeners;
- keep ALPN handling through the existing `enable_h2` and `set_alpn` methods.

Fluxheim should keep the vendored patch narrow and avoid unrelated edits to
vendored Pingora source.

## Pingora OpenSSL Patch

Fluxheim also vendors `pingora-openssl 0.8.0` for one dependency-policy change:
the crates.io package forces `openssl = { features = ["vendored"] }`.
Fluxheim's `tls-openssl-fips` path must be able to link against the
operator-installed OpenSSL 3 FIPS provider, so the local patch removes only the
`vendored` feature from `pingora-openssl`'s OpenSSL dependency.

This patch does not change Pingora's OpenSSL API or runtime behavior. It only
lets normal Cargo/OpenSSL discovery use the system OpenSSL selected by the
operator. Remove `vendor/pingora-openssl` and its `[patch.crates-io]` entry
when upstream makes OpenSSL vendoring optional or no longer enables it by
default.

## Proposed PR Steps

1. Fork the upstream Pingora repository and create a focused branch, for
   example `rustls-listener-cert-resolver`.
2. Apply only the rustls listener API change:
   - add a resolver field to the rustls listener `TlsSettings`;
   - add `TlsSettings::with_cert_resolver(...)`;
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
