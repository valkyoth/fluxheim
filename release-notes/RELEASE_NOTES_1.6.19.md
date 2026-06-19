# Fluxheim 1.6.19 Release Notes

Fluxheim 1.6.19 continues the Pingora-exit line by making the remaining
compatibility runtime explicit in Cargo features and proving a native TLS-only
web build can stay Pingora-free.

## Changed

- Add a `pingora-compat` feature for the remaining root compatibility runtime.
  Current proxy profiles still select it, but the dependency boundary is now
  visible and easier to remove profile by profile.
- Remove unconditional Pingora TLS feature forwarding from native TLS backend
  features. `tls-rustls-backend` now forwards `pingora?/rustls`, and
  `tls-openssl` now forwards `pingora?/openssl`, so native TLS-only builds do
  not pull Pingora just to use rustls or OpenSSL.
- Extend `scripts/validate-pingora-dependency-policy.sh` with a
  `native-web-tls` profile. The gate now records and verifies that
  `cargo tree --locked --no-default-features --features web,tls-rustls` has no
  Pingora crates.
- Move rustls downstream SNI certificate resolution into `fluxheim-tls`.
  Fluxheim now owns the reloadable certificate table, PEM certificate/private
  key loading, wildcard/exact SNI lookup, and TLS-ALPN challenge certificate
  adapter used by the compatibility listener.
- Add a Fluxheim-owned native rustls downstream `ServerConfig` builder. It
  applies the configured cipher suites, curve groups, minimum protocol, ALPN,
  client-auth verifier, and FIPS reporting check with typed errors instead of
  Pingora listener `build()` panics.
- Add a native rustls HTTP/1 downstream listener preview in `fluxheim-server`.
  It wraps the existing native HTTP/1 parser/handler with `tokio-rustls`,
  shares the listener connection budget, and bounds the TLS handshake before
  request parsing starts.
- Add the matching native OpenSSL HTTP/1 downstream listener preview for
  OpenSSL-only builds. It uses the same connection budget and handshake
  timeout as the rustls path, then hands the accepted stream to the same native
  HTTP/1 parser/handler.

## Security

- Tighten the release-gate proof around dependency ownership: native TLS-only
  builds cannot silently reintroduce Pingora through TLS feature forwarding.
- Isolate the old vendored Pingora rustls listener panic surface to the
  temporary acceptor shim. Certificate selection and key parsing now return
  typed Fluxheim errors and can be reused directly by the native listener
  cutover.
- Prepare the native downstream listener cutover with a no-panic rustls server
  config path that can replace the vendored Pingora rustls `TlsSettings`
  builder.
- Add socket-level test coverage proving a real rustls client can complete a
  downstream TLS handshake and receive an HTTP/1 response through the native
  listener path.
- Add socket-level OpenSSL client/server coverage for the OpenSSL downstream
  listener preview so the native cutover is not rustls-only.

## Compatibility Boundary

- Root proxy, admin, metrics, stream, UDP, and process-supervisor paths still
  use the Pingora compatibility runtime in this release. The next
  Pingora-exit slice removes the runtime/listener/admin compatibility layer as
  a tested behavior change.
