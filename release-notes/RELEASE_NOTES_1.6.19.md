# Fluxheim 1.6.19 Release Notes

Fluxheim 1.6.19 continues the Pingora-exit line by making the remaining
compatibility runtime explicit in Cargo features and proving a native TLS-only
web builds can stay Pingora-free.

## Changed

- Add a `pingora-compat` feature for the remaining root compatibility runtime.
  Current proxy profiles still select it, but the dependency boundary is now
  visible and easier to remove profile by profile.
- Remove unconditional Pingora TLS feature forwarding from native TLS backend
  features. `tls-rustls-backend` now forwards `pingora?/rustls`, and
  `tls-openssl` now forwards `pingora?/openssl`, so native TLS-only builds do
  not pull Pingora just to use rustls or OpenSSL.
- Extend `scripts/validate-pingora-dependency-policy.sh` with native web TLS
  profiles for rustls and OpenSSL. The gate now records and verifies that
  `cargo tree --locked --no-default-features --features web,tls-rustls` and
  `cargo tree --locked --no-default-features --features web,tls-openssl` have
  no Pingora crates.
- Add `scripts/validate-native-web-tls.sh` and wire it into the stable release
  gate and CI so the same native web TLS proof profiles are compiled during
  release checks, not only inspected with `cargo tree`.
- Extend runtime-baseline evidence with the native web TLS proof profiles so
  release artifacts record their Pingora dependency surface alongside the
  official compatibility profiles.
- Move rustls downstream SNI certificate resolution into `fluxheim-tls`.
  Fluxheim now owns the reloadable certificate table, PEM certificate/private
  key loading, wildcard/exact SNI lookup, and TLS-ALPN challenge certificate
  adapter used by the compatibility listener.
- Add a Fluxheim-owned native rustls downstream `ServerConfig` builder. It
  applies the configured cipher suites, curve groups, minimum protocol, ALPN,
  client-auth verifier, and FIPS reporting check with typed errors instead of
  Pingora listener `build()` panics.
- Add a Fluxheim-owned native OpenSSL downstream `SslAcceptor` builder for the
  fallback-certificate listener path. It applies certificate/key loading,
  cipher, curve, minimum-protocol, ALPN, and client-auth CA policy with typed
  errors.
- Move OpenSSL downstream SNI certificate storage, reload, pending-managed-cert
  handling, and certificate application into `fluxheim-tls`. The root runtime
  keeps only the temporary Pingora `TlsAccept` adapter.
- Align rustls and OpenSSL managed-certificate pending detection. A
  half-present ACME-managed cert/key pair is now treated as pending by both TLS
  backends instead of making rustls listener startup or reload fail during the
  issuance window.
- Add a native rustls HTTP/1 downstream listener preview in `fluxheim-server`.
  It wraps the existing native HTTP/1 parser/handler with `tokio-rustls`,
  shares the listener connection budget, and bounds the TLS handshake before
  request parsing starts.
- Add the matching native OpenSSL HTTP/1 downstream listener preview for
  OpenSSL-only builds. It uses the same connection budget and handshake
  timeout as the rustls path, then hands the accepted stream to the same native
  HTTP/1 parser/handler.
- Split the native HTTP/1 TLS handshake timeout from the HTTP request-head
  timeout. Preview TLS listeners now use a dedicated 5-second handshake window,
  so operator tuning of request-head parsing does not accidentally widen or
  shrink the TLS negotiation budget.
- Add a native runtime cutover summary to `ServerPlan`. Fluxheim now logs the
  remaining native-runtime blockers at startup while still retaining the
  compatibility adapter for this release.
- Add a root integration test proving the `fluxheim-tls` rustls downstream
  server-config builder can drive the native `fluxheim-server` HTTP/1 listener
  with a real TLS client handshake and request.
- Add the matching OpenSSL integration test proving the `fluxheim-tls`
  acceptor builder can drive the native OpenSSL HTTP/1 listener.
- Update the test-only `rcgen` dependency to `0.14.8`.
- Remove Fluxheim's direct `rustls-pemfile` dependency from `fluxheim-tls` by
  using the maintained `rustls-pki-types` PEM parser API.

## Security

- Tighten the release-gate proof around dependency ownership: native TLS-only
  builds cannot silently reintroduce Pingora through TLS feature forwarding.
- Isolate the old vendored Pingora rustls listener panic surface to the
  temporary acceptor shim. Certificate selection and key parsing now return
  typed Fluxheim errors and can be reused directly by the native listener
  cutover.
- Shrink the OpenSSL compatibility listener surface: SNI certificate material
  is now loaded, selected, reloaded, and applied by `fluxheim-tls`, leaving the
  Pingora layer as an adapter only.
- Fix rustls/OpenSSL backend divergence for pending managed certificates so an
  ACME issuance race with only one file present does not fail rustls startup or
  reload.
- Prepare the native downstream listener cutover with a no-panic rustls server
  config path that can replace the vendored Pingora rustls `TlsSettings`
  builder.
- Bound native TLS handshakes with their own timeout instead of reusing the
  HTTP request-head timeout.
- Add socket-level test coverage proving a real rustls client can complete a
  downstream TLS handshake and receive an HTTP/1 response through the native
  listener path.
- Add socket-level OpenSSL client/server coverage for the OpenSSL downstream
  listener preview so the native cutover is not rustls-only.
- Add server-plan coverage for native-runtime blocker reporting so the final
  Pingora removal slice has a tested checklist.
- Add end-to-end native rustls listener cutover coverage across the
  `fluxheim-tls` and `fluxheim-server` crates.
- Add end-to-end native OpenSSL listener cutover coverage across the same crate
  boundary.
- Remove direct use of the unmaintained `rustls-pemfile` parser from
  Fluxheim-owned TLS code.

## Compatibility Boundary

- Root proxy, admin, metrics, stream, UDP, and process-supervisor paths still
  use the Pingora compatibility runtime in this release. The next
  Pingora-exit slice removes the runtime/listener/admin compatibility layer as
  a tested behavior change.
- The native runtime cutover summary is diagnostic-only. It does not change
  which runtime adapter handles production traffic in 1.6.19.
