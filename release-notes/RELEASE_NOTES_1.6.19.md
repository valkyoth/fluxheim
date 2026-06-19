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

## Security

- Tighten the release-gate proof around dependency ownership: native TLS-only
  builds cannot silently reintroduce Pingora through TLS feature forwarding.
- Isolate the old vendored Pingora rustls listener panic surface to the
  temporary acceptor shim. Certificate selection and key parsing now return
  typed Fluxheim errors and can be reused directly by the native listener
  cutover.

## Compatibility Boundary

- Root proxy, admin, metrics, stream, UDP, and process-supervisor paths still
  use the Pingora compatibility runtime in this release. The next
  Pingora-exit slice removes the runtime/listener/admin compatibility layer as
  a tested behavior change.
