# Fluxheim 1.6.6 Release Notes

Fluxheim 1.6.6 continues the 1.6 Pingora-exit line by extracting downstream TLS listener planning and TLS provider policy into a focused `fluxheim-tls` workspace crate.

## Changed

- Added `fluxheim-tls` as the owner for downstream TLS listener plans, SNI certificate selection, wildcard matching, ALPN/cipher policy helpers, and rustls/OpenSSL provider/FIPS checks.
- Updated the runtime TLS listener adapter to consume `fluxheim-tls` plans while the current Pingora listener path remains the compatibility adapter for this release.
- Reduced duplicated SNI/certificate-selection logic in the root TLS module by delegating the selector to `fluxheim-tls`.
- Updated the Pingora dependency policy to keep `pingora-rustls` until the native server/listener cutover, since 1.6.6 extracts planning but does not yet replace the active listener adapter.

## Verification

- `cargo test -p fluxheim-tls --features acme,tls-rustls`
- `RUSTFLAGS='-D warnings' cargo check --workspace`
- Focused runtime TLS tests for ACME ALPN and SNI certificate reload behavior.
