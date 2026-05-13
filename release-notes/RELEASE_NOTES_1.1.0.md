# Fluxheim 1.1.0 Release Notes

## Release Metadata

- Version: `1.1.0`
- Release date: to be filled
- Git tag: `v1.1.0`
- Release type: stable TLS policy and certificate operations

## Summary

Fluxheim `1.1.0` focuses on making public TLS and certificate lifecycle
operations production-practical. It keeps the `1.0.0` gateway foundation and
adds explicit TLS profiles, backend-validated TLS policy controls, structured
HSTS, and native ACME issuance/renewal paths.

## Highlights

- TLS profiles:
  - `modern`: TLS 1.3 only.
  - `intermediate`: default TLS 1.2+ production compatibility baseline.
  - `compat`: explicit TLS 1.2+ compatibility alias, currently equivalent to
    `intermediate`.
- TLS policy controls for minimum protocol version, ALPN, curve preferences,
  and cipher-suite allow-lists.
- Backend validation for unsupported TLS policy combinations.
- Structured HSTS response policy with `max_age_secs`, `include_subdomains`,
  and `preload`.
- ACME-managed certificate paths derived safely from vhost names.
- HTTP-01 local challenge serving for ACME-managed vhosts.
- TLS-ALPN-01 challenge certificate generation and rustls ALPN serving for
  ACME-managed vhosts.
- Actalis External Account Binding secret loading from environment variables or
  file-backed secrets.
- Built-in Google Trust Services production and staging ACME issuers with
  separate EAB secret defaults.
- `acme-client` feature for live account/order/finalize support and background
  renewal checks.
- Official RPM and container builds now compile `profile-core,acme-client` so
  packaged deployments include the `acme-renew` CLI and renewal worker.
- `acme-init` command for guided issuer bootstrap, including Actalis EAB secret
  files and systemd credential drop-in creation.
- RPM packaging creates `/etc/fluxheim/secrets` and ships an optional Actalis
  systemd credential drop-in example.
- Reloadable downstream SNI certificate objects after successful ACME renewal
  when the selected TLS backend exposes a reloadable resolver or callback.

## Validated Scope

- Static and proxied vhosts from the `1.0.0` gateway release.
- Rustls default TLS backend with SNI certificate selection.
- OpenSSL and BoringSSL TLS policy wiring where the selected backend exposes
  listener controls.
- s2n config validation for unsupported custom listener policy.
- File-backed ACME EAB secrets for systemd credentials and container secrets.
- Due-only ACME renewal command flow and background renewal service.

## Known Limits

- HTTP/3/QUIC remains post-`1.1.0`.
- Encrypted Client Hello is planned, but not implemented.
- Post-quantum hybrid key exchange is not yet enforceable by the default
  rustls/ring backend. `X25519MLKEM768` is accepted by the schema for future
  planning, but the rustls backend rejects it until a stable crypto provider is
  available.
- TLS certificate compression is future work and depends on TLS stack and
  browser support.
- Advanced provider-specific certificate automation and cluster-wide
  certificate coordination remain later milestones.

## Checksums And Signatures

Record during the release:

- Commit: to be filled after the release-prep commit
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
