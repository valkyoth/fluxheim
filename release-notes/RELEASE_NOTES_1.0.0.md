# Fluxheim 1.0.0 Release Notes

## Release Metadata

- Version: `1.0.0`
- Release date: 2026-05-08
- Git tag: `v1.0.0`
- Release type: stable gateway foundation

## Summary

Fluxheim `1.0.0` is the first stable gateway foundation release. It is intended
for production testing of static sites, vhosts, redirects, TLS/SNI, HTTP/2,
secure defaults, systemd/RPM deployment, and external ACME challenge forwarding.

## Highlights

- Static site serving with secure path validation, index files, ETags, range
  requests, and optional directory listing.
- Vhost routing with default-vhost fallback, wildcard host matching, route
  exact/prefix/fallback matching, redirects, static route actions, and proxy
  route actions.
- HTTP to HTTPS redirects and canonical host redirects that preserve safe request
  URIs.
- TLS with rustls by default, static vhost certificates, SNI selection, and
  default-vhost fallback certificate support.
- External ACME HTTP-01 challenge forwarding helper for
  `/.well-known/acme-challenge/`.
- Dynamic request header templates for common proxy migrations.
- Native systemd/RPM packaging, packaged default config/site, and server
  preparation helper.
- CodeQL, cargo audit/deny, SBOM generation, reproducible-build checks, panic
  policy hardening, zeroized admin token handling, and constant-time admin token
  verification.

## Validated Scope

- Native RPM/systemd deployment.
- Static web roots and config preflight.
- HTTP/80 and TLS/443 listeners.
- HTTP/2 via ALPN.
- Multi-certificate SNI with rustls.
- External certbot/Actalis challenge forwarding.
- Basic proxy migration headers and route/vhost proxying.

## Known Limits

- Native ACME certificate issuance/storage is still future work; use an external
  ACME client plus deploy hook for this release.
- HTTP/3/QUIC is post-1.0 work.
- Advanced gateway modules such as compression policy, identity-aware auth,
  trusted proxy providers, secure links, WAF, and WASM are roadmap items.
- Vhost TLS certificate changes require the normal process restart/reload
  workflow; automatic renewal reload is not first-class yet.

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
