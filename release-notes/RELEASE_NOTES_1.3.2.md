# Fluxheim 1.3.2 Release Notes

## Summary

Fluxheim 1.3.2 starts the operational follow-up for ACME first issuance and
container diagnostics. The first implemented slice is a standalone
`fluxheim-config-tester` binary that can be downloaded from release assets and
used to validate mounted configs without starting the gateway container.

- Release type: operational follow-up
- Compatibility: no config format break intended
- Primary area: config validation, release diagnostics, and ACME operations

## Highlights

- Added `fluxheim-config-tester` as a separate binary target.
- Added target-profile validation for `full`, `cache`, `proxy`, `web-php`,
  `development`, and future `load-balancer` profiles.
- Added tester modes for runtime-path validation, TLS storage checks, ACME
  target preview, upstream DNS resolution, and `--explain` output.
- Added the `fluxheim-acme` companion binary with `renew` and `targets`
  commands.
- Added a local Unix-domain certificate reload socket for companion-driven live
  certificate activation after renewal.
- Packaged `fluxheim-acme` into RPMs and runtime images for external
  service/timer and container companion workflows.
- Kept the tester out of normal RPM installation and runtime images; it is a
  release diagnostics artifact.

## Build

Build the main runtime and tester for a profile explicitly:

```bash
cargo build --release --locked --no-default-features \
  --features profile-web-server,php-fpm,acme-client \
  --bin fluxheim --bin fluxheim-config-tester
```

## Checksums And Signatures

To be filled during release.
