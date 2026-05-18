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
- Added `fluxheim-acme status` and `fluxheim-acme renew --vhost <name>` for
  single-target ACME checks and renewal on multi-site gateways.
- Added `fluxheim-acme reload` for explicit certificate-handle reload requests
  through the local control socket.
- Added `fluxheim_acme_events_total{event}` metrics for pending, renewed,
  failed, and reload outcomes with bounded labels only.
- Packaged `fluxheim-acme` into RPMs and runtime images for external
  service/timer and container companion workflows.
- Kept the tester out of normal RPM installation and runtime images; it is a
  release diagnostics artifact.
- Hardened ACME reload socket responses with a bounded read, kept ACME/cache
  secret-file intermediates in zeroizing buffers, and capped Admin API JSON
  response/error sizes.
- Hardened the certificate reload control socket with private bind/listen
  sequencing and read timeouts.
- Hardened filesystem opens with portable Unix `O_NOFOLLOW` coverage for
  config, snapshot, web, runtime-log, ACME, and admin-token paths.
- Hardened trace-context generation so CSPRNG failure disables tracing for the
  request instead of spinning indefinitely.
- Hardened admin authentication and responses with per-process HMAC token
  digests, generic internal-error responses, and global-only throttling for
  indeterminate client sources.
- Documented the current protobuf advisory boundary: Fluxheim's Pingora metrics
  endpoint uses text encoding directly and does not expose protobuf parsing.

## Build

Build the main runtime and tester for a profile explicitly:

```bash
cargo build --release --locked --no-default-features \
  --features profile-web-server,php-fpm,acme-client \
  --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
```

## Checksums And Signatures

To be filled during release.
