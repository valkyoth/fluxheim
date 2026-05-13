# Fluxheim 1.2.3 Release Notes

## Release Metadata

- Version: `1.2.3`
- Release date: to be filled
- Git tag: `v1.2.3`
- Release type: focused cache-encryption follow-up

## Summary

Fluxheim `1.2.3` adds optional disk cache encryption at rest. Encryption is
disabled by default. Operators can use a local AES-256-GCM key file or
credential for simple deployments, or OpenBao Transit for external key custody
where Fluxheim should store only Transit ciphertext in the cache backend.

## Highlights

- Added `[cache.disk.encryption]` policy configuration for disk cache object
  encryption.
- Added local-key AES-256-GCM encryption using a safe key file or
  systemd/container credential.
- Added OpenBao Transit encryption over HTTPS or loopback HTTP with token
  loading from a safe file or credential.
- Bound encrypted cache objects to the configured key id and combined cache key
  as authenticated data.
- Kept encryption opt-in so normal filesystem and storage-bin cache deployments
  do not require OpenBao.
- Added `examples/podman-compose-openbao.yml` for a local OpenBao dev server.
- Added `scripts/smoke_openbao_cache_encryption.sh` to verify real
  Transit-backed proxy-cache `MISS` then `HIT` behavior and confirm that stored
  cache objects contain `vault:v...` ciphertext rather than plaintext response
  bodies.

## Known Limits

- OpenBao Transit adds an external encrypt/decrypt call for each disk cache
  object write/read. Use it where external key custody matters more than the
  extra latency, and keep OpenBao close to Fluxheim.
- Local-key encryption protects cache objects at rest, but it does not encrypt
  memory cache contents.
- Distributed cache metadata and peer-fill are planned for `1.2.4`.
- Wasm-based extension points, including cache-rule hooks comparable to VCL/Lua
  style customization, are planned for `1.4`.

## Checksums And Signatures

Record during the release:

- Commit: `v1.2.3` tag target
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
