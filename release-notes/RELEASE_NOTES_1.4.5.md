# Fluxheim 1.4.5 Release Notes

Fluxheim 1.4.5 is the bounded GeoIP/Geo-Context release.

## Highlights

- Development starts with the pinned Rust toolchain and minimum supported Rust
  version raised from 1.95 to 1.96.
- Container builder images and RPM build requirements are aligned with Rust
  1.96.
- New optional `geoip` feature for local MMDB Geo-Context lookup.
- Provider labels cover MaxMind GeoIP2/GeoLite2 and European CIRCL Geo Open
  MMDB-compatible datasets through the same reader path.
- Ordered local database fallback can fill missing country or ASN fields from a
  later MMDB file when `geoip.fallback_enabled = true`.
- Vhost and route access policies can now allow or deny by country code and
  ASN.
- Structured access logs include `geo_country` and `geo_asn` when the `geoip`
  feature is compiled and a lookup resolves those fields.
- GeoIP database loading now enforces the 512 MiB per-file limit at the read
  layer and caps a single runtime's loaded MMDB data at 1 GiB.
- Startup emits security warnings when country or ASN access policy is
  configured but the loaded MMDB database types do not appear to provide that
  record family.

## Scope

- GeoIP is local-only. Fluxheim does not download, poll, or refresh MMDB files
  by URL in-process.
- Database files are opened as regular files and symlink leaf paths are
  rejected.
- Keep GeoIP update jobs atomic: write a new MMDB beside the old one, verify
  it, then rename it into place before reloading Fluxheim.
- Geo allow lists fail closed when no Geo-Context is available for the client
  IP. Geo deny lists deny only on a resolved match.
- High-cardinality GeoIP data such as city, latitude/longitude, or raw provider
  fields is intentionally not exposed in metrics.

## Compatibility Notes

- Linux remains the production support baseline.
- macOS developer support remains Level 1 from 1.4.4.
- `privacy-mode` and `geoip` cannot be compiled together.
