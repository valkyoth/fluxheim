# Fluxheim 1.4.5 Release Notes

Fluxheim 1.4.5 is the planned bounded GeoIP/Geo-Context release.

## Highlights

- Development starts with the pinned Rust toolchain and minimum supported Rust
  version raised from 1.95 to 1.96.
- Container builder images and RPM build requirements are aligned with Rust
  1.96.

## Planned Scope

- Optional `geoip` feature using local MMDB databases.
- Provider-agnostic Geo-Context normalization for MaxMind GeoIP2/GeoLite2 and
  CIRCL Geo Open datasets where the supplied database is MMDB-compatible.
- Country/ASN route and access-policy decisions with privacy-conscious
  observability.

## Compatibility Notes

- Linux remains the production support baseline.
- macOS developer support remains Level 1 from 1.4.4.
