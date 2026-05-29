# GeoIP / Geo-Context

Fluxheim `1.4.5` adds a bounded optional `geoip` feature. It is a local
Geo-Context foundation for access policy, not a dynamic downloader or
programmable geo engine.

## Build Feature

```bash
cargo build --release --locked --no-default-features \
  --features profile-full \
  --bin fluxheim
```

`profile-full` includes `geoip`. Focused builds can enable it directly:

```bash
cargo build --release --locked --no-default-features \
  --features proxy,geoip,tls-rustls,security \
  --bin fluxheim
```

`privacy-mode` and `geoip` are mutually exclusive. Privacy builds reject
GeoIP lookup and Geo-Context metadata entirely.

## Local Databases

Fluxheim reads local MMDB files through a provider-agnostic layer. The initial
providers are labels for compatible MMDB datasets:

- `maxmind`: MaxMind GeoIP2 or GeoLite2 MMDB files.
- `circl-geo-open`: European CIRCL Geo Open MMDB-compatible datasets.

Fluxheim does not download or update databases in-process. Use an external
systemd timer, package job, or sidecar to fetch and verify database files, then
reload Fluxheim. Database files are opened as regular files and symlink leaf
paths are rejected.

Each MMDB file is capped at 512 MiB at both metadata and read time. A single
loaded GeoIP runtime is capped at 1 GiB of MMDB data, so keep the ordered
fallback set small. During hot reload, the old and new runtimes can briefly
coexist while in-flight requests finish, so size host/container memory for that
temporary overlap.

```toml
[geoip]
enabled = true
fallback_enabled = true

[[geoip.databases]]
provider = "maxmind"
path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"

[[geoip.databases]]
provider = "circl-geo-open"
path = "/var/lib/fluxheim/geo/circl-country.mmdb"
```

Databases are evaluated in order. When `fallback_enabled = true`, Fluxheim fills
missing country or ASN fields from later databases when possible. When it is
false, Fluxheim consults only the first configured database.

When country or ASN access rules are configured, Fluxheim checks the loaded
MMDB database type strings and emits a security warning if no loaded database
appears to provide the required record family. This is a diagnostic guard, not
a substitute for testing policy behavior with known source IPs.

## Access Policy

Geo rules live on the existing vhost and route access policy. Country codes are
ISO alpha-2 uppercase values. ASN values are numeric and must be greater than
zero.

```toml
[[vhosts]]
name = "app"
hosts = ["app.example.test"]

[vhosts.access]
deny_countries = ["RU", "KP"]
allow_asns = [12552, 32934]

[[vhosts.routes]]
name = "admin"
path_prefix = "/admin/"

[vhosts.routes.access]
allow_countries = ["SE", "NO", "DK", "FI"]
```

Vhost policy runs before route policy. Geo allow lists fail closed when no
Geo-Context is available for the client IP. Geo deny lists only deny when the
resolved country or ASN matches.

## Observability

When `geoip` is compiled and a lookup succeeds, structured access logs include:

- `geo_country`
- `geo_asn`

GeoIP metrics and trace attributes remain bounded follow-up work; do not add
high-cardinality labels from city, latitude/longitude, or raw database fields.
