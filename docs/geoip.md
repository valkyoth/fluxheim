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
reload Fluxheim. Database paths must be absolute. Files are opened through a
no-follow descriptor and must be regular files owned by root, the effective
Fluxheim service user, or the platform root-equivalent owner used by a user
namespace. The file and every parent directory must not be group- or
world-writable, and every parent must have a trusted owner. Symlink components,
descriptor identity changes, and in-place changes during the bounded read are
rejected.

Each MMDB file is capped at 512 MiB at both metadata and read time. Fluxheim
opens and inspects each descriptor, checks its size against the remaining 1 GiB
aggregate allowance, and only then allocates an exact-length input buffer,
reads that admitted length, and probes one extra byte without growing the heap
buffer. Shortened, grown, or metadata-changed files fail loading. At most eight
databases are accepted by both config validation and the runtime crate. During
hot reload, the old and new runtimes can briefly coexist while in-flight
requests finish, so size host/container memory for up to two admitted runtimes
plus parser overhead.

Country fields are decoded as borrowed MMDB strings. Raw values longer than
eight bytes are rejected before normalization or owned allocation; accepted
values must normalize to exactly two ASCII letters. Public `GeoContext`
construction enforces the same invariant, canonicalizes accepted countries to
uppercase, and rejects ASN zero so future policy consumers cannot introduce an
invalid context through the crate API.

### CIRCL Geo Open

CIRCL publishes Geo Open through Luxembourg's official open-data portal under
the ODC-By license. Review and retain the dataset attribution required by that
license. Fluxheim supports both the country-only MMDB and the combined Country
and ASN MMDB. The combined database stores its ASN as the string field
`country.AutonomousSystemNumber`; selecting `provider = "circl-geo-open"`
enables Fluxheim's bounded decoder for that CIRCL-specific schema.

The reproducible repository smoke pins this dated combined database:

```text
URL: https://cra.circl.lu/opendata/geo-open/mmdb-country-asn/2026-06-26-GeoOpen-Country-ASN.mmdb
SHA-256: dd2607402f0614e4d4ff7a4bd4627e5e0e9bdedc7a97492d57c6e6a5c91b8423
```

The [dataset page](https://data.public.lu/en/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/)
also publishes newer dated files. Treat a database update as a controlled
configuration change: download to a staging path, verify the checksum supplied
by your deployment policy, validate lookups, set trusted ownership and modes,
and atomically rename the file into the live directory. Do not replace the
dated filename in automation without reviewing and recording the new digest.

For example, install the verified combined file as a root-owned regular file:

```bash
install -d -o root -g root -m 0755 /var/lib/fluxheim/geo
install -o root -g root -m 0444 \
  2026-06-26-GeoOpen-Country-ASN.mmdb \
  /var/lib/fluxheim/geo/2026-06-26-GeoOpen-Country-ASN.mmdb
```

Then configure it with an absolute path:

```toml
[geoip]
enabled = true
fallback_enabled = true

[[geoip.databases]]
provider = "circl-geo-open"
path = "/var/lib/fluxheim/geo/2026-06-26-GeoOpen-Country-ASN.mmdb"
```

The following command performs direct lookups through the same runtime used by
Fluxheim. It is useful after replacing a database:

```bash
cargo run --locked -p fluxheim-geoip --features runtime --example lookup -- \
  circl-geo-open \
  /var/lib/fluxheim/geo/2026-06-26-GeoOpen-Country-ASN.mmdb \
  1.1.1.1 8.8.8.8
```

The opt-in end-to-end proof downloads and checksum-verifies the pinned database,
caches it under the secure smoke directory, then exercises country and ASN ACLs
for static web serving, direct proxying, and two-origin load balancing:

```bash
scripts/smoke_geoip_circl.sh
```

The approximately 79 MiB database download is why this smoke is available in
`scripts/test_starter.py` but intentionally excluded from normal CI and release
gates. Set `FLUXHEIM_GEOIP_CIRCL_CACHE_DIR` to retain the verified download in
another trusted directory, or set `FLUXHEIM_GEOIP_CIRCL_DATABASE` to an existing
regular file with the pinned digest. The latter is never chmodded by the script.

CIRCL Geo Open maps an address to the country associated with the announcing
BGP autonomous system. That can differ from an end user's physical location;
evaluate whether those semantics are appropriate before using country policy as
an authorization boundary.

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

Update jobs must prepare the replacement in a trusted directory, set safe
ownership and permissions, verify its checksum/signature and MMDB semantics,
then atomically rename it into place. Do not grant the downloader or unrelated
local users write access to the live GeoIP directory. A typical root-managed
deployment uses non-writable parent directories and a root-owned `0644` or
`0444` database readable by the Fluxheim service account.

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
