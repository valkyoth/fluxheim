# GeoIP: Country And Network Access Rules

GeoIP looks up a client's IP address in a local database and uses the result
to allow or deny an HTTP request. Fluxheim supports two pieces of information:

- **Country**: a two-letter code such as `US` or `SE`.
- **ASN**: an autonomous system number, identifying a network operator. For
  example, `13335` identifies Cloudflare's network, not an individual customer.

Use this for coarse network policy, not authentication. VPNs, shared networks,
stale records and provider methodology can all make the result differ from a
person's physical location. Keep application authentication and authorization.

This page covers the current source checkout. GeoIP is optional, off until
configured, and applies to HTTP vhost/route access policy. It is not a TCP/UDP
GeoIP firewall, database downloader, city lookup or latitude/longitude service.

## Build Feature

The full and Wasm packaged profiles include GeoIP. The default source build
does not; consult the [feature matrix](../reference/features.md) before selecting
a focused image. A small static/proxy build with GeoIP is:

```bash
cargo build --locked --no-default-features --features proxy,web,geoip --bin fluxheim
```

That command intentionally omits TLS for the loopback demonstration below.
For a TLS-capable full source build:

```bash
cargo build --release --locked --no-default-features \
  --features profile-full --bin fluxheim
```

Add `acme-client` if that source build should also obtain certificates.
`privacy-mode` and `geoip` are incompatible. Enabling GeoIP in a binary built
without it is a configuration error, not an ignored option.

Database loading has Unix ownership/mode checks on Linux/macOS and native
ACL/reparse-point checks on Windows. The live example evidence at the end of
this page is Linux evidence, not a new native macOS/Windows qualification.

## First Working Configuration

Use [the complete local example](../../examples/geoip/local.toml) and its
[static page](../../examples/geoip/site/index.html). Copy them into a directory
owned by the service user, with no writable-by-others parent directory.
Install a verified combined CIRCL MMDB as `database.mmdb` beside the TOML.
The database is not bundled with Fluxheim; see [Local Databases](#local-databases).

The important part of that complete example is:

```toml
[geoip]
enabled = true
fallback_enabled = true

[[geoip.databases]]
provider = "circl-geo-open"
path = "database.mmdb"

[[vhosts]]
name = "geo"
hosts = ["geo.example.test"]

[vhosts.web]
root = "site"
index_files = ["index.html"]

[vhosts.access]
enabled = true
allow_countries = ["US"]
allow_asns = [13335]
deny_countries = []
deny_asns = []
```

Both allow lists must match: a US record alone is insufficient if its ASN is
not 13335. The complete file binds only to `127.0.0.1:8088`, uses private
relative process paths, and does not trust forwarded IP headers.

After installing the database, run from the repository root:

```bash
target/debug/fluxheim --validate-config --config examples/geoip/local.toml
target/debug/fluxheim --config examples/geoip/local.toml
```

Use the path to your copied configuration instead if you installed it elsewhere.
In another terminal:

```bash
curl -i -H 'Host: geo.example.test' http://127.0.0.1:8088/
```

Expect **403**: the actual client is loopback, not a public address matching
both allow lists. Adding a forged `X-Forwarded-For: 1.1.1.1` must still give
403. This is the intended fail-closed result, not a broken static site.

For a controlled local test only, replace the complete example's
`trusted_proxies = []` with `trusted_proxies = ["127.0.0.1"]`, then restart:

```bash
curl -i -H 'Host: geo.example.test' -H 'X-Forwarded-For: 1.1.1.1' \
  http://127.0.0.1:8088/
```

With the pinned CIRCL fixture below, expect **200** and
`GeoIP policy allowed this request.`. Using `8.8.8.8` instead gives **403**:
it has a US record but a different ASN. Database results can change over time.

Trusting loopback means trusting other local processes to supply client
addresses. Do not copy that trust setting blindly into production.

## Which Address Is Checked?

Without a trusted proxy, Fluxheim uses the socket peer's IP address.
`server.trusted_proxies` defaults to an empty list. Forwarded client-IP headers
are considered only for a configured trusted direct peer. An effective address
from the configured PROXY-protocol path takes precedence.

Behind a CDN or reverse proxy, configure only your actual proxy peers and
ensure they sanitize client-supplied forwarding headers. Do not trust
`0.0.0.0/0` or `::/0`: doing so lets arbitrary clients supply policy inputs.
See [server configuration](../reference/config-reference.md#server) and
[CDN origin trust and current limits](cloudflare-origin-support.md).

## Option Reference

All GeoIP tables are global except access policy. Vhost policy applies before
route policy; the latter cannot relax a vhost denial.

| Key | Type and default | Accepted values and behavior |
| --- | --- | --- |
| `geoip.enabled` | Boolean, `false` | Loads local databases when true; requires the compiled feature. |
| `geoip.fallback_enabled` | Boolean, `true` | True fills missing country/ASN fields from later databases. False uses only the first for lookup. |
| `geoip.databases` | Array of tables, empty | When enabled: 1 to 8 entries, in lookup order. Every configured file is loaded and validated even when fallback is false. |
| `geoip.databases[].provider` | Required string | Exactly `maxmind` or `circl-geo-open`. No network call or automatic provider discovery. |
| `geoip.databases[].path` | Required path | Nonempty local MMDB path; relative paths are resolved by the config loader against the configuration base directory. |
| `vhosts.access.enabled` / `vhosts.routes.access.enabled` | Boolean, `true` | Disables the entire policy at that scope when false, including IP and client-certificate rules, not just GeoIP. Validation still applies. |
| `allow_countries` | String array, `[]` | Up to 512 entries; exactly two uppercase ASCII letters per entry, without duplicates. Empty means no country allow restriction. |
| `deny_countries` | String array, `[]` | Same syntax/limit; matching country is denied even if also allowed. |
| `allow_asns` | Integer array, `[]` | Up to 2,048 entries; 1 through 4,294,967,295, without duplicates. Empty means no ASN allow restriction. |
| `deny_asns` | Integer array, `[]` | Same syntax/limit; matching ASN is denied even if also allowed. |

The last four fields belong under either access table. Country syntax validation
does not verify membership in a current ISO registry. Choose codes actually
present in your dataset; `us`, `USA`, and `AS13335` are not valid policy values.

### Matching And Missing Records

- Any matching country or ASN deny rule rejects the request with 403.
- Each nonempty allow list must match. Country and ASN allow lists combine
  with **AND**, not OR.
- A missing country fails a nonempty country allow list; a missing ASN fails a
  nonempty ASN allow list.
- Deny-only rules permit missing/unmatched records. They are not a reliable
  way to block every unknown network.
- IP and client-certificate checks remain additional requirements.
- A route that has no GeoIP rule still remains subject to its vhost's rules.

For a deny-only policy, replace the base file's access table with
[deny-only.toml](../../examples/geoip/deny-only.toml). It rejects US records or
ASN 13335, but permits unknown records unless another access rule denies them.

Append [route.toml](../../examples/geoip/route.toml) to the base file to restrict
`/restricted/`. That route denies ASN 13335 even though the vhost allows it.
Disabling the route policy does not bypass the vhost policy.

### Disabling GeoIP

To remove GeoIP restrictions without disabling IP or certificate controls,
clear all four GeoIP lists at both vhost and route scopes. Then set
`geoip.enabled = false` and restart/apply the new configuration.

Setting only `access.enabled = false` does not remove validation requirements:
nonempty GeoIP lists still require global GeoIP to be enabled. Do not switch
off the entire access policy just to disable country checks.

## Local Databases

`maxmind` reads MaxMind GeoIP2/GeoLite2 country and ASN layouts. Country lookup
uses `country.iso_code`, with `registered_country.iso_code` as a fallback.
The ASN layout uses numeric `autonomous_system_number`.

`circl-geo-open` additionally understands CIRCL's combined-database string
field `country.AutonomousSystemNumber`. A country-only database cannot enforce
an ASN allow list on its own.

For separate country and ASN files, replace the base example's complete
GeoIP block with [two-databases.toml](../../examples/geoip/two-databases.toml).
Install both files beside the config first, observing their provider's license.

Databases are consulted in order, filling only missing fields. A later record
does not override a country or ASN already found. Consequently, country and ASN
can come from different datasets. Setting `fallback_enabled = false` means a
country-only first file cannot supply ASN, even if the second file contains it.

Fallback is **not startup failover**: a missing, unreadable, oversized, malformed
or untrusted later file still fails loading. Keep only files you intend to use.
A database-type warning about missing country/ASN support is diagnostic;
test known addresses, rather than trusting the type string alone.

### Permissions And Resource Limits

Use a real, regular file, not a symlink. On Unix, the file and every parent
must be owned by a trusted owner (root, the service user or the supported
namespace root-equivalent) and must not be writable by group/others.
The service user must be able to read the file and traverse its parents.
Windows uses trusted owner/ACL checks and rejects reparse-point traversal.

A root-managed installation can use these commands **after** verifying the
download. They require appropriate administrator privileges:

```bash
install -d -o root -g root -m 0755 /var/lib/fluxheim/geo
install -o root -g root -m 0444 \
  2026-06-26-GeoOpen-Country-ASN.mmdb \
  /var/lib/fluxheim/geo/2026-06-26-GeoOpen-Country-ASN.mmdb
```

Set the example's database `path` to that absolute installed path.
For a container, mount the containing trusted directory read-only at the same
in-container path and ensure its ownership/mode or ACL is acceptable to the
container service user. A host path alone does not make the database visible
inside the container.

Bounds are 512 MiB per file, 1 GiB aggregate input bytes and 8 databases.
The runtime checks size before allocating, reads the admitted length, probes
for unexpected growth, and rejects changed descriptors/metadata. These bounds
are not a total-process RAM limit: parsing and other services use memory too.
Old and new router generations can overlap during reload.

Raw country values longer than eight bytes are rejected before normalization;
accepted database values must normalize to two ASCII letters. ASN zero is not
accepted as valid context.

### Updating Without Guesswork

Fluxheim does not download databases, watch their modification time or
automatically reload after an atomic rename.

1. Download and verify a replacement under a staging directory. Obtain hashes
   or signatures through a source your deployment policy trusts.
2. Test known addresses and policy decisions; a well-formed database can still
   have unexpected geographical semantics.
3. Install a versioned regular file with trusted ownership and permissions.
4. Update the configured path and use the
   [verified snapshot/reload workflow](config-snapshots.md), or restart Fluxheim.
   If replacing bytes at an unchanged path, restart rather than relying on
   configuration-diff detection to notice the new data.
5. Verify real allowed and denied requests after application. Keep the old
   file/configuration for rollback until satisfied.

An invalid replacement must not be treated as permission to allow all clients.
A fresh process fails startup; do not stop a healthy deployment until its
replacement has passed your rollout checks.

### CIRCL Geo Open

CIRCL publishes Geo Open under ODC-By; retain the required attribution.
Its country result describes the announcing BGP autonomous system's country,
which may differ from an end user's location. See the
[official dataset page](https://data.public.lu/en/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/).

The reproducible repository smoke uses this historical fixture, not a
recommendation to keep an old database in production:

```text
URL: https://cra.circl.lu/opendata/geo-open/mmdb-country-asn/2026-06-26-GeoOpen-Country-ASN.mmdb
SHA-256: dd2607402f0614e4d4ff7a4bd4627e5e0e9bdedc7a97492d57c6e6a5c91b8423
```

Inspect local data with the same runtime lookup implementation:

```bash
cargo run --locked -p fluxheim-geoip --features runtime --example lookup -- \
  circl-geo-open /var/lib/fluxheim/geo/2026-06-26-GeoOpen-Country-ASN.mmdb \
  1.1.1.1 8.8.8.8
```

## Observability

Current structured access events do **not** export `geo_country` or `geo_asn`.
There are no GeoIP-specific metric labels or trace attributes. Earlier guide
wording promised fields that the current event model does not emit.

Use controlled lookup checks and observed HTTP results to diagnose policy.
Never assume an access-log field, city coordinate or raw MMDB field is available
as a routing template. See [logging](logging.md) for the actual event contract.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| GeoIP module not compiled | Select a GeoIP-capable profile or add the feature; changing TOML cannot add compiled code. |
| Global GeoIP required | Check every vhost/route for nonempty GeoIP lists, including disabled access policies. |
| Startup fails inspecting a path | Check the in-container path, file readability, ownership, parents and symlinks. Do not solve it with `chmod 777`. |
| Everyone receives 403 | Verify the actual client IP, trusted proxy configuration, dataset coverage and both allow lists. |
| Country works but ASN does not | Use an ASN-capable file and correct provider; check fallback order and the ASN lookup result. |
| Forged header unexpectedly works | Audit `server.trusted_proxies` and upstream header sanitization immediately. |
| New file has no effect | The router keeps loaded data in memory; apply a changed configuration or restart. |
| No GeoIP fields in dashboards | Those fields are not emitted by the current telemetry implementation. |

## Verification And Coverage

```bash
cargo test --locked -p fluxheim-config --features geoip geoip
cargo test --locked -p fluxheim-config --no-default-features geoip
sh scripts/smoke_geoip_circl.sh
```

The live smoke downloads/checksums about 79 MiB and proves static serving,
direct proxying and two-origin load balancing with real country/ASN decisions.
It is opt-in through `scripts/test_starter.py`, not an automatic normal-CI gate.
Use `FLUXHEIM_GEOIP_CIRCL_DATABASE` for an existing file with the pinned digest,
or `FLUXHEIM_GEOIP_CIRCL_CACHE_DIR` for its trusted download cache.

The [coverage ledger](../reference/documentation-coverage.md) distinguishes
configuration tests, live Linux evidence and remaining native/provider gaps.
