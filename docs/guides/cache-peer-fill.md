# Peer-Assisted Cache Fill

Peer fill lets a Fluxheim node ask another node for an already-cached public
object before fetching from origin. It is not cache replication, consensus,
distributed locking, or automatic cluster-wide invalidation. Each node owns its
cache and its lifetime. See [caching](cache.md) for admission and storage basics.

## Variant Safety And Upgrades

Peer fills use version 2 of the internal protocol. Both nodes must support this
version, including when no shared secret is configured. Older responses are
discarded; there is no automatic downgrade. Upgrade peers together or temporarily
disable peer fill. During a mixed rollout, `fail_open = true` permits normal
origin fallback; `false` returns a peer-fill failure when no compatible peer hits.

`Accept`, `Accept-Encoding` and `Accept-Language` are preserved automatically.
For a custom **public, non-secret** representation selector, name it explicitly
in `vary_request_headers` on the requesting node:

```toml
[vhosts.cache]
enabled = true
vary_request_headers = ["x-edition"]

[vhosts.cache.peer_fill]
enabled = true
fail_open = true

[[vhosts.cache.peer_fill.peers]]
name = "cache-a"
base_url = "http://127.0.0.1:18081"
```

Merge these tables into an otherwise complete cache/vhost configuration. The
peer must either configure the same selector or have stored an origin response
with `Vary: X-Edition`. With `X-Edition: special`, a peer's default edition is
never stored as the special edition. A response varying on an unpreserved field
is rejected, even if that field was absent from this particular client request.
Origin-declared custom fields therefore still need explicit configuration on
the requesting node; Fluxheim does not forward all client headers speculatively.

Header names are case-insensitive. Missing, present-but-empty and repeated
values remain distinct; the order of repeated values is preserved. The context
is limited to 19 unique fields (three defaults plus at most 16 configured
fields), 128-byte names, 64 occurrences per field and 8 KiB of encoded context.
Unsupported or over-limit contexts skip the peer attempt, following `fail_open`.
Credentials, cookies, hop-by-hop fields, connection-nominated fields, forwarding
identities, conditional/range controls and internal peer headers are not forwarded.
Reserved authentication/secret-related names are rejected as selectors. Operators
must still ensure their explicitly configured custom selectors contain only
public representation metadata, never application credentials or personal data.

HMAC version 2 binds method, target, Host, nonce and the same bounded variant
context in both directions. The response also authenticates status, body and
end-to-end headers, including `Age`, variant metadata and an internal cache-date
field. That date is restored after verification because the HTTP/1 writer
generates its own wire `Date`. Generated framing fields are not signed; the body
digest binds the delivered bytes. Internal response metadata is removed before
ordinary client delivery and local cache storage.

Use verified HTTPS or an independently authenticated encrypted transport on any
untrusted network. HMAC provides integrity, not confidentiality or an independent
trust domain. Numeric-loopback HTTP examples are local development fixtures.

## How A Fill Works

1. The receiving node evaluates normal request eligibility and its own cache.
2. For an eligible GET miss, it tries peers in configured order with bounded
   connection/read times and an outbound concurrency permit.
3. Each peer receives the original Host and path/query, `only-if-cached`, and
   an internal marker. A peer miss returns `504` without fetching from origin
   or recursively filling from another peer.
4. An acceptable fresh `200` peer response is rechecked by the receiving node's
   admission policy and stored locally. `Age` reduces its remaining freshness.
5. If no peer supplies an admissible object, `fail_open = true` allows ordinary
   origin fallback; false returns a bounded failure, normally `504` with a peer
   miss/concurrency reason. This is cache availability policy, not bypass of
   request authentication.

Peers must agree on what a Host/path represents and on relevant response
variants. Point `base_url` at the peer's serving listener, not its admin API.
HTTPS SNI comes from that URL's hostname while HTTP Host remains the requested
site's Host. Ensure both identities are intentional.

## Configure Peers

The [complete example](../../examples/cache-peer-fill.toml) points at two
loopback peers and an origin on port 3000. Its peer-specific settings are:

```toml
[vhosts.cache.peer_fill]
enabled = true
connect_timeout_secs = 2
read_timeout_secs = 10
max_object_bytes = "32MiB"
max_concurrent_requests = 64
allow_insecure_http = false
fail_open = true

[[vhosts.cache.peer_fill.peers]]
name = "cache-a"
base_url = "http://127.0.0.1:18081"

[[vhosts.cache.peer_fill.peers]]
name = "cache-b"
base_url = "http://[::1]:18082"
```

Both peers need the same `cache-peer.example.test` vhost and a compatible public
asset policy. Start and warm a peer, then request the same URL on the example's
port 8080. Expect `PEER-HIT` then a local `HIT`. Confirm the origin request count
does not increase during the peer fill; a successful 200 alone is not proof.

```sh
curl -i -H 'Host: cache-peer.example.test' http://127.0.0.1:18081/asset.webp
curl -i -H 'Host: cache-peer.example.test' http://127.0.0.1:8080/asset.webp
curl -i -H 'Host: cache-peer.example.test' http://127.0.0.1:8080/asset.webp
```

There is no automatic peer bootstrap: configure their listeners, vhosts and
storage independently. The repeatable local smoke starts all required nodes:

```sh
cargo build --features metrics
sh scripts/smoke_peer_fill_cache.sh
```

It covers peer/local hits, Accept-Language variants, fail-open/fail-closed
behavior and metrics. The cross-platform variant smoke additionally starts two
real peers and a counted origin, checking exact bodies and origin counts for
missing, empty and repeated custom values across memory, filesystem disk and
storage-bin caches:

```sh
cargo build --locked --no-default-features --features profile-load-balancer,acme-client --bin fluxheim
python3 scripts/smoke_peer_variants.py target
```

## All Peer Options

These tables may also appear under `vhosts.cache` or `vhosts.routes.cache`.

| Field under `peer_fill` | Default | Meaning / limit |
| --- | --- | --- |
| `enabled` | `false` | Needs cache feature, enabled cache and a usable storage tier |
| `peers` | `[]` | 1-32 peers when enabled, tried in order, not a load-balanced pool |
| `connect_timeout_secs` | `2` | 1-300 seconds per peer connection |
| `read_timeout_secs` | `10` | 1-3600 seconds for peer response handling |
| `max_object_bytes` | unset | Defaults to cache maximum; effective cap is the smaller of both limits |
| `max_concurrent_requests` | `64` | 1-1024 active peer fills per runtime policy, not a cluster-wide cap |
| `allow_insecure_http` | `false` | Explicit non-loopback HTTP opt-in; not recommended for an untrusted network |
| `shared_secret_file` | unset | File holding 32-4096 secret bytes; trailing CR/LF trimmed; required for non-loopback HTTP |
| `fail_open` | `true` | Fall back to origin when peers miss/fail or peer concurrency is exhausted |

Each peer has `name` (1-64 ASCII letters/digits or `._-`) and `base_url`.
Names and normalized URLs must be unique. URLs require an explicit nonzero
port and may not contain credentials, a path prefix, query or fragment.
Use a numeric loopback address for local HTTP tests. For HTTPS the native peer
client requires a DNS hostname, a compiled TLS backend and verified server
certificates; it does not expose peer-specific CA, mTLS or verification-disable
fields. Do not copy the origin proxy's TLS knobs into this table.

## Shared Secret And Operations

If using the optional HMAC layer, install the same high-entropy secret on each
participating node and set `shared_secret_file`. The path is config-relative or
absolute. Use a private regular file, restrictive service-readable permissions,
trusted parent directories and private distribution. A password or public
example string is not a suitable secret. Do not place it in a URL or Git.

The HMAC layer detects unsigned/modified responses and binds a fresh nonce and
variant context. Peers sharing the key are one
trust domain: a compromised trusted peer is not made safe by its valid signature.
Rotate keys as a coordinated rollout; mismatched keys cause misses/failures.

Changing local namespace or purging one node does not invalidate the others.
Coordinate application versioning and purges across nodes; otherwise a cold node
can refill from an old peer. Do not share one encrypted disk root across hosts.
Use independent storage roots and appropriate encrypted transport.
