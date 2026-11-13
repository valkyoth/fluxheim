# Range And Slice Caching

A byte range asks for part of a representation, for example a portion of a
download or video. A slice is an internal fixed-size cache object used to build
that response. A 1 MiB slice does not mean the client must request 1 MiB chunks.
Start with [ordinary caching](cache.md); do not enable slicing just to serve
small images or CSS files.

## Choose The Right Mode

| Mode | What the native proxy does | Current limitation |
| --- | --- | --- |
| Full-object cache plus bounded Range | Can serve a single `bytes=start-end` window from an already-cached full body | An uncached range request bypasses normal cache fill (`range-miss`); do not expect automatic partial-object warming |
| Fixed-slice cache | Fetches normalized ranges, validates them, then assembles the requested bytes | Uses configured memory/filesystem/storage-bin tiers; assembly still buffers bytes in process memory |
| Local static files | Applies the file server's conditional/range behavior | Separate from proxy slices; see the local-static guide |

The normal proxy full-body path and fixed-slice path are not interchangeable.
For instance, warming a URL with an ordinary GET is not proof that its slice
entries are warm. Tests should issue the actual Range requests used by clients.

## Configure A Slice Route

The complete [slice example](../../examples/cache-slice-range.toml) uses one
fixed loopback origin, a 512 MiB memory tier plus filesystem disk, a 2 MiB
maximum object, and:

```toml
[vhosts.cache.range]
enabled = true
max_bytes = "128MiB"

[vhosts.cache.range.slice]
enabled = true
size_bytes = "1MiB"
max_slices = 128
fill_missing = true
```

`max_bytes` bounds requested range content and `max_slices` bounds the number
of slices needed to assemble it. Multipart framing adds overhead. Slice size
must be positive and no larger than `max_object_bytes`; max_bytes must fit
size_bytes times max_slices. The response is assembled in memory, not streamed
without buffering. Size these limits for concurrent clients, not only one file.

Run an origin on port 3000 that supports valid `206` responses with a known total
length in `Content-Range`, positive freshness and identity content encoding.
Python's simple file server is not a substitute for a range-capable origin.
For example, serve an immutable `demo.bin` through another Fluxheim static-file
listener, or use an existing tested HTTP range origin. Then run:

```sh
install -d -m 0700 state/slices
fluxheim --config examples/cache-slice-range.toml --validate-config
fluxheim --config examples/cache-slice-range.toml
curl -i -H 'Host: slice-cache.example.test' -H 'Range: bytes=0-1023' http://127.0.0.1:8080/demo.bin
curl -i -H 'Host: slice-cache.example.test' -H 'Range: bytes=0-1023' http://127.0.0.1:8080/demo.bin
```

For an eligible object, expect `206`, a correct `Content-Range`, and MISS then
HIT. The first fill may fetch more bytes than requested: Fluxheim first obtains
the slice beginning at zero to learn total length, then fetches required slices.
An origin that returns the entire body with `200`, changes validators, supplies
an unexpected range or ignores identity encoding cannot be assumed slice-safe.

## Supported Client Requests

With slice mode enabled, the parser supports bounded (`bytes=10-99`), open-ended
(`bytes=100-`), suffix (`bytes=-100`) and multipart (`bytes=0-9,20-29`) requests,
subject to limits. Missing or malformed policies/headers can bypass the slice
path; unsatisfiable or over-budget resolved ranges can produce `416`. Do not
design clients to interpret every fallback as a slice hit.

`If-Range` is compared against the slice identity. Every slice must contain
exactly one syntactically valid strong ETag (for example, `"revision-42"`).
Missing, weak (`W/"revision-42"`), duplicate or malformed ETags bypass slice
caching; Last-Modified alone is insufficient. Slices must agree on total length,
strong ETag and Last-Modified when present; mismatches are not composed into one
cached response. Recovered disk entries are checked by the same rule.

If `cache.hide_response_headers` contains `etag`, slice caching is bypassed,
including existing entries, and ordinary proxy handling applies. The current
cache format keeps the validator in its cached headers, so removing it would
lose the identity needed for safe composition. Serve immutable/versioned URLs
with stable strong validators; equal length alone never establishes identity.

After an origin returns a discovery/fill `206` without a valid strong ETag,
Fluxheim skips slice probes for that configured request variant for five seconds.
Requests still use ordinary proxy/cache handling; the first rejected probe can
therefore add one origin request before fallback. Reads and concurrent failures
do not extend this deadline. A cache policy retains at most 1,024 hashed variant
keys, including in disk-only mode; these short-lived hints are not persisted.
At capacity, new hints are not retained. This is not a global origin rate limit:
key churn and already-running fills can still cause additional probes.

Exact primary-key purge clears its hints. Other mutating purges reset all hints
in the matching virtual-host/route policy without changing object purge counts;
stale-purge dry runs do not reset them. A successfully admitted full-object `200`
with a strong ETag (including a revalidated response) clears that variant's hint,
and expiry allows discovery to try again automatically. Configured variants
remain independent, and unrelated full-object caching is not disabled.

Fluxheim requests `Accept-Encoding: identity` for origin slices. Do not combine
byte offsets for compressed and uncompressed representations. A range miss
must never be stored under an ordinary un-ranged full-object key.

## Variant And Fill Controls

If origin slices use `Vary`, every returned variant field must already be in
`cache.vary_request_headers`, because the lookup key is needed before fetching:

```toml
[vhosts.cache]
vary_request_headers = ["accept-language"]
```

Merge that field into the existing cache table. Sensitive identity headers are
not allowed as variance keys. Authorization and configured request bypass rules
remain in force. Do not use slicing as a way around private-response admission.

Same-slice concurrent fills use the normal bounded cache lock. Origin-fill
protection also applies. `fill_missing = false` allows use of existing slices
but prevents this path from obtaining missing ones; a cold cache therefore
cannot be populated by slice requests. It does not block ordinary origin proxying.

## Storage And Recovery

Slices use the same bounded storage backends, encryption and recovery rules as
complete proxy objects. To retain slices without a memory cache, change the
example's memory table to `enabled = false`; disk must remain enabled. Disk-only
means no retained memory entries, not zero working memory for responses.

For storage bins, replace the example's disk backend with `"storage-bin"` and
use a fresh directory with a compatible [storage-bin layout](cache-backends.md).
[Disk encryption](cache-encryption.md) protects persisted slices using the same
provider as other objects. The local-key provider is covered by slice-specific
native restart tests; OpenBao uses the shared encryption implementation and its
separate provider tests, not a slice-specific live OpenBao qualification.

Each range/variant has its own key and contributes to the disk capacity and purge
index. Exact-object and scoped path/tag purges include slices. Slices cannot be
returned as a complete object. Tiered fills write both eligible tiers; disk hits
are read through without retaining another memory copy. A slice too large for
the memory budget can still fit on disk. A full disk or rejected store can serve
the validated current origin response without retaining it for the next request.

Restart retains only successfully persisted, still-fresh slices. Filesystem
recovery discovers accepted object files; storage bins require the persisted
index and compatible layout. Abrupt shutdown can lose recent uncheckpointed bin
entries. Missing/corrupt entries are cache misses, not partial hits. A saturated
disk-worker admission limit returns `503` rather than starting unbounded work.
See [recovery](cache-recovery.md) for operational limits.

## Multiple Origins And Discovery

With the load-balancer feature, each missing slice uses the same pool selection,
health/drain state, backup policy, admission limits and bounded retry policy as
ordinary buffered requests. Failed selection does not fall through to static
members. Attempts update upstream status/latency and release admission on
completion, error or cancellation. Cached slices require no origin selection.

For two replicas, replace the example's proxy table with this configuration:

```toml
[vhosts.proxy]
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
upstream_max_in_flight = [16, 16]

[vhosts.proxy.load_balance]
selection = "least-time"
all_down_status = 503

[vhosts.proxy.load_balance.health_check]
enabled = true
protocol = "http"
path = "/healthz"
interval_secs = 5

[vhosts.proxy.load_balance.retry]
enabled = true
max_retries = 1
budget_per_window = 20
budget_window_secs = 1
```

Both replicas must serve the same representation with the same strong ETag,
length and Last-Modified value. Each slice may reach a different replica;
conflicting identities cause ordinary request fallback, never mixed cached
bytes. A strong ETag is the origin's promise of identical bytes, not a digest
verified by Fluxheim. Keep origins trusted and use authenticated TLS where needed.

File, HTTP and DNS discovery use the same selection path. For example, replace
the entire proxy table and its children with the following local HTTP-discovery
recipe; the service must return at least two valid members:

```toml
[vhosts.proxy]
upstreams_http_url = "http://127.0.0.1:9005/members"
upstreams_http_refresh_secs = 5
upstreams_http_allow_private_backends = true

[vhosts.proxy.load_balance]
selection = "round-robin"
```

Numeric-loopback HTTP is a local exception; use HTTPS for a remote discovery
service. See [load balancing](load-balancer.md) for file/DNS discovery configuration,
trust requirements and supported per-member settings. Membership changes govern
new fills, but do not purge fresh cached slices or cancel an already selected
attempt. Pool initialization loads membership before use; background refreshes
continue to apply the discovery policy. File and DNS initialization inherit
the platform's filesystem/resolver behavior.

Retries share the pool budget with normal requests and revalidation, rather than
receiving a fresh retry allowance for every slice. This budget counts **retries**,
not initial attempts: a cold range can require discovery plus several fills,
and a rejected slice may still be followed by ordinary proxy fallback. Keep
`max_slices`, fill locking, origin concurrency and route rate limits bounded.
Budgets remain per pool, not a process-wide or cluster-wide traffic ceiling.

## Verification And Diagnosis

`sh scripts/smoke_proxy_cache.sh` exercises a real range origin and native
Fluxheim, including range hits, slice composition and limits. Native server
range tests cover inconsistent identity, variance, collapsed fills and timeout
handling. The cross-platform persistence smoke starts a real counted range
origin, fills two language variants, restarts Fluxheim, and checks exact bodies
and unchanged origin counts on both disk backends with and without memory:

```sh
cargo build --locked --no-default-features --features profile-load-balancer,acme-client --bin fluxheim
python3 scripts/smoke_slice_storage.py target
python3 scripts/smoke_slice_upstreams.py target
```

The upstream smoke checks actual origin counts during drain, health failure and
recovery, HTTP/file discovery replacement, concurrent fills and conflicting
replica validators. Its `--container` mode uses the locally built non-root
slice smoke image and exercises HTTP discovery (file discovery runs natively).

When a slice misses repeatedly, inspect `x-cache-reason`, origin `Content-Range`,
body length, identity encoding, freshness, Vary coverage and tier capacity.
A 206 by itself proves only partial HTTP delivery, not cache admission.
