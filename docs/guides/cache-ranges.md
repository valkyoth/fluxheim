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
| Fixed-slice cache | Fetches normalized ranges, validates them, then assembles the requested bytes | Slices are memory-only today, even when the general policy also enables disk |
| Local static files | Applies the file server's conditional/range behavior | Separate from proxy slices; see the local-static guide |

The normal proxy full-body path and fixed-slice path are not interchangeable.
For instance, warming a URL with an ordinary GET is not proof that its slice
entries are warm. Tests should issue the actual Range requests used by clients.

## Configure A Slice Route

The complete [slice example](../../examples/cache-slice-range.toml) uses one
fixed loopback origin, a 512 MiB memory tier, a 2 MiB maximum object, and:

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

`If-Range` is compared against the slice identity. Slices must agree on total
length, ETag and Last-Modified when present; mismatches are not composed into
one cached response. Serve immutable/versioned URLs with stable validators.
Matching length alone cannot establish that validator-less content is unchanged.

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

## Current Runtime Gaps

- **Current limitation:** slice lookup/store uses the in-memory object map,
  not either disk backend. Tiered slices go cold after restart; disk-only mode
  cannot retain them because its memory budget is zero. Enabling disk encryption
  does not make in-memory slices encrypted or persistent. The example therefore
  uses memory only until persistent slice storage is implemented and qualified.
- **Current limitation:** slice origin fetches use the static upstream-slot
  loop, not load-balancer selection/admission. Do not combine slice fills with
  health/drain/persistence/queue policies and assume those policies govern them.
  Discovery-only pools have no configured static origin and are not supported
  by this slice path. Use a single fixed origin until the integration is repaired.

These are pending runtime corrections, not promises fulfilled by parsing the
configuration. Neither issue is fixed by this documentation batch.

## Verification And Diagnosis

`sh scripts/smoke_proxy_cache.sh` exercises a real range origin and native
Fluxheim, including range hits, slice composition and limits. Native server
range tests cover inconsistent identity, variance, collapsed fills and timeout
handling. The documentation characterization test demonstrates the current
filesystem and storage-bin slice restart gap rather than claiming persistence.

When a slice misses repeatedly, inspect `x-cache-reason`, origin `Content-Range`,
body length, identity encoding, freshness, Vary coverage and available memory.
A 206 by itself proves only partial HTTP delivery, not cache admission.
