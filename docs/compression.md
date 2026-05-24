# Compression

Status: initial optional `1.4` module.

Cargo features:

- `compression`: shared config and response filter integration.
- `compression-brotli`: Brotli response encoding through `brotli`.
- `compression-gzip`: gzip response encoding through `flate2`.
- `compression-zstd`: Zstandard response encoding.

Compression remains opt-in. Default builds do not include compression code, and
`privacy-mode` builds reject compression at compile time because response-body
transforms can create side-channel and retention risks.

## Goals

- Keep gzip as a conservative compatibility baseline.
- Keep Zstandard and Brotli behind explicit Cargo features because they add
  extra codec dependencies and operational behavior.
- Avoid compressing already-compressed or low-value content.
- Keep request workers responsive by moving expensive compression work out of
  the main request path.
- Integrate with cache keys, `Vary: Accept-Encoding`, validators, and range
  behavior safely.
- Make all resource costs explicit: CPU budget, output size, input size,
  compression level, and concurrency.

## Negotiation

Fluxheim negotiates response compression from `Accept-Encoding` when
`compression.enabled = true` and the binary is built with at least one codec
feature. Gzip is available through `compression-gzip`, Zstandard through
`compression-zstd`, and Brotli through `compression-brotli`. `q=0` is respected
for each coding. When multiple accepted codings are enabled, Fluxheim prefers
`br`, then `zstd`, then `gzip`.

Identity is served when no enabled coding is accepted by the client, the
response is already encoded, the response is too small or too large, the
content length is unknown, or policy disables compression.

Every compressed response must set or update:

- `Content-Encoding`;
- `Vary: Accept-Encoding`;
- `ETag` or validator behavior according to the selected variant;
- `Content-Length` only when the encoded length is known.

## Eligibility

Do not compress by default:

- JPEG, PNG, GIF, WebP, AVIF, MP4, WebM, MP3, OGG, WOFF2, ZIP, gzip, Brotli,
  Zstandard, or other already-compressed formats;
- responses with `Cache-Control: no-transform`;
- responses carrying sensitive per-user content unless the operator explicitly
  allows it and cache admission remains disabled;
- partial/range responses unless a future range-aware design exists;
- responses above configured input/output limits.

Initial positive MIME types should be conservative:

- `text/html`;
- `text/css`;
- `text/plain`;
- `text/javascript`;
- `application/javascript`;
- `application/json`;
- `application/xml`;
- `image/svg+xml`.

## Execution Model

The first codec implementation is intentionally bounded:

- only responses with a known `Content-Length` are compressed;
- input must fit between `compression.min_bytes` and
  `compression.max_input_bytes`;
- `compression.max_input_bytes` is capped at 64 MiB by config validation;
- gzip levels are restricted to `0..=9`;
- zstd levels are restricted to `1..=19`;
- Brotli quality is restricted to `0..=11`;
- Fluxheim removes `Content-Length` after enabling compression because the encoded
  length is streamed out through the body filter.

A later implementation may add bounded compression worker pools, per-vhost
concurrency, and precompressed static asset variants.

## Cache Integration

Future shared-cache compression variants must be cache-isolated by:

- vhost;
- route;
- source cache key;
- normalized `Accept-Encoding` bucket;
- selected encoding;
- compression policy version.

`Vary: Accept-Encoding` is added to every compressed response. Shared cache
admission must still reject unsafe personalized responses such as responses
with `Set-Cookie`.

Precompressed static assets may be supported later through files such as
`index.html.br`, `app.js.zst`, or `style.css.gz`, but config validation and
cache lookup must prevent serving a variant to a client that did not advertise
support.

## Hardware And Native Acceleration

Hardware acceleration and CPU-specific codecs are future beta work. Any QAT,
SIMD, or platform-specific backend must be selected through explicit feature
flags or runtime capability detection with a safe fallback. Release artifacts
must document whether they are generic or CPU-specific.

## Privacy And Security

Compression can create side-channel risk when secrets and attacker-controlled
input share the same compressed response. Safe defaults:

- do not compress admin, metrics, auth, or internal control responses;
- do not compress responses with cookies or authorization-dependent content
  unless explicitly enabled per route;
- do not log compressed bytes or response bodies;
- reject the module with `privacy-mode` until a no-retention, no-side-channel
  design is written and tested.

## Configuration

```toml
[compression]
enabled = true
min_bytes = "1KiB"
max_input_bytes = "1MiB"
gzip = true
gzip_level = 4
zstd = false
zstd_level = 3
brotli = false
brotli_quality = 4
```

Compression is currently global. Per-vhost and per-route compression policy is
tracked for later `1.4.x` work.

## Test Plan

- Negotiates `br`, `zstd`, `gzip`, and identity correctly for compiled codecs.
- Adds `Vary: Accept-Encoding`.
- Does not compress excluded MIME types or `no-transform` responses.
- Does not compress cookie, authorization, `Set-Cookie`, range, or already
  encoded responses.
- Enforces input size and level limits.
- Proves compression code is absent from default and `privacy-mode` builds.
