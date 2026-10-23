# Compression

Status: optional production response-compression module.

Cargo features:

- `compression`: shared config and response filter integration.
- `compression-brotli`: Brotli response encoding through `brotli`.
- `compression-gzip`: gzip response encoding through `flate2`.
- `compression-zstd`: Zstandard response encoding.

Compression remains opt-in. Default builds do not include compression code, and
`privacy-mode` builds reject compression at compile time because response-body
transforms can create side-channel and retention risks.

The `1.4.0` production profile aliases used by official full, cache-edge,
proxy-edge, load-balancer-edge, and PHP/web artifacts compile all three codecs
so operators can enable compression by vhost or route without rebuilding. A
compiled codec is inert until `compression.enabled = true` is set in config.

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
for each coding, and an explicit coding always takes precedence over `*`.
Malformed parameters, unknown parameters, duplicate quality parameters, and
empty list members fail closed to identity. When multiple accepted codings are
enabled, Fluxheim prefers `br`, then `zstd`, then `gzip` when their quality
values are equal.

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
- responses with `Cache-Control: no-transform`, `private`, or `no-store`,
  including qualified directives such as `private="Set-Cookie"`;
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
- encoded output must stay within `compression.max_output_bytes`;
- `compression.max_input_bytes` is capped at 64 MiB by config validation;
- `compression.max_output_bytes` is capped at 128 MiB by config validation;
- every codec writes through a bounded sink that rejects a write before the
  logical encoded length would cross `compression.max_output_bytes`;
- emitted chunks transfer their owned allocation into `Bytes` without copying,
  and a codec is discarded permanently after an output or allocation failure;
- gzip levels are restricted to `0..=9`;
- zstd levels are restricted to `1..=19`;
- Brotli quality is restricted to `0..=11`;
- Fluxheim removes `Content-Length` after enabling compression because the encoded
  length is streamed out through the body filter.

A later implementation may add bounded compression worker pools, per-vhost
concurrency, and precompressed static asset variants.

`max_output_bytes` is an encoded-byte limit, not an exact per-request RSS
ceiling. The Rust allocator may reserve more `Vec` capacity than the current
logical length, and each codec has internal CPU and working-memory costs that
are separate from its output sink. Use route/vhost concurrency controls to
bound aggregate request pressure until a dedicated compression worker pool is
available.

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
  unless explicitly enabled for a selected vhost;
- do not log compressed bytes or response bodies;
- reject the module with `privacy-mode` until a no-retention, no-side-channel
  design is written and tested.

## Configuration

```toml
[compression]
enabled = true
min_bytes = "1KiB"
max_input_bytes = "1MiB"
max_output_bytes = "2MiB"
gzip = true
gzip_level = 4
zstd = false
zstd_level = 3
brotli = false
brotli_quality = 4
```

The global block is the default for every vhost. A vhost can override it with
`[vhosts.compression]`, and a route can override the vhost with
`[vhosts.routes.compression]`. This lets one site enable compression while
another site keeps identity responses, or lets one path prefix opt in while the
rest of the vhost stays uncompressed.

```toml
[compression]
enabled = false

[[vhosts]]
name = "static-site"
hosts = ["static.example.com"]

[vhosts.compression]
enabled = true
gzip = true
zstd = true
brotli = true
min_bytes = "1KiB"
max_input_bytes = "2MiB"
max_output_bytes = "4MiB"
```

Path-scoped compression can be modeled as a route override:

```toml
[compression]
enabled = false

[[vhosts]]
name = "wordpress"
hosts = ["www.example.com"]

[vhosts.compression]
enabled = false

[[vhosts.routes]]
name = "uploads"
path_prefix = "/wp-content/uploads/"

[vhosts.routes.proxy]
upstream = "127.0.0.1:8080"

[vhosts.routes.compression]
enabled = true
gzip = true
zstd = true
min_bytes = "1KiB"
max_input_bytes = "2MiB"
max_output_bytes = "4MiB"
```

Eligibility checks still apply inside that path: already-compressed media types
such as JPEG, PNG, WebP, AVIF, and most archives are served as identity.

## Test Plan

- Negotiates `br`, `zstd`, `gzip`, and identity correctly for compiled codecs.
- Adds `Vary: Accept-Encoding`.
- Does not compress excluded MIME types or `no-transform`, `private`, and
  `no-store` responses, including qualified directives.
- Does not compress cookie, authorization, `Set-Cookie`, range, or already
  encoded responses.
- Enforces input, encoded-output, and level limits before excess output can be
  allocated.
- Fails closed for malformed `Accept-Encoding` parameters and proves explicit
  coding rejection takes precedence over wildcard acceptance.
- Proves compression code is absent from default and `privacy-mode` builds.
