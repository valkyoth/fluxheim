# Compression

Status: future optional module.

Planned Cargo features:

- `compression`: shared config, negotiation, eligibility checks, and response
  body filter integration.
- `compression-zstd`: Zstandard response encoding.
- `compression-brotli`: Brotli response encoding.
- `compression-gzip`: gzip compatibility fallback.

Compression should be a CPU-efficiency feature, not just a smaller-response
feature. The default build should stay free of compression code until the body
filter, cache-variant, and resource-limit behavior is proven.

## Goals

- Prefer modern encodings first: Zstandard for dynamic or streaming responses
  and Brotli for static web assets where it wins.
- Keep gzip as a compatibility fallback for older clients.
- Avoid compressing already-compressed or low-value content.
- Keep request workers responsive by moving expensive compression work out of
  the main request path.
- Integrate with cache keys, `Vary: Accept-Encoding`, validators, and range
  behavior safely.
- Make all resource costs explicit: CPU budget, output size, input size,
  compression level, and concurrency.

## Negotiation

Fluxheim should negotiate response encoding from `Accept-Encoding` and route
policy:

1. choose `zstd` when the client supports it and the policy allows it;
2. choose `br` for eligible static assets when the client supports it;
3. choose `gzip` only as a fallback;
4. serve identity when content is already compressed, too small, too large,
   streaming in an unsupported way, or policy disables compression.

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

Compression can be CPU-heavy. Fluxheim should use a bounded worker pool or
blocking task pool for non-trivial compression so Pingora request workers do
not stall behind large JSON or static asset encoding jobs.

The module must enforce:

- global and per-vhost compression concurrency;
- maximum input bytes;
- maximum buffered bytes before switching to streaming or identity;
- per-encoding level bounds;
- timeout or cancellation behavior when clients disconnect.

## Cache Integration

Compression variants must be cache-isolated by:

- vhost;
- route;
- source cache key;
- normalized `Accept-Encoding` bucket;
- selected encoding;
- compression policy version.

`Vary: Accept-Encoding` must be present for all negotiated variants. Shared
cache admission must still reject unsafe personalized responses such as
responses with `Set-Cookie`.

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

## Configuration Sketch

```toml
[compression]
enabled = true
encodings = ["zstd", "br", "gzip"]
min_bytes = "1KiB"
max_input_bytes = "16MiB"
concurrency = 8

[compression.zstd]
level = 3

[compression.brotli]
level = 5
static_only = true

[compression.gzip]
level = 4

[[vhosts.routes]]
name = "assets"
match = { prefix = "/assets/" }
action = "web"
compression = { enabled = true, encodings = ["br", "gzip"] }
```

## Test Plan

- Negotiates `zstd`, `br`, `gzip`, and identity correctly.
- Adds `Vary: Accept-Encoding`.
- Does not compress excluded MIME types or `no-transform` responses.
- Keeps cache variants isolated by encoding.
- Rejects unsafe cache admission for personalized compressed responses.
- Enforces input size, output size, level, and concurrency limits.
- Cancels compression work when the downstream client disconnects.
- Proves compression code is absent from default and `privacy-mode` builds.
