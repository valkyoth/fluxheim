# Response Compression

Compression reduces response bytes at the cost of CPU and working memory.
Use it for public HTML, CSS, JavaScript, JSON and other text. It does not
decompress uploads, optimize images or turn a buffered response into a stream.

Fluxheim supports gzip, Brotli (`br`) and Zstandard (`zstd`). Compression is
disabled by default in configuration. The native runtime buffers the body,
encodes it synchronously and sends the completed result. The older design goal
of a separate compression worker pool is **not implemented**.

## Choose A Build

| Cargo feature | Provides |
| --- | --- |
| `compression` | Integration feature; select at least one actual codec below |
| `compression-gzip` | gzip encoder |
| `compression-brotli` | Brotli encoder |
| `compression-zstd` | Zstandard encoder |

The full, Wasm, cache, proxy, load-balancer and PHP release profiles include all
three codecs; consult [feature profiles](../reference/features.md) for the
selected artifact. Minimal developer builds do not. A compiled codec remains
inactive until configuration enables compression and selects that codec.
`privacy-mode` application builds forbid compression; do not combine it with
codec features. This is a compile-time boundary, not a runtime toggle.

For the complete local tests below:

```sh
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls,compression-gzip,compression-zstd,compression-brotli
```

Config validation alone does not prove a selected codec exists in the binary.
Do not configure a Brotli-only policy in a gzip-only build and expect Brotli.
Check actual Content-Encoding with an accepting client.

## Run The Example

The complete [local recipe](../../examples/compression/local.toml) provides a
static site, an inherited-compression proxy route, and an uncompressed route.
All listeners/origins in this example are loopback-only.

From the repository root, prepare a file large enough to pass the 1 KiB minimum:

```sh
mkdir -p examples/compression/site
python3 -c 'from pathlib import Path; Path("examples/compression/site/asset.txt").write_text("public text example\n" * 200)'
target/debug/fluxheim --config examples/compression/local.toml --validate-config
target/debug/fluxheim --config examples/compression/local.toml
```

In another terminal:

```sh
curl -sS -D - --compressed -H 'Host: compress.example.test' http://127.0.0.1:8080/asset.txt
curl -sS -D - -H 'Host: compress.example.test' -H 'Accept-Encoding: identity' http://127.0.0.1:8080/asset.txt
curl -sS -D - --compressed -H 'Host: compress.example.test' http://127.0.0.1:8080/plain/asset.txt
```

`--compressed` asks curl for supported encodings and decodes the response. Look
at Content-Encoding to see what the server chose; displayed plaintext alone is
not evidence that compression was skipped. HEAD is not compressed, so
`curl -I` is not a compression test.

The `/origin/` route requires an HTTP origin on `127.0.0.1:9001`. The repository
smoke starts its own bounded fixture and tests that route automatically:

```sh
python3 scripts/test_compression_examples.py
python3 scripts/smoke_compression_examples.py
```

For deployment, change listener/host/root settings deliberately, use [TLS](tls.md)
for HTTPS, and review [static serving](static-files.md) and [proxy](reverse-proxy.md)
limits. The example's default vhost is for local testing, not a strict host allowlist.

## Configure Every Option

```toml
[compression]
enabled = true
gzip = true
zstd = false
brotli = false
min_bytes = "1KiB"
max_input_bytes = "1MiB"
max_output_bytes = "2MiB"
gzip_level = 4
zstd_level = 3
brotli_quality = 4
```

| Field | Default | Meaning and accepted values |
| --- | --- | --- |
| `enabled` | `false` | Enable this policy; at least one codec boolean must be true |
| `gzip` | `true` | Consider gzip when compiled and accepted by the client |
| `zstd` | `false` | Consider Zstandard when compiled and accepted |
| `brotli` | `false` | Consider Brotli when compiled and accepted |
| `min_bytes` | `1KiB` | Inclusive minimum original size; positive, no larger than max_input_bytes |
| `max_input_bytes` | `1MiB` | Inclusive maximum original size; positive, at most 64 MiB |
| `max_output_bytes` | `2MiB` | Maximum logical encoded output; at least min_bytes, at most 128 MiB |
| `gzip_level` | `4` | Integer 0 through 9; 0 still emits gzip framing, it is not a disable switch |
| `zstd_level` | `3` | Integer 1 through 19 |
| `brotli_quality` | `4` | Integer 0 through 11 |

Sizes accept integer bytes or size strings: `min_bytes = 1024` and
`max_input_bytes = "1MiB"`. Higher levels trade CPU for potential savings,
not guaranteed smaller output. There is no custom MIME allowlist, minimum
saving ratio, compression deadline, worker-count or codec concurrency setting.

Bounds and levels are checked when the policy is enabled, including levels
for unselected codecs. A disabled policy's bounds are not validated until enabled.

## Global, Vhost And Route Policy

A vhost without a compression block uses `[compression]`. A route without one
uses its vhost's effective policy. **Declaring a child block replaces the whole
policy**, with omitted fields taking built-in defaults, not parent values.
For example, a route declaring only `enabled = true` resets a parent's gzip
level 8 to default 4 and its size limits to defaults.

Disable an entire existing site:

```toml
[vhosts.compression]
enabled = false
```

Or enable all codecs on one existing route with explicit bounds:

```toml
[vhosts.routes.compression]
enabled = true
gzip = true
zstd = true
brotli = true
min_bytes = "1KiB"
max_input_bytes = "1MiB"
max_output_bytes = "2MiB"
gzip_level = 4
zstd_level = 3
brotli_quality = 4
```

These are fragments, not standalone configurations. The full recipe demonstrates
inheritance and route opt-out. Include-fragment merging is separate from scope
selection; it does not make child policies inherit individual parent fields.

## Eligibility

All these conditions must hold:

- Request method is GET and response status is exactly 200.
- Policy is enabled and a compiled, selected codec is accepted by the client.
- No request Cookie or Authorization header, even with an empty value.
- No response Set-Cookie or Content-Range header.
- No active Content-Encoding. Explicit `identity` is not active; encoded origin
  responses are not decoded and recompressed.
- Response Cache-Control has no `private`, `no-store` or `no-transform`,
  including qualified forms such as `private="Set-Cookie"`.
- Content-Type is `text/*`, `application/javascript`, `application/json`,
  `application/xml` or `image/svg+xml`, ignoring case and parameters.
- Original length is within the configured inclusive bounds.

Other/missing media types are skipped, including ordinary image, video, font
and archive types. `application/problem+json` is not automatically included.
Eligibility uses Content-Type, not filename. No operator switch bypasses the
sensitive-header exclusions.

The native filter uses known response length or the already-buffered body size.
An origin response without Content-Length can therefore be compressed after
collection; unknown origin length does not imply streaming or exclusion.
A range response with status 206 is skipped; an origin ignoring Range and
returning a full eligible 200 can still be compressed.

Response `no-transform` is enforced. Request `no-transform` is not inspected
by this filter; do not use it as the application's only opt-out. Set the origin
response directive or disable the route. The advisory request directive is
described in [RFC 9111 section 5.2.1.6](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.6).

## Negotiation And Metadata

All Accept-Encoding field values are considered. Quality values range from 0
to 1 with up to three decimal places. Explicit coding entries override wildcards;
duplicate entries for a coding use the lowest quality. At equal quality the
preference is `br`, then `zstd`, then `gzip`.

```text
Accept-Encoding: br, zstd, gzip                 -> br when all are enabled
Accept-Encoding: br;q=0.1, gzip;q=1             -> gzip
Accept-Encoding: gzip;q=0, *;q=1                -> no gzip
```

No field, an empty field, malformed quality, unknown parameter, duplicate quality
parameter or empty list member currently leaves the response uncompressed.
Unknown valid coding names are not themselves malformed.

Successful compression removes original ETag, Content-Digest and Repr-Digest,
sets Content-Encoding and adds Accept-Encoding to Vary without removing other
Vary fields. The native HTTP/1 writer emits a fresh Content-Length for the
completed encoded body, not the original length. Configured digest generation
on the proxy finishing path can calculate fresh metadata after encoding.

Two open correctness gaps:

- **Current limitation:** Vary is added only after successful compression. Identity,
  HEAD and static 304 responses can lack Accept-Encoding variation even when
  another request to that URL receives gzip. A downstream cache can reuse an
  identity response without considering the next client's preferences.
- **Current limitation:** identity is not included in the acceptability decision.
  Even `identity;q=0` or `*;q=0` can receive identity 200 when no codec is
  chosen or encoding fails. This contradicts the identity-exclusion rule in
  [RFC 9110 section 12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3).

These are queued corrections, not accepted protocol guarantees. Falling back
to identity is not universally safe merely because the bytes remain intact.

## Caches And Validators

The native proxy stores origin responses before final downstream compression;
compression applies to returned responses, including cache hits. It is not a
persistent precompressed-variant store. Origin-supplied encodings, Vary admission,
personalized responses and keys still require the [cache policies](cache.md).

Until the documented limitation is corrected, operators can explicitly include Accept-Encoding
in response Vary policy for affected resources. Preserve all other variation
fields: replacing Vary: Origin with only Accept-Encoding creates another problem.
This workaround does not fix forbidden identity fallback, representation
validators or [static conditional gaps](static-files.md#validators-and-byte-ranges).

Files such as `app.js.br` or `app.js.gz` are not automatically selected.
There is no precompressed-sidecar mapping or hardware-accelerator selection.
Do not expose sidecars as ordinary JavaScript without correct negotiation,
Content-Encoding, MIME and caching.

## Resource And Security Boundaries

The input cap is 64 MiB and encoded-output cap is 128 MiB. The bounded sink
rejects writes before crossing its logical output limit. Encoding failure leaves
the original response intact, not partial encoded output. Encoded output can
be larger than input; no saving is required.

These are not RSS or CPU budgets. Original body, encoded output, allocator
capacity and codec state can coexist. **Current limitation:** tracks synchronous
full-body compression on request-executor threads, without dedicated worker
admission or an enforceable compression deadline. This is source-confirmed;
quantified concurrent latency/resource proof remains pending. Keep input caps
and levels conservative and use route/vhost concurrency controls, recognizing
they are not compression-worker isolation.

Size variation can leak information when secrets and attacker-controlled input
share a compressed response. Header/cache-policy exclusions cannot recognize
custom authentication or every personalized body. Disable compression for those
routes; do not remove protective headers to force compression. Admin/metrics
listeners are separate control surfaces, not public compression examples.

## Troubleshooting And Evidence

| Symptom | Check |
| --- | --- |
| No Content-Encoding | Actual GET, client encoding, effective scope, compiled codec, size, status, MIME and sensitive/cache headers |
| Route unexpectedly uses default levels | A child block replaces the policy; repeat intended fields |
| Curl prints readable text | It decodes with --compressed; inspect headers |
| Compression without origin Content-Length | Body was collected first; this is current native behavior |
| Identity after a codec attempt | Output cap or encoder failure; diagnose without logging bodies |
| CPU spikes / delayed unrelated requests | Synchronous encoding and concurrent pressure; the documented limitation |

The live smoke verifies gzip byte-for-byte decoding and encoded length,
static/proxy inheritance, route opt-out, exclusions, missing-origin-length
handling, three-codec wire selection and the two negotiation gaps. Existing
codec tests independently decode gzip, Brotli and Zstandard streams and exercise
output-limit failures. This is not fresh Windows/macOS, H2 or container
qualification. See [coverage](../reference/documentation-coverage.md) and the
[correction plan](../roadmap/observability-commit-plan.md) before release.
