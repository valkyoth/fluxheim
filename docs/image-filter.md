# Image Filter

Status: future optional module.

Planned Cargo feature: `image-filter`.

This module adds safe, bounded image validation and transformation at the edge.
It is intended for small static sites, media-heavy origins, and cache-backed
deployments that want predictable image variants without adding a separate
image service.

## Design Goals

- Keep image transformation code out of the default binary.
- Enable per-vhost and per-route policies.
- Support static files and proxied origin responses.
- Transform only explicitly allowed image content types.
- Bound input bytes, decoded pixels, output bytes, CPU time, and concurrency.
- Integrate with cache keys so transformed variants are isolated and purgeable.
- Prefer memory-safe Rust codecs where practical.

## Planned Transformations

Initial stable candidates:

- validate image type;
- report image metadata as JSON: width, height, format, animation flag;
- resize while preserving aspect ratio;
- crop to a target box;
- rotate by `90`, `180`, or `270` degrees;
- strip metadata by default;
- set JPEG/WebP/AVIF quality;
- choose output format based on explicit config and `Accept` negotiation.

Future candidates:

- sharpen;
- blur;
- grayscale;
- background fill for transparent input;
- animated image policy: reject, preserve first frame, or preserve animation
  only when a reviewed codec supports it safely.

## Format Policy

Input formats should be explicit:

- JPEG;
- PNG;
- GIF, with animation policy disabled by default;
- WebP;
- AVIF after codec review.

Output formats should be explicit:

- JPEG;
- PNG;
- WebP;
- AVIF after codec review.

Default modern behavior should prefer WebP when the client advertises support
and the vhost policy allows it. AVIF should remain beta until encoding speed,
resource use, and codec maintenance are proven acceptable.

## Resource Limits

Image processing is dangerous without hard limits because small compressed
files can decode into very large pixel buffers.

Required limits:

- `max_input_bytes`;
- `max_decoded_pixels`;
- `max_output_bytes`;
- `max_width`;
- `max_height`;
- `max_operations_per_request`;
- per-vhost concurrent transform limit;
- global concurrent transform limit;
- transform timeout.

All limits must be enforced before decoding where possible and immediately
after header parsing when dimensions are known. If dimensions are not known
without a full decode, the request should use the stricter input-byte and
timeout limits.

## Cache Interaction

Transformed images must use separate cache keys from original images.

Variant key inputs:

- vhost;
- source cache key or source path;
- source ETag/Last-Modified when available;
- transform policy name and version;
- requested dimensions;
- crop mode;
- rotation;
- output format;
- quality;
- normalized `Accept` bucket.

The module should support:

- cache transformed variants when `cache` is enabled;
- purge original and variants together when an index exists;
- refuse disk cache in `privacy-mode`;
- never cache transformed output when request or response policy says
  `Cache-Control: no-store`.

## Security Requirements

- The module is disabled by default at compile time and runtime.
- Transform policy must be explicit per vhost or route.
- Only configured content types and extensions are eligible.
- Do not transform untrusted arbitrary binary responses.
- Do not process images from admin, metrics, ACME, CGI, PHP, or legacy
  listeners.
- Reject oversized metadata, malformed files, decoder errors, and unsupported
  formats with `415 Unsupported Media Type` or a configured safe error.
- Strip EXIF/GPS/comment metadata by default.
- Do not log raw image bytes or full source URLs with sensitive queries.
- Codec dependencies require license and advisory review before enabling the
  module in release builds.
- FFI-backed codecs must be behind separate feature flags and never included
  in default builds.

## Configuration Sketch

```toml
[image_filter.profiles.thumbnail]
input_formats = ["jpeg", "png", "webp"]
output_formats = ["webp", "jpeg"]
prefer_webp = true
strip_metadata = true
max_input_bytes = "8MiB"
max_decoded_pixels = 12000000
max_output_bytes = "4MiB"
timeout = "500ms"
quality_jpeg = 82
quality_webp = 78

[[image_filter.profiles.thumbnail.transforms]]
kind = "resize"
width = 480
height = 480
mode = "fit"

[[vhosts]]
name = "example"
hosts = ["example.com"]

[vhosts.image_filter]
enabled = true
profile = "thumbnail"
paths = ["/images/*"]
```

## Test Plan

- Reject unsupported formats.
- Reject oversized input before decode.
- Reject decode bombs through pixel limits.
- Validate resize, crop, and rotate output dimensions.
- Validate WebP negotiation and fallback behavior.
- Ensure transformed variants use distinct cache keys.
- Ensure metadata stripping removes EXIF/GPS data.
- Ensure malformed images return safe errors.
- Ensure transform timeouts and concurrency limits work.
- Ensure default builds do not include image-filter code.
- Ensure `privacy-mode` rejects incompatible transform/cache combinations.
