# Programmable Media Edge

Status: far-future optional module family.

Planned Cargo features:

- `media-edge`
- `media-hls`
- `media-dash`
- `media-ssai`
- `media-watermark`
- `media-transmux`

This track is for media-aware video delivery. It is intentionally separate from
the image filter because video processing has a much larger blast radius:
manifests, segments, timed metadata, encryption, ad policy, privacy, DRM
boundaries, and bandwidth cost all interact.

## Design Goals

- Keep all video-aware code out of default builds.
- Start with HLS/DASH manifest parsing and rewriting, not bitstream
  manipulation.
- Preserve normal static/proxy behavior when no media policy is configured.
- Treat media requests as structured state, not plain text or arbitrary binary
  blobs.
- Bound manifest size, segment size, parser complexity, outbound subrequests,
  cache footprint, and per-vhost media concurrency.
- Integrate with `auth-request`, identity-aware routing, cache, metrics, and
  privacy profiles only through explicit policy.

## Stage 1: Manifest Engine

The first realistic milestone is a manifest-aware engine.

Planned behavior:

- parse HLS playlists (`.m3u8`);
- parse DASH manifests (`.mpd`) after XML parser review;
- normalize and validate segment URLs;
- reject traversal, absolute URL escapes, unexpected schemes, and manifest
  recursion loops;
- rewrite segment URLs for signed routes, cache routes, or media policy routes;
- inject or remove safe timed metadata only when explicitly configured;
- expose manifest metrics such as variant count, segment count, target
  duration, and parse errors.

This is the best first step because it avoids decoding video while still
unlocking media-specific routing and cache behavior.

## Stage 2: Segment-Aware Cache And Routing

Video segments should not be treated exactly like arbitrary files.

Planned behavior:

- identify HLS TS, fMP4, and DASH segment requests;
- isolate cache keys by vhost, route, asset ID, representation, byte range,
  media sequence, encryption key ID, and policy version;
- support bounded range requests for segments;
- respect `Cache-Control`, segment immutability policy, and live-window TTLs;
- support stale segment serving only when explicitly safe;
- expose per-vhost media cache metrics when `metrics` is enabled.

Security baseline:

- never cache personalized encrypted segments unless the policy explicitly
  marks the variant safe;
- never mix users, tenants, regions, or entitlement policies in one segment
  cache key;
- never cache media keys or authorization tokens.

## Stage 3: Dynamic Manifest Stitching

Dynamic stitching should operate at the manifest level before any bitstream
work is attempted.

Planned behavior:

- replace configured ad markers with media segment URLs selected by a trusted
  decision service;
- support per-vhost ad policy;
- integrate with `auth-request` or `identity-*` claims for audience segments;
- keep ad decision timeouts isolated from the primary request;
- fail closed or fall back according to explicit policy;
- log only decision IDs and policy IDs, not raw user profiles.

WASM policy plugins may be evaluated later, but only inside a strict sandbox
with CPU, memory, wall-time, outbound-network, and host-call limits.

## Stage 4: Forensic Watermarking

Forensic watermarking is high value but high risk. It should remain research
until the media parser, cache model, and privacy model are mature.

Safer first options:

- manifest-level forensic markers;
- personalized segment URL tokens;
- timed metadata markers where the player and workflow support them.

Harder future options:

- segment-level watermarking for TS or fMP4;
- bitstream-level watermarking;
- invisible per-user watermarks.

Requirements before any segment or bitstream watermarking:

- reviewed TS/fMP4 parser;
- strict segment size and structure limits;
- codec/container compatibility matrix;
- proof that watermarking cannot corrupt streams;
- legal/privacy review for user-identifying marks;
- ability to disable IP-based identifiers and use account/session identifiers
  only when a lawful policy permits it.

## Stage 5: Transmuxing And Packaging

Edge transmuxing is a research track, not an early production feature.

Potential scope:

- fMP4 to HLS packaging;
- HLS/DASH manifest generation from one normalized source;
- CMAF-aware segment handling;
- limited container remuxing without re-encoding.

Non-goals for the first implementation:

- full video transcoding;
- arbitrary codec conversion;
- GPU scheduling;
- frame-level processing.

Any native or FFI media library must be behind a separate feature flag with
license, advisory, sandbox, and fuzzing review.

## Security Requirements

- Disabled by default at compile time and runtime.
- Per-vhost/per-route media policy required.
- Reject oversized manifests and segments.
- Reject nested or recursive manifests beyond small limits.
- Reject unexpected protocols, absolute URL escapes, and host escapes unless
  allow-listed.
- Do not mirror or stitch admin, metrics, ACME, PHP, CGI, or legacy routes.
- Do not log raw manifests, tokens, cookies, media keys, entitlement claims, or
  full personalized URLs.
- Do not enable in `privacy-mode` by default.
- Treat DRM keys and license flows as out of scope unless a separate threat
  model is written.

## Configuration Sketch

```toml
[media_edge.profiles.live_hls]
formats = ["hls"]
max_manifest_bytes = "512KiB"
max_segment_bytes = "32MiB"
max_variants = 32
max_segments = 2048
rewrite_segments = true

[media_edge.profiles.live_hls.cache]
enabled = true
live_window_ttl = "30s"
vod_segment_ttl = "24h"

[media_edge.profiles.live_hls.stitching]
enabled = false
decision_service = "https://ads.internal.example/decision"
timeout = "150ms"
fail_mode = "fallback"

[[vhosts]]
name = "media"
hosts = ["media.example.com"]

[vhosts.media_edge]
enabled = true
profile = "live_hls"
paths = ["/live/*", "/vod/*"]
```

## Test Plan

- Parse valid HLS manifests.
- Reject malformed, oversized, recursive, and escaping manifests.
- Validate segment URL normalization.
- Validate cache-key isolation for live, VOD, range, tenant, and policy
  variants.
- Validate ad-stitch fallback behavior and timeouts.
- Validate redaction of tokens and personalized URLs.
- Validate metrics cardinality safety.
- Validate media features are absent from default and privacy builds.
- Fuzz manifest parsers before beta.
- Fuzz TS/fMP4 parsers before any segment-aware mutation.
