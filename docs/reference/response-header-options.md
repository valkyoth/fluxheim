# Response Header Options

See the [operator guide](../guides/response-headers.md) and
[complete recipe](../../examples/headers/response.toml). These settings live at
`headers.response`, `vhosts.headers.response`, or `vhosts.routes.headers.response`.
Unknown fields fail parsing. Child scalars inherit when omitted; TOML has no
null value to clear an inherited optional string. Use targeted removal and
review the current generic-mutation inheritance limitations.

## Main Table

| Field | Default | Accepted form / behavior |
| --- | --- | --- |
| `enabled` | `true` | Skip the complete response-policy stage when false; CORS remains separate. |
| `hardening` | profile off | Table with `profile`: `off`, `baseline`, `cross-origin-isolated`. A supplied child object replaces the parent object. |
| `strict_transport_security` | absent | Raw HSTS string, for example `max-age=0`; cannot coexist with `hsts` in the merged policy. |
| `hsts` | absent | Typed table below. |
| `content_security_policy` | absent | Header-safe string; replaces origin CSP. No semantic CSP validation or automatic nonce generation. |
| `content_security_policy_report_only` | absent | Independent report-only CSP string. |
| `permissions_policy` | absent | Typed table below; explicit disabled table removes the header. |
| `cross_origin_opener_policy` | absent | `unsafe-none`, `same-origin-allow-popups`, `same-origin`. |
| `cross_origin_resource_policy` | absent | `same-site`, `same-origin`, `cross-origin`. |
| `cross_origin_embedder_policy` | absent | `unsafe-none`, `require-corp`, `credentialless`. |
| `x_permitted_cross_domain_policies` | absent | `none`, `master-only`, `by-content-type`, `all`; legacy policy header, not CORS. |
| `reporting_endpoints` | empty map | Named HTTPS URLs, serialized into Reporting-Endpoints; no collector is created. Child map replaces the entire parent map. An empty map stops generation but does not remove an origin value. |
| `x_content_type_options` | `nosniff` | Nonempty header-safe string. |
| `x_frame_options` | `DENY` | Nonempty header-safe string; for example `SAMEORIGIN`. |
| `referrer_policy` | `no-referrer` | Nonempty header-safe string; for example `same-origin` or `strict-origin-when-cross-origin`. |
| `unset` | `["x-powered-by"]` globally | Legacy removal list. Setting this global list replaces the default; child lists append. |
| `remove` | empty | Removal list combined with unset and operations.remove. |
| `set` | empty map | Legacy replacement map. |
| `add` | empty map | Replacement map, not append. Conflicting aliases rejected; child override caveat below. |
| `append` | empty map | Map of strings or arrays of strings; append individual field lines after replacements. Child values extend inherited values. |
| `operations` | empty | Table containing `remove` list and `add` map, aliases for generic mutations. No nested append field. |
| `rewrite` | empty | Four rule arrays described below. Child arrays append after inherited rules. |
| `metadata` | all switches false | Table described below, field-by-field inheritance. |

Default profile off does not disable the three default headers. Absent optional
typed fields generally leave an origin field untouched unless a profile or
explicit mutation owns it. Typed settings override profile values; generic
mutations run later. This is not a guarantee that every early error passes through
the policy; the documented limitation records the coverage gap.

Static values must be nonempty after trimming and contain no ASCII controls,
including tabs, CR, LF or DEL. Names must be HTTP tokens without surrounding
whitespace. Generic values currently also pass request-template syntax validation
but are not interpolated in the response path. Do not use braces
as a request-variable feature.

Mutation limits are 128 names per effective removal, replacement and append
collection; at most 32 values per appended name. These are count limits, not a
universal response-header byte budget. Keep values small. Same-name entries
across add/set/operations.add can fail validation. Case-sensitive map merging
does not provide reliable case-insensitive child overrides.

## HSTS and Permissions Tables

`[headers.response.hsts]` (or a child equivalent):

| Field | Default when table exists | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Generate typed HSTS. False preserves an origin HSTS value in the config-driven runtime. |
| `max_age_secs` | `63072000` | Unsigned seconds; must be nonzero when enabled. |
| `include_subdomains` | `false` | Append includeSubDomains. |
| `preload` | `false` | Append preload; no automatic registration or eligibility check. |

A child HSTS object replaces the parent object: unspecified fields use the table
defaults, not parent subfields. Review a child's duration explicitly.

`[headers.response.permissions_policy]` has `enabled = true` and
`profile = "deny-sensitive"` defaults. `profile = "deny-all"` is also supported.
A child object replaces the parent object. `deny-sensitive` emits empty allowlists
for camera, geolocation, microphone, payment and usb. `deny-all` emits empty
allowlists for this fixed set:

```text
accelerometer, autoplay, camera, display-capture, encrypted-media, fullscreen,
gamepad, geolocation, gyroscope, hid, identity-credentials-get, idle-detection,
local-fonts, magnetometer, microphone, midi, otp-credentials, payment,
picture-in-picture, publickey-credentials-create, publickey-credentials-get,
screen-wake-lock, serial, storage-access, usb, web-share, window-management,
xr-spatial-tracking
```

This is a bundled list, not a browser-feature wildcard. Use a generic literal
Permissions-Policy replacement for a different policy, after application review.

## Reporting Endpoints

At most 16 entries, names up to 64 ASCII bytes. The first character is a lowercase
letter or `*`; subsequent characters can also be digits, `_`, `-`, `.` or `*`.
URLs must be valid HTTPS endpoints suitable for structured-field strings.
The complete serialized header is limited to 16384 bytes. Fluxheim quotes and
escapes values. Use a matching CSP `report-to` name; a map alone does not enable
CSP reporting. An empty child map drops inherited generation, not an origin's
Reporting-Endpoints header; remove that header explicitly when needed.

## Rewrite Rules

Each array contains `from` and `to` string fields. No regex or request templates
are expanded. The first matching rule wins, with parent rules before child rules.

| Array under `rewrite` | Limits / matching |
| --- | --- |
| `location` | Up to 32 rules. Each endpoint at most 2048 bytes, beginning `http://`, `https://` or `/`, but not `//`; no control bytes. Literal prefix match, case-sensitive. Authority-only prefixes check an authority boundary. |
| `refresh` | Same bounds as Location, but only the URL part is replaced. Quotes and surrounding text remain. |
| `cookie_domain` | Up to 32 rules. At most 255 ASCII bytes per endpoint; letters, digits, dots and hyphens with validation restrictions. Matching is case-insensitive and ignores a leading dot. No subdomain wildcard. |
| `cookie_path` | Up to 32 rules. At most 2048 bytes per endpoint; absolute `/` path, not `//`, no ASCII whitespace/control bytes or semicolons. Literal case-sensitive prefix matching, not route-segment matching. |

Duplicate `from` values are rejected, case-insensitively for cookie domains.
Use trailing slashes where prefix continuation would be surprising. Validation
of Location/Refresh prefixes is not a full URL parser or redirect-destination
allowlist. Inputs come from trusted configuration, not an arbitrary public API.

## Metadata

| Field | Default | Behavior |
| --- | --- | --- |
| `identifier` | absent | Required if either status switch is true; Structured Fields token, at most 64 bytes, beginning with a letter or `*`. Public deployment label, not a secret/backend address. |
| `cache_status` | `false` | Append Cache-Status when an internal cache outcome exists. Current mappings: HIT to hit; MISS to fwd=uri-miss; stored; REVALIDATED to fwd=stale; fwd-status=304; stored; EXPIRED to fwd=stale; BYPASS to fwd=bypass. STALE maps to hit except upstream-error/status reasons map to fwd=stale. This is the current formatter, not independent proof of disk persistence. |
| `proxy_status` | `false` | Append Proxy-Status for an internal proxy error: connection_refused, connection_terminated, connection_timeout, destination_unavailable or http_protocol_error. No raw error text. |
| `content_digest` | `false` | Replace Content-Digest with SHA-256 of the final buffered message content where the digest stage runs. |
| `repr_digest` | `false` | Replace Repr-Digest only for complete GET/200 with no Content-Range and compatible content length; otherwise remove it where the digest stage runs. |

Status fields preserve origin members and avoid duplicate emission of Fluxheim's
own member. Digest metadata is unsigned. Compression can invalidate/remove
origin digests; do not claim that merely disabling these switches preserves every
origin header through other response filters. No unbuffered digest trailers are
provided by this implementation.

## Implementation and Qualification

Sources: [response configuration](../../crates/fluxheim-config/src/config_header_response.rs),
[validation/merge](../../crates/fluxheim-config/src/config_header_validation.rs),
[hardening](../../crates/fluxheim-config/src/config_header_hardening.rs),
[native policy](../../crates/fluxheim-server/src/native_http1_route_response_headers.rs),
[rewrite helpers](../../crates/fluxheim-headers/src/lib.rs),
[metadata](../../crates/fluxheim-server/src/native_http1_response_metadata.rs).

[Evidence and pending platform coverage](documentation-coverage.md) distinguish
tested wire behavior from remaining qualifications. the documented limitation are
planned corrections, not fixed by this reference.
