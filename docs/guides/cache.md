# Caching

Caching lets Fluxheim reuse a public response instead of asking the origin server
for it on every request. It is most useful for static assets such as images,
stylesheets, fonts and JavaScript. It is not an automatic full-page cache for
WordPress, an application session store, or a replacement for the origin.

This guide covers the native proxy cache and the smaller local-file memory cache.
Use the [option reference](../reference/cache-options.md) for settings/defaults,
[cache operations](cache-operations.md) for warming/purge/inspection commands,
[cache recovery](cache-recovery.md) for restart, reload and layout changes,
and [encryption](cache-encryption.md) for local-key and OpenBao configuration.
The [backend reference](cache-backends.md) compares resource costs and storage
layouts. The [coverage ledger](../reference/documentation-coverage.md) separates
reviewed behavior from remaining recipe/platform qualification and runtime fixes.

## Choose A Cache

| Need | Configuration | Important boundary |
| --- | --- | --- |
| Fast proxy hits without persistent state | Memory enabled, disk disabled | Cold after restart; budget is per runtime policy, not total process RAM |
| Persistent proxy objects | Disk enabled, memory disabled | Disk I/O on hits; still requires RAM for requests/responses |
| Hot objects in memory, persistent objects on disk | Both tiers enabled | Each tier has its own byte budget |
| Many disk objects in larger container files | Disk `backend = "storage-bin"` | Bin sizing, index recovery and eviction still matter; not a distributed cache |
| Local files served by `[web]` | `local_static = true`, memory enabled, disk disabled | Native local-static caching does not support disk or tiered storage |

Use a binary with the `cache` feature and the required proxy/web capabilities.
The full and cache profiles include caching; enabling it in a binary without
that feature is an error, not a fallback. See [build profiles](../reference/features.md).
Validate with the same binary and service account that will run the server.

## Try A Public Asset

The complete [local example](../../examples/cache/local.toml) listens only on
`127.0.0.1:8088` and forwards to `127.0.0.1:9001`. It caches CSS responses for
120 seconds, with an 8 MiB memory budget and a 256 KiB maximum object body.
It deliberately bypasses requests containing cookies or a `preview` query.
TLS is disabled only for this loopback demonstration.

From the repository root, start the fixture origin in one terminal:

```sh
python3 -m http.server 9001 --bind 127.0.0.1 --directory examples/cache/site
```

Start Fluxheim in another terminal (substitute your installed binary path):

```sh
fluxheim --config examples/cache/local.toml --validate-config
fluxheim --config examples/cache/local.toml
```

Then request the same file twice:

```sh
curl -i http://127.0.0.1:8088/asset.css
curl -i http://127.0.0.1:8088/asset.css
```

Expect `x-cache-status: MISS`, then `HIT`, with the same CSS body. A hit also
includes `Age`. Do not use `curl -I` to test proxy hits: `HEAD` currently bypasses
proxy caching even though it appears in the default method list.

The fixture's Python server does not emit a freshness policy, so the example
explicitly sets `status_ttls = { "200" = 120 }`. For a production origin that
already emits `Cache-Control: public, max-age=...`, remove that override to let
the origin choose its lifetime. The override is appropriate only for content
you have established is public; normal refusal of private/no-store responses
and `Set-Cookie` remains active.

## Decide What Is Public

An eligible URL alone does not guarantee storage. Fluxheim checks request
method and extension, bypass rules, response status and content type,
freshness, size and safe variance. By default the allowed types/extensions
cover common static assets, not HTML or arbitrary JSON API responses.

Keep these boundaries in place:

- Requests with `Authorization` or `Proxy-Authorization` always bypass shared
  cache lookup and storage. An empty configurable bypass list cannot disable it.
- Responses carrying `Set-Cookie`, private/no-store/no-cache or zero freshness
  are not ordinarily admitted. Keep `ignore_origin_cache_headers = false`.
- Cookies are not all bypassed automatically by the base defaults. If a route
  can personalize its response, use `bypass_request_headers = ["cookie"]`, as
  the example does, or define narrowly reviewed cookie bypass rules.
- Do not strip `Set-Cookie` to make a personalized response cacheable. Header
  removal happens before admission and removes that safety signal.
- Keep the host and query in the key unless you can prove they never change
  content. Omitting them can make different requests share the same object.
- Do not add credentials to `vary_request_headers`; sensitive headers are
  rejected. Bypass personalized traffic rather than sharing it by credential.

For example, these must bypass the example cache, including when the normal
asset is already warm:

```sh
curl -i -H 'Cookie: session=example' http://127.0.0.1:8088/asset.css
curl -i -H 'Authorization: Bearer example' http://127.0.0.1:8088/asset.css
curl -i 'http://127.0.0.1:8088/asset.css?preview=1'
```

`asset.css?v=one` and `asset.css?v=two` use different keys with `include_query =
true`. This is important for asset versioning. Ignoring queries is not the same
as bypassing requests with queries.

## Add Persistent Storage

Append the tables from [filesystem.toml](../../examples/cache/filesystem.toml)
to the local example. They add a 32 MiB disk tier alongside memory:

```toml
[cache.disk]
enabled = true
backend = "filesystem"
path = "state/cache"
max_size_bytes = "32MiB"
```

The path is relative to the configuration file. Create an owner-controlled
directory writable by the Fluxheim service, not a world-writable shared
temporary directory. On Unix a private `0700` directory is a suitable starting
point; on Windows grant access only to the service identity and trusted
administrators. Keep every parent trustworthy and avoid symlinks/reparse points.
For a container, persist the directory in a correctly owned, labeled volume.

To use disk only, change the existing `[cache.memory]` table to `enabled =
false`. Do not append another `[cache.memory]` table: duplicate TOML tables
are invalid. Every enabled tier's budget must be at least `max_object_bytes`.

Alternatively use [storage-bin.toml](../../examples/cache/storage-bin.toml)
instead of the filesystem fragment. It groups objects into 1 MiB bins, with
four open bins allowed. The bin must fit a maximum object and must not exceed
the disk budget. Start with `preallocate = false` unless you intentionally
want the backend to reserve bin space.

With either disk backend, the same fresh asset should remain a hit after a
normal server restart with the same configuration and disk directory. A memory
cache starts cold. Cache contents are disposable acceleration data, not the
only copy of application content. Do not rename/delete live index or bin files
to perform an operational purge; use the protected cache operations.

Neither a disk-only cache nor its byte budget means zero response buffering.
The native ordinary proxy admission path receives a materialized response body.
Plan RAM for in-flight requests, response limits, metadata and concurrency in
addition to memory-tier budgets. Budget limits are not a process RSS ceiling.

## Local Static Files

Use [static.toml](../../examples/cache/static.toml) instead of the proxy example:

```sh
fluxheim --config examples/cache/static.toml --validate-config
fluxheim --config examples/cache/static.toml
curl -i http://127.0.0.1:8088/asset.css
curl -i http://127.0.0.1:8088/asset.css
```

Stop the proxy example first because both use port 8088. This serves the checked-in
CSS file directly, without the Python origin. The policy requires all of
`enabled = true`, `local_static = true`, memory enabled and disk disabled.
Do not enable a disk tier and expect a local-static memory fallback.

The native local cache stores eligible `200` file responses in memory and keys
them using request identity plus canonical file identity metadata. Normal
conditional and range handling still applies. It is not the proxy's stale
origin-recovery system: the local cache uses a fresh lifetime, not the proxy's
stale-while-revalidate/stale-if-error windows. Do not assume every proxy-specific
setting changes local-file behavior merely because both share a config type.

## Scope And Variants

Cache policy can be selected at global, vhost or route scope using `[cache]`,
`[vhosts.cache]` and `[vhosts.routes.cache]`. Keep a policy close to the routes
whose public-content contract you have reviewed. The route policy and action
must agree: local-file recipes are not interchangeable with proxy recipes.
See [vhost configuration](vhost-config.md) for inheritance and fragment loading.

A named vhost does not automatically inherit the root `[cache]` policy: enable
and configure `[vhosts.cache]` explicitly. Do not mistake a valid TOML file for
proof that the chosen host has caching enabled. The
[operations example](../../examples/cache/operations.toml) shows a complete
vhost-owned policy and its own tiers.

`key_namespace = "public-css-v2"` separates new objects from the old namespace
without changing public URLs. It is not a purge: old disk objects can still
occupy space until expiry/eviction/purge. Use different namespaces when changing
what a route serves or how it varies.

Origin `Vary` is handled with bounded, hashed variant keys. If an origin varies
on a safe header but forgets to emit `Vary`, configure it explicitly, for example
`vary_request_headers = ["accept-language"]`. All requests for a stored variant
must use the matching header value. Never use this to share authenticated data.

## Freshness And Origin Failures

Fresh objects can be served without an origin request. An expired retained
object with validators can be revalidated using ETag/Last-Modified; a valid
`304` refreshes metadata rather than replacing the body with an empty response.
The following are opt-in, per-policy behaviors:

- `stale_while_revalidate_secs`: permit a bounded stale response while a
  background refresh runs. Choose a window consistent with the content's risk.
- `stale_if_error_secs`: permit a retained stale response after selected upstream
  errors, within a bounded window. Choose error categories and HTTP statuses.
- `allow_client_cache_refresh`: let client no-cache/max-age=0/Pragma requests
  trigger revalidation. Off by default to limit public origin amplification.
- `status_ttls`: explicitly cache selected statuses, such as a short-lived 404
  for an immutable asset URL. Negative caching can delay visibility of a new file.

The [policy fragment](../../examples/cache/policy.toml) demonstrates these
controls and four concurrent origin fills. **Merge its fields into the existing
cache table**; do not concatenate duplicate tables. Its 404 TTL does not retain
the example's 200 override if you replace the entire `status_ttls` map. Configure
both entries explicitly if that is your intention. Origin cache restrictions
such as mandatory revalidation can still forbid stale reuse.

Current limitation, tracked as `the documented limitation` / the local follow-up: `read`, `write` and
`tls` are accepted `stale_if_error_on` values, but the native error classifier
does not produce them. It maps I/O error kinds to `connect`, `timeout`,
`connection-closed`, `protocol` or `other`; HTTP-status handling is separate.
A policy containing only `tls` therefore does not mean TLS failures are handled
as requested. Do not broaden the allowlist to `other`/`protocol` as a workaround
for a strict security policy. Leave stale-on-error off where precise phase
classification is required until the correction is implemented and tested.

## Protect The Origin

Cache locks collapse matching concurrent misses into a single fill. They are
enabled by default. A waiter that exceeds its bounded wait receives `503` with
`Retry-After: 1`; it should not turn into another simultaneous origin fetch.
Choose lock timeouts above normal origin latency but below the user-facing
deadline. Writer age can shorten the effective reader wait.

Origin protection caps fills across different keys in one runtime cache scope.
It is not a cross-cluster limit. `min_uses` delays storing one-off objects;
`pass_uncacheable_after` can temporarily bypass repeated uncacheable keys.
The opt-in predictor uses bounded, expiring counters, not a promised LRU policy.
Inspect rejection reasons before enabling it so temporary pass decisions do not
hide an origin header/configuration mistake.

## WordPress And Advanced Cases

`preset = "wordpress"` adds bypasses for administration/login/feed endpoints,
WordPress cookie families and query-bearing requests. It is an additional guard,
not a plugin, a FastCGI page cache, or proof that every plugin's private URL is
covered. Review your application's own session cookies and preview parameters.
For PHP itself see [PHP recipes](php-fpm-app-recipes.md).

Use separate reviewed recipes for [range/slice caching](cache-ranges.md),
[peer-assisted fill](cache-peer-fill.md), and
[encrypted storage](cache-encryption.md). Do not copy an advanced fragment into
an unrelated route and assume it supplies all the required origin, trust and
storage settings. Their full option-by-option recipe audit remains tracked in
the coverage ledger.

## Diagnose And Operate

| Symptom | Check first |
| --- | --- |
| No cache header | Selected route, feature/profile, enabled policy and whether this response enters caching |
| `BYPASS` | Method (`HEAD`), credentials/cookies, query/path rules and diagnostic reason |
| Repeated `MISS` | Response content type, extension, positive TTL, size, Set-Cookie/private headers, min-use threshold |
| `STALE` | Retained object window, refresh result and configured error policy |
| 503 during a miss burst | Fill-lock timeout and origin protection, then upstream health/latency |
| Disk does not survive restart | Same resolved path/namespace/policy, ownership, actual disk writes and expiry |
| RAM exceeds the tier budget | In-flight bodies, concurrency, metadata and additional policies, not just stored body bytes |

Cache-status/reason headers are optional diagnostics. Review their exposure
before enabling them on public endpoints. Use `cache-key` to inspect eligibility
and identity, `cache-lookup` to inspect persisted objects, and `cache-warm` to
make real requests through the selected policy. These tools are not a way to
inspect another process's private memory directly. The protected admin API
provides live status and purge operations; keep its control token private.
See [cache operations](cache-operations.md) for command syntax, safe warm inputs,
hard/soft/tag/prefix purge and bounded stale cleanup.
