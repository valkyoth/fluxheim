# Read-only stale-purge preview

The control API's `purge-stale?dry_run=true` inspects an indexed disk object
without treating it as a cache hit. It neither refreshes eviction priority
nor deletes the object, even if it is fully expired or damaged. The explicit
purge removes only a validated stale or expired generation. Missing, invalid
and unreadable objects have separate counters; they are not proof of expiry.
See the [cache operations guide](../guides/cache-operations.md) for the response
fields and how to continue a bounded scan.

## Qualification

- Regression tests compare cache contents, eviction order, allocation stats,
  lookup counts and stored bytes before and after preview. They cover both disk
  backends, each with and without encryption, and verify that an explicit
  purge still removes the stale and fully expired objects but keeps the fresh
  object. A busy mutation stripe reports incomplete work instead of waiting.
- Separate cases leave damaged files, missing files, unreadable objects and
  orphaned memory-index rows untouched by preview. Admin response tests check
  that inspection counts survive aggregation across batches.
- The live cache-operations fixture exercises the control endpoint for memory,
  filesystem, storage-bin and both tiered layouts. Anonymous and observer
  requests cannot preview. Repeated control-token previews report the same
  eligible count with no removals, and the response remains available for
  revalidation or permitted stale serving. These checks passed on Linux,
  Apple Silicon macOS, Windows 11 x64 and in a non-root Podman container.

Read-only describes the cache, not the entire host. The preview cursor still
advances independently of the purge cursor; reading a file may also update
its OS access time. Inspection is not an atomic snapshot of a running cache.
