# Cache Recovery And Maintenance

A cache is replaceable acceleration data, not the authoritative copy of your
content. Keep the origin available during recovery and plan for cold-cache
traffic. Start with [caching](cache.md), use [protected operations](cache-operations.md)
for routine invalidation, and read [encryption](cache-encryption.md) before
changing an encrypted root or its keys.

## Current Operational Warnings

- **Current limitation:** a native router reload can succeed while losing
  its storage-bin disk cache. The candidate tries to acquire the old router's
  exclusive root lease before that router releases it. Disk-only caching then
  disappears; a tiered policy can continue with memory alone. A manifest/layout
  mismatch can similarly produce a running router without its configured disk
  tier. These are confirmed pending corrections, not healthy degradation to
  assume during a rollout. Avoid live reload of affected bin-backed routers;
  use a controlled stop/start and verify actual caching afterward.
- **Current limitation:** native filesystem recovery skips corrupt or
  unindexable objects and abandoned temporary files. They can remain on disk
  outside tracked occupancy and eviction. The configured cache byte budget is
  not a filesystem quota. Monitor free disk space independently.
- **Current limitation:** `storage_bin.max_open_bins` is validated and
  recorded in the manifest, but the current file set opens a handle per
  operation without enforcing that setting as a concurrent-open cap. Do not
  use it as your only file-descriptor capacity control.

These warnings do not authorize deleting live files, disabling path/ACL checks,
or removing an allocator lock to force startup. See the
[findings queue](../reference/documentation-coverage.md#review-records-and-publication).

## What Survives A Restart

| State | Filesystem backend | Storage-bin backend |
| --- | --- | --- |
| Complete persisted objects | One encoded `.fhc` object per hashed identity | Encoded objects occupy ranges inside `bins/*.fhbin` |
| Restart discovery | Parse eligible files beneath root child directories | Read `.fluxheim-storage-bin-index-v1`, then validate referenced objects |
| Layout contract | Existing safe directory and compatible object format | `.fluxheim-storage-bin-v1` must match configured layout |
| Index persistence | Native runtime does not use `.fluxheim-disk-index-v1` | Debounced index writes, normally no more than once per second per root; final flush is best-effort |
| Memory entries and in-flight fills | Not durable | Not durable |
| Fixed slices | Currently memory-only | Currently memory-only |

Healthy disk recovery rebuilds object, variant and purge metadata from accepted
records and prunes tracked objects over budget. A returned HIT after restart
must also have the right body and freshness; validate origin counts to prove
that it was not fetched again. Stale objects remain subject to configured
revalidation/stale-serving rules, not a fresh TTL starting at every restart.

For filesystem storage, reads are bounded and unsafe paths/symlinks are rejected.
The native rebuild enumerates root child directories; it is not the historical
checkpoint-plus-fixed-shard algorithm. Do not put unrelated files in the root.
Skipped invalid objects are not proof of automatic cleanup.

For bins, the index is the location map, not an optional accelerator. A missing
index starts cold; Fluxheim does not scan raw bin bytes to salvage unindexed
objects. Latest admissions may be lost after a crash before index persistence.
Do not remove/rewrite the index as a maintenance shortcut. If layout or index
recovery reports an error, investigate it and verify disk caching explicitly;
process startup alone is not a successful recovery check.

## Storage-Bin Layout And Space

The layout manifest binds all four fields:

```toml
[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "/var/cache/fluxheim/assets-v2"
max_size_bytes = "20GiB"

[vhosts.cache.disk.storage_bin]
bin_size_bytes = "256MiB"
preallocate = false
max_open_bins = 16
```

This is a fragment for an existing enabled vhost cache, not a complete server.
`max_size_bytes`, `bin_size_bytes`, `preallocate` and `max_open_bins` must match
the existing manifest. Even raising `max_open_bins` is not an in-place tuning
operation today. Use a new root for a deliberate layout change; do not edit
the manifest to suppress a mismatch.

An encoded object, including metadata/encryption overhead, must fit inside one
bin. Setting the maximum body equal to bin size does not reserve that overhead.
Keep headroom and check actual store results. `preallocate = true` extends a
new file to bin size; physical allocation depends on the filesystem, so this
is not a guarantee of reserved device capacity.

The allocator reuses free ranges and merges adjacent ranges. It can remove
fully free highest-numbered bins without moving live objects. It does not
compact live objects between bins or provide an operator `compact` command.
Therefore freeing objects does not always shrink files or return space to the
filesystem. Fragmentation can require eviction even when total free bytes look
sufficient; compare the largest free range with the incoming encoded object.

Inspect live cache status for tracked bytes/entries and, for bins, allocated
bytes, free ranges, largest free range and bin count. Also monitor operating
system free space, inode availability and file-descriptor limits. Application
cache counters do not include every file/block on the device.

## One Owner Per Root

Give every storage-bin policy and replica its own canonical root. The allocator
holds `.fluxheim-storage-bin.lock` while alive. An incompatible or competing
allocator must not gain access, even if the server currently mishandles the
resulting initialization error. Never delete the lock file to bypass that rule.

Do not point a rolling replacement process at the previous process's bin root
while both are alive. Use independent roots for overlapping replicas, or a
maintenance stop/start for a single root. Filesystem storage does not have the
same allocator lease; that absence is not a promise of multi-writer consistency.
Separate roots are the predictable deployment model for either backend.

Standalone `cache-lookup` can rebuild a filesystem cache view but cannot inspect
another process's RAM. It also cannot construct an independent storage-bin
allocator: bin inspection requires a registered cache in the same process.
Thus an empty CLI bin lookup is not evidence that the running server has no
cached object. Use live responses and protected status for running bins. The
inspection follow-up in the local follow-up must preserve this single-owner boundary.

## Change Backend Or Layout Safely

There is no online filesystem-to-bin converter. Treat a backend/layout change
as a new, initially empty cache:

1. Save the known-good configuration. Estimate cold-origin load and arrange a
   maintenance window or replicas with independent roots.
2. Create a new service-owned directory with trusted, nonsymlinked parents and
   suitable permissions/Windows ACLs. Keep it on a filesystem with the required
   locking and rename semantics. Do not clone an initialized encrypted root.
3. Change the intended policy's backend/path and layout fields. Validate the
   complete configuration as the service identity. Validation cannot prove
   successful runtime lease acquisition, key loading or disk admission.
4. For a single-root replacement, stop the old process normally and confirm it
   has exited. Start Fluxheim using the new configuration. Examine startup
   errors, especially manifest, lease, key and index failures.
5. Request a known public object twice. Confirm MISS then HIT, body equality and
   one origin fetch. Test disk-only mode or a controlled restart with the same
   root to distinguish disk reuse from a memory hit.
6. Verify protected status, stale/revalidation behavior and a narrowly scoped
   purge. Warm public assets gradually; do not overwhelm origin to refill.
7. Retire the old unencrypted root only after confirming no process uses it.
   For encrypted roots follow the key/nonce lifecycle rules instead of copying,
   rolling back or deleting individual hidden state files.

Rollback of configuration is not rollback of origin content, keys or cache
freshness. A retired root may contain obsolete public representations. Use a
new namespace/root and warm again when correctness is uncertain, rather than
assuming retained bytes are safe to serve.

## Reload And Cleanup

The configuration classifier treats ordinary cache policy changes as snapshot
changes, while changes to `[cache_purger]` require a process upgrade. Other
startup-owned services can also prevent live reload. The native reload builds
a replacement router and lets pinned requests finish on the old generation;
it does not promise to transfer memory entries or in-flight fills.

Because of the documented limitation, snapshot classification is not enough to establish
that bin caching survived. Until corrected, use the stop/start workflow above
for bin-backed routers and verify each required tier. Do not make encryption-key
or root migrations against a directory still used by an old generation.

Use protected indexed purges and the background stale purger for normal work.
The [operations warnings](cache-operations.md#current-invalidation-warnings)
qualify this advice: bounded purges can report false completion, the bin soft
purge deletes instead of retaining stale bytes, and disk dry-run can mutate
objects. Verify effects, not just success flags.
They operate on recognized indexed objects, not arbitrary corrupt files and
leftovers. If disk consumption exceeds tracked bytes, investigate offline after
stopping every owner; moving to a fresh root is safer than guessing which live
files to remove. Do not automate broad `rm` or recursive permission changes in
the root, particularly when encryption state is present.

## Verification

The repository's real proxy-cache and storage-bin smokes check live admission
and normal persistence behavior. Dedicated native lifecycle tests additionally
exercise reload against a real loopback origin, manifest mismatch, missing-index
cold recovery and retained invalid filesystem objects. These characterization
tests expose current gaps; passing them does not mean the gaps are fixed.
The proxy-cache smoke also runs the guide recipes, migrates disk-only filesystem
storage to a fresh bin root and changes bin size through another fresh root.
It checks bodies, origin counts, restart reuse and retained old object/metadata
bytes. It does not certify encrypted migration or all admin maintenance steps.

```sh
cargo build --locked --features metrics
sh scripts/smoke_proxy_cache.sh
sh scripts/smoke_storage_bin_cache.sh
cargo test --locked -p fluxheim-server documented_
```

Keep the platform qualification boundary explicit: filesystem locking, rename
and permission behavior must be retested on native macOS and Windows, not
inferred from Linux results.
