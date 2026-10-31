# Cache Backends

A cache backend decides where admitted objects live. It does not decide whether
an application's response is public. Keep the admission, credential bypass and
variance rules from [caching](cache.md) regardless of storage choice.

This page describes the **native serving path**. Storage-library interfaces,
historical adapter designs and configuration acceptance are not proof that a
particular feature is active in that path. The [option reference](../reference/cache-options.md)
contains every setting/default; this page explains backend selection, resource
costs, on-disk state and inspection. Use [operations](cache-operations.md) for
commands and [recovery](cache-recovery.md) for stop/start and layout changes.

## Current Implementation

| Mode | Configuration | Where objects live | After process restart |
| --- | --- | --- | --- |
| Memory | Memory enabled, disk disabled | Process-local weighted map per runtime policy | Cold |
| Filesystem disk | Disk enabled, `backend = "filesystem"` | One encoded object file per stored identity | Rebuild from accepted object files |
| Storage-bin disk | Disk enabled, `backend = "storage-bin"` | Encoded objects in allocated ranges within bin files | Rebuild from the persisted index and referenced objects |
| Memory plus disk | Both tiers enabled, either disk backend | Hot copies in memory, persistent copies on disk | Memory starts cold; eligible disk hits can repopulate it |

Native local/static caching requires memory enabled and disk disabled.
Fixed-slice proxy caching is also currently memory-only, even when the ordinary
object policy has a disk tier. Slice fills have separate upstream-selection
limits. See [range caching](cache-ranges.md), the documented limitation; selecting a disk
backend does not resolve them.

Cache state is local to a runtime policy/process, not a shared distributed
database. [Peer fill](cache-peer-fill.md) fetches responses from peers; it does
not replicate allocator state or provide cluster-wide purge. Its variant-context
limitation remains the documented limitation.

### Try Each Backend

Start with the complete [local public-CSS example](../../examples/cache/local.toml)
and the origin/start/request commands in [the caching guide](cache.md#try-a-public-asset).
It uses an 8 MiB memory budget, a 256 KiB maximum body and a 120-second TTL.

For memory plus disk, append exactly **one** of these fragments to that base:

| Fragment | Result |
| --- | --- |
| [filesystem.toml](../../examples/cache/filesystem.toml) | Memory plus 32 MiB filesystem disk |
| [storage-bin.toml](../../examples/cache/storage-bin.toml) | Memory plus 32 MiB storage-bin disk; 1 MiB bins |

Fragments are not standalone servers. Do not append both: they define the same
table. Keep the generated configuration beside the base so `state/cache` has
the intended configuration-relative meaning. For example, from the repository
root, with a fresh private `examples/cache/state/cache` owned by the service:

```sh
cat examples/cache/local.toml examples/cache/filesystem.toml > examples/cache/filesystem-local.toml
fluxheim --config examples/cache/filesystem-local.toml --validate-config
fluxheim --config examples/cache/filesystem-local.toml
```

Use `storage-bin.toml` instead for a separate bin-backed trial. Stop the previous
server first and use a **new cache root** when changing backend/layout; do not
point both trials at populated `state/cache`. Follow the explicit
[migration steps](cache-recovery.md#change-backend-or-layout-safely).

For disk-only mode, change `enabled = true` to `false` in the existing
`[cache.memory]` table. Do not add a duplicate table. Request `/asset.css` twice:
expect MISS then HIT and the same body. Restart with the same disk configuration
before the TTL expires and verify a HIT without an extra origin fetch. A HIT
before restart with memory enabled is not evidence of a disk write.

For local files, use the independent [static-memory recipe](../../examples/cache/static.toml),
not a disk fragment. The recipe harness exercises these modes and restart behavior;
its evidence scope is described below.

## Budgets And Memory Costs

`max_object_bytes` bounds stored body size. Every enabled tier budget must be at
least that large. Real objects also need keys, headers and metadata, so a body
at the configured limit is not guaranteed to fit a tier/bin of the same size.

| Setting | What it bounds | What it does not bound |
| --- | --- | --- |
| `memory.max_size_bytes` | Tracked object weight in that memory tier | Whole-process RSS, allocator overhead, in-flight bodies or every policy's combined state |
| `disk.max_size_bytes` | Tracked backend storage budget | A filesystem quota or every orphaned/invalid/temporary file on the device |
| `disk.storage_bin.bin_size_bytes` | Single bin layout and allocation size | Maximum process memory or guaranteed physical reservation |
| `disk.storage_bin.max_open_bins` | Validated, manifest-bound value | Currently **not enforced** as a concurrent-open cap  |

The disk budget is not a filesystem quota. Allow headroom outside tracked
objects and monitor the actual device, not only cache counters.

Native memory weight includes body length, key, reason, header lengths and a
fixed per-entry estimate. It is not `budget / max_object_bytes` slots and is not
a precise measurement of all allocated memory. Pruning removes objects beyond
their allowed stale lifetime and, if over budget, removes oldest stored entries.
That memory policy is not the disk backend's access-time LRU policy.

Native disk eviction maintains an ordered access-time index and removes oldest
tracked objects when admitting a new object needs space. In a bin backend it
also releases allocation ranges. An admission can still fail due to encoding
overhead, fragmentation, disk errors or encryption/provider errors.

Ordinary native proxy admission sees a materialized response body, including
for disk-only policies. Storage streaming interfaces do not make that request
path an unbuffered origin-to-disk stream. Count concurrent request/response RAM
separately from tier budgets. Partial writes are not served as complete hits.

With both tiers enabled, lookup can promote an eligible disk object to memory
when it fits. Stores are attempted for the selected tiers; a successful memory
fill does not prove that disk storage succeeded. Purge acts on the local tiers,
with the backend-specific limitations below.

## Filesystem Layout

The native filesystem backend uses hash-derived shard paths ending in `.fhc`.
Objects include status, headers, body, freshness/validator data and identity
metadata. Current plaintext object envelopes include combined/primary keys,
tags and path-index metadata. Treat unencrypted cache files as potentially
sensitive operational data, not as anonymous blobs.

Writes use same-directory temporary files and replacement. Reads are bounded
and require acceptable regular-file/path checks. Unix and Windows use their
respective filesystem helpers; do not infer Windows ACL behavior from a Linux
test. Give the root trusted ownership and no symlink/reparse-point aliases.
Do not let unrelated processes mutate it under the same service identity.

Restart enumerates root child directories and parses eligible object files.
The native path does **not** load the historical `.fluxheim-disk-index-v1`
checkpoint. Accepted objects rebuild the runtime object, variant and purge
indexes. Unsupported or invalid files can remain outside that inventory;
temporary files are not automatically age-cleaned by this rebuild
. Monitor filesystem space and inode use independently.

There is no storage-bin-style exclusive allocator lease for the filesystem
backend. That is not a multi-writer consistency guarantee. Use a separate root
per policy/replica instead of treating one shared directory as cluster storage.

## Storage-Bin Layout

Bins group objects in larger files and reuse freed ranges. This can reduce the
number of object files, at the cost of an allocator/index and fragmentation.
It does not guarantee faster storage for every workload.

| Root-relative state | Purpose |
| --- | --- |
| `.fluxheim-storage-bin-v1` | Manifest binding disk budget, bin size, preallocation and max-open-bins setting |
| `.fluxheim-storage-bin.lock` | Exclusive allocator ownership for its lifetime |
| `.fluxheim-storage-bin-index-v1` | Object identity to `(bin_id, offset, len)` map |
| `bins/NNNN.fhbin` | Encoded objects; actual IDs are 16-digit hexadecimal names |

Each encoded object must fit within a single bin. The allocator uses first-fit
free-range reuse, merges freed adjacent ranges and can reclaim fully free
highest-numbered bins. It does not compact live objects between bins. Total
free bytes alone do not prove that the next object fits; inspect the largest
free range too.

`preallocate = true` extends newly created bins to their configured size.
Physical block allocation depends on the filesystem; this is not a device-space
reservation guarantee. Manifest-bound values cannot be changed in place by
editing TOML or the manifest. Even a max-open-bins change needs the documented
new-root procedure today.

One process-wide persistence worker coalesces native bin-index updates with a
one-second debounce per root. Request paths mark the index dirty; final teardown
attempts a flush. A crash can lose recently admitted index entries. Restart
validates indexed objects and reconstructs free ranges; it does not scan raw
bin data to recover unindexed entries. Cache storage is not a durable database.

Every bin policy needs its own canonical root. The allocator obtains its lease
before preparing the layout and retains it while alive. Never delete the lock
file or bypass it. Shared filesystems must supply the required locking/rename
semantics, but single-owner local storage is the simpler deployment model.
Independent roots are required for overlapping replicas or rolling replacements.

## Startup, Reload And Operations Limits

**A running listener is not proof that its configured disk tier initialized.**
The native construction path can log a backend, encryption or index-service
failure and omit the disk tier. It does not deliberately downgrade encrypted
objects to plaintext storage, but a memory tier or ordinary origin requests can
mask the unavailable disk cache.

| Finding | Operator consequence | Required correction |
| --- | --- | --- |
| the documented limitation | Candidate reload can contend with the old bin allocator; layout errors can also leave the router running without configured disk caching | the local follow-up; until fixed, controlled stop/start and explicit disk verification |
| the documented limitation | Invalid/unindexed files and abandoned temporaries remain outside tracked occupancy | the local follow-up; monitor actual filesystem usage and use offline maintenance guidance |
| the documented limitation | Configured max-open-bins is not a handle cap | the local follow-up; provision OS descriptor limits without relying on this value |
| the documented limitation | Bounded indexed purge may report no continuation while objects remain | the local follow-up; verify remaining scope, do not assume a false completion flag proves emptiness |
| the documented limitation | Bin soft purge deletes instead of retaining a stale body | the local follow-up; do not depend on bin stale fallback after soft purge |
| the documented limitation | Disk stale dry-run can delete during lookup | the local follow-up; do not use it as a guaranteed read-only preview |

These are open corrections, not accepted behavior merely because documented.
Use [recovery](cache-recovery.md) and [operation safeguards](cache-operations.md#current-invalidation-warnings).
A configuration reload is not an online backend converter or a promise to
transfer in-flight fills and memory objects to a new generation.

## Encryption And Network Boundaries

Both ordinary disk backends support the configured local AES-256-GCM or OpenBao
Transit provider. Memory remains plaintext. Encryption does not bypass public
content admission or protect application traffic/logs; see the complete
[encryption guide](cache-encryption.md) for all options and setup examples.

The local provider reads a private master-key file/credential and maintains
root-specific key/nonce state. OpenBao encrypts/decrypts complete values through
Transit and returns ciphertext for storage. Transit needs HTTPS or allowed
numeric-loopback HTTP, not arbitrary plaintext service-network HTTP. No
per-policy CA/mTLS/timeout fields exist in this table. FIPS-required transport
has additional constraints in [FIPS guidance](fips.md).

Encrypted lookup names/index identities use root-bound HMACs; object identity
is verified after decryption. This does not hide lengths, activity or all
envelope metadata. Do not clone initialized encrypted roots, restore nonce state
from a backup or delete hidden key/counter files. Follow the guide's cold-root
rotation and migration rules, including when data is merely a disposable cache.

Peer fill is a separate HTTP trust boundary, not encrypted disk replication.
Neither at-rest encryption nor a shared peer secret fixes negotiation-context
limitations. See [peer fill](cache-peer-fill.md) before enabling it.

## Inspect The Correct State

| Interface | Useful output | Important limit |
| --- | --- | --- |
| `cache-key` | Scope, vhost/route, key/namespace, eligibility, lock/predictor/origin/peer policy and tier selection | Config-derived; root-only proxy lookup has the documented limitation; no proof of a running hit |
| `cache-lookup` | Matching tier, status, body length, freshness timestamps/state, stale eligibility, tags and header names | Separate process cannot inspect live RAM or acquire another bin allocator; filesystem recovery can mutate state |
| `cache-warm` | Actual HTTP statuses and cache-status transitions | Real traffic; cannot infer disk success from a memory HIT |
| Admin cache status | Live activity, tracked occupancy, tier/policy coverage and bin allocation/free-space summaries | Not every file/block or a cluster-wide inventory |

Key/lookup expectations can assert scope/vhost/route, namespace, tier counts and
policy flags. Lookup also supports object count/presence, tier/status/size,
fresh/stale fields, indexed-purge metadata, cache tags and stored header tests.
Repeated tag/header assertions search matching objects; they do not imply one
object satisfied every independent assertion. `--expect-header` compares a
stored value without needing to print all values. Use actual command `--help`
and the [CLI guide](command-line.md) for the complete inventory.

Inspection output can disclose URLs, namespaces and tags. Default lookup output
does not print response bodies or stored header values, but that does not make
the metadata public or inspection non-mutating. An assertion failure is not an
instruction to repair an object; earlier recovery/lookup work may already have
changed filesystem state. Lookup is not guaranteed read-only. Consult
[cache operations](cache-operations.md).

For HTTP diagnostics, `status_header` reports an outcome such as `MISS`, `HIT`,
`STALE`, `BYPASS`, `EXPIRED` or `REVALIDATED`; reason values depend on the native
producer. A MISS means lookup missed, not necessarily that admission succeeded.
The standardized [Cache-Status formatter](../reference/response-header-options.md#metadata)
also is not independent proof that disk persistence succeeded. Use body/origin
checks and restart proof instead of treating a header as a storage receipt.

Metrics and status summarize local activity. Purge counts/ratios apply to the
reported work, not all matching bytes on disk. See [metrics](metrics.md) and
[operations](cache-operations.md) for current progress and disclosure limits.

## Verification And Source Map

The [recipe harness](../../scripts/smoke_cache_examples.py) assembles the actual
base/fragments and runs memory, filesystem, bin, tiered, disk-only and static
cases. It checks body equality, origin counts, credential/cookie bypass, query
isolation, HEAD bypass and restart reuse, plus a named-vhost operation example
and stop/start migrations into fresh roots. The
[unit checks](../../scripts/test_cache_examples.py) protect assembly and options.

That is local recipe proof, not a new qualification of all encrypted templates,
shared filesystems, Windows/macOS archives, every protocol or recovery fault.
Exact evidence and remaining work live in the
[coverage ledger](../reference/documentation-coverage.md).

| Implementation | Responsibility |
| --- | --- |
| [Native memory](../../crates/fluxheim-server/src/native_http1_cache_memory.rs) | Object weight, expiry pruning and stored-age eviction |
| [Native disk](../../crates/fluxheim-server/src/native_http1_cache.rs) | Initialization, encoding/admission, lookup, occupancy and mutation |
| [Backend selection](../../crates/fluxheim-server/src/native_http1_cache_backend.rs) | Filesystem/bin selection, access-time index and allocator lease |
| [Bin persistence](../../crates/fluxheim-server/src/native_http1_cache_storage_bin.rs) | Native index debounce, rebuild and flush |
| [Allocator](../../crates/fluxheim-cache/src/storage_bin_alloc.rs) | Bin/free-range allocation and reclamation |
| [Native encryption](../../crates/fluxheim-server/src/native_http1_cache_encryption.rs) | Provider, protected keys, envelopes and root identity |

## Historical Memory Cache Evaluation

Earlier adapter research evaluated `pingora-memory-cache` 0.8.0 on 2026-05-04
and `moka` 0.12.15 / `sha2` 0.11.0 on 2026-05-05. The former used count-based
capacity; the Moka adapter used weighted capacity, and SHA-256 supplied fixed
lookup identities. These are dated design notes, **not current dependency pins**
or a description of the native memory map. Consult `Cargo.lock` for this checkout.

Fluxheim-owned `FluxCacheStorage`, `FluxHandleHit` and `FluxHandleMiss` interfaces
describe storage-library behavior. Earlier discussions of `HttpCacheDigest`,
`ForcedFreshness` and `CachePut` were adapter/API ideas, not public TOML or CLI
options. Native timing metrics, pass decisions and HTTP warming have their own
documented implementation; do not infer support from those historical names.

## Adapter Requirements

Treat a new backend as runtime work requiring admission, byte budgets, identity,
HTTP freshness/variance, cleanup, concurrency, restart and failure tests. A
library's streaming or purge method alone does not qualify the native gateway.
Update the canonical guides, correct the relevant characterization tests and
rerun native/packaged qualification before changing advertised support.
