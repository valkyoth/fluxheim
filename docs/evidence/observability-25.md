# Commit 25: Storage-Bin Handle Admission

Base: `0dc112549af5204c2c261504a174ae7825e5ddd9`.

## Contract

`StorageBinFileSet` clones share a bounded admission state. Each bin read,
write or deletion reserves capacity before path inspection and opening files.
Read/write operations use independent file handles and seek positions. The
file is dropped before its permit; failed opens, short reads, errors and
unwinding release admission. Zero limits fail closed even for direct callers.
Poisoned bookkeeping rejects new work while owned permits can still release.

There is no idle handle pool or queue waiting for bin capacity. A short
bookkeeping mutex protects counts, but is never held across filesystem I/O.
Full admission returns `WouldBlock`. Cache reads treat that result as a miss
without deleting the object's allocation, accounting or purge metadata. Other
read failures keep their existing corruption/error handling. Concurrent
exclusive creation collisions reopen the existing bin through the same safe
path API, without truncation or a second capacity reservation.

Per-key synchronization prevents purge/replacement from recycling a reader's
allocation until its record has been read and validated. Deletion cannot race
an admitted operation on that bin, even when other capacity remains. Compatible
router generations retain the shared allocator and budget; incompatible live
layout changes remain rejected. Existing manifest equality is unchanged,
including `max_open_bins`: changing it requires a fresh independent root.

The limit covers bin data-file operations, not all OS handles, all caches,
all processes or the cluster. Directory traversal, leases, manifest, index and
encryption metadata use additional handles. Blocking-work admission remains
independent; cancellation does not forcibly interrupt an OS call. A busy write
may skip caching, and a busy tail removal can leave an empty bin for later
reuse. Small limits can increase origin traffic. The
[maintenance guide](../guides/cache-recovery.md#bin-file-concurrency) explains
these operational boundaries.

## Regression Proof

- Eight concurrent threads hold actual bin handles behind test barriers. Limits
  one and two admit exactly that many handles; all other opens fail promptly
  with `WouldBlock`. After release every bin remains readable.
- A retained handle blocks reads/writes/removal through a clone at limit one;
  dropping the original file set does not reset the clone's budget. Closing the
  handle allows reclaim and reopening, including on Windows.
- Two handles on one bin consume two slots and have independent seek offsets.
  Concurrent creation and disjoint writes preserve both byte ranges and the
  preallocated file size over repeated reclaim/recreate cycles.
- Missing files, invalid locations, length errors, short reads, unwinding,
  cancellation of a future owning a handle, exclusive deletion and poisoned
  bookkeeping exercise cleanup and failure behavior.
- Injected `WouldBlock` at the server reader boundary preserves the original
  object, byte charge and purge index. Later read, removal, replacement and
  restart succeed. A real reader paused under its key lock prevents concurrent
  purge from releasing that allocation until reading finishes.
- The existing live lifecycle matrix now uses `max_open_bins = 1` for bins.
  It proves MISS/HIT, compatible reload, changed-limit rejection, rollback,
  restart, content-policy isolation and origin cutover. Each bin case also
  serves 64 requests through eight clients and then proves a new stable HIT.
  Both encryption modes and memory-enabled/disk-only configurations run.

The HTTP smoke checks body correctness, progress and recovery, not OS descriptor
counts; the concurrent low-level tests provide the explicit open-count proof.
No claim of OS-call cancellation, fairness or immediate disk reclamation is made.

## Qualification

Qualification date: 2026-11-14, Rust 1.99.1.

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing opt-in tests remain skipped |
| Linux all-feature server library | 794 passed, one manual capacity test ignored |
| Cache crate, final test source | 76 passed on Linux, macOS and Windows |
| Native server with load-balancing | macOS 638 and Windows 635 passed; one manual capacity test ignored on each |
| Strict cache/server all-feature, all-target Clippy | Passed on Linux |
| Native cache/server Clippy | Passed on macOS; Windows trusted toolchain lacks Clippy |
| Live lifecycle matrix and concurrent traffic | Passed on Linux, macOS, Windows and non-root Podman |
| Existing plain/encrypted filesystem recovery smoke | Passed on Linux, macOS and Windows |
| Existing proxy-cache and storage-bin shell smokes | Passed on Linux |
| Python cache fixtures | 29 passed on Linux/macOS; Windows passed with two platform/privilege skips |
| Documentation layout / CI qualification classifier | 28 / 11 passed |
| Windows security helper | 11 native tests passed |
| Windows release-script / filesystem-audit validators | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no audit or policy failures |
| Formatting, documentation links and diff checks | Passed |

The runtime image was built from the qualified runtime source as
`sha256:342c071d931f13da394e8053b7820c42716eeae70963f2f33f20850c85b5cc18`.
Its qualification layer runs as UID 65532 with no host mounts or external
network, all capabilities dropped, `no-new-privileges`, two CPUs and 768 MiB.
Loopback origin/server/admin traffic remains available inside the container.

No Rust dependencies, versions, cache format, manifest schema, ACL policy or
TLS policy changed. The Windows source-audit fingerprint was stale after
Commit 24's retained-handle link-count helper. That narrow delta was reviewed,
its native regression rerun, and the
[audit record](dependency-audits/windows-filesystem-security.md) refreshed;
the helper itself is unchanged in this commit.

The new cases run within existing workspace/cache tests and the live lifecycle
smoke already selected by Linux/macOS/Windows CI. No workflow or qualification
classifier was weakened. Native release archives, ARM64 and reproducibility
remain final release gates, not rerun for this checkpoint. Independent pentest
and exact-commit GitHub acceptance remain pending.
