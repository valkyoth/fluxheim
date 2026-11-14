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
Full admission returns `WouldBlock`. Following the pentest correction below,
cache reads propagate that result as saturation: bounded async retries, then
HTTP 503 without origin contact
or deleting the object's allocation, accounting or purge metadata. Other
read failures keep their existing corruption/error handling. Concurrent
exclusive creation collisions reopen the existing bin through the same safe
path API, without truncation or a second capacity reservation.

Shared per-key read synchronization prevents purge/replacement from recycling a reader's
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
reuse. Small limits can increase temporary saturation responses. The
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

## Initial Qualification

Qualification date: 2026-11-14, Rust 1.99.1. These results describe the initial
Commit 25 candidate, before the pentest correction below.

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

## Pentest Correction

Correction base: `8d421e1a7004ca77ad5211e6214297332b7e8497`.

Two findings changed the server-side admission contract:

- Reads now take shared key ownership. A busy writer is reported immediately
  from the blocking lookup instead of occupying a worker waiting on that key.
  Corrupt-record cleanup drops read ownership first, tries exclusive ownership
  without waiting, and compares an allocation-independent record identity.
  A replacement cannot be deleted by cleanup of the previous record; LRU
  timestamp updates do not prevent cleanup of the same record.
- A busy bin or key is a distinct error, never a cache miss. Complete-object
  and slice lookups retry asynchronously at 25 ms intervals, at most 11 attempts
  within a 250 ms retry window. No bin handle or blocking-work permit is held
  between attempts. Persistent saturation returns 503 without origin contact.
  The global blocking-work ceiling still rejects immediately when exhausted.

The retry window bounds resubmission, not an individual OS operation. Already
running blocking I/O retains its permit until it finishes even if the caller
is cancelled. Writes remain best-effort and mutation remains exclusive; these
changes do not promise writer fairness or cancellation of filesystem calls.

### Additional Regression Proof

- Thirty-two same-key readers enter the read section simultaneously, for both
  filesystem and storage-bin backends. The test would fail with the previous
  exclusive-read lock.
- Held writer/read locks prove nonblocking read admission and cleanup; replacing
  a record before cleanup proves the replacement survives. Existing paused-read
  tests still prove purge cannot reclaim an active reader's allocation.
- Injected bin admission saturation remains an error while preserving object
  accounting, purge membership and later restart recovery.
- Live HTTP tests warm complete objects and slices on both backends, then hold
  the actual key mutation lock while 32 concurrent requests arrive. Every
  response is an explicit saturation 503, the origin count stays at one, and
  the stored response becomes available again after contention ends.
- Bounded retry tests cover transient recovery, persistent contention,
  cancellation, and non-retryable errors. Existing concurrent slice-fill
  coalescing tests pass on all three native platforms. Immediate rejection
  during the first implementation failed that existing test; the final bounded
  async retry implementation was requalified rather than relaxing the test.
- The low-bin-limit live matrix now warms eight distinct keys before concurrent
  traffic. It accepts only verified HITs or explicit saturation 503s and checks
  that no extra origin requests occurred. Fixture tests reject MISS responses,
  wrong bodies, wrong saturation reasons and unrelated failures.

### Corrected Qualification

Qualification date: 2026-11-14, Rust 1.99.1.

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing opt-in tests remain skipped |
| Linux all-feature server library | 800 passed, one manual capacity test ignored |
| Native server with load-balancing | macOS 644 and Windows 641 passed; one manual capacity test ignored on each |
| Cache crate | 76 passed on Linux, macOS and Windows |
| Strict all-feature, all-target server Clippy | Passed on Linux |
| Native cache/server Clippy | Passed on macOS; Windows trusted toolchain lacks Clippy |
| Eight-case lifecycle matrix | Passed on Linux, macOS, Windows and non-root Podman |
| Plain/encrypted filesystem recovery smoke | Passed on Linux, macOS and Windows |
| Repeated encrypted filesystem/memory restart case | Three consecutive final-source Linux runs passed |
| Full proxy-cache and storage-bin shell smokes | Passed on Linux, including guide/inspection/admin and lifecycle/recovery cases |
| Python cache fixture suite | 30 tests on Linux/macOS; Windows passed with two existing platform/privilege skips |
| Documentation layout / CI qualification classifier | 28 / 11 passed |
| Windows release-script / filesystem-audit validators | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no audit or policy failures |
| Formatting, documentation links and diff checks | Passed |

The corrected runtime image is
`sha256:dd911897f83ebbe01025dbeb924f5b40d406dd2a5d77d6265cdfb5d1d514f920`.
Its qualification layer is
`sha256:fc02dae09bf5e936fe8d14fbc5715469e1235c81aae4002b24e1ff1d01dd06f2`.
It uses the same non-root, no-host-mount, no-external-network isolation described
above. No dependencies, persisted formats, ACL policy, TLS policy or CI gates
changed. Native archives, ARM64, reproducibility, independent pentest and
exact-commit GitHub acceptance remain separate gates.

## Fragmentation And Lookup Retest

Correction base: `30f11c6bc2f52fd72d962b7e0f82f85bab7954d0`.

The follow-up report confirmed the previous fixes and identified a pre-existing
fragmentation deadlock plus repeated admission retries during one lookup.

Storage-bin allocation now only attempts allocation. When fragmentation requires
eviction, the store drops both its incoming key guard and capacity reservation
before selecting a victim. It then repeats normal admission and allocation.
Publication and replacement still hold the incoming key's exclusive guard.
No eviction path nests a second key stripe beneath that guard. The fix does not
depend on making stripe collisions unpredictable.

Fresh, stale-while-revalidate and revalidation classification now share the same
disk result. Saturation cannot trigger another disk phase, including a separate
range-key read. Eligible entries already in memory retain their existing
behavior, including stale-while-revalidate under disk pressure. A genuine
complete-object miss may still lead to a distinct range-key lookup; slice
assembly and later origin-error handling are separate operations. The change
does not claim one read for an entire multi-slice HTTP response.

### Regression Coverage

- A subprocess constructs two full logical bins with real serialized objects,
  frees a large range in each, and proves that total free bytes exceed the next
  object's size while neither hole fits. Distinct request-shaped incoming and
  victim keys deliberately share the same production lock stripe. The store
  must finish within 20 seconds; the parent kills and reaps only that test child
  on failure. The test verifies the victim, surviving object, byte accounting,
  refunded admission and a real close/reopen of the cache.
- The allocator-only call must return `None` without evicting anything. This
  catches accidental reintroduction of eviction inside the allocation helper.
- A test-only per-cache counter proves exactly one disk read for missing,
  fresh, stale, revalidatable and fully expired entries, on both backends with
  and without `Vary` keys. It is absent from deployed builds.
- The live saturation regression counts attempts for a single HTTP request
  before its 32-client contention phase. It enforces the existing 11-attempt
  bound and retains the zero-extra-origin-request and post-contention HIT checks.
- The existing memory-stale-under-disk-saturation test remains unchanged and
  passes. A first fail-fast implementation rejected that valid memory response;
  the final code preserves it without submitting further disk jobs.

### Qualification

Qualification date: 2026-11-14, Rust 1.99.1.

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing opt-in tests remain skipped |
| Linux all-feature server library | 803 passed, one manual capacity test ignored |
| Native load-balancing server library | macOS 647 and Windows 644 passed; one manual capacity test ignored on each |
| Cache crate | 76 passed on Linux, macOS and Windows |
| Strict all-feature/all-target server Clippy | Passed on Linux |
| Native cache/server Clippy | Passed on macOS; Windows trusted toolchain lacks Clippy |
| Native lifecycle/recovery smokes | Passed on macOS and Windows |
| Isolated Podman lifecycle matrix | Eight cases passed |
| Linux encrypted filesystem/memory restart repeat | Three consecutive runs passed with the unchanged three-second request timeout |
| Linux storage-bin shell smoke | Passed |
| Full Linux proxy-cache smoke rerun | Passed, including guide, admin, lifecycle and recovery checks |
| Python cache fixtures / documentation layout / CI classifier | 30 / 28 / 11 passed; Windows fixtures retain two existing platform/privilege skips |
| Windows release-script and security-source validators | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no findings |
| Formatting and documentation links | Passed |

An initial broad Linux proxy-cache smoke timed out on an encrypted restart
request while other qualification builds were running. The three isolated
repeats above used the same runtime and unchanged timeout, with additional
debug logging. The subsequent full proxy-cache smoke also passed with unchanged
runtime and timeouts. The initial timeout's cause was not established; passing
repeats alone are not proof that it was caused by host load.

Runtime image:
`sha256:37838a8e4b3dd3edac539fd8ba8fdc48d3ecd5df007067ff265bd289e0a25930`.
Qualification layer:
`sha256:2f61d57587f1aeb4363a678a3da621b732830f6b5a4a03a36c1edb8fbb85b182`.
The container runs under the same restricted conditions described above.
No Cargo dependency, cache format, authentication policy, filesystem trust
boundary or CI gate changed. Mutation waits and individual filesystem calls
remain subject to the previously documented operational limits.

## Encoded Admission And Write Contention Retest

Correction base: `4b06bfaeaad1b4806912b34758f3bfca1123f8d9`.

The follow-up report identified an impossible-allocation eviction path and
blocking store/eviction key locks. Both are corrected without changing the
persisted format or dependencies.

The store checks the complete serialized, optionally encrypted object's size
against one bin before removing or evicting any entry. An object that cannot
fit is a rejected best-effort fill, including when it targets an existing key.
The check includes headers, key metadata and encryption, not just response-body
size. Exact-bin-sized encoded objects remain admissible.

Stores acquire their incoming key stripe using `try_write` before capacity
eviction. A busy stripe skips the fill rather than consuming a disk worker
waiting for that lock. Eviction also uses `try_write` and stops at a busy victim.
Fragmentation still releases the incoming stripe and reservation before
eviction. Explicit purge keeps its existing synchronized removal semantics;
individual filesystem calls and internal state/allocator operations are not
made asynchronously interruptible by this change.

The related slice-read caller validates under the disk read guard. Rejected
slices use the existing nonblocking, generation-checked removal rather than an
unconditional blocking purge after lookup. Busy cleanup follows the bounded
async retry path. A newer replacement is not removed. Existing invalid-slice
removal behavior is preserved; an intermediate retain-as-miss approach was
rejected by the legacy-validator regression and is not included in this change.

### Regression Coverage

- Plain and encrypted caches start with eight real entries. Oversized bodies,
  oversized headers and an oversized replacement must preserve all entries,
  record identities and byte accounting. A real close/reopen retains all eight,
  and subsequent smaller writes still work.
- Exact encoded-bin-size admission is checked with and without encryption.
- Filtered-read cleanup is tested on both backends while another read guard
  remains held. It must return `WouldBlock`, preserve the old record, refuse to
  remove a subsequently published generation, and remove a rejected entry once
  uncontended. The existing slice legacy-validator and restart tests remain
  unchanged and enabled.
- An isolated child reserves all 32 real disk-worker permits and starts stores
  for distinct keys sharing an intentionally held stripe. Both a read guard and
  a write guard are tested, on filesystem and storage-bin backends. All stores
  must finish while the guard remains held, all permits must become available,
  and an independent cached read must succeed. Full-cache accounting is unchanged.
- A separate incoming stripe needing eviction encounters a read-locked or
  write-locked oldest victim. It skips promptly, preserves accounting and
  refunds worker capacity; a subsequent store succeeds after contention ends.
- A 30-second subprocess watchdog kills and reaps only the regression child if
  a blocking-lock regression occurs. Existing purge/read coordination and
  same-stripe fragmentation regressions remain enabled.
- The opt-in 57,344-object filesystem concurrent-churn and restart qualification
  passed separately on Linux, in addition to ordinary bounded-capacity tests.

### Qualification

Qualification date: 2026-11-14, Rust 1.99.1.

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing opt-in tests remain skipped |
| Linux all-feature server library | 807 passed, one manual capacity test ignored |
| Native load-balancing server library | macOS 651 and Windows 648 passed; one manual capacity test ignored on each |
| Cache crate | 76 passed on Linux, macOS and Windows |
| Manual full-capacity filesystem test | Passed on Linux |
| Strict all-feature/all-target server Clippy | Passed on Linux |
| Native cache/server Clippy | Passed on macOS; Windows trusted toolchain lacks Clippy |
| Native macOS/Windows lifecycle and recovery smokes | Passed |
| Isolated Podman lifecycle matrix | Eight cases passed |
| Full Linux proxy-cache smoke | Passed, including guide, admin, lifecycle and recovery checks |
| Linux storage-bin shell smoke | Passed on unchanged rerun; initial startup timeout noted below |
| Python cache fixtures / lifecycle / recovery / recovery-capacity | 30 / 5 / 9 / 6 passed |
| Documentation layout / CI qualification classifier | 28 / 11 passed |
| Windows release-script / security-source validators | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no findings |
| Formatting, documentation links and diff checks | Passed |

Runtime image:
`sha256:8806b783d746fc1fe6dd0aa3b3a1992196f6342f4af148986a21d8b3708234ed`.
Qualification layer:
`sha256:180300900d2f7330db65835344015599743adcf084309894003d2720893a5027`.
The container runs non-root, without external networking, host mounts or
capabilities, with `no-new-privileges` and CPU/memory limits.

An initial Windows lifecycle run timed out on the first request after an origin
change (encrypted storage-bin, memory disabled). Three isolated diagnostic runs
with debug logging and the original three-second request timeout passed. The
unchanged full Windows rerun passed, as did final-source native qualification
after the additional slice cleanup correction. A final-source Linux bin smoke
also hit its listener-startup timeout; an unchanged rerun passed. The causes of
these intermittent timeouts were not established. No timeout was increased and
no automatic test retry was added; passing reruns do not establish their cause.
Windows Python fixtures retain two existing platform/privilege skips.

The bounded store/cleanup regressions and manual filesystem capacity test pass.
Native archives, ARM64, reproducibility, independent pentest and exact-commit
GitHub acceptance remain separate gates.
