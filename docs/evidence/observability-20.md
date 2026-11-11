# Persistent Range Slice Qualification

Local qualification: 2026-11-11. Commit 20 follows
`ea7108f52fa5b1f92c3bb83a7fb3529ba7adc8e0`. Implementation and local tests are
complete; independent pentest and exact-commit GitHub acceptance remain pending.
This is not final release qualification.

## Delivered

Native proxy slices now use configured memory, filesystem and storage-bin
tiers. Disk-only policies no longer depend on a nonzero memory-cache budget.
Slices retain their exact range/variant key, primary-object identity, path and
cache tags when persisted through the existing disk serialization, encryption,
capacity and recovery machinery. Complete-object variant lookup cannot select
a slice, and slice admission does not erase complete-object variant mappings.

Disk reads and writes use the existing bounded blocking-work admission. Read
saturation or worker failure returns `503` with a bounded reason instead of
starting unbounded work or silently fetching from origin. Storage remains
best-effort, as for complete objects: a rejected store does not make a valid
current origin response unusable, but does not promise a later cache hit.

Memory retention checks the full weighted entry, independently of disk capacity.
Disk-only reads do not promote entries to memory. Fresh disk slices must have
status 206, a valid complete body and the requested normalized bounds. Existing
origin admission, Vary coverage and representation-identity checks remain in
force. Mismatched validators cannot produce a mixed cached representation.

Exact invalidation now consults the existing purge index so it includes slices,
not only the complete object's variant map. Path/tag indexes, scoped purge,
eviction and byte accounting use the same backend machinery as ordinary objects.

The [range guide](../guides/cache-ranges.md), option references and checked-in
slice example now describe persistent tiers and their limits. No Cargo
manifests or locked dependencies changed. Load-balancer selection for slice
fills is not changed by this checkpoint.

## Verification

| Check | Result |
| --- | --- |
| Full locked Linux workspace suite | Passed; existing privileged ACME test remains ignored |
| Combined Wasm/PHP/load-balancer/Rustls server suite | 714 passed |
| Linux OpenSSL/load-balancer server suite | 609 passed |
| Native macOS Apple Silicon Rustls/load-balancer server suite | 612 passed |
| Native Windows x86_64 Rustls/load-balancer server suite | 610 passed |
| Focused Linux slice tests | 21 passed, including the isolated concurrency child |
| Live native slice restart smoke | Five cases passed on each of Linux, macOS and Windows |
| Fresh non-root Wolfi slice restart smoke | Five cases passed |
| Existing cache guide, restart and backend migration smoke | Passed on macOS and Windows |
| Strict Clippy | Combined-feature Linux server and native macOS server passed |
| Minimal server without default features | Passed |
| Python slice/cache fixture tests | 14 passed on Linux; slice fixture tests also passed natively |
| Checked-in slice configuration | CLI validation and configuration example regression passed |
| RustSec and cargo-deny | 449 locked dependencies, zero known vulnerabilities; all deny policies passed |
| Formatting, documentation layout/links, modularity and diff checks | Passed |

The real-process smoke fills two language representations, each spanning two
slices, then restarts the server. It checks exact bodies, `slice` hit reasons and
unchanged origin counts for filesystem and storage-bin policies with memory
enabled or disabled. A memory-only control must refill after restart. Complete
GETs after slice recovery must still fetch and cache the complete representation.
The container restarts the same non-root container and retains its private
writable layer; it does not expose a writable host directory to the guest.

Rust tests cover both disk backends with memory enabled/disabled and local-key
encryption enabled/disabled. They assert disk entries, memory absence, variant
isolation, exact invalidation and recovery. Additional cases cover scoped path
purge, complete-object coexistence, byte-budget eviction, insufficient capacity,
invalid/truncated bodies, unexpected ranges and encoding, corruption of plain
and encrypted objects, a missing storage-bin index and cancellation before a
complete origin response. The cancellation test verifies lock release, zero
partial entries, successful refill and a subsequent disk hit.

A real 32-client disk-only fill test requires one origin request and no retained
memory objects. Its initial Windows run shared the global 32-worker disk budget
with unrelated parallel tests and correctly received a saturation `503`. The
test now runs in an isolated child process; its assertions and production
admission limit are unchanged. Separate saturation tests explicitly require
`503` for slices when that budget is exhausted. Full native reruns passed.

Tested Wolfi image:
`sha256:d9570cec1bdb363217322a7ed8712bbc84b99f494a910422596d4aea087b1d98`.
This identifies the local runtime test image, not independent artifact provenance.

## Boundaries

- Persistence is cache recovery, not durable storage. Abrupt termination can
  lose uncheckpointed storage-bin entries. A missing index starts cold; this
  change does not salvage unverified bin contents.
- Slice-specific encrypted tests use the local-key provider. OpenBao shares
  the disk encryption path and its existing provider tests, but no live
  slice-specific OpenBao deployment was qualified here.
- Responses are still assembled in process memory. Disk-only disables retained
  memory entries, not request working memory; range limits remain important.
- Native Linux ARM64 and release archives were not rebuilt for this checkpoint.
  Final release-wide qualification remains required.
- Native Windows lacks Clippy; Linux and macOS provide strict Clippy checks.
- No public server, shared-project VM or system certificate store was modified.
- Machine-specific logs and unresolved correction planning remain local.
- Local qualification does not replace the independent pentest and CI gates.
