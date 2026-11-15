# Commit 26: Bounded Cache Purge Progress

Date: 2026-11-15. Accepted base: `3c1f65aceeff74d95f781ddc91fd9e0d9d3d3711`.
Local qualification only: independent pentest and exact-tip GitHub/CodeQL
acceptance remain required before progression. No release is authorized here.

## Corrected Contract

The shared purge index now has an ordered insertion-sequence index and bounded
per-selector/mode progress. A batch examines at most its entry limit, including
nonmatches. A subsequent batch advances past fresh or unrelated entries rather
than restarting at the front. Replacements receive new sequence identities.
Each pass observes an upper sequence boundary; later fills/replacements and
failed mutations require continuation instead of a false completion result.

There are at most 64 pending scans per index and at most 8 KiB of selector text
per scan. Cursor eviction restarts traversal, never certifies completion.
Concurrent scan admission uses `try_lock`; contention remains visible through
`truncated`. Disk indexed mutations use nonblocking key admission. Stale
removal checks the captured object generation before deleting it.

Memory and disk generations share their tier's entry budget. Empty-generation
visits cost one unit and retained generations receive work in rotating order.
Admin batching continues after a fresh-only batch and supports bounded
multi-batch previews. Background cleanup shares its entry budget across disk
targets and reports final-batch continuation rather than an earlier partial
batch. Soft-purge counts represent actual fresh-to-stale changes, not repeated
visits to an already stale filesystem/memory object.

Storage-bin release failures now preserve the indexed record and accounting.
Filesystem unlink failures likewise remain incomplete. Neither is counted as a
successful removal. Exact purge now records successful memory effects in the
bounded Prometheus activity counters. Bounded exact slice traversal returns an
explicit incomplete-operation error when continuation is needed; it does not
silently claim all slices were processed.

## Regression Proof

- Six shared-index tests cover sparse prefix/exact/wildcard/tag selectors,
  sequence replacement, failure carry-forward, independent modes, cursor
  capacity and fail-closed concurrent/invalid scan admission.
- Thirteen disk/memory purge contract tests include both backends, encrypted
  restart persistence, retained live generations, fresh-prefix progress,
  repeated soft purges, failed unlink/release, busy mutation guards and repeated
  background ticks. The background test uses the checked native-server
  self-launcher to isolate the process-wide registry.
- Existing adjacent soft-bin and disk-preview characterizations remain in
  place; this change does not claim those separate contracts are corrected.
- Admin batching tests cover dry-run continuation, a fresh-only first batch,
  batch limits and final continuation flags.
- The live authenticated smoke exercises memory-only, filesystem-only,
  storage-bin-only and both tiered layouts. It verifies anonymous/observer
  rejection, exact/bulk purges, over-limit scope/prefix/wildcard/tag requests,
  remaining HITs, subsequent origin requests and per-tier counts. With
  `--metrics`, it verifies exact-purge counters by scraping Prometheus.
- The broader proxy-cache smoke now requires that metrics-enabled proof too.

## Completed Checks

| Check | Result |
| --- | --- |
| Full locked Linux workspace tests | Passed |
| Root load-balancer/ACME/metrics library | 351 passed |
| All-feature server library | 816 passed; 1 manual capacity test ignored in this invocation |
| Cache crate | 82 passed |
| Manual 57,344-object filesystem churn/restart | Passed separately |
| Native macOS ARM64 server/cache libraries | 660 server and 82 cache tests passed; manual capacity test not run there |
| Native Windows 11 x64 server/cache libraries | 657 server and 82 cache tests passed; manual capacity test not run there |
| Native Linux/macOS/Windows live purge matrix | Five layouts passed on each, including Prometheus counters |
| Native macOS/Windows lifecycle and recovery | Eight lifecycle combinations and two encrypted/plain recovery cases passed on each |
| Fresh non-root Debian Podman image | Five live purge layouts passed with no external network, dropped capabilities and no-new-privileges |
| Full Linux proxy-cache smoke | Passed on unchanged rerun, including guide, admin, metrics, lifecycle and recovery cases |
| Storage-bin shell smoke | Passed |
| Strict all-feature/all-target cache/server Clippy | Passed |
| Strict root load-balancer/ACME/metrics profile Clippy | Passed |
| Python cache/fixture checks | 31 passed locally; native runs passed 30 on macOS and 28 plus two existing platform skips on Windows before the final readiness-only test addition |
| Documentation layout / qualification policy | 28 / 11 passed |
| Windows release-script and filesystem-audit validators | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no audit or policy failures |
| Formatting, Python/shell syntax, doc links and diff checks | Passed |

The final Python-only fixture adjustment waits up to ten seconds for the metrics
TCP listener before issuing its single GET. It retries connection establishment
only, not HTTP requests; a mocked refusal/timeout regression verifies that
boundary. Native runtime code did not change after native qualification.

An initial metrics assertion incorrectly inspected the admin status activity
fields rather than the actual Prometheus counters. It was replaced with direct
per-tier/scoped scrape assertions, which passed on all three native platforms.
One Linux operation smoke timed out on an initial origin request; the first
broader Linux run also hit its unchanged five-second curl deadline. A separate
metrics scrape exposed a listener-readiness race fixed in the fixture above.
Final runs passed without increasing request deadlines or replaying failed HTTP
requests. These reruns do not prove the earlier request timeouts were caused by
load, nor replace the final release gate.

## Boundaries

Completion means a finished traversal, not an atomic fence against future fills,
secure disk erasure or durable persistence of the purge. Counts are tier/object
visits, not globally unique resources. Registry bookkeeping and individual
filesystem operations are not bounded wall-clock operations. A limit too small
to visit all retained generations, continuous churn, selector churn or persistent
errors can keep continuation set; use finite retries and retire old generations
or increase the limit when appropriate.

The [operations guide](../guides/cache-operations.md) retains the separate
storage-bin soft-deletion and disk dry-run warnings. No dependencies, cache
representation domain, authentication or audit-admission policy changed.
Windows was shut down normally after testing. Linux ARM64, native archives and
the final release qualification still require their scheduled release checks;
macOS ARM64 is not relabeled as Linux ARM64 evidence.
