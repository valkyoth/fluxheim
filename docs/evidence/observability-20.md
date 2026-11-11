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

## Strong Validator Correction

The follow-up review of `075ed84e` identified that optional validators did not
establish byte identity across slices. The correction requires exactly one
syntactically valid strong ETag before constructing a slice object. Missing,
weak, duplicate, list-valued and malformed ETags are rejected; Last-Modified
alone is not sufficient. The same constructor validates memory hits and
recovered disk records, so older invalid entries become misses and are removed.
Composition still requires equal total length and representation identity.

When configuration hides ETag, slice handling bypasses both existing entries
and new admission. This deliberately uses ordinary proxy handling rather than
removing the validator required for composition. The cache serialization format
and dependencies are unchanged. Origins remain responsible for changing their
strong ETag whenever the representation bytes change.

Regression coverage includes admission syntax, hidden-header policy, legacy
memory and disk records with both plain and encrypted backends, and real TCP
requests that must return the intact fallback body instead of combining a valid
first slice with an unproven second slice. Those requests run before and after
restart across memory, filesystem and storage-bin policies. The multipart
success fixture now provides a strong ETag; date-only rejection is tested
separately rather than retaining the unsafe expectation.

Follow-up verification:

- Full locked Linux workspace suite passed.
- Linux server suites: 617 Rustls/load-balancer, 613 OpenSSL/load-balancer,
  and 718 combined Wasm/PHP/load-balancer tests passed.
- Native macOS: 616 server tests, strict Clippy, five live slice restart cases
  and existing cache-guide/migration checks passed.
- Native Windows: 614 server tests, five live slice restart cases and existing
  cache-guide/migration checks passed.
- Linux live slice restart checks and the five fresh non-root Wolfi container
  cases passed. Image identity:
  `sha256:cc07f293fdbd9b5d3e4f1ebe8ac6d9e3f5d1c8f47284ab24269c9fbe2d890a4c`.
- Strict Linux Clippy, minimal server compilation, 14 Python fixture tests,
  28 documentation-layout tests, links, formatting and modularity checks passed.
- Fresh RustSec scan: 449 dependencies, zero known vulnerabilities;
  cargo-deny advisories, bans, licenses and sources passed.

Independent retest and exact-commit GitHub acceptance remain pending.

## Discovery Probe Backoff

The availability follow-up to `904660f3` suppresses repeated slice discovery
after an origin `206` lacks a valid strong ETag. The hint is independent of the
ordinary cache-pass predictor: it affects only slice handling, not full-object
cache admission or forwarding of the original request.

Hints expire five seconds after recording and cannot be extended by reads or
repeated failures. Each cache-policy instance retains at most 1,024 entries,
using fixed-size SHA-256 digests for configured variant and primary identity.
Hints are memory-only even for disk-only policies. Saturation skips insertion
instead of growing the map. Configured variants remain independent.

Fill-lock waiters recheck the hint before becoming another origin writer.
Exact primary purge clears its hints, other scoped mutating purges reset the
policy's hints, and stale-purge dry runs leave them intact. A cacheable full
`200` with a strong validator, including revalidation, clears only the matching
configured variant's hint. Response purge counts and memory-body statistics
do not include these policy hints.

Linux verification passed:

- Full locked workspace tests and the 724-test combined Wasm/PHP/load-balancer
  server suite.
- 28 focused slice tests, including 100,000-key capacity churn, deterministic
  expiry, non-extension, variant isolation, recovery and purge behavior.
- Real TCP request-sequence checks across memory, filesystem and storage-bin
  policies: repeated requests skip discovery until purge resets it.
- A 32-request concurrent test with the ordinary cache-pass predictor disabled:
  one failed discovery probe followed by 32 intact original-range responses.
- Five live standalone slice restart cases, strict Clippy, minimal compilation,
  14 Python fixture tests, documentation checks, formatting and modularity.
- RustSec and cargo-deny, with no dependency or manifest changes.

This follow-up was not rerun on native Windows/macOS or in a fresh container;
their preceding strong-validator qualification is recorded above. Native CI
acceptance and independent retest remain required. This is a short-lived
availability optimization, not a process-wide origin request limit: initial
probes, key churn, capacity pressure and already-running unlocked fills can
still generate additional origin traffic.

## Test Fixture Code Scanning Review

Four CodeQL alerts on `0782b82a` were reviewed. None targets production Rust
request handling or changes the accepted slice-integrity/backoff contract.

- Alert 455: the loopback Python origin reflected `Accept-Language` into its
  ETag. It now maps requests to two fixed representations and emits literal
  strong ETags. New real-HTTP regression tests cover valid languages, unknown
  and quoted values, oversized fixture input, and obsolete folded header text.
  Response headers must contain no injected field or embedded line break.
- Alerts 456 and 457: directory iteration in the corruption test starts from
  its own newly created private temporary directory and only inspects cache
  files written by that test. It takes no external archive, request path or
  operator-supplied directory. These are test-only false positives under the
  trusted test-workspace boundary, not a production path traversal finding.
- Alert 458: the concurrency regression re-executes the current test binary
  with a literal test name, fixed arguments and no shell. Process isolation is
  necessary to test the full disk-worker budget without contention from other
  parallel tests. The binary and test workspace belong to the trusted developer
  or CI environment; replacing them already permits same-identity code execution.
  This is a test-only false positive, not command injection through Fluxheim.

No Rust test is disabled or weakened and no scanner rule is suppressed. With
explicit maintainer approval, alerts 456, 457 and 458 were dismissed on GitHub as
false positives, each with a rationale linking to this evidence. Alert 455 was
not dismissed: it requires reanalysis of the pushed correction before GitHub
can mark it fixed.

Verification: all five slice Python fixture tests, eleven cache example tests,
28 focused Rust slice tests, five standalone live restart cases, Python syntax
and diff checks passed. No production Rust or dependency file changed.
