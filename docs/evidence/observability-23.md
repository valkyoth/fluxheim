# Commit 23: Required Disk Cache Lifecycle

Base: `12f4e3fe54db7335484efb14a5496a09e04f2f14`.

## Contract

Enabled proxy disk tiers must initialize successfully before their router can
serve. Backend, key, index recovery and index-service failures propagate through
root, vhost and route construction. Disk-only and tiered configurations cannot
silently continue without the configured disk cache. Errors exposed to operators
are bounded; encryption failures retain their existing operational reason code.

A process-local registry shares the disk cache only between compatible
unencrypted policies in the same representation context, scope and canonical
root. All cache settings
must match except `status_header` and `status_reason_header`. Entries are weak,
so the registry does not extend allocator lifetime, and at most 4,096 live roots
are admitted. Separate scopes/policies need separate roots, including at initial
startup. This does not add a filesystem-backend cross-process lease or promise
multi-writer safety. Storage-bin ownership remains exclusive across processes.

Incompatible live-root policies and all encrypted-root reloads require a
stop/start or a fresh independent root. Even an unchanged encrypted policy is
rejected before key loading/migration can alter a root still used by the active
generation. No encrypted migration or key-rotation semantics were broadened.

A rejected candidate leaves the active router and runtime snapshot unchanged.
Admin reload currently reports HTTP 500 for construction failures; it does not
undo prior publication of the snapshot store's current pointer. Pinned requests
retain their generation. Memory entries and in-flight fills are not transferred.
Shared disk state is counted once in runtime totals and registered once per scope
for disk purges.

Storage-bin initialization writes its initial checkpoint synchronously and
propagates failure. Final teardown closes its background task and attempts the
final flush before releasing the backend lease. A retained worker cannot later
overwrite a newer generation's index. Later writes and shutdown flushing remain
best-effort, not durable-database acknowledgements; missing indexes still start
cold and filesystem recovery retains its existing limitations.

Configured Rust proxy builders return initialization failure to callers.
Unscoped cache attachment helpers are now test-only; production construction
binds the effective router context. No dependency version, lockfile,
authentication, TLS, CodeQL or release-gate policy changed. The already-locked
`serde_json` dependency is now unconditional in the server crate for canonical
configuration hashing.

## Regression Coverage

- Filesystem/storage-bin, disk-only/tiered, plain/encrypted startup and restart.
- Compatible reload, rejected policy and late candidate failure, rollback,
  pinned old generations, task cancellation and lease release.
- Manifest mismatch, competing allocator, missing encryption key, unusable
  root and corrupt index; failed recovery preserves the corrupt index bytes.
- Encryption identity remains unchanged after rejected live-root candidates.
- A blocked final flush retains the lease; retained tasks cannot overwrite an
  index after teardown. Shared disk metrics do not duplicate generations.
- Live authenticated reload/rollback, unchanged runtime identity on rejection,
  correct bodies, MISS/HIT and origin counts, and persisted HIT after restart.
- Existing cache guide recipes, encryption, offline inspection, route isolation
  and stop/start backend/layout migration.

The final-flush regression holds the flush lock to make the teardown ordering
deterministic. Its post-teardown lease acquisition retries only `AlreadyExists`
for at most five seconds: parallel subprocess creation can briefly retain Unix
descriptors before exec. It does not weaken production lease handling.

## Qualification

Tested on 2026-11-13 with Rust 1.99.1:

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing privileged ACME test ignored |
| Native server with load-balancing | Linux 610, macOS 609, Windows 610 passed |
| Native load-balancer application library | macOS 283, Windows 259 passed |
| Strict all-target server Clippy | Linux and macOS passed |
| Strict all-target load-balancer application Clippy | Linux passed |
| Privacy profile without cache | Compiled |
| Eight live lifecycle combinations | Linux, macOS, Windows and non-root Podman passed |
| Existing live cache example matrix | Linux, macOS, Windows and non-root Podman passed |
| Full proxy-cache / storage-bin shell smokes | Linux passed, including protected operations and the new lifecycle matrix |
| Python cache fixture suite | 19 passed on Linux, macOS and Windows |
| Documentation layout / CI classification | 28 / 11 passed |
| Formatting, Python compilation, shell syntax, documentation links and diff checks | Passed |
| RustSec / cargo-deny | 449 locked dependencies; 1,509 advisories checked; no advisory or policy failures |

The container used runtime image
`sha256:c3902de685ea679078f2f4e4fe597346a265441f822f46ed0533ac6e8a69434d`.
Its fixture layer adds scripts/examples and a private working directory. Tests
run as UID 65532 with no external network, all capabilities dropped and
no-new-privileges; test services use loopback only.

## Issues Caught During Qualification

The first lifetime implementation let a background task retain the allocator
lease beyond cache teardown. Windows restart testing caught this; explicit
task closure and ordered final flushing replaced that design. Two old unit
fixtures also needed explicit encrypted teardown or independent policy roots.
The broader shell smoke shared one filesystem root between different scopes;
it now gives each policy its own root rather than bypassing the new boundary.

macOS initially used a symlinked system temporary directory and Apple's older
Python. Qualification uses the existing private canonical temporary directory
and installed Homebrew Python. A PowerShell comma-separated feature argument
needed quoting, and Clippy caught a test module placed before production items.
These harness issues were corrected without relaxing runtime trust checks.
Native Windows Clippy is unavailable in its read-only toolchain; no compiler
installation or machine-wide configuration change was made.

Native release archives, ARM64 and byte reproducibility were not requalified;
they remain final release gates. Independent pentest and exact-commit GitHub
acceptance remain required before proceeding. This is not release approval or
an absence-of-vulnerabilities claim.

## Pentest Follow-Up: Representation Isolation

Review of `aa9cbb96` identified that policy/scope equality alone did not bind
shared disk state or persisted keys to the origin representation context.
The correction hashes ordered configuration serialization into SHA-256 and
uses a versioned, length-delimited namespace binding that digest, scope and
the operator's namespace. Serialization streams into the digest; it does not
retain or log a serialized copy of injected credentials.

The whole-router identity includes configured upstreams, headers, rewrites,
authorization, access policy, trusted sources and Wasm configuration. It
excludes admin/metrics configuration, operational logging settings (but retains
access/correlation settings), server listen/process settings and cache policies;
cache policies remain independently checked by the reuse registry. This is
deliberately conservative and can invalidate unaffected routes. Configured Wasm
plugins require valid content pins when caching is enabled. Origin file content,
dynamic discovery changes and external authorization state are not continuously
attested; operators must rotate the explicit namespace and retire old roots
when those changes represent a trust-domain cutover.

A changed context is incompatible with an active root. A fresh independent root
allows cutover while old requests finish. Restarting against the retired root
cannot match old-context entries, including late fills. Legacy unbound keys
start cold; files are not silently deleted. Offline preview/lookup and exact
purge use the same derivation as serving, while preview still reports the
operator's configured namespace separately.

Regression coverage includes distinct A/B response bodies, a pinned delayed A
fill released only after B activates, same-root rejection, fresh-root cutover
and restart on A's old root. It runs for filesystem/storage-bin and
disk-only/tiered caches. Live authenticated tests also reject an injected-header
change without changing the active runtime, then verify origin-switch MISS/HIT
and origin counts across all eight plain/encrypted lifecycle combinations.

Final qualification on 2026-11-13:

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing privileged ACME test ignored |
| Linux server with Wasm and load-balancing | 684 passed, including two consecutive final runs |
| Native server with load-balancing | macOS 613 and Windows 614 passed |
| Native load-balancer application library | macOS 284 and Windows 260 passed |
| Strict Clippy | Linux all-feature server and application profile; macOS server passed |
| Minimal server and cache-free privacy profile | Compiled |
| Updated eight-case lifecycle and existing guide matrix | Linux, macOS, Windows and non-root Podman passed |
| Linux full proxy-cache and storage-bin smokes | Passed, including inspection and exact-purge behavior |
| Linux peer-fill and six-case peer-variant matrix | Passed |
| Cache Python regressions / peer fixtures | 26 / 4 passed |
| Documentation layout / CI classification | 28 / 11 passed |
| Formatting, Python compilation, documentation links and diff checks | Passed |
| RustSec / cargo-deny | 449 dependencies, 1,509 advisories; no failures |

Final container runtime image:
`sha256:b14b0ce0350e7c8021d8f9680b1f9906b2a6d636043e115979015b58ea83c0b1`.
The same non-root, network-none, capability-free fixture isolation described
above was used. Native Windows Clippy remains unavailable; Linux checked all
server features and native Windows executed the tests and live matrix.

An initial Wasm-suite run encountered an initialization failure in an existing
missing-index recovery fixture. That fixture now preserves the actual I/O error
instead of reducing it to `None`. Subsequent full runs passed without retries
inside the test or weakened lease checks. One Linux shell smoke timed out at
the existing five-second revalidation request limit; the unchanged full smoke
passed on rerun. These observations are retained rather than attributed to a
proven cause. No timeout or runtime enforcement was relaxed.

Independent retesting and exact-commit GitHub acceptance remain pending.
