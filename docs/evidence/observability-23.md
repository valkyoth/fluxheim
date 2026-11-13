# Commit 23: Required Disk Cache Lifecycle

Base: `12f4e3fe54db7335484efb14a5496a09e04f2f14`.

## Contract

Enabled proxy disk tiers must initialize successfully before their router can
serve. Backend, key, index recovery and index-service failures propagate through
root, vhost and route construction. Disk-only and tiered configurations cannot
silently continue without the configured disk cache. Errors exposed to operators
are bounded; encryption failures retain their existing operational reason code.

A process-local registry shares the disk cache only between compatible
unencrypted policies in the same scope and canonical root. All cache settings
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

The public Rust proxy cache builder methods now return `Result`; callers must
handle initialization failure. No dependency, lockfile, authentication, TLS,
CodeQL or release-gate policy changed.

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
