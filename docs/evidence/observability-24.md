# Commit 24: Bounded Filesystem Cache Recovery

Base: `ce6af1efff52434950580be2e6579c5591e8a8e9`.

## Contract

Filesystem recovery recognizes the writer's hexadecimal shard/object/temp
layout and supported format markers. Under exclusive recovery ownership it
removes identifiable invalid objects and identifiable temporary writes at least
one hour old. Ambiguous names/bytes, fresh or future-dated temps, links, special
files and undecryptable objects remain. Root encryption identities, key markers,
nonce counters and allocator metadata are not cleanup targets.

All filesystem cache handles retain a shared recovery lease. Cleanup, migration
and startup pruning require exclusive ownership before the cache becomes live;
another cache or standalone inspection handle suppresses them. Shared encrypted
inspection loads existing state without initializing or rotating it. The lease
does not introduce multi-writer index consistency or protect against the trusted
host owner changing files. Older binaries do not participate: stop every old
owner before upgrading. Never replace/remove a live lease file.

Scans are limited to 65,536 directory entries, the greater of 2 GiB or twice the
configured disk budget in charged reads, and cooperative 30-second time checks.
An exhausted budget or directory scan error rejects initialization, not merely
part of the recovered index. Previously completed cleanup is not rolled back.
Operating-system filesystem calls are not forcibly interruptible.

Recovery logs removed and retained file counts/lengths, unknown entries, failed
removals and exclusive-cleanup status. These are startup observations, not a
physical-space quota, continuous gauges or durable reclamation acknowledgements.
The [recovery guide](../guides/cache-recovery.md) explains exclusions and rollout.

Cleanup checks the retained file's single-link status on Unix and Windows;
ordinary readers retain their existing open-file semantics after unlink.
Unix opens reject special files without blocking on FIFOs. A small Windows
security helper queries link count through the existing retained handle; its
FFI is isolated from the server's unsafe-forbidden code.

Both cache lease implementations explicitly release Unix locks at teardown so
a briefly inherited descriptor cannot prolong ownership after the cache stops.
Duplicate-descriptor regressions retain that descriptor across teardown and
prove a new owner can acquire the root without losing its own lease afterward.
Temporary creation collisions no longer authorize removing an existing file.
No dependency, version, authentication, routing or TLS policy changed.

## Regression Coverage

- Valid persisted bodies survive repeated recovery; recognizable corrupt and
  oversized objects and aged partial writes are removed only on idle roots.
- Unknown bytes, legacy/nonmatching names, fresh temps, hard links, symlinks,
  FIFOs, directories and inaccessible deletion targets are preserved.
- Entry/read/time budgets fail closed; retained and failed-removal accounting
  does not claim those bytes were reclaimed.
- Active and pinned cache handles suppress cleanup across cache instances;
  actual standalone CLI inspection proves the cross-process shared lease.
- Existing encryption loading cannot create missing state, complete migration,
  rotate keys or reset nonce state. Ciphertext with an unavailable key survives.
- Live plain/encrypted restart HITs, matching bodies/origin counts, observed
  removed bytes, preserved encryption/nonce state and eviction under pressure.
- Existing lifecycle, inspection, encrypted cache, storage-bin and guide tests.

## Qualification

Qualification date: 2026-11-14, Rust 1.99.1.

| Check | Result |
| --- | --- |
| Linux locked workspace | Passed; existing privileged ACME test remains ignored |
| Linux all-feature server suite | 786 passed |
| Native server with load-balancing | macOS 630, Windows 627 passed |
| Native application library | macOS 284, Windows 260 passed |
| Windows security helper | 11 passed, including retained-handle link-count checks |
| Strict server all-feature/all-target Clippy | Passed on Linux |
| Strict native server Clippy | Passed on macOS; Windows toolchain has no Clippy installation |
| Application Clippy / privacy-profile compile | Passed on Linux |
| Python cache fixtures / documentation layout / CI qualification policy | 23 / 28 / 11 passed on Linux; Windows skips the symlink-creation fixture without that privilege |
| RustSec / cargo-deny | 449 locked dependencies, 1,509 advisories; no audit or policy failures |
| Live recovery smoke, plain and encrypted | Passed on Linux, macOS, Windows and non-root Podman |
| Existing proxy-cache / storage-bin shell smokes | Passed on Linux |
| Native lifecycle and cache guide matrix | Passed on macOS and Windows |

The Podman runtime image was built from the final runtime source as
`sha256:c3d6788f19a8542338158b9fbf7d0cdae21fe798be148d50fb09831a55de6741`.
Its Python qualification layer runs as UID 65532, without host mounts, external
network access or Linux capabilities, with `no-new-privileges` and bounded
CPU/memory. Loopback origin/server traffic remains available inside it.

The new smoke is wired into Linux's proxy-cache suite and native macOS/Windows
CI. Changing the CI workflow intentionally selects full qualification under the
existing path policy; the classifier itself is unchanged.

## Qualification Corrections And Limits

An old encrypted-migration fixture used a non-writer filename. It now exercises
the real reserved layout; separate tests prove nonstandard names are retained.
The FIFO regression uses the installed fixed-path `mkfifo` on Unix because the
Rustix helper used initially is not exposed on macOS. Native Windows needs no
new global configuration or compiler installation.

Initial broader smokes hit existing short HTTP timeouts on Linux and Windows;
unchanged reruns passed. One workspace run reported a generic peer-fixture cache
initialization failure that did not reproduce on subsequent full workspace and
all-feature runs. No production retry, weakened initialization check or longer
smoke timeout was introduced to hide those observations.

The Windows smoke initially added inheritable ACLs to a synthetic shard. A later
writer visit hardens that directory without inheritance, which removed the
fixture files' inherited access. An isolated native check reproduced that
permission failure. The smoke now inserts leftovers into the actual writer's
warm shard without changing its ACL; eviction forces another write into that
same shard and the retained-file byte assertions pass. No production ACL policy
was weakened and no permission-error retry was added.

Native release archives, ARM64 and byte reproducibility remain final release
gates and were not rerun locally for this correction. Independent pentest and
exact-commit GitHub acceptance are still required before proceeding. This is
not release approval or a guarantee of absence of vulnerabilities.
