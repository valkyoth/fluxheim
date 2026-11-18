# Storage-bin soft purge and build-tool refresh

An indexed soft purge now expires a fresh storage-bin object instead of
deleting it. The replacement retains the encoded response headers, body,
validators, variant metadata and absolute stale deadlines. The existing
response policy still decides whether revalidation or stale serving is
permitted. Already-stale objects do not count as newly purged.

The purge holds the key's exclusive mutation stripe, writes a separate bin
extent (with fresh encryption when enabled), then checkpoints the index before
publishing the new record and releasing the old extent. It does not evict
other objects to get scratch space. A busy index or unavailable extent can
leave a fresh object in place; the operator must check continuation flags.
Checkpoint cost scales with bin index size, not just the purge batch count.
Soft purge is not a secure deletion or a fence against future fills.

## Qualification

- Restart tests compare retained bodies, validators and stale eligibility for
  filesystem and storage-bin caches, both plaintext and encrypted. Other
  regressions cover an exhausted allocator, failed checkpoint replacement and
  mandatory revalidation. See the [operator guide](../guides/cache-operations.md).
- The live fixture seeds a real proxied response, soft-purges it via the
  authenticated admin API, and observes a conditional 304 or a 503 served
  from an eligible stale copy. It checks origin request counts and all five
  memory/disk layouts alongside its existing hard-purge and metrics checks.
- Native Linux, Apple Silicon macOS, Windows 11 x64 and an isolated, non-root
  Debian Podman container passed the live fixture. The first Windows smoke
  timed out waiting for a filesystem-layout HTTP response; the complete rerun
  passed without relaxing the deadline. The cause of that timeout was not
  established. The final Windows server and web suites passed 660 and 16
  tests respectively, with one manual capacity test excluded on Windows.
- Linux workspace and all-feature server tests and all 16 CI Clippy feature
  combinations passed. Cargo itself reports unused dependency warnings for
  some feature selections; these are distinct from Rust/Clippy lint failures.
- Linux ARM64, final release archives and reproducibility are release gates,
  not results inferred from these tests.

## Soft-purge checkpoint follow-up

A storage-bin soft purge stages up to 32 examined entries per disk batch.
It writes at most one foreground index checkpoint for that bin, and none if
no fresh object could be staged. A checkpoint still costs a full index write;
this change bounds how often it occurs, not the latency of the filesystem.
The admin API limits indexed soft purges to one batch per request and four
requests per rolling second per admin app. Indexed purge work runs off the
async worker with at most two in flight, including work whose client disconnected.

- Plain and encrypted bin tests count checkpoints across a 40-object pass
  (32 then 8), re-scan already stale objects and verify persistence after
  restart. An injected checkpoint failure preserves both previous objects
  and allocator free capacity, and permits a successful retry.
- The live admin fixture checks continuation over 35 objects in all five
  layouts. It passed on Linux, Apple Silicon macOS, Windows 11 and in a
  non-root Debian Podman container without external networking. On Linux the
  metrics listener was unavailable using the pre-existing local binary; the
  rerun after building the required metrics profile passed.
- The locked Linux workspace passed. The all-feature Linux server suite passed
  820 tests with the manual capacity test excluded. The Windows server suite
  passed 661 tests with that same exclusion.

### Process-wide storage checkpoint limit

All storage-bin indexed soft purges share one nonblocking slot. After staging
a fresh replacement, the next bin scan must wait at least five seconds, even
across cache roots or after a failed write. A deferred bin scan reports
continuation without advancing its cursor. The four-per-second admin limit
is separate; ordinary background persistence is not a soft purge.

Snapshot construction and the writer enforce the reader's 64 MiB, entry-count
and encoded-key limits. The atomic file writer leaves the destination intact
when it rejects invalid input. The runtime's recovery policy for that condition
is described below. The writer sorts references instead of cloning keys.
A permitted checkpoint still processes the full index.

The Linux workspace, affected all-feature suites and strict Clippy passed.
The five-layout live fixture passed on Linux, Apple Silicon macOS, Windows 11
and in an isolated non-root Podman container. Initial native smoke runs
included HTTP timeouts; their cause was not established. A separate Windows
run demonstrated legitimate partial tier progress. The fixture now follows
explicit continuation only, with bounded attempts and exact per-tier totals;
it does not retry a timed-out mutation.

### Hard purge and restart

Per-root index reservations precede destructive store operations and include
concurrent writers. Restart applies the same conservative row budget. An
unexpectedly unpublishable snapshot freezes admission and replaces the old
checkpoint with an empty one, including on final flush. After an I/O failure,
the background worker retries the empty publication rather than rebuilding the
invalid snapshot.

Tests cover competing reservations, replacement at capacity, budget recovery
after removal and restart, legacy index headroom, and transient cold-publication
failure. The restart regression persists two real objects in one bin, injects
invalid state and hard-purges one object. Neither the plaintext nor the
encrypted bin restores the purged entry.

The Linux workspace and 825 all-feature server tests passed. Native macOS
server tests and the Windows rerun (666 server and 16 web tests) passed.
The five-layout live admin fixture passed on Linux, macOS, Windows and in
non-root Podman. The existing manual filesystem capacity test was not run.
The first Windows run returned zero instead of one in a soft-purge fixture;
the affected tests now serialize fixture creation before seeding expiring
objects, without changing production deadlines or retry assertions.

### Index capacity and LRU replacement

An otherwise admissible new bin key can displace up to eight LRU entries to
reserve index capacity. The store checks that the whole set fits, obtains the
victim stripes without waiting, then rechecks their order and reserves the
incoming row before releasing any space. A busy victim, temporary reservation,
disabled index or impossible row does not trigger index eviction. This is not
a frequency filter and does not prevent ordinary cache churn.

Regression tests use small index budgets with real bins. They check LRU order,
restart membership in plaintext and encrypted bins, concurrent stores, busy
and colliding stripes, and preservation of entries when a fill would exceed
the eviction cap. The prior hard-purge restart tests remain enabled.

The Linux workspace and all-feature server suite passed (828 server tests;
one manual filesystem capacity test skipped). The native macOS and Windows
suites passed. All five live layouts passed in Podman and on the three native
platforms. Earlier Linux and Windows live runs had loopback HTTP timeouts;
the complete reruns passed without changing the harness. Their cause was
not established.

## Toolchain

The active workspace, release metadata and Rust builder images select
Rust 1.100.0. The historical HTTP/3 probe keeps its separate compiler.
The test self-launcher checks Cargo's new per-package, per-unit-hash
executable directory rather than searching PATH. Windows runtime qualification
uses a test-account toolchain, not an official release builder.

Cargo Audit 0.23.0 reported the unmaintained chrono dependency in the web
directory listing. Local timestamps now use Jiff, already present in the
runtime graph; the UTC HTTP-date path is unchanged. The refreshed lockfile
passes both the warning-denied audit and Cargo Deny 0.21.0. No advisory was
suppressed. Rustup bootstrap downloads remain checksum-pinned; the updated
setup-python and Docker login actions remain pinned to full commit SHAs.
