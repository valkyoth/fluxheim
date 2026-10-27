# Commit 09: Read-Only Operational Contract

Date: 2026-10-27. Base: `fa2f5381dc04ca35035fca902378b4ff090b30b1`.
Status: implemented and locally qualified; pentest and exact-SHA GitHub checks
remain required. This is not release acceptance or authorization for Commit 10.

Commit 08 was accepted after the owner's clean retest and verified green
Rust CI run `40390306858` plus the code-scanning workflow on `fa2f5381`.

## Boundary

The new `GET /_fluxheim/operational-status` uses the existing admin listener,
bearer authentication and HTTP client-certificate policy. It has no unauthenticated
health exception, including when the configured public health path collides.
The Unix operations socket requires a bearer token for this route even when other
local reads do not. The pentest follow-up adds an optional distinct status-only
credential; see the follow-up verification below. Full role management remains
outside this checkpoint.

The observer uses cached, fixed-size configuration counts and short nonblocking
reads. It does not enumerate snapshot files, contact backends/collectors or mutate
recovery. Existing routes and watchdog recovery semantics are unchanged. An
expired or failed rollback is visible as `recovery_required`; subsequent admin
confirmation remains blocked by the existing enforcement. Telemetry degradation
is independent of this control-plane readiness signal.

Collection admits four readers, caps serialization before growth at 16 KiB and
checks a 50 ms elapsed budget. It returns fixed 503 errors on lock contention,
poisoning, admission exhaustion, size overflow or budget expiry. This is bounded
work, not a hard real-time scheduling/network guarantee. Inventory publication
visits at most 1,024 scopes; incomplete counts are marked explicitly. Configuration
labels, paths, credentials and snapshot identities are not copied into the result.

Generation is scoped to a random process-local admin instance, starts at one,
and increments on apply. Last-change completion records cover reload/live rollback
and automatic/manual self-heal rollback, including failure. They are not durable
audit records or atomic transactions with the independently sampled telemetry.
Subsystem runtime measurements that are not available without potentially expensive
enumeration remain `unavailable`, never invented zeros or claims of health.

See the [operator contract and limitations](../guides/operational-status.md),
[OpenAPI 3.1 description](../reference/operational-status.openapi.json), and
[JSON Schema](../reference/operational-status.schema.json). Schema validation uses
pinned Python development tooling only. No Rust manifest or lockfile changed.

## Verification

### Pentest Follow-Up (2026-10-27)

The review of `6e6b003f` identified excess privilege for monitoring consumers
and version-only Python dependency pinning. Both are addressed:

- Optional `admin.operational_token_file` uses the existing confidential-file
  trust boundary, bounded reads and zeroized plaintext. Startup rejects the same
  credential as the control-plane token. Unix permits root or the service owner,
  not arbitrary owners; Windows enforces confidential ACLs. This supports rootless
  deployment without weakening the existing secret-file policy.
- Both token comparisons are evaluated before route authorization. Only the exact
  GET observer route accepts the limited credential. Other protected routes,
  mutation admission and recovery enforcement are unchanged. Client-certificate
  policy and failed-authentication throttling still apply. Public health and
  explicitly tokenless Unix socket reads retain their existing public/local policy.
- Configuration merging, relative path resolution, missing/empty/large/duplicate
  tokens, Unix public permissions/symlinks, Windows Everyone-read ACLs, HTTP/socket
  authorization, expired recovery and throttle/certificate policy have regressions.
- Python tooling now has a wheel-only SHA-256 lock for CPython 3.10-3.14 on the
  supported host architectures. CI requires hashes and reinstalls the locked
  artifacts rather than trusting already-installed distributions. The additional
  typing-extensions pin closes referencing's Python-before-3.13 dependency.
  Hashes establish artifact consistency, not proof of trustworthy upstream code.
- Six Python contract/security tests pass, including offline pip rejection of a
  substituted wheel and an unhashed dependency. Hash-enforced fresh installs passed
  on Linux, native macOS and native Windows; Linux CPython 3.12 wheel resolution
  also passed.
- Full locked Linux workspace, strict observability/PHP Clippy, privacy tests,
  documentation checks, Windows release-policy validator, RustSec audit and
  cargo-deny passed. No Cargo manifest/lockfile changes.
- Updated live API tests passed on Linux, Apple Silicon macOS and Windows x64:
  observer reads succeed, observer mutations/snapshot reads fail, and control
  reload/rollback plus telemetry failure/recovery still work.
- Native Windows library suite: 284 passed, including all four applicable observer
  security tests and the confidential ACL rejection. Native macOS library suite:
  306 passed, plus strict Clippy and live API. macOS became unreachable for the
  final test-only rerun (additional throttle case and a narrowed Windows path
  assertion); production code was unchanged from its successful run. Exact-SHA
  native CI and a fresh pentest remain acceptance gates.

### Initial Commit Qualification

- Full locked Linux workspace: passed after the final code/test changes.
- Observability/PHP profile library tests: Linux 306, native macOS 302 and
  native Windows 280 passed. Native platform counts differ because Unix-only and
  Linux-only regressions are conditionally compiled.
- Focused operational/reduced-profile tests: Linux/macOS 14 and Windows 13 passed.
  Privacy-mode operational tests: 14 passed on Linux.
- Full Unix feature-profile admin suite: 124 passed on Linux.
- All-features observability suite: Linux/macOS 72 and Windows 70 passed, plus
  one compile-fail documentation test on each platform.
- Strict observability/PHP all-targets Clippy: Linux and macOS passed.
  Linux all-features observability and web-only Clippy passed. Native Windows
  Clippy was unavailable in its administrator-protected compiler installation;
  that installation was not modified. Native compilation and execution passed.
- OpenAPI/schema validation and positive/negative fixtures: four Python tests
  passed on all three native platforms. The client rejects unsafe origins before
  connecting and never needs server-file access.
- Live operational API tests passed on Linux, Apple Silicon macOS and Windows,
  with both observability/PHP and reduced proxy/web binaries. They verify auth,
  schema, redaction, generation, failed reload, successful reload/rollback, restart,
  concurrent polling, and metrics/trace collector degradation and recovery while
  public serving and readiness remain available.
- Existing live OTLP lifecycle and HTTP/1.1, TLS HTTP/2, FastCGI, WebSocket,
  retry/cancellation, request-correlation and exact-metric smokes passed on all
  three platforms. No public CA or customer traffic was used.
- Regression tests cover a broken snapshot store, pending validation, failed
  rollback preservation, certificate-policy enforcement, health-path collision,
  oversized inventories, size/deadline/admission bounds, busy state locks and
  concurrent reads. The existing recovery/audit-admission suites also passed.
- RustSec audit: 449 locked packages, no known vulnerabilities; full cargo-deny
  policy passed. Formatting, documentation links/layout, modularity, Python
  compilation and diff whitespace checks passed.

## Native Reproduction

Native environments: Rust 1.99.1 on Linux x86_64, Apple Silicon macOS 27.0.1
(26A434), and dedicated Windows 11 x86_64 KVM guest build 26300.9711. Windows ran
as the non-administrator build identity using the established read-only compiler.
macOS used the existing private Fluxheim development directory and isolated
Python 3.14 environment. Windows used its private Python 3.13 environment.
No other project's directories, compiler installations or VM baselines changed.

Source transfer SHA-256:

```text
d8a132f082a1fa6148ae6a88ce60ea537e3a6926acf07724949e96e438ee0fb5  initial source archive
8f951326653b383e0148146585d1ad9b427948b0afe5746de45ab33c7dbcdd8c  final code/test overlay
```

The final overlay added explicit deadline, certificate-policy, broken-store and
pending-validation regressions and expanded live exporter status checks to both
signals. Both hosts verified the archive hashes before extraction and reran their
profile tests and live operational tests. These hashes identify transferred test
inputs, not independently built release artifacts. Documentation and CI wiring
were finalized locally afterward. Windows shut down normally after qualification.

Core commands (Windows uses `cargo.exe`, `python.exe` and `fluxheim.exe`):

```sh
cargo test --locked --no-default-features --features profile-observability,php-fpm --lib
cargo test --locked -p fluxheim-observability --all-features
python scripts/test_operational_status_contract.py
cargo build --locked --no-default-features --features profile-observability,php-fpm --bin fluxheim
python scripts/smoke_operational_status.py --binary target/debug/fluxheim
python scripts/smoke_otlp_lifecycle.py --binary target/debug/fluxheim
python scripts/smoke_request_correlation.py --binary target/debug/fluxheim
cargo test --locked --lib --no-default-features --features proxy,web operational_
cargo build --locked --no-default-features --features proxy,web --bin fluxheim
python scripts/smoke_operational_status.py --binary target/debug/fluxheim --reduced
```

CI now includes the schema/API checks on all three native OS gates. Packaged
archives, ARM Linux and actual Grafana/SigNoz stacks remain later checkpoints;
these development-binary tests do not replace that release qualification.
