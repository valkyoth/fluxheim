# Commit 11: Native Platforms And Extracted Archives

Date: 2026-10-29. Status: implementation and native qualification complete;
independent pentest and exact-checkpoint GitHub acceptance pending.
This does not authorize a 1.9.0 release or advance to Commit 12.

## Candidate And Results

Runtime candidate: `4b4864c0c098bdc029d200ae55189eeb3fa67fab`, Rust **1.99.1**,
Fluxheim **1.9.0 unreleased**. This checkpoint changes qualification scripts,
CI and documentation, not Rust runtime sources, manifests or lockfiles.

The [machine-readable archive report](observability-11-archives.json) records
the native host, version/build identity, checks and SHA-256 of both formats
for each profile. These are development artifacts, not signed release assets.
Their source was independently checked out at the exact candidate on each
remote host. Qualification scripts were then copied into those checkouts;
no runtime sources were patched there.

| Native platform | Host | Profiles | Result |
| --- | --- | --- | --- |
| Linux x86_64 GNU | Linux 7.2.11, glibc 2.44 | All seven | Passed |
| Linux aarch64 GNU | AWS ARM, Linux 7.0.0, glibc 2.43 | All seven | Passed |
| macOS aarch64 | Apple Silicon, macOS 27.0.1 | All seven | Passed |
| Windows x86_64 MSVC | Windows 11 build 26300, dedicated KVM guest | All seven | Passed |

All seven means `full`, `wasm`, `cache`, `proxy`, `load-balancer`, `php` and
`config-tester`: **28 native profile runs, 56 archive checksums**.
No cross-compiled execution, Wine or skipped collector gate substitutes for
these results. Linux musl, older OS versions and Windows ARM are not qualified
by this matrix.

## Package Contract

`scripts/smoke_native_archives.py` verifies tar/ZIP payload equivalence, bounded
member counts/sizes, safe paths, executable architecture and candidate identity.
It rejects archive links, special files, duplicate/case-aliased names, Windows
device names and traversal. It extracts into a fresh private fixture, creates
files exclusively and rechecks each extracted payload hash. Archive ownership
and permissions are not restored; only validated executable files become
executable. Archive inputs and the host owner remain trusted build-domain
inputs, not independently authenticated release provenance.

Every server profile then runs from the extracted directory:

- HTTP proxy and certificate-verified HTTPS, including concurrent requests.
- Exact compiled capability inventory through authenticated operational status.
- Static serving, memory-cache MISS/HIT, disk-cache MISS/HIT and two-origin
  round-robin selection wherever those capabilities are compiled.
- Unsupported PHP/cache configuration rejection. Feature-off metrics settings
  remain accepted for shared configs, but capabilities stay false and no metrics
  listener opens. This is intentionally different from rejecting an unavailable
  request-serving module.
- Protected file rotation, replacement/recovery, concurrent reload and status
  checks using the existing file-lifecycle harness.
- Bounded graceful shutdown with ongoing traffic: SIGTERM on Unix, the existing
  native console CTRL_BREAK helper on Windows. Exit must be successful. This is
  separate from the rotation harness's forced Windows cleanup.

The config-tester runs valid and invalid configuration cases; it is not treated
as a server. Its CLI takes `--config`, not the server's `--validate-config`.

Windows additionally passed 11 native security-helper tests and 19 filesystem
trust tests, including junction rejection, retained handles, ACL inheritance,
confidential creation/reopen and directory flush behavior. The external packaged
profile harness passed proxy, round-robin routing, cache restart/persistent HIT
with origin offline and full-profile HTTP/HTTPS from the Linux host through the
dedicated VM's loopback port forwards.

## Real Collectors

Both extracted `full` and `wasm` binaries passed on **each of the four platforms**:

1. Send HTTP and certificate-verified HTTPS requests with sampled trace context.
2. Observe stored traces in Jaeger and counters/histograms in Prometheus,
   selected by a fresh per-run service identity, not a prior run's data.
3. Stop the actual OpenTelemetry Collector container, continue serving requests,
   and observe exporter failure counters increase locally.
4. Restart that container and require a newly generated HTTPS trace and stored
   request-counter value above the local pre-recovery count to arrive. A cached
   Prometheus sample or mock collector response is not sufficient.

Backends are the existing digest-pinned OpenTelemetry Collector **0.163.2**,
Prometheus **3.15.1** and Jaeger **2.22.0** from
[`examples/observability/images.json`](../../examples/observability/images.json).
Only these backends and a namespace-owner fixture ran in this test; Grafana and
SigNoz dashboard qualification remains the separate [Commit 10 proof](observability-10.md).

The controller ran containers on Linux, publishing only numeric loopback
addresses. Remote collectors/APIs were reached through SSH reverse forwards,
also bound to loopback. Plaintext OTLP existed only at those loopback endpoints;
the cross-host transport was authenticated SSH, not exposed HTTP. No production
credentials, public collector listener or production CA was used.

## PHP And Wasm

The extracted PHP profile on Linux x86_64, Linux ARM and macOS passed real PHP-FPM
POST-body execution over HTTP and verified HTTPS. A disposable pinned PHP
**8.4.27** FPM image supplied external TCP FastCGI. The identical PHP fixture was
mounted read-only at the guest's script path inside that container; host roots,
source trees and credentials were not mounted. For remote hosts, loopback SSH
forwards carried FastCGI and the externally issued HTTP/HTTPS test requests.
This proves external FastCGI support, not managed PHP-FPM on macOS or ARM.

Windows separately passed `smoke_windows_public_php.sh` with real checksum-pinned
native PHP **8.4.25** `php-cgi.exe`, executing GET and POST requests from Linux
through the VM forwards. Managed Windows PHP remains unsupported.

Extracted Wasm packages passed the existing policy examples on Linux x86_64,
ARM and macOS, and the archived allow/deny policy test on Windows. No system-wide
PHP installation, toolchain weakening or changes to another project's VM were
needed.

## Reproduction

Build in a clean checkout of the exact candidate, on its matching native host.
The candidate must have a commit-bearing development build identity; for CI
qualification (including tag-triggered CI), explicitly use
`FLUXHEIM_BUILD_ID=qualification-g<eight-character-commit>` when building. This
metadata convention is not a signature or independent provenance check.

```sh
sh scripts/build_release_assets.sh 1.9.0 --kind linux
python3 scripts/test_native_archives.py
python3 scripts/smoke_native_archives.py --version 1.9.0 \
  --commit 4b4864c0c098bdc029d200ae55189eeb3fa67fab \
  --target x86_64-unknown-linux-gnu --report native-archives.json
```

Use `--kind macos` and `aarch64-apple-darwin` on Apple Silicon, or
`aarch64-unknown-linux-gnu` for Linux ARM. Python 3.11+ is required; on macOS use
the qualification venv rather than the older system Python. Windows uses
`build_release_assets.ps1 -Version 1.9.0 -Architecture x86_64`, then the same Python
runner with `--target x86_64-pc-windows-msvc`. Its existing `pwsh.exe` console
helper provides graceful termination. Do not enable `PYTHONOPTIMIZE`.

Real collector lifecycle is an explicit controller/runner protocol:

```sh
python3 scripts/native_collector_backend.py --runtime podman
# Read the printed loopback port map. Forward these to the remote host if needed.
python3 scripts/smoke_native_collector.py --version 1.9.0 \
  --target x86_64-unknown-linux-gnu --profile full \
  --otlp OTLP_PORT --prometheus PROMETHEUS_PORT --jaeger JAEGER_PORT
```

At runner `OUTAGE_READY`, send `stop` to backend stdin. Only after its
`collector stop: ok`, send `stopped` to runner stdin. At `RECOVERY_READY`, send
`start` to the backend and, after confirmation, `started` to the runner. Repeat
for `wasm`; finish with backend `quit`. Missing acknowledgements fail within
180 seconds. Backend cleanup targets only its randomized owned containers.
For remote runs use SSH `-R 127.0.0.1:REMOTE:127.0.0.1:LOCAL`, host-key checking
and `ExitOnForwardFailure=yes`. Do not bind these APIs to public interfaces.

`smoke_native_php.py` provides the equivalent extracted PHP frontend protocol:
it prints `php_root`, expects `started` after real FPM is listening on loopback
39000, then prints `READY`. Mount the fixture's exact `index.php` read-only at
that script path in the pinned PHP container. Test POST `/index.php` through
HTTP 39080 and HTTPS 39443 using the repository localhost test CA; require
`native-php-proof|POST|native-body` for body `native-body`. Send `stopped` only
after both checks pass. Use loopback SSH forwards for a remote frontend.

## Remaining Release Gates

Focused validation also passed: 14 archive/controller regressions on each native
OS, 46 collector-harness regressions, 12 rotation-fixture tests (the one
Windows-native test is skipped in the Linux unit run), documentation-layout,
release-metadata and observability-baseline tests, Windows release-policy
validation, portable-plan validation, Python compilation, YAML parsing, Markdown
links, Rust formatting and diff checks. RustSec reported zero known advisories
across 449 locked dependencies. No full Rust workspace rerun is claimed for this
script/documentation-only checkpoint; native packages were built and executed,
and the targeted Windows filesystem suites ran as described above.

The CI change makes extracted-profile checks mandatory on Linux x86_64, macOS
and Windows and uploads their machine-readable reports. Native ARM and the
cross-host collector/PHP lifecycle remain explicit qualification runs, not
claims that every GitHub job starts those external hosts automatically.

These results qualify this development runtime candidate, not a future changed
one. Commit 12 must rerun affected native/container gates on the final candidate;
Commit 13 documentation acceptance, independent pentest and green exact-SHA CI
are still required. No new security, signing, durable-audit or reproducibility
guarantee is inferred from a successful build or its checksum.
