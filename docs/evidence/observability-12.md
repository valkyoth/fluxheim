# Commit 12: Operator Documentation And Refreshed Candidate

Date: 2026-10-29. Status: candidate checks completed with the approved generic
RPM scope and measurement limits below; independent pentest and
exact-checkpoint GitHub acceptance pending. This is not release authorization.
Commit 13's whole-product documentation and website work is still required.

## Candidate Identity

The owner approved compatible dependency updates in this checkpoint. Runtime
candidate **babbe3e71e439e6c9f8cbf626dfc50493c0794bf**, Rust **1.99.1**, updates
27 production lockfile packages and the corresponding fuzz dependencies.
Wasmtime/WASI stays at 50.0.0. No production Rust implementation was changed.
The later checkpoint adds operator documentation, example tests, alerts and a
performance-harness correction; it does not change those runtime build inputs.

All remote builds used a clean checkout of that candidate. Local builds used
the same runtime inputs with documentation/test changes present. Archive
documentation is therefore a development snapshot, not the final release
documentation payload. [Archive identities and checksums](observability-12-archives.json)
identify exactly the tested files. Neither self-reported build IDs nor hashes
are independent provenance. No signed 1.9.0 tag or publication is authorized.
Final publication must package the accepted documentation, and runtime/build
input changes require affected qualification again.

## Native And Collector Results

| Qualification | Result |
| --- | --- |
| Seven native profiles on Linux x86_64, Linux ARM64, Apple Silicon and Windows x64 | 28 passed; 56 TAR/ZIP archive checksums recorded |
| Extracted full and Wasm with real Collector/Prometheus/Jaeger, outage and recovery | Eight platform/profile runs passed |
| Real PHP-FPM HTTP/verified HTTPS on Linux x86_64, ARM64 and macOS | Passed using external TCP FastCGI |
| Real native Windows PHP-CGI HTTP/HTTPS through VM loopback forwards | Passed; not managed Windows PHP |
| Packaged Wasm policy execution on all four platforms | Passed |
| Native Windows filesystem security and configuration ACL tests | 11 and 19 passed |
| Grafana and SigNoz stored signals, dashboard rendering, canaries and fault recovery | Passed with both real stacks |
| Prometheus alert rules: healthy, down, missing and telemetry-loss fixtures | Passed with pinned Prometheus 3.15.1 promtool |

The [Commit 11 procedures and boundaries](observability-11.md) apply unchanged;
this is a new execution against the refreshed dependencies, not reused evidence.
Local raw reports are under `release-reports/commit12-collectors` and the
`/tmp/fluxheim-12-*` qualification logs. The collector summary records six
correlated traces, observed sink failure and graceful shutdown under traffic.
Grafana and SigNoz screenshots were also inspected for populated panels.
Backend versions and immutable images remain in
[`images.json`](../../examples/observability/images.json).

## Operator Examples And Regression Checks

The [new overview](../guides/observability.md) links signal-specific references,
explains reload versus restart, loss/privacy, audit ambiguity and platform
restrictions. The [management handoff](../reference/management-api-handoff.md)
separates implemented routes from future configuration/jobs/fleet management.

The local TOML example passed the actual config tester and a live static HTTP,
Prometheus scrape, structured-access-record and graceful-shutdown check. Its
OTLP fragment is tested with the base file, without implicitly trusting traffic.
Config example tests passed with telemetry features (three), minimal features
(two), and privacy mode (two), including remote-plaintext rejection. Alert rule
tests now run inside the required collector gate, not just as a one-time check.

Other completed checks: full locked workspace tests, fresh RustSec audit of
449 packages with no advisories, cargo-deny policy, native-archive negatives
(20), collector regressions (46), release-helper tests (21), metadata/scope/docs
checks, PowerShell release policy, and the performance harness tests (five).
Exact-checkpoint CI, CodeQL and independent whole-release pentest remain
external acceptance gates; an earlier green run is not substituted for them.

## Performance And Bounds

[Compact measurements](observability-12-performance.json) retain all six run
summaries and binary identity; only individual latency samples are omitted.
The original `results.json` SHA-256 is
`563f450b2207e45f2d9738f613685338dd016bc958c0e2b81bd9c41c96ff9d56`.
Three paired runs used 10,000 requests each, eight clients and two runtime
threads on Linux x86_64. Median observations:

| Measurement | Off | On |
| --- | ---: | ---: |
| Throughput, requests/sec | 3757 | 3698 |
| p99, ms | 3.198 | 3.167 |
| Process CPU, seconds | 1.37 | 1.42 |
| Peak RSS, MiB | 19.72 | 21.51 |
| Shutdown, seconds | 1.015 | 1.015 |

These are noisy local observations, not portable performance guarantees or a
claim that logging improves latency. Access records are rate-limited (300 per
enabled run); this is not lossless per-request logging. The fixture deliberately
uses untrusted unsampled traffic, so zero exported traces is expected. Real
sampled trace delivery is proved by the separate collector matrix above.
The harness now counts structured access records as well as legacy access
targets; previously it incorrectly reported zero for the new schema.

The saturated-pipe test passed both recovery and shutdown for legacy and typed
logging: 128 pending records, 664,576 queued payload bytes, 1,077 queue-full
observations, and zero writes before drain. Measured p99 was below 0.27 ms and
peak RSS below 21.3 MiB in that fixture; the bounded shutdown assertion passed.
This validates the tested queue/deadline behavior, not a hard real-time OS I/O
guarantee. Quantitative platform-wide throughput/CPU/RSS budgets still need
operator acceptance; native platform functional tests are not that measurement.

Additional three-pair runs used the same full-profile runtime on
[Linux ARM64](observability-12-performance-arm.json) (10,000 requests/sample)
and [macOS](observability-12-performance-macos.json) (1,000 requests/sample).
ARM median throughput was 2458 off / 2450 on, p99 4.609 / 4.624 ms, CPU
2.37 / 2.46 seconds, RSS 26.04 / 30.86 MiB and shutdown about 1.015 seconds.
Mac throughput was 2789 / 2752, p99 5.837 / 6.121 ms and shutdown
1.046 / 1.053 seconds. Mac CPU/RSS are null, not zero: this harness only reads
those counters on Linux. No comparable Windows performance run is claimed.
The observed deltas remain below the baseline proposal's investigation triggers
(5% throughput, 10% latency/CPU with the stated noise floor, buffers +16 MiB).
This is not proof of unchanged performance against an old binary or a
feature-stripped build; both modes use the same compiled candidate.

The first ARM fixture was rejected for group-writable files under its default
umask; rerunning with `umask 077` passed without weakening validation. The Mac's
60,000 short-lived-connection attempt exhausted its ephemeral-port pool;
the smaller run passed without changing OS socket settings. Raw-result SHA-256:

- ARM: `3cb2735ac36354cb2b3844fb9481e6a89d1b55dc0c9b0b669df5c506c6449aeb`.
- macOS: `1eb8cc7ce1bb74bace3369cf18826a35440720dcc79a56e79b997f910f1cf177`.

## Deep Gate Ledger

The deep gate exited 0 in `release-reports/20261029T142358Z-release`, with RPM
explicitly excluded and qualified separately as approved below. Together these
cover the approved generic-RPM scope, not the failed native-RPM variant.
The log SHA-256 is
`e64bc985fb0ecb2348010c63f8ff9900676d3d68b42be3d57c9f1f4d216bcca1`.
It passed workspace lint/tests, feature matrices, OWASP regression baseline,
live cache/storage/encryption/peer fill, OpenBao, Redis/MySQL/Postgres health,
WordPress external and managed PHP modes, Wasm, all four managed PHP images,
privacy, dependency policy, SBOM, TLS backends, FIPS-capable image/provider
smokes, TLS scan, load, framing, fuzz compilation, isolated ACME bind-mount,
required images and both required collector stacks. FIPS-capable tests are not
deployment certification. The optional UDP and Wasm-container switches are not
enabled by the deep wrapper; both were run separately afterward and passed:
`smoke_udp_proxy.sh` (25 iterations) and `smoke_wasm_container.sh` (read-only
plugin mount and actual policy execution).

Default-feature Linux `fluxheim` binary equality across two target directories
passed with SHA-256
`a17b57e3f555d3d5831c2a8091df4b7be341524d85613225ba8d02a90ce3474d`.
This is same-host default-binary reproducibility, not all-profile archive
reproducibility or independent trust-domain provenance. Generated SPDX and
CycloneDX SBOMs have SHA-256 respectively
`cda38f72a78639445556513f2c9cbf3bd0b886d3151d340876221bc49796df44`
and `db538a12d5d40b192ad46ed25fa649cff809d8554c55b6ee483a94e160c391c7`.
The fresh deep-gate audit loaded 1,386 advisories and found none applicable.

Local report directories retain earlier attempts instead of overwriting failures:

- An existing 503-line root validator exceeded the modularity threshold. A
  scoped [temporary exception](modularity-exceptions.md) records the required
  future split; security-reviewed ACME validation order was not refactored here.
- Freshness correctly blocked the old dependency graph; the owner approved
  the refresh, then all native profiles were rebuilt.
- Formatting caught the new test file before formatting was applied.
- One proxy-cache smoke hit its five-second curl deadline during concurrent
  builds. An isolated unchanged rerun and the subsequent gate passed it; the
  timeout was not raised to conceal the failure.
- WordPress proxy/TLS hit occupied port 18080, already used by the dedicated VM.
  The rerun uses the existing smoke's port overrides (28080/28140/28443 and
  generic smoke port 28081), without changing VM networking or assertions.
- The CPU-native RPM build and its isolated identical retry both crashed Rust
  1.99.1's LLVM backend with SIGILL compiling `p256` 0.14.0 with
  `-C target-cpu=native`. The owner explicitly approved qualifying the standard
  generic RPM and documenting native optimization as blocked. The gate now
  defaults to the helper's generic mode; `FLUXHEIM_GATE_RPM_BUILD_TYPE=native`
  remains an explicit option. No compiler flag workaround or dependency
  downgrade was applied. Generic RPM build and installation passed separately,
  including config validation and HTTP serving as the packaged non-root user;
  the remainder of the deep gate records `FLUXHEIM_GATE_RPM_BUILD=0` so this
  exclusion is visible, not represented as a native pass.

The development binary RPM `fluxheim-1.9.0-1.fc44.x86_64.rpm` SHA-256 is
`5ed065eefbb3ed10fae1de494ebdbce1bff88eb13156c73b34a9d253e0a42dde`.
It is unsigned, built by the local convenience helper, and not a published
release-spec SRPM/repository build. The first install fixture lacked `cmp`;
installing the fixture's `diffutils` dependency made the unchanged package
pass the exact HTTP-body comparison. No host RPM installation was performed.

The refreshed runtime candidate's GitHub [Rust CI run](https://github.com/valkyoth/fluxheim/actions/runs/40883140534)
and [scanning run](https://github.com/valkyoth/fluxheim/actions/runs/40883138393)
are green. The final documentation/tooling commit still needs its own checks.

Next acceptance steps: review this checkpoint and its measurement limits, run the
incremental pentest from `390cfc9c` and whole-release review from `v1.8.3`, obtain
green CI/CodeQL on the exact checkpoint, then await owner approval for Commit 13.
