# 1.8.3 Maintenance Qualification

Candidate preparation date: 2026-10-21; final qualification started
2026-10-22. **Not release approval.**

## Provenance And Scope

- Branch `1.8.x` starts at signed release v1.8.2,
  `6ed82b5a9ebd5b8f1bb4bc03f986edd9a33ae855`.
- Selected maintenance files come from main `792cd9d2`, including prior
  Windows helper/evidence fixes and container refresh tooling. The protocol
  probes, HTTP/3 source gate and 1.9 observability implementation plan are not
  included. Version fields and maintenance release documentation are specific
  to 1.8.3.
- External production dependency name/version pairs match the tested main
  graph; Fluxheim package versions differ intentionally. The only first-party
  runtime source change from v1.8.2 is the equivalent Rust 1.99 atomic API
  spelling in UDP session admission.

## Refresh Inventory

Rust stable was checked against the official
[toolchain manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml):
1.99.1. Rustup 1.29.2 Linux and Windows installers were downloaded and their
SHA-256 hashes compared with the official archive checksum files before pinning.
Workspace and fuzz dependency locks were refreshed through Cargo; direct
workspace dependency freshness was checked with `cargo outdated --workspace
--depth 1`.

Notable versions: Wasmtime/WASI 50.0.0 (v1.8.2 used 48.0.2), Tokio 1.54.1,
Rustls 0.23.46, sanitization 2.1.1, base64-ng 2.1.0. No prerelease provider or
QUIC library was admitted. The vendored instant-acme patch remains unchanged
and its checksum policy passes.

GitHub Actions were checked against upstream releases and retain immutable
commit pins: checkout 7.0.1, QEMU 4.4.0, Buildx 4.4.1, build-push 7.4.0, login
4.6.0. cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-sbom 0.10.0 and PyYAML
6.0.3 remain current in the configured tooling. Actionlint 1.7.12 was used for
validation. All runtime/Rust/UBI container base digests were resolved afresh
within the existing OS release lines; this is not an OS-major migration.

The isolated HTTP/3 research workspace on main is not part of this maintenance
branch or its production dependencies. Legacy external smoke
fixture release lines (for example the Jaeger v1 fixture) are not promoted
to new major versions in this maintenance patch.

## Initial Local Evidence (2026-10-21)

Linux x86_64, Rust 1.99.1, candidate working tree before commit. Test-built
archives/images are development evidence, not signed-tag release artifacts.

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked --features profile-development,wasm-proxy-abi,wasm-wasi,udp-proxy` | 2,078 passed; one mount-namespace test ignored in this invocation |
| `cargo test --workspace --locked` | 1,761 passed; one mount-namespace test ignored in this invocation |
| `sh scripts/smoke_acme_mount_boundary.sh` | The isolated mount test passed separately |
| Workspace/all-targets Clippy with the same features and `-D warnings` | Passed |
| `cargo fmt --all --check` | Passed |
| `cargo check --locked --manifest-path fuzz/Cargo.toml` | Passed; not a fuzz campaign |
| `cargo audit`, production and fuzz locks | Passed; no known advisories reported |
| `cargo deny --locked check` | Advisories, bans, licenses and sources passed |
| `cargo outdated --workspace --depth 1` | No newer direct dependencies reported |
| `sh scripts/smoke_wasm_release_asset.sh` | Linux Wasm tar.gz/ZIP built; extracted binary passed live policy examples |
| `sh scripts/smoke_1_0_core.sh` | Profile checks and live static/proxy/TLS passed |
| `sh scripts/smoke_upstream_tls_local.sh` | Verified upstream HTTPS passed |
| `cargo check --locked --no-default-features --features profile-fips-rustls` | Passed; not live provider/compliance evidence |
| Same check with `profile-fips-openssl` | Passed; not live provider/compliance evidence |
| Container refresh regressions | 15 passed |
| Windows scripts/security audit, portable plan, Wasm profile, PHP image plan | Passed |
| Release metadata/helpers, FIPS plan, vendored patch, modularity, Markdown links | Passed |
| Actionlint 1.7.12 on all four workflows; Git whitespace integrity | Passed |
| `sh scripts/smoke_wasm_container.sh` | Passed; live policy execution from a read-only module mount |
| `FLUXHEIM_PHP_IMAGE_VARIANTS=wolfi sh scripts/smoke_fluxheim_php_images.sh` | Passed; PHP 8.5.12 extension checks and live managed PHP-FPM response |

## Security Retest And Native CI (2026-10-22)

Candidate `0b6af03d9dbd868ce1add4d114f36e10677da190` adds authenticated
container-refresh source selection and digest-bound promotion. The independent
retest reported no remaining Critical or High findings; 35 adversarial refresh
tests pass. No Rust runtime or dependency changes were made by that fix.

[Rust CI run 39734670489](https://github.com/valkyoth/fluxheim/actions/runs/39734670489)
completed successfully on that exact maintenance candidate:

- Linux format/lint/default tests, feature/profile builds, configuration checks,
  isolated ACME mount regression, localhost runtime smokes, dependency audit,
  SBOM generation and default-binary reproducibility.
- Native Windows x86_64 workspace and trust-boundary tests, all seven portable
  profiles, live runtime parity, archives and packaged Wasm policy execution.
- Native Apple Silicon macOS profile checks, live static/proxy/TLS/cache/admin/
  load-balancer/observability parity, all seven archive profiles and packaged
  Wasm policy execution.

These are candidate tests, not published signed-tag artifacts. A separate
Windows VM is not needed to repeat identical native candidate checks; the
normal disposable Windows builder remains necessary when producing official
release ZIPs after tagging. Public staging-ACME and off-host Windows tests
from 1.8.2 are historical evidence, not newly executed 1.8.3 tests.

## Final Local And ARM64 Qualification

The local deep release gate and native Ubuntu ARM64 AWS candidate gate passed
against `0b6af03d` plus the following qualification fixes. These are dirty-tree
qualification builds, not final signed-tag publication artifacts.
The build/metadata fixes were subsequently committed as `a8e9bb87`; final
release documentation does not change the qualified runtime or dependencies.

- The standalone systemd example exposed rustix 1.1.5's missing `timespec`
  feature dependency in a `net`-only build. Explicitly enabling `time` fixes
  the isolated build; four boundary tests and the live systemd activation
  smoke passed locally. CI now tests the crate without workspace feature
  unification. No application Rust source or dependency version changed.
- RPM metadata now requires Rust 1.99.1, not 1.99, matching Cargo. Three
  metadata regressions cover exact patch requirements, rejection of lower
  minima, and support for a minor-only Cargo requirement.
- The initial ARM test workspace inherited Ubuntu's group-writable umask and
  was correctly rejected by filesystem trust checks. The qualification
  workspace was restricted and subsequent runs use `umask 077`. No trust
  check was relaxed. The regular release helper already uses this umask.

Local evidence is retained under
`release-reports/20261022T080342Z-release/` (not committed):
`stable_release_deep_gate.log`, `arm-gate.log`, `x64-archives.log`, and
`rpm-install-capability-smoke.log`. The initial failed local run is retained
under `release-reports/20261022T075450Z-release/`.

| Final check | Result |
| --- | --- |
| Local deep gate, `release` mode | Passed, exit 0; all optional deep checks enabled, plus Wasm container, UDP and all four standard OS variants |
| Default Linux x86_64 workspace tests | 1,761 passed; mount-namespace test passed separately in isolation |
| Linux ARM64 full workspace with development, Wasm ABI/WASI and UDP features | 2,078 passed; one privileged mount test ignored in this invocation |
| ARM64 standalone systemd tests and live activation | Passed |
| ARM64 live static/proxy/TLS, verified upstream TLS, admin, snapshot lifecycle, cache and load balancer | Passed |
| ARM64 all seven profiles, tar.gz/ZIP integrity and executable versions | Passed |
| x86_64 all seven profiles, ZIP integrity and executable versions from extracted tar.gz archives | Passed |
| Linux x86_64 and ARM64 extracted Wasm archive live policy execution | Passed |
| Linux Wasm sandbox/configuration/policy tests and read-only container module mount | Passed |
| WordPress external and managed static/dynamic/ondemand PHP-FPM; HTTPS proxy | Passed |
| PHP extension loading and live managed PHP-FPM, Wolfi/Alpine/Debian/SUSE BCI | Passed |
| Root image and full-profile Debian/Alpine/Wolfi/SUSE Micro smokes | Passed |
| Load-balancer image, OpenBao, Redis/MySQL/PostgreSQL health smokes | Passed |
| TLS backend profiles, OpenSSL and AWS-LC FIPS-capable validation | Passed |
| Isolated OpenSSL and AWS-LC provider images, downstream and verified upstream TLS | Passed; not a FIPS certification claim |
| Local TLS scan, load, UDP, request framing and privacy smokes | Passed |
| Cargo audit (449 locked dependencies) and deny | No known advisories; bans/licenses/sources passed |
| SBOM generation and fuzz-target compilation | Passed; compilation is not a fuzz campaign |
| Default-binary two-directory reproducibility, x86_64 and ARM64 | Passed |
| Fedora 44 native convenience RPM build, install, config validation and HTTP | Passed; HTTP ran as `fluxheim` with the unit's `CAP_NET_BIND_SERVICE` capability |
| Source RPM spec metadata/parse and exact compiler minimum | Passed; the vendored offline source-spec build was not rerun |
| Metadata regressions, refresh regressions, workflow lint, portable/Windows/helper validators and Markdown links | Passed |

Prometheus scraping and OTLP metrics ingestion passed. The Jaeger API was
reachable, but no Fluxheim trace was observed; trace ingestion is not a required
gate in this release and remains an existing documented limitation. Native
Windows/macOS evidence is the exact-candidate CI run above, not a new off-host
production deployment. No new public-CA issuance was performed.

## Remaining Release Gates

Wait for GitHub green on the final preparation commit, including the added
regressions. Final signed-tag
artifacts, checksums/SBOM, reproducibility and explicit
tag/publication approval remain release work. No 1.8.3 tag, image publication
or official release upload has occurred.

Wasm 50 must pass all native/platform gates as well as Linux sandbox and
policy tests; matching Linux behavior alone is not proof of platform parity.
Rebuild release artifacts from the final approved signed tag, not from the
dirty-tree smoke outputs produced during this preparation.

Automatic runtime-refresh publication remains disabled by missing trust setup:
the protected `container-refresh-release` environment and its independently
verified `FLUXHEIM_RELEASE_ALLOWED_SIGNERS` secret must be provisioned first.
This is separate from ordinary signed-tag release packaging and fails closed.
