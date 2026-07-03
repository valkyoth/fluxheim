# Release Checklist

Use this checklist before publishing a Fluxheim release, changing dependency
versions, changing TLS/cache/proxy behavior, or building an image for other
people to run.

## Version And Toolchain

- Confirm the Rust version in `rust-toolchain.toml`, `Cargo.toml`, `README.md`,
  and the `Containerfile` all agree.
- Run the release metadata preflight:

```bash
scripts/validate-release-metadata.sh
```

- Check that the pinned Rust version is still the current stable release before
  release work starts.
- Re-check the latest `cargo-deny` and `cargo-audit` versions:

```bash
cargo info cargo-deny
cargo info cargo-audit
cargo info cargo-sbom
```

Install or update the tools with locked dependency resolution:

```bash
cargo install --locked cargo-deny
cargo install --locked cargo-audit
cargo install --locked cargo-sbom --version 0.10.0
```

## Dependency, License, And Advisory Gates

- Run `cargo update` only as a deliberate dependency maintenance step.
- Before tagging, verify compatible dependency updates are exhausted. This gate
  intentionally ignores `pingora*` packages because supported Fluxheim profiles
  no longer compile Pingora; separate Pingora dependency and boundary policy
  gates verify that this remains true.

```bash
scripts/check_latest_crates.sh
```

- During the `1.6.x` native-runtime line, capture the runtime baseline evidence
  before tagging. `check` mode records locked dependency trees, proves the
  per-profile Pingora dependency surface remains empty, and includes native web
  TLS proof profiles; `release` mode also records the default release-binary
  size and local performance baseline:

```bash
scripts/capture-runtime-baseline.sh check
scripts/capture-runtime-baseline.sh release
scripts/capture-runtime-performance-baseline.sh release
scripts/validate-pingora-dependency-policy.sh check
scripts/validate-native-web-tls.sh check
scripts/validate-native-runtime-cutover.sh
scripts/validate-runtime-fixtures.sh check
```

- Review every new dependency for maintenance status and SPDX license metadata.
- Review every new build script, procedural macro, `*-sys` crate, vendored
  native source, native tool invocation, Cargo alias, and CI workflow edit as
  build-host code execution.
- Keep `deny.toml` strict: unknown registries, git sources, and unknown licenses
  stay denied.
- Keep `.cargo/audit.toml` exceptions narrow, versioned, and documented with a
  removal condition.
- For unmaintained transitive dependencies inherited from TLS backends or other
  optional integrations, prefer upstream fixes over local forks. Track the
  package, advisory ID, upstream source, Fluxheim reachability, and removal
  condition in `SECURITY.md` and release notes. Do not promote an ignored
  advisory from warning to accepted risk without a written reason.
- Run the release wrapper:

```bash
scripts/release_checks.sh
```

The wrapper runs formatting, clippy, tests, selected feature builds, example
config validation, `cargo deny check`, `cargo audit`, and localhost smoke tests.
It may include incubator-module smoke checks during development. The `0.5.x`
preview scope is basic static/proxy/TLS behavior; the `1.0` gateway scope is
defined in the versioning plan and must cover representative multi-site gateway
configs before a stable tag.

For the stable-release gate without incubator module checks, use:

```bash
scripts/stable_release_gate.sh release
```

Run the core localhost smoke directly when changing stable static/proxy
behavior:

```bash
scripts/smoke_1_0_core.sh
```

This smoke requires `openssl` for a temporary self-signed certificate. It covers
HTTP static hosting, HTTP proxying, static certificate storage validation, HTTPS
static hosting, and HTTPS proxying.

Confirm GitHub CodeQL default setup is enabled for `main`. Do not also enable an
advanced CodeQL workflow for the same repository; GitHub rejects advanced SARIF
uploads when default setup is active.

Confirm the Rust CI workflow still runs the core feature matrix in both check
and release modes, plus the `scripts/smoke_1_0_core.sh` localhost smoke.

## TLS And Certificate Storage

- Static certificate chains and private keys are supported. Bought certificates
  remain a first-class deployment mode.
- In the default rustls build, validate the default downstream certificate and
  at least one vhost-specific SNI certificate per TLS listener.
- The core smoke generates temporary static certificates and proves static,
  proxied, and SNI-selected vhosts over a TLS listener.
- ACME config and renewal queue planning are implemented, but account/order and
  challenge runtime work is not release-ready yet. Do not document automated
  ACME issuance as operational until that runtime is implemented and tested.
- Validate production-like TLS storage before startup:

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

On Unix, private keys should be owner-only (`0600`) and ACME storage directories
should be owner-only (`0700`).

## Core Build Matrix

For a `0.5.x` preview or `1.0.x` release, confirm the stable core binaries
compile. This matrix intentionally excludes post-1.0 modules such as load
balancing, metrics, admin, ACME runtime, WAF, PHP/CGI, Cloudflare automation,
legacy HTTP, and WASM.

```bash
scripts/validate-1-0-core.sh release
```

For faster local iteration before a release tag, run the same matrix as checks
instead of release builds:

```bash
scripts/validate-1-0-core.sh check
```

Validate the representative split-config fixture set before a `1.0.x` release:

```bash
scripts/validate-1-0-fixtures.sh
```

## Stable Release Security And Stability Gate

Passing memory-safe Rust builds is not enough for a proxy. Before every stable
release, run this gate against the stable modules included in that release and
record the results in the release notes. For `0.5.x`, the target is the
documented basic-sites preview. For `1.0.x`, the target is the gateway core
needed for representative multi-site configs. For later minors, include every
module promoted to `stable` in that release.

Local checks that can be run from this repository:

- Run the local gate wrapper:

```bash
scripts/stable_release_gate.sh release
```

For faster iteration before release week, run the same local gate in check mode:

```bash
scripts/stable_release_gate.sh check
```

The stable gate includes the mapped OWASP Top 10 2025 baseline in quick
`check` mode. Run the deeper representative-test mode when the release touches
request handling, admin, PHP, TLS, logging, cache, dependency, or
error-handling code:

```bash
scripts/validate-owasp-top10-2025.sh run
```

The stable gate includes the promoted cache and observability smoke tests for
the `1.2` line. In `release` mode it also requires a local container image
smoke before tagging: the root `Containerfile` plus representative Debian and
Alpine variant builds. This catches workspace, packaging, and image build
context mistakes before an immutable tag is pushed.

For `udp-proxy` beta changes, include the optional UDP smoke before tagging:

```bash
FLUXHEIM_GATE_UDP=1 scripts/stable_release_gate.sh check
```

Use `FLUXHEIM_UDP_SMOKE_ITERATIONS=<count>` with that gate for a longer local
soak when UDP forwarding, rate limits, or passive health behavior changed.

If a release builder cannot run Podman, do not skip this silently. Run the
image gate on another builder and attach the evidence before tagging. The
emergency-only bypass is:

```bash
FLUXHEIM_SKIP_IMAGE_GATE=1 scripts/stable_release_gate.sh release
```

Optional gates below still cover slower or environment-specific checks such as
TLS backend matrices, load testing, fuzz target compilation, and full Podman
variant image smoke tests.

For release-candidate validation, run the deeper local gate. It enables the TLS
backend matrix, OpenSSL FIPS-capable validation, rustls/AWS-LC FIPS-capable
validation, local TLS scan, local load smoke, raw request-framing smoke, real
Wasm sandbox execution, and fuzz target compile check:

```bash
scripts/stable_release_deep_gate.sh release
```

If the local release builder can run the rest of the deep gate but is not an
AWS-LC-supported rustls FIPS builder, disable only that gate and attach rustls
evidence from the supported builder separately:

```bash
FLUXHEIM_GATE_FIPS_RUSTLS=0 scripts/stable_release_deep_gate.sh release
```

Enable optional local matrices when the release includes those deliverables:

```bash
FLUXHEIM_GATE_TLS_BACKENDS=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_FIPS_OPENSSL=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_FIPS_RUSTLS=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_OWASP_RUN=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_TLS_SCAN=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_LOAD=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_WASM=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_FRAMING=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_FUZZ_CHECK=1 scripts/stable_release_gate.sh release
FLUXHEIM_GATE_IMAGE_VARIANTS="debian alpine wolfi suse-micro" scripts/stable_release_gate.sh release
```

For release builders that are expected to have a working OpenSSL FIPS provider,
make absence a hard failure:

```bash
FLUXHEIM_REQUIRE_FIPS_PROVIDER=1 \
FLUXHEIM_GATE_FIPS_OPENSSL=1 \
scripts/stable_release_gate.sh release
```

- Dependency and license policy:

```bash
cargo deny check
cargo audit
scripts/generate-sbom.sh
scripts/reproducible_build_check.sh
```

- Static analysis and regression suite:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
scripts/validate-1-0-core.sh release
scripts/smoke_1_0_core.sh
```

- Direct unsafe policy. Fluxheim's crate roots use `#![forbid(unsafe_code)]`;
  this is enforced by the normal compile, clippy, and feature-matrix gates.
  Do not add direct `unsafe` blocks or raw FFI to Fluxheim source. Prefer safe
  wrapper crates for platform APIs and safe task/waker primitives in tests.
- Panic and overflow policy. Release artifacts build with `panic = "abort"` and
  `overflow-checks = true`, and crate roots deny production `unwrap()`,
  `expect()`, and `panic!()` through clippy. Keep operational errors on
  `Result` or explicit fallback responses. Test-only assertions may continue
  using panicking helpers.
- Native dependency policy. FIPS-capable profiles can intentionally pull native
  cryptographic modules such as OpenSSL providers or `aws-lc-fips-sys`. Record
  the provider/module certificate, compiler, platform, and Security Policy in
  release evidence, and run sanitizer builds where supported by that native
  dependency and target platform.
- Secret handling policy. Admin bearer tokens are read into zeroing buffers,
  hashed, and compared through a vetted constant-time equality primitive.
  Keep new long-lived credentials in `sanitization` secret containers or
  existing audited zeroing buffer types, and use `sanitization::ct` for any
  equality check involving authentication tokens, signing secrets, or derived
  verifiers. Disk cache encryption keys and OpenBao tokens are long-lived
  credentials and must follow this policy. Do not classify normal cache object
  bodies as secrets unless a future module explicitly stores private user data.
- Third-party unsafe inventory. Before a stable release, run `cargo-geiger` as
  an informational dependency review and record unexpected changes in the
  release notes. Do not treat every dependency-level unsafe finding as an
  automatic blocker: the networking, TLS, OS, and runtime stack may contain
  audited unsafe internals. Treat new unsafe in direct dependencies as a review
  trigger alongside `cargo deny` and `cargo audit`.
- Supply-chain evidence. Stable release gates must generate SPDX and CycloneDX
  SBOMs with `cargo-sbom`, record their checksums, and run a local
  reproducible-build check that compiles the release binary twice from separate
  target directories and compares the resulting executable hash. This does not
  prove cross-machine bit-for-bit reproducibility; it proves the published
  builder can reproduce its own release artifact from the tagged source and
  pinned lockfile. Cross-distro/container reproducibility remains a future
  hardening goal.
- Human dependency review. Track the `cargo-vet` adoption path in
  [Rust Supply-Chain Security](supply-chain-security.md). Do not make `cargo-vet`
  a blocking release gate until the initial exemption set and trusted audit
  imports have been reviewed.

- Request framing and smuggling regression tests. The unit suite must keep
  coverage for ambiguous `Content-Length` and `Transfer-Encoding`, invalid
  `Content-Length`, oversized headers, oversized body streams, unsafe `Host`
  values, and redirect target construction. Later stable modules must add their
  own malicious-input regression tests before release.

Run the raw-socket framing smoke before tagging a stable proxy release:

```bash
scripts/smoke_request_framing.sh
```

This smoke bypasses browser/client normalization and verifies malformed request
framing is rejected on the wire.
- Header scrubbing checks. The 1.0 smoke must continue proving that the default
  response policy does not expose version banners and strips common upstream
  implementation headers from proxied responses. Later stable modules must prove
  equivalent secret/banner scrubbing for their own outputs.
- Local load test with a release binary and a representative 1.0 config:

```bash
cargo build --release
hey -z 30s -c 64 -host static.test http://127.0.0.1:18080/
```

Watch CPU, memory, open file descriptors, and logs during this test. The server
should reject or shed load cleanly rather than panic.

Fluxheim also includes a local wrapper for this check:

```bash
scripts/load_smoke_1_0.sh
```

The default duration is intentionally modest. Tune it for release validation:

```bash
FLUXHEIM_LOAD_DURATION=60s FLUXHEIM_LOAD_CONCURRENCY=128 scripts/load_smoke_1_0.sh
```

- TLS policy check. The current Fluxheim TLS listener configuration uses
  Fluxheim-owned rustls/OpenSSL policy helpers for ALPN, protocol versions,
  curves, and cipher lists. Release scans remain an enforcement gate: a stable
  release must not ship if a selected TLS backend negotiates deprecated
  protocol versions or weak cipher suites.
- Local TLS smoke. The localhost smoke already proves a static certificate over
  a TLS listener. For a deeper local scan, use a temporary copy of the latest
  stable `testssl.sh` release against the release binary. Re-check the latest
  stable tag before each release; as of 2026-05-06, GitHub lists `v3.2.3` as
  the latest stable release:

```bash
curl -sSfL -o /tmp/testssl.sh https://raw.githubusercontent.com/testssl/testssl.sh/v3.2.3/testssl.sh
chmod +x /tmp/testssl.sh
/tmp/testssl.sh --fast --parallel https://127.0.0.1:18443/
```

Fluxheim also includes a local wrapper that starts a temporary TLS listener,
downloads the pinned stable scanner, and stores the report:

```bash
scripts/tls_scan_local.sh
```

Do not vendor this script into the repository. Re-download it for release
validation and record the commit/version it reports.

Checks that should be run by the maintainer from a deployment-like environment:

- Run an authenticated or allowlisted OWASP ZAP/Burp active scan against a
  staging deployment that has no real secrets, users, or customer content.
- Run `testssl.sh` or a public TLS scanner against the real public hostname
  after DNS, certificates, and firewall rules are final.
- Run a larger `hey`, `wrk`, `k6`, or Gatling load test from a separate host.
  Local loopback hides network and socket pressure.
- Run a slow-client test from a separate host to confirm header/body timeouts
  and connection limits are effective. If using a tool such as `slowhttptest`,
  point it only at infrastructure you own.
- Confirm upstream handoff uses one of the supported safe deployment patterns:
  private network, loopback/service network, TLS upstream verification, or mTLS
  where the backend supports it.
- Confirm trusted-proxy settings are not enabled for public traffic unless the
  actual ingress proxy IP ranges are pinned and reviewed.

Fuzzing gate:

- Before tagging a stable release, add or run fuzz targets for custom parser and
  policy code rather than Pingora internals. For `1.0.x`, cover Host
  normalization, redirect URL construction, header mutation policy, static path
  resolution, cache key generation, and cache-header parsing. Later stable
  modules must add fuzz targets for their own parsers and security policy
  boundaries.
- Fuzzing is release-blocking if it finds a panic, path escape, open redirect,
  request-boundary ambiguity, or unbounded memory growth.

Initial fuzz targets live under `fuzz/` and can be run with `cargo-fuzz`:

```bash
cargo install --locked cargo-fuzz
scripts/validate-fuzz-targets.sh
cargo fuzz run host_normalization -- -max_total_time=60
cargo fuzz run cache_headers -- -max_total_time=60
```

Increase the runtime substantially before a stable tag. Keep generated corpora
and artifacts out of git unless a minimized regression case should be promoted
into a normal unit test.

Property-testing gate:

- `cargo test` includes property-based checks for Host normalization, dynamic
  request-header templates, and ACME retry backoff. These tests are intended to
  protect invariants that are easy to miss with hand-picked examples.
- Add a property test when a parser, normalizer, path resolver, or security
  policy accepts attacker-controlled input and the expected behavior can be
  stated as an invariant.
- Property-test failures are release-blocking if they show a panic, invalid
  header generation, path escape, open redirect, arithmetic overflow, or
  acceptance of a malformed security-sensitive value.

Formal-verification note:

- Kani or another Rust verifier is not part of the mandatory `1.0` release gate.
  Before enabling it in CI, add a small harness for one bounded parser and prove
  that the toolchain is reproducible on the supported release builders.
- Candidate future harnesses are header-template parsing, Host normalization,
  ACME date/backoff arithmetic, and static path containment checks.

## Incubator Feature Matrix

Run this matrix for normal development and for pre-release validation when
post-1.0 modules changed. Passing these commands does not make the modules part
of the `1.0` stable scope.

```bash
cargo build --release --no-default-features --features proxy,load-balancer
cargo build --release --no-default-features --features proxy,metrics
cargo build --release --no-default-features --features proxy,tls-rustls,acme
cargo build --release --no-default-features --features profile-full
cargo build --release --no-default-features --features profile-cache-edge
cargo build --release --no-default-features --features profile-proxy-edge
cargo build --release --no-default-features --features profile-load-balancer-edge
cargo build --release --no-default-features --features profile-observability
scripts/validate-fips-openssl.sh check
scripts/validate-fips-rustls.sh check
scripts/smoke_peer_fill_cache.sh
scripts/smoke_observability_local.sh
```

TLS backend validation is split into its own helper so release builders can
check the supported rustls and OpenSSL backend families explicitly:

```bash
scripts/validate-tls-backends.sh release
```

The rustls/AWS-LC FIPS validation helper requires the `aws-lc-fips-sys` build
toolchain, including CMake, Go, and a C compiler. Skip it on release builders
that are not intended to produce rustls/AWS-LC FIPS candidate evidence.

For release evidence, use an AWS-LC-supported FIPS builder. Rolling
distribution compilers can be too new for `aws-lc-fips-sys`; the helper fails
early for known newer GCC/Clang families unless the investigation-only
`FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1` override is set.

If local OpenSSL FIPS evidence works but rustls/AWS-LC evidence must be
collected elsewhere, run `scripts/release_evidence.sh VERSION
--skip-fips-rustls` locally and attach the rustls/AWS-LC evidence captured from
the supported builder separately. Use `--skip-fips-openssl` for the opposite
case, or `--skip-fips` only when no FIPS evidence is relevant to that release.

For a clean container check on common stable tooling, run the helper inside a
Debian Bookworm Rust image with CMake, Go, Clang/libclang, and pkg-config:

```bash
podman run --rm -v "$PWD:/work:Z" -w /work docker.io/library/rust:1-bookworm \
  bash -c 'set -e; export PATH=/usr/local/cargo/bin:$PATH; apt-get update; apt-get install -y --no-install-recommends cmake golang-go clang libclang-dev pkg-config perl ca-certificates; CARGO_TARGET_DIR=/tmp/fluxheim-target scripts/validate-fips-rustls.sh release'
```

For hardware-specific local binaries, use `target-cpu=native` only for the
machine that will run the binary. Do not publish those binaries as portable
artifacts:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Rootless Podman

Run the Podman smoke before publishing a container image:

```bash
FLUXHEIM_RELEASE_PODMAN=1 scripts/release_checks.sh
```

Before publishing multi-OS container images, run the variant smoke matrix:

```bash
scripts/podman_smoke_variants.sh
```

Or include it in the release wrapper:

```bash
FLUXHEIM_RELEASE_PODMAN=1 FLUXHEIM_RELEASE_PODMAN_VARIANTS=1 scripts/release_checks.sh
```

If Codex or another sandboxed tool cannot reach the rootless socket, export the
socket explicitly:

```bash
CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" scripts/podman_smoke.sh
```

The smoke builds the image, validates the packaged config, and checks that the
runtime process does not run as root.

Fluxheim publishes variant images from the explicit Containerfiles under
`containers/`: `wolfi`, `alpine`, `suse-micro`, and `debian`. Each OS variant
is published for the full/default, cache, proxy, PHP, and, starting with the
`1.5` line, load-balancer image profiles. Pre-`1.5` tags can include the
load-balancer profile only through manual workflow dispatch. GitHub Container
Registry publishing uses the repository `GITHUB_TOKEN`; Docker Hub publishing
requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets.

The published default images should keep `FLUXHEIM_RUNTIME_UID=65532` and
`FLUXHEIM_RUNTIME_GID=65532`. Root-runtime images are supported through build
args, but should be tagged deliberately and not replace the non-root defaults.

## Final Release Gate

- Confirm `git status` contains only intentional release changes.
- Update `CHANGELOG.md` before tagging.
- Prepare release notes from `docs/release-notes-template.md`.
- Confirm the repository still carries the `EUPL-1.2` license.
- Confirm reviewed advisory exceptions still match current `cargo audit`
  output.
- Capture a local release-gate report for the tag:

```bash
scripts/capture_release_gate_report.sh release
```

- For release candidates, capture the deep gate with scanner, load, framing,
  fuzz-target, and TLS-backend checks enabled:

```bash
FLUXHEIM_CAPTURE_DEEP=1 scripts/capture_release_gate_report.sh release
```

- Attach or summarize the stable release security and stability gate results in
  the release notes.
