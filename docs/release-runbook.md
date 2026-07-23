# Release Runbook

This is the maintainer procedure for publishing a Fluxheim release. It is the
step-by-step operational companion to the broader release checklist.

Use this from a clean `main` checkout. Set the release variables once, then
reuse them through the commands below:

```bash
RELEASE_VERSION=1.4.0
TAG="v${RELEASE_VERSION}"
TITLE="Fluxheim ${RELEASE_VERSION}"
RELEASE_NOTES="release-notes/RELEASE_NOTES_${RELEASE_VERSION}.md"
TARGET="$(rustc -vV | sed -n 's/^host: //p')"
```

When starting a new release, use the version helper for the mechanical package
and RPM fields, then update the human-facing release text that the metadata
validator checks:

```bash
scripts/bump_version.py "${RELEASE_VERSION}"
scripts/validate-release-metadata.sh
```

## 1. Preflight

Confirm you are on the release commit and the worktree is clean:

```bash
git status --short --branch
git pull --ff-only origin main
git status --short --branch
```

Run the local release checks that match the release scope:

```bash
cargo fmt --all --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo audit
scripts/generate-sbom.sh
scripts/reproducible_build_check.sh
scripts/validate-release-metadata.sh
scripts/validate-owasp-top10-2025.sh check
scripts/podman_smoke.sh
scripts/smoke_load_balancer_container.sh
FLUXHEIM_CONTAINER_VARIANTS="debian alpine" scripts/podman_smoke_variants.sh
```

For humans doing focused local evidence collection, use the test starter to
discover and run the available live smokes without memorizing every script name:

```bash
scripts/test_starter.py --list
scripts/test_starter.py --category load-balancer
scripts/test_starter.py --run privacy
scripts/test_starter.py --run images
scripts/test_starter.py --run wasm
```

For PHP-FPM releases, also run:

```bash
scripts/smoke_wordpress_php_fpm.sh both
scripts/smoke_wordpress_proxy_tls.sh
scripts/smoke_fluxheim_php_wolfi.sh
```

When collecting release evidence on a host that cannot build every FIPS
backend, use the per-backend evidence skips and attach the missing backend
evidence from its supported builder. For example, rolling distro compilers may
be too new for `aws-lc-fips-sys`, so rustls/AWS-LC FIPS evidence can be
collected in the Bookworm container documented in
[Release Checklist](release-checklist.md):

```bash
scripts/release_evidence.sh "${RELEASE_VERSION}" --skip-fips-rustls
```

For stable or release-candidate builds, prefer the stable gate:

```bash
scripts/stable_release_gate.sh release
```

In `release` mode this stable gate is intentionally tag-blocking for container
images: it runs the root image smoke plus representative Debian and Alpine
variant image smokes before a tag should be pushed. Use
`FLUXHEIM_GATE_IMAGE_VARIANTS="debian alpine wolfi suse-micro"` when the release
needs full local variant evidence. Use `FLUXHEIM_SKIP_IMAGE_GATE=1` only when
equivalent image evidence has already been collected on another builder.
Set `FLUXHEIM_GATE_LOAD_BALANCER_CONTAINER=1`, or use
`scripts/stable_release_deep_gate.sh release`, to also build and run the
focused load-balancer image against two local origins before tagging.
The deep gate also enables the smoke dependency image check, OpenBao cache
encryption, database health checks, WordPress, Wasm sandbox execution, PHP
Wolfi, RPM build, privacy mode, framing, and fuzz-target compile checks by
default. The observability smoke starts disposable Prometheus and Jaeger
containers unless external URLs are configured; Prometheus scrape and OTLP
metrics ingestion are required in that self-contained mode, while Jaeger trace
ingestion remains opt-in through `FLUXHEIM_JAEGER_REQUIRE_TRACE=1` until native
span export is implemented.
Disable an individual deep gate only when equivalent evidence has already been
captured on another builder.

For the `1.3` and later lines this stable gate includes the proxy cache and
local observability smoke suites, plus compile and packaged-config checks for
the published image profiles. That keeps cache, Prometheus/OpenTelemetry
basics, and focused image feature wiring covered by the same command used for
release evidence.

If `cargo audit` reports a known upstream advisory that cannot be fixed in this
repository yet, record it explicitly in the release notes with the package,
advisory ID, impact, and removal condition.

## 2. Commit The Release Prep

Commit any release-note, README, packaging, or metadata changes:

```bash
git add .
git commit -S -m "Prepare Fluxheim ${RELEASE_VERSION} release"
git push origin main
```

If Git reports `nothing to commit`, continue from the current `HEAD`.

Record the commit:

```bash
git rev-parse HEAD
```

## 3. Create And Push The Signed Tag

Create a signed tag:

```bash
git tag -s "${TAG}" -m "${TITLE}"
git tag -v "${TAG}"
git push origin "${TAG}"
```

Record the `Good "git" signature ...` line from `git tag -v`.

Pushing the tag starts the container image workflow.

## 4. Build The Binary Release Assets

Build Linux runtime and config-tester release assets with the helper script.
It names artifacts by normalized platform label instead of raw Rust target
triple:

| Rust target | Artifact label |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `x86_64-linux` |
| `aarch64-unknown-linux-gnu` | `aarch64-linux` |
| `x86_64-apple-darwin` | `x86_64-macos` |
| `aarch64-apple-darwin` | `aarch64-macos` |
| `x86_64-pc-windows-msvc` | `x86_64-windows` |
| `aarch64-pc-windows-msvc` | `aarch64-windows` |

Build the current Linux host target:

```bash
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind linux
```

Build Linux ARM64 on an ARM64 Linux builder or configured cross-builder:

```bash
rustup target add aarch64-unknown-linux-gnu
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind linux --target aarch64-unknown-linux-gnu
```

This produces, for each Linux target, the
full/wasm/cache/proxy/load-balancer/php runtime archives and the config-tester
archive. Every staged directory is emitted as both `.tar.gz` and `.zip`; the
two formats contain the same files:

```text
fluxheim-${RELEASE_VERSION}-full-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-wasm-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-cache-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-proxy-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-load-balancer-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-php-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-config-tester-x86_64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-full-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-wasm-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-cache-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-proxy-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-load-balancer-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-php-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-config-tester-aarch64-linux.tar.gz
fluxheim-${RELEASE_VERSION}-full-x86_64-linux.zip
fluxheim-${RELEASE_VERSION}-wasm-x86_64-linux.zip
# ...matching .zip files for every profile and architecture above
```

Build and live-test only the packaged Wasm profile during development:

```bash
scripts/smoke_wasm_release_asset.sh
```

The smoke extracts the release archive and runs the F5 iRules-style,
OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like policy examples through
that exact packaged binary.

Validate the common operating-system archive plan without compiling:

```bash
scripts/validate_portable_release_plan.py
```

Build the seven portable profiles on a matching supported host. During
`1.8.0`, native CI builds representative macOS `full` and `wasm` archives.
Windows is plan-only until native runtime and archive work begins in `1.8.2`;
do not publish Windows artifacts before that gate is restored:

```bash
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind macos
```

Future Windows binaries retain `.exe`; both operating systems use matching
`.tar.gz` and `.zip` payload contracts. These archives are unsigned previews,
not notarized or Authenticode-signed installers. See
[Portable Releases](portable-releases.md).

The older combined macOS development artifact remains available for local
developer workflows:

```bash
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind macos-dev
```

Apple Silicon Macs produce
`fluxheim-${RELEASE_VERSION}-dev-aarch64-macos.{tar.gz,zip}`. Intel Macs
produce `fluxheim-${RELEASE_VERSION}-dev-x86_64-macos.{tar.gz,zip}`. These
remain unsigned development conveniences and are separate from the portable
profile matrix.

Record all runtime and config-tester binary checksums.

Generate SBOMs for the tagged source tree:

```bash
scripts/generate-sbom.sh
sha256sum target/release-evidence/fluxheim.spdx.json
sha256sum target/release-evidence/fluxheim.cyclonedx.json
```

Upload both SBOM files as release assets, and record their checksums in the
release notes.

Verify that the local release builder can reproduce the release binary from two
separate target directories:

```bash
scripts/reproducible_build_check.sh
```

Record the reported binary hash as reproducible-build evidence.

Do not commit `dist/`; it is local release output.

### Optional FIPS-Capable Evidence

For releases that changed FIPS-capable TLS code or docs, capture the local
backend evidence when the release builder has the selected provider/toolchain
installed:

```bash
scripts/validate-fips-openssl.sh release
scripts/validate-fips-rustls.sh release
```

Record the command output, package/provider version, provider or build config,
and the selected module Security Policy reference. The rustls/AWS-LC validation
requires the `aws-lc-fips-sys` build toolchain, including CMake, Go, and a C
compiler. If the local builder can collect OpenSSL FIPS evidence but not
rustls/AWS-LC evidence, use `scripts/release_evidence.sh VERSION
--skip-fips-rustls` locally and attach rustls/AWS-LC evidence from the
supported builder separately. If the release builder does not have a FIPS
provider/toolchain installed, record the expected fail-closed output instead.
OpenSSL `release` mode fails closed by default; set
`FLUXHEIM_REQUIRE_FIPS_PROVIDER=0` only for explicit stub-only validation
environments where provider evidence is intentionally not being collected.

### Optional Common Criteria-Aligned Evidence

For releases that changed security-enforcing behavior, complete the relevant
sections of [Compliance Evidence Package Template](compliance-evidence-template.md)
and record any relevant notes from
[Common Criteria Readiness Roadmap](common-criteria-roadmap.md):

- TOE boundary assumptions affected by the release.
- Security Target-style draft notes: security problem, objectives, and
  security-relevant interfaces affected by the release.
- Security-relevant interfaces changed by the release.
- Validation scripts or pentest regressions that provide evidence.
- External dependencies and operational-environment assumptions.
- Vulnerability-analysis records for pentest, CodeQL, audit, or internal
  findings, including the fixed/accepted/false-positive/deferred decision and
  remediation commit.

This is evidence organization only. Do not describe the release as Common
Criteria certified, Protection Profile compliant, or EAL compliant.

### OWASP Baseline Evidence

For releases that changed request parsing, TLS, authentication-adjacent
controls, PHP-FPM handling, config validation, or observability, capture the
mapped in-repo OWASP Top 10 2025 baseline:

```bash
scripts/validate-owasp-top10-2025.sh run
```

Record the script output as release evidence. This is an engineering baseline
for Fluxheim-owned controls, not an OWASP compliance claim for applications
served behind Fluxheim.

## 5. Draft The GitHub Release

On GitHub:

1. Open Releases.
2. Draft a new release.
3. Select the tag from `$TAG`.
4. Use `$TITLE` as the release title.
5. Paste the contents of `$RELEASE_NOTES`.
6. Upload both formats of every runtime profile archive built in step 4:
   `dist/fluxheim-${RELEASE_VERSION}-{full,wasm,cache,proxy,load-balancer,php}-{x86_64,aarch64}-linux.{tar.gz,zip}`.
7. Upload both formats of the unified config-tester archive built in step 4:
   `dist/fluxheim-${RELEASE_VERSION}-config-tester-{x86_64,aarch64}-linux.{tar.gz,zip}`.
8. If the release includes unsigned portable previews, upload every
   successfully gated profile from
   `dist/fluxheim-${RELEASE_VERSION}-{full,wasm,cache,proxy,load-balancer,php,config-tester}-{aarch64,x86_64}-{macos,windows}.{tar.gz,zip}`.
   Do not upload an untested target or describe these files as signed
   installers.
9. If a legacy combined macOS developer artifact is needed, upload
   `dist/fluxheim-${RELEASE_VERSION}-dev-{aarch64,x86_64}-macos.{tar.gz,zip}`.
10. Upload `target/release-evidence/fluxheim.spdx.json`.
11. Upload `target/release-evidence/fluxheim.cyclonedx.json`.
12. Publish the release.

It is normal to publish before every evidence field is filled. Source archives
and container digests are available only after the tag/release and image
workflow exist.

## 6. Record Source Archive Checksums

After the tag is visible on GitHub, download GitHub's generated source archives
and hash them:

```bash
mkdir -p dist/checksums
curl -L -o "dist/checksums/fluxheim-${RELEASE_VERSION}.tar.gz" "https://github.com/valkyoth/fluxheim/archive/refs/tags/${TAG}.tar.gz"
curl -L -o "dist/checksums/fluxheim-${RELEASE_VERSION}.zip" "https://github.com/valkyoth/fluxheim/archive/refs/tags/${TAG}.zip"
sha256sum "dist/checksums/fluxheim-${RELEASE_VERSION}.tar.gz"
sha256sum "dist/checksums/fluxheim-${RELEASE_VERSION}.zip"
```

Edit the GitHub release notes and add these checksums.

After the tag and image workflows are available, the maintainer helper can
collect the release evidence block:

```bash
scripts/release_evidence.sh "${RELEASE_VERSION}"
```

The helper includes OpenSSL and rustls/AWS-LC FIPS-capable evidence by running
`scripts/validate-fips-openssl.sh release` and
`scripts/validate-fips-rustls.sh release`, and OWASP Top 10 2025 baseline
evidence by running `scripts/validate-owasp-top10-2025.sh run`. Use
`--skip-fips-openssl` or `--skip-fips-rustls` when that backend's evidence is
collected on another builder. Use `--skip-fips` or `--skip-owasp` only for
release lines where that evidence is not relevant.

## 7. Publish And Verify Container Images

The image workflow publishes the configured image variants after the tag push.
Wait for the workflow to finish before collecting digests.

For GHCR, the package must be public if anonymous users should pull it:

1. Open the Fluxheim container package on GitHub.
2. Open Package settings.
3. Use Danger Zone -> Change visibility -> Public.

Then collect immutable digests:

```bash
for image in \
  "${TAG}-wolfi" \
  "${TAG}-alpine" \
  "${TAG}-suse-micro" \
  "${TAG}-debian" \
  "${TAG}-cache-wolfi" \
  "${TAG}-cache-alpine" \
  "${TAG}-cache-suse-micro" \
  "${TAG}-cache-debian" \
  "${TAG}-proxy-wolfi" \
  "${TAG}-proxy-alpine" \
  "${TAG}-proxy-suse-micro" \
  "${TAG}-proxy-debian" \
  "${TAG}-php-wolfi" \
  "${TAG}-php-alpine" \
  "${TAG}-php-suse-micro" \
  "${TAG}-php-debian"
do
  podman pull "ghcr.io/valkyoth/fluxheim:${image}"
  podman inspect "ghcr.io/valkyoth/fluxheim:${image}" --format '{{index .RepoDigests 0}}'
done
```

If Docker Hub publishing is enabled, repeat the same pull/inspect process for
the Docker Hub tags. If Quay publishing is enabled, repeat it for the Quay
release tags as well:

```bash
for image in \
  "${TAG}-wolfi" \
  "${TAG}-alpine" \
  "${TAG}-suse-micro" \
  "${TAG}-debian" \
  "${TAG}-cache-wolfi" \
  "${TAG}-cache-alpine" \
  "${TAG}-cache-suse-micro" \
  "${TAG}-cache-debian" \
  "${TAG}-proxy-wolfi" \
  "${TAG}-proxy-alpine" \
  "${TAG}-proxy-suse-micro" \
  "${TAG}-proxy-debian" \
  "${TAG}-php-wolfi" \
  "${TAG}-php-alpine" \
  "${TAG}-php-suse-micro" \
  "${TAG}-php-debian"
do
  podman pull "quay.io/valkyoth/fluxheim:${image}"
  podman inspect "quay.io/valkyoth/fluxheim:${image}" --format '{{index .RepoDigests 0}}'
done
```

For `v1.5.x` and newer tags, also collect the `load-balancer` image profile
digests, for example `${TAG}-load-balancer-wolfi`.

Edit the GitHub release notes and add one digest per image variant.

## 8. Final Release Evidence Format

The release notes should end with concrete evidence, not placeholders:

```markdown
## Checksums And Signatures

- Source archive checksums:
  - `...  fluxheim-${RELEASE_VERSION}.tar.gz`
  - `...  fluxheim-${RELEASE_VERSION}.zip`
- Binary checksums:
  - `...  fluxheim-${RELEASE_VERSION}-linux-x86_64.tar.gz`
- SBOM checksums:
  - `...  fluxheim.spdx.json`
  - `...  fluxheim.cyclonedx.json`
- Reproducible build:
  - `...  target/reproducible-a/release/fluxheim`
- Container digests:
  - GHCR full/default Wolfi: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - GHCR full/default Alpine: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - GHCR full/default SUSE Micro: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - GHCR full/default Debian: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - GHCR cache/proxy/php variants: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - Quay full/default Wolfi: `quay.io/valkyoth/fluxheim@sha256:...`
  - Quay full/default Alpine: `quay.io/valkyoth/fluxheim@sha256:...`
  - Quay full/default SUSE Micro: `quay.io/valkyoth/fluxheim@sha256:...`
  - Quay full/default Debian: `quay.io/valkyoth/fluxheim@sha256:...`
  - Quay cache/proxy/php variants: `quay.io/valkyoth/fluxheim@sha256:...`
- Tag signature:
  - `Good "git" signature for ...`
```

## 9. Post-Release Smoke

Pull one published image and confirm the packaged default site starts:

```bash
podman run --rm -d --name fluxheim-release-smoke -p 127.0.0.1:18080:8080 "ghcr.io/valkyoth/fluxheim:${TAG}-wolfi"
curl -I http://127.0.0.1:18080/
podman logs fluxheim-release-smoke
podman stop fluxheim-release-smoke
```

Expected result:

- HTTP status is `200 OK`.
- The response includes `server: fluxheim`.
- Logs do not show startup errors.

## 10. Local Cleanup

Remove local release artifacts when no longer needed:

```bash
rm -rf dist/
```

Keep the signed tag and GitHub release immutable unless a serious release
mistake requires a documented replacement release.
