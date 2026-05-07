# Release Runbook

This is the maintainer procedure for publishing a Fluxheim release. It is the
step-by-step operational companion to the broader release checklist.

Use this from a clean `main` checkout. Replace `0.5.0` with the release version
you are publishing.

## 1. Preflight

Confirm you are on the release commit and the worktree is clean:

```bash
git status --short --branch
git pull --ff-only origin main
git status --short --branch
```

Run the local release checks that match the release scope:

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo audit
scripts/validate-release-metadata.sh
scripts/podman_smoke.sh
```

For stable or release-candidate builds, prefer the stable gate:

```bash
scripts/stable_release_gate.sh release
```

If `cargo audit` reports a known upstream advisory that cannot be fixed in this
repository yet, record it explicitly in the release notes with the package,
advisory ID, impact, and removal condition.

## 2. Commit The Release Prep

Commit any release-note, README, packaging, or metadata changes:

```bash
git add .
git commit -S -m "Prepare Fluxheim 0.5.0 release"
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
git tag -s v0.5.0 -m "Fluxheim 0.5.0"
git tag -v v0.5.0
git push origin v0.5.0
```

Record the `Good "git" signature ...` line from `git tag -v`.

Pushing the tag starts the container image workflow.

## 4. Build The Binary Release Asset

Build the release binary:

```bash
cargo build --release --locked
```

Create the release bundle:

```bash
mkdir -p dist/fluxheim-0.5.0-linux-x86_64
cp target/release/fluxheim dist/fluxheim-0.5.0-linux-x86_64/
cp README.md LICENSE CHANGELOG.md RELEASE_NOTES_0.5.0.md dist/fluxheim-0.5.0-linux-x86_64/
cp -r docs examples packaging dist/fluxheim-0.5.0-linux-x86_64/
tar -C dist -czf dist/fluxheim-0.5.0-linux-x86_64.tar.gz fluxheim-0.5.0-linux-x86_64
sha256sum dist/fluxheim-0.5.0-linux-x86_64.tar.gz
```

Record the binary checksum.

Do not commit `dist/`; it is local release output.

## 5. Draft The GitHub Release

On GitHub:

1. Open Releases.
2. Draft a new release.
3. Select tag `v0.5.0`.
4. Title it `Fluxheim 0.5.0`.
5. Paste the contents of `RELEASE_NOTES_0.5.0.md`.
6. Upload `dist/fluxheim-0.5.0-linux-x86_64.tar.gz`.
7. Publish the release.

It is normal to publish before every evidence field is filled. Source archives
and container digests are available only after the tag/release and image
workflow exist.

## 6. Record Source Archive Checksums

After the tag is visible on GitHub, download GitHub's generated source archives
and hash them:

```bash
mkdir -p dist/checksums
curl -L -o dist/checksums/fluxheim-0.5.0.tar.gz https://github.com/valkyoth/fluxheim/archive/refs/tags/v0.5.0.tar.gz
curl -L -o dist/checksums/fluxheim-0.5.0.zip https://github.com/valkyoth/fluxheim/archive/refs/tags/v0.5.0.zip
sha256sum dist/checksums/fluxheim-0.5.0.tar.gz
sha256sum dist/checksums/fluxheim-0.5.0.zip
```

Edit the GitHub release notes and add these checksums.

## 7. Publish And Verify Container Images

The image workflow publishes the configured image variants after the tag push.
Wait for the workflow to finish before collecting digests.

For GHCR, the package must be public if anonymous users should pull it:

1. Open the Fluxheim container package on GitHub.
2. Open Package settings.
3. Use Danger Zone -> Change visibility -> Public.

Then collect immutable digests:

```bash
podman pull ghcr.io/valkyoth/fluxheim:v0.5.0-wolfi
podman inspect ghcr.io/valkyoth/fluxheim:v0.5.0-wolfi --format '{{index .RepoDigests 0}}'

podman pull ghcr.io/valkyoth/fluxheim:v0.5.0-alpine
podman inspect ghcr.io/valkyoth/fluxheim:v0.5.0-alpine --format '{{index .RepoDigests 0}}'

podman pull ghcr.io/valkyoth/fluxheim:v0.5.0-suse-micro
podman inspect ghcr.io/valkyoth/fluxheim:v0.5.0-suse-micro --format '{{index .RepoDigests 0}}'

podman pull ghcr.io/valkyoth/fluxheim:v0.5.0-debian
podman inspect ghcr.io/valkyoth/fluxheim:v0.5.0-debian --format '{{index .RepoDigests 0}}'
```

If Docker Hub publishing is enabled, repeat the same pull/inspect process for
the Docker Hub tags.

Edit the GitHub release notes and add one digest per image variant.

## 8. Final Release Evidence Format

The release notes should end with concrete evidence, not placeholders:

```markdown
## Checksums And Signatures

- Source archive checksums:
  - `...  fluxheim-0.5.0.tar.gz`
  - `...  fluxheim-0.5.0.zip`
- Binary checksums:
  - `...  fluxheim-0.5.0-linux-x86_64.tar.gz`
- Container digests:
  - Wolfi: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - Alpine: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - SUSE Micro: `ghcr.io/valkyoth/fluxheim@sha256:...`
  - Debian: `ghcr.io/valkyoth/fluxheim@sha256:...`
- Tag signature:
  - `Good "git" signature for ...`
```

## 9. Post-Release Smoke

Pull one published image and confirm the packaged default site starts:

```bash
podman run --rm -d --name fluxheim-release-smoke -p 127.0.0.1:18080:8080 ghcr.io/valkyoth/fluxheim:v0.5.0-wolfi
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
