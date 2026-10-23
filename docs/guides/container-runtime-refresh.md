# Released Container Runtime Refreshes

Fluxheim's application version and its container runtime are separate update
streams. PHP, libc, OpenSSL, CA certificates and distribution packages can need
security updates even when Fluxheim has no new release.

## Operation

The **Refresh Released Containers** workflow runs weekly on Monday at 05:23 UTC.
Maintainers can also run it immediately from Actions, or with:

```sh
gh workflow run container-refresh.yml --ref main
```

The workflow must be present on the default branch. It selects the latest
published, non-prerelease GitHub Release with a `vMAJOR.MINOR.PATCH` tag and
resolves that tag to one exact commit for the entire matrix. It never builds
unreleased application code from `main`. Workflow tooling comes from the
workflow commit; application sources, Cargo.lock, Rust builder image, feature
profiles, package manifests and default configurations come from the release.
No Git tag, Cargo version, archive or RPM is changed.

### Required Release Trust Setup

Before enabling refresh publication, create the GitHub Actions environment
`container-refresh-release`. Restrict its deployment branches to `main` and
configure its approval policy for your release process. Add the environment
secret `FLUXHEIM_RELEASE_ALLOWED_SIGNERS` containing the SSH allowed-signers
entries for authorized release signers, for example:

```text
release-maintainer@example.invalid namespaces="git" ssh-ed25519 AAAA...authorized-public-key...
```

Use the actual maintainer identity and public key verified through an independent
trusted channel. Never populate this secret from a key shipped in the selected
release, from its tag message, or automatically from the account being verified.
Only public signing keys belong here, never private keys. Restrict who may change
this environment and secret, and rotate/revoke entries when authorization changes.
Required reviewers pause scheduled runs until approved; choose that policy
deliberately rather than assuming scheduled publication is unattended.

The resolver fails closed if the secret is missing. It fetches the release tag,
requires an annotated SSH-signed tag whose signed name matches the selected
release, verifies it against this separate trust anchor, then builds only its
signed commit. Lightweight, unsigned, renamed, tampered or unauthorized tags
cannot reach the build jobs. GitHub's latest-release flag is selection metadata,
not authentication. Workflow code and the protected trust configuration remain
trusted; this gate does not defend against compromise of both.

All 24 supported profile/distribution combinations are refreshed: full, Wasm,
cache, proxy, load-balancer and PHP, across Wolfi, Alpine, Debian and SUSE.
PHP uses SUSE BCI; other SUSE profiles use Micro. The existing distribution
track is retained (for example Alpine's released minor line), not upgraded
to a different distribution release. Wolfi's rolling base follows `latest`.

Each runtime base tag is resolved to a new digest and recorded in image labels.
The runtime stage bypasses the build cache and upgrades installed packages
before installing the release's package set. SUSE Micro has no package manager;
its updates come from the refreshed vendor base. Rust compilation may reuse
cached builder layers. This is not a dependency or compiler update.

## Verification And Publication

Every image must report the expected Fluxheim version and serve a live HTTP
request. The cache profile also demonstrates a cache HIT; proxy and load-balancer
profiles reach a live origin. PHP images must load the required extensions and
execute a PHP request through managed FPM. Wolfi PHP has an explicit minimum of
8.5.12 for the October 2026 critical security fixes. Debian and SUSE may backport
patches without changing to the upstream fixed version; their vendor advisories
still need review during an incident.

Passing images are first published under unique candidate tags such as
`v1.8.2-rebuild-123456-1-php-wolfi` (workflow run ID and attempt). Only after
the entire matrix succeeds are the existing versioned aliases updated, including
Wolfi's short aliases. Publishing records the digest directly from the copy of
the locally tested image, not by subsequently resolving its mutable registry tag.
Each matrix job uploads that digest in an immutable Actions artifact identified
by profile, distribution and run attempt. Promotion downloads only that exact
artifact from the same run; missing evidence, evidence from a previous attempt,
or a candidate tag pointing at another digest blocks promotion. Every registry
copy uses the recorded digest, including if the tag changes after comparison.
Promotion does not rebuild the image. GHCR and configured Quay/Docker Hub mirrors receive the images.
`sha-*`, `dev-*` and `latest*` aliases are not rewritten by this workflow.

The current refresh platform is `linux/amd64`, matching the existing image
workflow's release default. Promotion refuses to overwrite an alias containing
other platforms; extend the build/test matrix first if multi-platform release
images are introduced. A failed build/test leaves all stable aliases unchanged.
Registry promotion is not transactional: a network failure during promotion
can leave some aliases updated and others unchanged. Inspect the job summaries
and rerun the workflow; do not assume cross-registry atomicity.

Unique rebuild tags and job summaries provide rollback references. For a strict
immutable deployment, pin `registry/repository@sha256:...`; a versioned image tag
now identifies the Fluxheim version, not an immutable set of OS packages.

## Operator Updates And Limits

Pull the refreshed image and recreate the running container. Restarting an
existing container does not install updated packages. Update explicit digest
pins yourself. Derived images (such as custom WordPress images) must also be
rebuilt with a fresh base and redeployed. Keep the previous digest for rollback.

A successful refresh is not proof that all vulnerabilities are fixed. It can
only consume packages and bases the vendors have published. During an urgent
advisory, manually trigger the workflow, check each affected vendor's patch
status and installed package versions, inspect the smoke results, and announce
the replacement digests. Do not wait for the weekly schedule. Failed or delayed
scheduled runs need maintainer attention; deployed containers do not auto-update.

This smoke gate supplements, rather than replaces, normal release CI and
application-level testing. No registry publication is performed by local tests:

```sh
python3 -m pip install PyYAML==6.0.3
python3 scripts/test_container_refresh.py
bash -n scripts/promote_container_refresh.sh
```
