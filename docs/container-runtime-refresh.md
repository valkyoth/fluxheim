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
Wolfi's short aliases. Promotion copies the tested candidate by digest; it does
not rebuild it. GHCR and configured Quay/Docker Hub mirrors receive the images.
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
