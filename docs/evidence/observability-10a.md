# Commit 10A: ACME Operation Scope And Server Feature Parity

Date: 2026-10-29. Base: `76c938bc6b57146c19b1bc3cced53b5aaec61da9`.
Status: implemented and qualified locally on Linux x86_64 with rootless Podman.
Pentest and exact-SHA GitHub acceptance remain required before Commit 11.
No release, production certificate operation or maintenance-branch backport was
performed. Main remains 1.9.0 unreleased.

## Reproduction

The released Wolfi images reproduced both operator errors with synthetic config:

| Image | Observed image digest | Renewal failure |
| --- | --- | --- |
| `v1.8.3-wolfi` | `sha256:d169f5287ad10e2ce003adc07f939ab8e021045396490eb50fdf95b11d950132` | Missing managed PHP-FPM executable |
| `v1.8.3-php-wolfi` | `sha256:db03607978fd187b554cc02f87c98b90d00b51b2f636e8e907f5f2cac463a000` | Cache module not compiled |

The released PHP image also started and served a nonempty HTTP 200 PHP response
using that same PHP/cache-enabled configuration. This establishes an inconsistent
startup/renewal check, **not** evidence that the cache feature was active.
The reproduction is available through `scripts/smoke_acme_scope.py
--reproduce-legacy`, with both locally available images supplied explicitly.

## Contract

- `ValidationScope::Server` preserves full configuration validation. Normal
  startup, `--validate-config` and `--check-config` now consistently invoke
  the existing compiled-module checks before serving traffic.
- `ValidationScope::Acme` retains parsing, include trust and relative-path
  resolution; TLS/issuer/ACME policy, vhost identity, domain and source checks;
  and the existing ACME engine's account/EAB, storage and challenge protections.
  It does not validate unrelated PHP/cache/web/proxy runtime prerequisites.
  Configuration is not silently rewritten or disabled.
- Both renewal entry points use this scope. Shared companion callers were
  reviewed: targets, status, doctor, account operations and revocation consume
  ACME state, not server application runtime settings.
- Certificate-control operations validate the reload socket separately.
  Companion renew/revoke validates that path before mutation when reload is
  requested; connection-time validation remains in the reload helper.
  `--no-reload` does not require the control socket. Installed certificates
  are not claimed active without a separate reload.
- Server reload compatibility, snapshot loading, secret readers, certificate
  installation and challenge publication algorithms are unchanged.

See the [renewal guide](../guides/certificate-renewal.md#renewal-and-server-validation)
for image differences, mount layout, SELinux sharing and activation guidance.

## Live Proof

`sh scripts/check_acme_scope.sh` builds both actual production Wolfi recipes and
passes immutable image IDs to the smoke harness. Qualified local image IDs:

- Full: `sha256:265df5cd226082f0166c227678934ddd69eae1276aa3e97d597e952d84f611cf`
- PHP: `sha256:c379d8c59e8bc99a611e66fdee54c469090683dfeb79b5277dd70a134ff07933`

The full profile includes cache but no packaged PHP runtime. The PHP profile
includes managed PHP-FPM but no cache. Both read the same unmodified renewal
config containing enabled PHP and cache.

| Packaged operation | Result |
| --- | --- |
| Full `fluxheim acme-renew --force-renew` | Fresh certificate installed |
| PHP `fluxheim acme-renew --force-renew` | Fresh certificate installed |
| Full `fluxheim-acme renew --force-renew --no-reload` | Fresh certificate installed |
| PHP `fluxheim-acme renew --force-renew --no-reload` | Fresh certificate installed |

Assertions require four distinct successful HTTP-01 authorizations at the CA,
four distinct certificate serials, the requested DNS SAN, more than one day of
validity and installed private-key mode/owner `600:65532`. The subsequent
non-forced run observes the installed certificate and attempts zero renewals.
The packaged server, `--validate-config` and `--check-config` each reject missing
PHP in the full image and unsupported enabled cache in the PHP image.

This is real local ACME protocol execution, not a successful-parser-only test:
the gateway serves challenge tokens from shared state, and Pebble's validation
agents fetch them. Authorization reuse is disabled; `PEBBLE_VA_ALWAYS_VALID`
is never enabled. No production CA, DNS name, secret or account is contacted.

### Local CA Adapter

Pebble is pinned to OCI digest
`sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54`.
Its [pinned upstream source](https://github.com/letsencrypt/pebble/blob/b1e1ca4f3c30abb64111adaca4544bc5374cc306/wfe/wfe.go)
advertises a `data:` terms URL. Fluxheim deliberately requires an HTTPS terms
URL. A test-only TLS adapter changes exactly this expected directory metadata
value to the fixture's HTTPS URL; unexpected terms fail the adapter test.
It forwards all account/JWS, authorization, challenge and certificate exchanges
without fabricating results. TLS certificate verification remains enabled on
both client hops. This does not qualify public-CA terms handling or EAB issuance.

The Python adapter image is pinned to
`sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f`.
Control files are written before containers start and mounted individually
read-only. Synthetic CA keys are not production secrets. Mutable ACME state
uses an owned engine volume, not a writable host control directory. Ports are
published only on loopback; container resources, helper timeouts and logs are
bounded. Cleanup removes only resources named by this run.

## Regression Coverage

Passed locally:

- Full locked workspace test suite.
- ACME-enabled configuration suite: 445 tests.
- Reduced proxy/ACME root library suite: 196 tests before the additional
  control-scope regression; the final focused CLI suite also passed.
- PHP-profile and reduced proxy-profile CLI tests without workspace feature
  unification, including cache rejection and reload-control scope.
- ACME all-feature suite: 88 passed; its one normally ignored bind-mount test
  passed separately via `scripts/smoke_acme_mount_boundary.sh` in an isolated
  user/mount namespace.
- New scope tests retain rejection of malformed includes, unknown fields,
  duplicate/invalid targets, unsafe storage/CA/EAB parents, missing ACME
  capability, invalid TLS/issuer policy and unsafe reload paths.
- Both existing reload protocol and response-bound tests remain enabled.
  Their temporary sockets moved from `/tmp` into a short trusted `target`
  directory because control-path validation correctly rejects unsafe parents.
  Neither the protocol assertions nor production path checks were relaxed.
- Nine Python harness security/fixture tests and four documentation-layout tests.
- Strict PHP/ACME-profile all-target Clippy, formatting and diff validation.
- `cargo audit --deny warnings`: 449 locked packages, no advisories.
- `cargo deny check`: advisories, bans, licenses and sources passed.

CI now requires the packaged local-CA workflow with Docker as well as the
focused profile/config tests. Local evidence uses Podman, not Docker. Native
Windows/macOS and extracted archive qualification are not claimed here; the
existing CI gates and Commit 11 platform matrix remain required. No Cargo
manifest, lockfile or third-party runtime dependency changed.
