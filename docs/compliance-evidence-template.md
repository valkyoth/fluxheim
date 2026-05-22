# Compliance Evidence Package Template

This template helps operators collect repeatable release and deployment
evidence for Fluxheim security reviews. It is not a certification claim.
Completing it does not make Fluxheim FIPS 140-3 certified, ISO/IEC 19790
certified, Common Criteria certified, Protection Profile compliant, or EAL
compliant.

Use this with:

- [FIPS-Capable Deployments](fips.md)
- [Common Criteria Readiness Roadmap](common-criteria-roadmap.md)
- [Release Runbook](release-runbook.md)
- `scripts/release_evidence.sh`

## Release Metadata

| Field | Value |
| --- | --- |
| Fluxheim version | |
| Git tag | |
| Tag commit | |
| Tag signature verification | |
| Release date | |
| Release builder identity | |
| Build host OS/image | |
| Rust toolchain | |
| Cargo build command | |
| Selected feature profile | |
| `Cargo.lock` hash | |

## Candidate TOE Boundary

Pick one candidate Target of Evaluation (TOE) boundary for this evidence
package. Do not mix boundaries in the same evidence record.

| Candidate TOE | Included | Excluded / Operational Environment |
| --- | --- | --- |
| Gateway binary | `fluxheim` binary and selected Cargo features | OS, systemd, OpenSSL provider, PHP-FPM, OpenBao, ACME CA, upstream apps |
| RPM profile | RPM files, helper binaries, systemd units, default filesystem layout | Host OS packages, external crypto providers, runtime directory ownership |
| Container image | Image layers, entrypoint, bundled helper binaries, filesystem layout | Container runtime, host kernel, mounted secrets, external services |
| FIPS/ISO OpenSSL profile | Fluxheim configuration and OpenSSL integration checks | Validated OpenSSL provider module, provider install, provider Security Policy |
| FIPS/ISO rustls/AWS-LC profile | Fluxheim configuration and rustls provider status checks | AWS-LC FIPS module build environment, module Security Policy, platform evidence |

Selected candidate TOE:

```text
<fill in one TOE shape and why it matches this deployment>
```

## Security Target-Style Draft

This is a Security Target-style engineering draft, not an evaluated Security
Target.

### Security Problem Definition

Assets:

- TLS private keys and certificate material.
- Admin tokens and control-socket access.
- Configuration files and snapshots.
- Cache keys, cache metadata, and cached response bodies.
- PHP-FPM request metadata and spooled bodies.
- Logs, traces, metrics, request IDs, and routing metadata.

Threats considered:

- Remote routing bypass, request smuggling, header injection, cache poisoning,
  path traversal, and request/response resource exhaustion.
- Local symlink, permission, ownership, and runtime-state attacks.
- Misconfiguration that silently disables security controls.
- Compromised upstream, PHP-FPM, OpenBao, ACME, OTLP, or crypto-RPC services.
- Build, dependency, container, and release-artifact supply-chain attacks.

Operational assumptions:

- Fluxheim runs as a dedicated service user.
- Runtime directories are owned by the service user and are not writable by
  untrusted users.
- Admin endpoints and control sockets are local or otherwise restricted to
  trusted operators.
- External cryptographic modules are installed and operated according to their
  own Security Policies when a regulated deployment claims them.
- Operators preserve release evidence, SBOMs, checksums, signatures, scanner
  output, and provider evidence.

### Security Objectives

Fluxheim objectives:

- Enforce configured TLS, routing, cache, PHP-FPM, and static-file policies.
- Reject unsafe filesystem paths, symlinked runtime paths, unsafe permissions,
  and insecure config combinations.
- Fail closed when FIPS/ISO-required mode selects unsupported crypto paths.
- Emit diagnostics and structured evidence for security-relevant decisions.

Operational-environment objectives:

- Provide a trustworthy OS, filesystem, service manager, container runtime, and
  network boundary.
- Protect secrets and credential mounts.
- Provide validated crypto module evidence when FIPS/ISO claims are made.
- Provide external-service evidence for OpenBao, PHP-FPM, ACME, OTLP, and
  upstream systems when they are part of the deployment security argument.

### Security-Relevant Interfaces

| Interface | Direction | Security role | Evidence |
| --- | --- | --- | --- |
| Downstream HTTP/TLS listener | inbound | TLS policy, host routing, request limits | config, tests, TLS diagnostics |
| Upstream proxy connector | outbound | upstream TLS, headers, retries, timeouts | config, tests |
| Static web root | filesystem | path traversal and symlink prevention | tests, docs |
| PHP-FPM FastCGI | outbound/local | CGI params, body limits, response parsing | tests, PHP-FPM docs |
| Cache store | filesystem/OpenBao | object limits, encryption boundary | config, smoke tests |
| ACME challenge and renewal | inbound/outbound | certificate lifecycle | ACME docs, FIPS gates |
| Admin API | inbound | management and rollback | admin docs, auth tests |
| Control socket | local IPC | certificate reload command | runtime tests, permissions |
| OTLP metrics/traces | outbound | telemetry metadata export | config, CA, FIPS gates |
| Logs | outbound/filesystem | audit trail and diagnostics | logging config, redaction docs |

## Cryptographic Evidence

| Field | Value |
| --- | --- |
| Required mode | none / FIPS 140-3 / ISO/IEC 19790 |
| TLS backend | rustls / OpenSSL / BoringSSL / s2n |
| Fluxheim feature profile | |
| Module provider | OpenSSL FIPS provider / AWS-LC FIPS / other |
| CMVP certificate number | |
| Module Security Policy document and revision | |
| Provider install/config files | |
| Provider self-test evidence | |
| `fluxheim crypto` output archived | yes/no |
| FIPS validation script output archived | yes/no |
| Non-TLS crypto gates reviewed | yes/no |

Attach:

- Exact Cargo build command.
- `fluxheim crypto` or `fluxheim-config-tester --crypto` output.
- `scripts/validate-fips-openssl.sh release` or
  `scripts/validate-fips-rustls.sh release` output when applicable.
- Module Security Policy and platform/provider installation evidence.
- Explanation for every external crypto boundary, such as OpenBao Transit.

## Release Artifact Evidence

| Artifact | Evidence |
| --- | --- |
| Source archive checksums | |
| Binary archive checksums | |
| Config tester checksum | |
| SBOM SPDX checksum | |
| SBOM CycloneDX checksum | |
| Reproducible-build hash | |
| Container image digests | |
| GitHub release URL | |
| RPM repository metadata/checksums | |

## Validation Script Identifiers

Use these stable identifiers in release notes, pentest responses, and evidence
records.

| ID | Script / check | Purpose | Artifact |
| --- | --- | --- | --- |
| FH-REL-001 | `scripts/validate-release-metadata.sh` | Release metadata consistency | command output |
| FH-FEAT-001 | `scripts/validate-features.sh` | Cargo feature graph validation | command output |
| FH-FIPS-OPENSSL-001 | `scripts/validate-fips-openssl.sh` | OpenSSL FIPS/ISO fail-closed and provider evidence | command output |
| FH-FIPS-RUSTLS-001 | `scripts/validate-fips-rustls.sh` | rustls/AWS-LC FIPS/ISO fail-closed and provider evidence | command output |
| FH-OWASP-2025-001 | `scripts/validate-owasp-top10-2025.sh` | OWASP Top 10 2025 baseline checks | command output |
| FH-SBOM-001 | `scripts/generate-sbom.sh` | SPDX and CycloneDX SBOM generation | SBOM files and checksums |
| FH-REPRO-001 | `scripts/reproducible_build_check.sh` | Reproducible-build evidence | hash output |
| FH-RELEASE-EVID-001 | `scripts/release_evidence.sh` | Aggregated release evidence bundle | generated markdown |
| FH-CARGO-AUDIT-001 | `cargo audit` | RustSec advisory check | command output |
| FH-CARGO-DENY-001 | `cargo deny check` | license/source/advisory policy | command output |
| FH-CODEQL-001 | GitHub CodeQL/code scanning | static-analysis baseline | GitHub run URL |

## Scanner Output Checklist

Archive the output or URL for each applicable item:

- GitHub CI workflow run.
- CodeQL/code scanning alerts state.
- `cargo audit`.
- `cargo deny check`.
- OWASP baseline script output.
- FIPS OpenSSL and/or rustls validation script output.
- SBOM generation output and checksums.
- Reproducible-build output.
- Container image digests.
- Pentest report identifier and remediation commit list.

## Vulnerability Analysis Record

| ID | Source | Finding summary | Decision | Remediation commit | Regression evidence |
| --- | --- | --- | --- | --- | --- |
| VA-YYYY-NNN | pentest / CodeQL / audit / internal | | fixed / accepted / false positive | | |

Decision guidance:

- `fixed`: code, docs, or tests changed.
- `accepted`: documented design limitation with no new exploit path.
- `false positive`: finding does not apply, with reason.
- `deferred`: tracked for a future release with clear risk owner.

## External Dependency And Operational Evidence

Record external systems that are outside the selected TOE but required by the
deployment security argument.

| Component | Role | Evidence required | Collected |
| --- | --- | --- | --- |
| OpenSSL FIPS provider | TLS crypto module | CMVP certificate, Security Policy, provider config | |
| AWS-LC FIPS module | rustls crypto module | CMVP certificate, Security Policy, build/toolchain evidence | |
| OpenBao Transit | external cache encryption boundary | module/platform evidence, policy, network boundary | |
| PHP-FPM | PHP execution environment | pool config, user/group, socket permissions | |
| ACME issuer/renewal process | certificate lifecycle | issuer policy, account handling, renewal logs | |
| OTLP collector | telemetry sink | endpoint TLS/locality, CA, retention/redaction policy | |
| Container/runtime OS | operational environment | image digest, hardening settings, secret mounts | |

## Non-Claims

Use this wording in evidence packages and releases:

- "FIPS-capable build path"
- "ISO/IEC 19790 terminology alias"
- "Common Criteria evidence-aligned"
- "Security Target-style engineering draft"
- "TOE boundary candidate"

Do not use:

- "FIPS certified Fluxheim"
- "ISO/IEC 19790 certified Fluxheim"
- "Common Criteria certified"
- "EAL compliant"
- "Protection Profile compliant"
- "evaluated Security Target"
