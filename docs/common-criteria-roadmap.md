# Common Criteria Readiness Roadmap

This document tracks how Fluxheim can use ISO/IEC 15408:2026 concepts as an
engineering and evidence framework. It is not a certification claim. Common
Criteria evaluation is a product evaluation track, while FIPS 140-3 and
ISO/IEC 19790 are cryptographic-module tracks. They can support each other, but
they are not interchangeable.

The practical value for Fluxheim is to make product boundaries, security
functions, operator assumptions, tests, and lifecycle evidence explicit enough
that a future Protection Profile or Security Target can be written without
reconstructing years of engineering decisions.

## Source Scope

The local reference set reviewed was the ISO/IEC 15408:2026 series:

- Part 1: introduction and general model.
- Part 2: security functional components.
- Part 3: security assurance components.
- Part 4: evaluation methods and activities framework.
- Part 5: predefined packages of security requirements.

Do not copy licensed standard text into Fluxheim docs. Use this roadmap as a
derived engineering checklist only.

## Product Boundary

A future evaluation has to define the Target of Evaluation (TOE). Fluxheim
should prepare for multiple possible TOE shapes:

- `fluxheim` gateway binary only.
- RPM installation including systemd units, default directories, and helper
  binaries.
- Container image including entrypoint, base image, runtime filesystem layout,
  and `fluxheim-acme` / `fluxheim-config-tester`.
- FIPS/ISO OpenSSL profile where the validated OpenSSL provider is outside the
  Fluxheim TOE but part of the operational environment.

For each TOE shape, the evidence should identify:

- Physical and logical scope.
- Required non-TOE hardware, software, firmware, services, and operator
  procedures.
- Security functionality provided by Fluxheim itself.
- Security functionality delegated to the operating system, OpenSSL, OpenBao,
  ACME issuer, container runtime, or external upstream.
- Interfaces that are security-enforcing or security-supporting.

## Security Problem Definition

Fluxheim should keep a living product-level security problem definition. It
should not be limited to cryptography.

Candidate assets:

- TLS private keys and ACME account material.
- Admin bearer tokens and control-socket access.
- Configuration snapshots and release artifacts.
- Cache encryption keys, object metadata, and cached response bodies.
- Request identity metadata, logs, traces, and metrics.
- PHP-FPM request parameters and spooled request bodies.

Candidate threat classes:

- Remote request smuggling, routing bypass, cache poisoning, header injection,
  path traversal, request-body exhaustion, and protocol downgrade.
- Local filesystem and symlink attacks against runtime state, cache, spool,
  ACME, snapshot, and TLS paths.
- Misconfiguration that silently disables security controls.
- Compromised or lagging upstream services in proxy, PHP-FPM, ACME, OpenBao,
  OTLP, and future crypto-RPC deployments.
- Supply-chain compromise of build inputs, dependencies, container bases, and
  release artifacts.

Candidate operational assumptions:

- The service runs as a dedicated Unix user.
- Runtime state directories are owned by the service user and not writable by
  untrusted users.
- Admin endpoints and control sockets are reachable only from trusted networks
  or local operators.
- Operators preserve release evidence, SBOMs, checksums, signatures, and module
  Security Policies.
- External cryptographic modules and services are installed and operated within
  their own validation boundaries when a regulated deployment claims them.

## Functional Requirement Mapping

Fluxheim should map existing and planned features to Common Criteria-style
security functional areas. This is a roadmap classification, not formal SFR
language.

### Security Audit

Current and planned evidence should cover:

- Structured access logs with request IDs.
- Admin, config reload, self-healing, ACME, cache, TLS provider, and startup
  events.
- Clear separation between security-relevant events and routine traffic noise.
- Log size, retention, and redaction guidance for secrets and personal data.
- Failure behavior when logging sinks are unavailable.

### Cryptographic Support

This links to [FIPS / ISO-Capable Deployments](fips.md):

- Backend selection and status reporting.
- TLS protocol, cipher, group, and signature restrictions.
- Clear handling for non-TLS crypto such as ACME, cache encryption, OpenBao,
  request IDs, and outbound HTTPS.
- Evidence showing whether crypto is internal, delegated to a validated module,
  or disabled in regulated profiles.

### Identification And Authentication

Relevant Fluxheim surfaces:

- Admin API bearer-token validation.
- Control socket permissions and command scope.
- Optional future mTLS or stronger admin authentication.
- Login throttling, lockout, token rotation, and audit events.

### Security Management

Relevant Fluxheim controls:

- Config validation and `fluxheim-config-tester` profiles.
- Safe defaults, deny-unknown-fields parsing, and fail-closed feature guards.
- Runtime reload, self-healing snapshots, and rollback controls.
- Clear operator roles for package install, service runtime, admin API, ACME
  renewal, and release signing.

### Protection Of Security Functionality

Evidence should cover:

- Safe path handling with ownership, mode, symlink, and `O_NOFOLLOW` checks.
- Config snapshot integrity and rollback behavior.
- Startup diagnostics and self-tests for selected crypto providers.
- Panic policy, error handling, and no-unsafe-code boundaries.
- Separation between Fluxheim-controlled state and untrusted web content.

### Resource Utilization

Evidence should cover:

- Request header/body limits.
- PHP-FPM response/body/spool limits.
- Cache memory, disk, peer-fill, and object-size limits.
- Upstream retry, timeout, and connection-pool limits.
- Fuzzing and regression tests for parser and buffering limits.

### Trusted Channels And Paths

Evidence should cover:

- Downstream TLS policies.
- Upstream TLS policies.
- OTLP HTTPS and custom CA behavior.
- OpenBao Transit connectivity.
- ACME issuer connectivity.
- Admin API and control-socket access expectations.

## Assurance Evidence

The ISO/IEC 15408-3 assurance families are useful as a release evidence
checklist even without claiming an EAL.

Fluxheim should maintain:

- Architecture notes for security-enforcing modules and interfaces.
- Functional specifications for config validation, routing, TLS, ACME, cache,
  PHP-FPM, admin, snapshots, logging, and telemetry.
- Operational guidance and preparative procedures for RPM, container, systemd,
  and source builds.
- Configuration management evidence: signed tags, SBOMs, lockfiles, release
  notes, changelog, build scripts, and dependency audit output.
- Delivery evidence: checksums, signatures, image digests, release runbook, and
  reproducible-build output where available.
- Flaw remediation evidence: security policy, issue process, pentest fixes,
  CodeQL, cargo-audit, cargo-deny, fuzzing, and regression tests.
- Developer test coverage and independent-test entry points that a third party
  can run without privileged production access.
- Vulnerability analysis records for public-domain issues and pentest findings.

## Evaluation Methods

ISO/IEC 15408-4 is most useful to Fluxheim as a format for repeatable local
security checks.

Every major security check should have:

- A stable identifier.
- Scope and objective.
- Required inputs and environment.
- Tool requirements.
- Execution steps.
- Pass/fail criteria.
- Output artifacts to archive.
- Rationale linking the check to a threat, requirement, or release gate.

Existing scripts that fit this pattern include release metadata validation,
OWASP baseline checks, FIPS-capable OpenSSL and rustls/AWS-LC validation,
config fixture validation, fuzzing targets, cargo-audit, cargo-deny, CodeQL,
and PHP-FPM regression tests.

## Package Strategy

ISO/IEC 15408-5 packages are useful for long-term planning, but Fluxheim should
not claim an EAL or Common Criteria conformance until a real Security Target
and accredited evaluation path exist.

Practical near-term approach:

- Use EAL terminology only internally as an evidence maturity reference.
- Avoid "EAL-ready" marketing language.
- Prefer "Common Criteria evidence-aligned" for documentation.
- Track composed deployments separately, because Fluxheim often depends on
  OpenSSL, PHP-FPM, OpenBao, container runtimes, ACME issuers, and upstream
  applications.

## Roadmap

### Phase 1 - Evidence Alignment

- Added in `1.3.6`: [Compliance Evidence Package Template](compliance-evidence-template.md)
  provides sections for TOE boundary, assumptions, security functions,
  operational environment, external dependencies, cryptographic module
  evidence, scanner output, and vulnerability-analysis records.
- Added in `1.3.6`: stable validation-script identifiers are documented in the
  evidence template for release metadata, feature validation, FIPS OpenSSL,
  FIPS rustls, OWASP baseline, SBOM, reproducible-build, cargo-audit,
  cargo-deny, CodeQL, and aggregated release evidence.
- Expand docs so each security feature has operator guidance and test evidence.

### Phase 2 - Security Target Draft

- Draft a non-certification Security Target-style document for one TOE shape:
  the RPM gateway profile is likely the most concrete first target.
- Define the TOE boundary, security problem, objectives, requirements mapping,
  and summary specification in Fluxheim terminology.
- Keep it explicitly marked as an engineering draft, not an evaluated ST.

### Phase 3 - Protection Profile Research

- Check whether an existing firewall, TLS gateway, web server, reverse proxy,
  or network device Protection Profile can reasonably fit Fluxheim.
- If no profile fits, document why and identify which SFR groups would need a
  custom PP or direct-rationale ST.

### Phase 4 - External Evaluation Decision

- Only pursue formal Common Criteria evaluation if there is a sponsor, a fixed
  TOE boundary, a lab, a target assurance package, and a maintenance budget.
- Do not combine formal Common Criteria claims with FIPS/ISO cryptographic
  module claims unless the evidence boundary for each is separately clear.

## Documentation Rules

Use:

- "Common Criteria evidence-aligned"
- "ISO/IEC 15408-inspired evidence"
- "Security Target-style draft"
- "TOE boundary candidate"
- "operator assumptions"

Avoid:

- "Common Criteria certified"
- "EAL compliant"
- "Protection Profile compliant"
- "evaluated Security Target"
- Any wording that implies an accredited evaluation has happened.
