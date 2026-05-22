# OWASP Top 10 2025 Baseline

This page maps Fluxheim's automated checks to the OWASP Top 10 2025
categories. It is a baseline gate, not a compliance certificate. Some OWASP
risks are application/business-logic risks that Fluxheim cannot prove for an
origin application. The goal is to keep the web-server, reverse-proxy,
PHP-FPM, cache, admin, TLS, and release controls from regressing.

Run the quick CI baseline:

```bash
scripts/validate-owasp-top10-2025.sh check
```

Run the deeper local baseline, which executes each representative regression
test filter:

```bash
scripts/validate-owasp-top10-2025.sh run
```

## Scope

The automated baseline checks:

- policy files and CI gates that should always exist;
- representative unit tests for each OWASP category;
- secure example defaults for headers, admin tokens, dotfile denial, and FIPS
  diagnostics;
- supply-chain gates such as `cargo deny`, `cargo audit`, and SBOM generation.

The baseline does not prove:

- application-specific authorization or ownership checks;
- origin application authentication strength;
- business transaction rollback correctness inside a backend application;
- monitoring and alert delivery in an operator's external SOC stack;
- FIPS compliance of an operator's full deployment boundary.

## Mapping

| OWASP 2025 category | Fluxheim-owned baseline checks |
| --- | --- |
| [A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) | Static traversal and dotfile denial tests, admin bearer-token tests, authenticated cache purge tests, safe redirect host tests. |
| [A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) | Directory listing disabled by default, default security headers, admin auth required, remote admin rejected by default, secure example configs. |
| [A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | CI requires `cargo deny check`, `cargo audit`, SBOM generation, registry allow-listing, and FIPS-capable OpenSSL/rustls profile validation. |
| [A04 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) | TLS FIPS policy rejection tests, TLS storage symlink/permission tests, OpenSSL and rustls/AWS-LC FIPS-capable validation scripts, FIPS documentation. |
| [A05 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) | Header value validation tests, PHP FastCGI parameter control-character rejection, cache-warm header injection rejection, route traversal rejection, dynamic header control-character stripping. |
| [A06 Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) | Request header count/byte limits, bounded admin JSON, capped PHP parameter lists, saturating body counters, explicit feature-policy gates. |
| [A07 Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) | Admin token file size/path tests, full bearer-token comparison, per-source and global admin-auth throttle tests. |
| [A08 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/) | Snapshot store safe-path tests, symlinked config rejection, reload process-upgrade rejection, self-healing rollback fail-closed tests. |
| [A09 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | JSON log escaping, access-log escaping, request-id generation, release evidence and observability smoke gates. |
| [A10 Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Oversized admin error clamping, config parse context tests, permission-error diagnostics, saturating response counters, `forbid(unsafe_code)` and release `panic = "abort"` checks. |

## Maintenance Rule

When a security-sensitive feature is added, update
`scripts/validate-owasp-top10-2025.sh` if the feature changes one of the
baseline control areas above. If a category cannot be represented by an
automated test, document the manual/operator boundary here instead of leaving
the category implicit.
