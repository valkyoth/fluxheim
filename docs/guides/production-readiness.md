# Production Readiness

Use this checklist before exposing a deployment to real users. It describes
this source checkout, not a blanket stability promise for every configuration.
For an installed release, use its tagged guides and
[release notes](../../release-notes). Historical milestone descriptions are not
evidence that the current native runtime implements every old promise.

A successful build or configuration check is necessary but insufficient:
it does not prove live authorization, certificate renewal, recovery or capacity.
The [coverage ledger](../reference/documentation-coverage.md) records reviewed
behavior, open corrections and tests still needed. The documentation audit is
not release approval; do not deploy a workflow that depends on an unresolved
blocker merely because it has a configuration field.

## Choose And Identify The Build

- Select the actual [package profile](installation.md), not only a version.
  PHP, Wasm, metrics and other modules are not present in every artifact.
- Verify release checksums and the published source identity. Keep the artifact
  digest, configuration revision and deployment time in your operational record.
  Checksums and repeat builds from one builder do not prove independent provenance;
  see [supply-chain boundaries](supply-chain-security.md).
- Use supported [platforms and archives](portable-releases.md). Windows managed
  PHP-FPM is unavailable; use external FastCGI over TCP. Container instructions
  do not qualify an installed Windows service or a macOS binary.
- Recheck image digests and bundled OS/PHP dependencies when applying a
  [container runtime refresh](container-runtime-refresh.md).

## Validate As The Service User

First complete the loopback example in [installation](installation.md#native-quick-start).
Then validate your real configuration with the same binary, identity, mounts
and environment that the service will use:

```bash
fluxheim --version
fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
fluxheim --config /etc/fluxheim/fluxheim.toml --check-tls-storage
```

Run those as separate commands. Do not combine validation flags with mutation
subcommands: the current [CLI mode limitation](command-line.md) can execute the
subcommand instead. `--check-tls-storage` checks configured local certificate
material; it does not contact a CA or prove that an origin's TLS policy works.

The [standalone tester](command-line.md) is useful for diagnostics, but its
profile filter is not an exact simulation of every released binary.
`--no-runtime-paths` skips filesystem checks; `--runtime-cutover` is a diagnostic
report, not an authoritative readiness exit status. Neither substitutes for
starting the actual package and making requests.

Review [configuration composition](configuration.md): includes, relative paths,
duplicate names and replacement rules matter. Test the assembled configuration,
not each fragment in isolation. Keep credentials out of printed resolved configs
and support logs.

## Protect Files And Interfaces

- Run as an unprivileged service identity. For containers, start with the
  [rootless deployment guide](build-and-podman.md); for Linux services, review
  the [systemd unit](systemd.md) and its capability/mount policy.
- Keep config, TLS keys, ACME state, token files, logs and snapshot stores under
  trusted ownership. Use private secret files and log replacements (`0600` on
  Unix), private directories and a restrictive umask such as `0077`. Audit
  extended ACLs too; a mode-bit check is not a universal effective-access proof.
  Use the corresponding Windows ACL policy rather than treating chmod as portable.
- Keep state and secrets outside static document roots. Do not expose PHP source,
  application backups, configuration dumps or secret mounts through an alias.
- Restrict public listeners and trusted proxies explicitly. Treat forwarding
  headers and request IDs as metadata, not authenticated identity.
- Keep admin and metrics listeners private and authenticated. Configure separate
  control/observer credentials where appropriate. A remote admin hop needs the
  documented trusted TLS terminator; a declaration alone does not encrypt it.
  Read [admin](admin.md) and [metrics](metrics.md) for current token/socket limits.
- Remote OTLP collectors require HTTPS; a bearer token requires HTTPS even on
  loopback. Provision trust and protect token files using [OTLP export](otlp-export.md).
- Review [logging](logging.md) before enabling debug output. Typed event schemas
  and JSON escaping are not general redaction of arbitrary dependency messages.
  The [privacy profile](zero-retention-privacy-mode.md) is reduced retention, not
  anonymity or zero retention across the application, OS and collectors.

## Prove Your Actual Workflows

Test a disposable deployment before changing a production site. Keep real
requests, expected outcomes and bounded failure/recovery cases in the record.

| Deployment uses | Minimum checks and current boundaries |
| --- | --- |
| Static files and routing | Known/unknown hosts, index and missing files, traversal rejection and your rewrite/method rules; review [static semantics](static-files.md) and [routing](routing.md) |
| TLS and certificates | Verified client handshake with the right hostname and CA, SNI, expired/untrusted certificate rejection and any required client certificate; read [TLS](tls.md) and [origin trust](upstream-tls.md) |
| ACME | Use the [HTTP-01 workflow](acme.md) with staging first, persist state, confirm publication and renewed serving certificate; scheduling, backoff, recovery and native TLS-ALPN integration have open corrections |
| Authorization and identity | Test rejected credentials, absent identity and upgrade paths; current [auth](external-authorization.md) limitations mean ordinary HTTP success does not prove WebSocket authorization |
| Proxy, HTTP/2 or gRPC | Validate origin TLS, deadlines, failures, cancellation and actual application protocol; [gRPC](grpc.md) has trailer/streaming gaps, not general pass-through support |
| Load balancing | Observe selected members, unhealthy/all-down behavior, failover, draining and restart state; configured retry/latency knobs are not all wired into native dispatch; see [pool boundaries](load-balancer.md) |
| Caching | Prove public/private response admission, variants, byte ranges, purge, stale behavior and restart; use [cache guidance](cache.md) and its advanced pages, not only a HIT counter |
| PHP | Exercise uploads, login, static assets and errors against the real application/pool; review [routing](php.md) and [runtime limits](php-runtime-support.md) |
| Logs, metrics and traces | Confirm actual emitted signals in your collector, test token rejection and exporter loss/recovery, and distinguish a missing series from zero; see [collector integration](collector-integrations.md) |
| Reload and rollback | Verify the baseline and serving response, apply one candidate, confirm it, then test explicit recovery; [snapshot identity/overlap corrections](config-snapshots.md#current-recovery-limitations) remain open |
| Shutdown or upgrade | Use the real supervisor and a request lasting through shutdown; keep its stop deadline beyond Fluxheim's drain/teardown needs; see [lifecycle](service-lifecycle.md) and [upgrades](zero-downtime-upgrades.md) |

This table highlights cross-cutting risks, not an exhaustive new finding list.
Consult each feature guide and the ledger for the full set. Documented limits
are not automatically accepted risks or completed fixes.

## Capacity And Recovery

Set request/body/header limits, timeouts, worker counts, cache/spool budgets and
connection limits for your workload. Exercise modest load and cancellation with
representative payload sizes. Check host CPU, memory and disk as well as gateway
latency; collecting a body before proxy/PHP dispatch can change the memory budget.

Back up configuration and persistent certificate/account state with appropriate
secret protection. Test restoration on a separate instance. A configuration
snapshot is not a backup of every external application, database or credential.
Protect swap, crash capture and privileged diagnostics at the OS level; Linux
dump suppression does not qualify the non-Linux host policy.

Audit queue admission is not durable audit persistence. If your environment
requires durable or independently protected audit records, the current logging
contract alone does not satisfy that requirement.

## Repository Qualification

These commands are for maintainers in a source checkout, not commands to run
inside a production container. They require the toolchain and external services
listed in the [release checklist](release-checklist.md) and
[runbook](release-runbook.md):

```bash
scripts/stable_release_gate.sh check
```

That local gate has optional checks. A successful exit with skipped services
does not qualify them. Enable applicable checks explicitly, for example:

```bash
FLUXHEIM_GATE_PODMAN=1 scripts/stable_release_gate.sh check
FLUXHEIM_GATE_WORDPRESS=1 scripts/stable_release_gate.sh check
FLUXHEIM_GATE_OPENBAO=1 scripts/stable_release_gate.sh check
FLUXHEIM_GATE_TLS_BACKENDS=1 scripts/stable_release_gate.sh check
```

For deployments requiring a FIPS-capable backend, follow [FIPS qualification](fips.md)
and its supported builder requirements first. `profile-fips-rustls` and the
OpenSSL alternative are build choices, not Fluxheim certification:

```bash
FLUXHEIM_GATE_FIPS_OPENSSL=1 scripts/stable_release_gate.sh check
FLUXHEIM_GATE_FIPS_RUSTLS=1 scripts/stable_release_gate.sh check
```

Use `scripts/capture_release_gate_report.sh check` to record a gate run. Retain
the exact revision, features, platform, commands, pass/fail/skip results and
limitations. Do not reuse an old report to qualify a changed binary. Native
Windows/macOS runs, collector/container tests and exact archive checks remain
distinct evidence. Cross-compilation is not native execution.

The [final release gate](../roadmap/observability-commit-plan.md#final-release-gate)
also requires the queued corrections or explicit owner-approved dispositions,
fresh qualification, pentest and green CI/CodeQL before release authorization.
