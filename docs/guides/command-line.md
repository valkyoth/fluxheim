# Command Line And Configuration Tester

Fluxheim ships three command-line programs. Use `fluxheim` to start the gateway
or perform local operations, `fluxheim-config-tester` to inspect configuration,
and `fluxheim-acme` for certificate/account administration. These are different
programs, not remote clients for the entire [admin API](admin.md).

Commands below use Unix shell syntax. On Windows use `fluxheim.exe`,
`fluxheim-config-tester.exe` and `fluxheim-acme.exe`, with your Windows paths;
PowerShell uses `$env:FLUXHEIM_CONFIG = 'C:\fluxheim\fluxheim.toml'` for an
environment variable. On every platform run checks as the actual service
identity, with the same mounts and permissions as the service. A successful
administrator/root check does not prove that a restricted service can start.

## Find A Command

```sh
fluxheim --help
fluxheim --version
fluxheim cache-warm --help
fluxheim snapshots prune --help
fluxheim-config-tester --help
fluxheim-acme --help
```

`-h`/`--help` prints usage; `-V`/`--version` prints the binary version/build ID.
Help describes syntax, not proof that a module is compiled in: cache and ACME
commands may be listed in a build that reports a missing-feature error when
they run. Select the right [package](installation.md) and use `fluxheim crypto`
to inspect crypto features. A self-reported build ID is not a signature.

Put `-c`/`--config` **before** the subcommand. The option accepts a TOML file or
configuration directory despite the shorter main-CLI help description.
`FLUXHEIM_CONFIG` supplies a default; an explicit `--config` takes precedence.
See [configuration loading](configuration.md) for discovery, includes, relative
paths and trust checks. Use an explicit path in automation rather than relying
on working-directory discovery.

## Start Or Validate

```sh
# Separate invocations: each performs its own load and checks.
fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
fluxheim --config /etc/fluxheim/fluxheim.toml --check-tls-storage
fluxheim --config /etc/fluxheim/fluxheim.toml
```

The last command starts the service and keeps running. Foreground shutdown,
drain behavior and packaged service settings are in [service lifecycle](service-lifecycle.md).
These validation commands do not start public listeners or perform a complete
live request/renewal test.

| Invocation | What success establishes | What it does not establish |
| --- | --- | --- |
| `--check-config` | Configuration loading/validation and selected compiled-module checks; prints the resolved config | Full runtime construction, listener availability or redacted public output |
| `--validate-config` | Configuration plus this binary's runtime validation/construction path; quiet on success | That every startup subsystem, admin credential, port bind, origin, PHP process or certificate renewal will work |
| `--check-tls-storage` | Configuration plus the dedicated TLS/ACME storage permission check | A complete runtime/feature check, TLS handshake, certificate issuance or proof of all future filesystem operations |
| `--reload-from OLD_CONFIG --config NEW_CONFIG` | Both configurations load and their differences can be classified | Application of the new config, contact with a running server or a restart-free change |

Runtime validation can initialize local resources such as cache storage; it is
not a transaction with guaranteed zero filesystem effects. Use a staging copy
and the intended service identity for deployment checks. `--check-config`
prints a detailed Debug representation, including topology and configured
values; it is not a sanitized export. Do not paste it into a public issue or
retain it in unrestricted CI logs. Prefer quiet `--validate-config`.

**Current limitation:** use exactly one top-level checking
mode and no subcommand in that invocation. `--check-config` and
`--validate-config` conflict, and `--reload-from` conflicts with the checking
flags, but not all combinations are rejected. A subcommand takes precedence
over checking flags: adding `--validate-config` before `snapshot` still creates
a snapshot. It is **not a dry-run**. Combining `--validate-config` with
`--check-tls-storage` silently skips the latter. the local follow-up is queued to make
these combinations explicit errors before any operation.

For reload classification:

```sh
fluxheim --config candidate.toml --reload-from running-source.toml
```

Read `reload impact`, its reasons and the recommended action. A zero exit code
can accompany `process-upgrade`: the comparison succeeded, not the proposed
hot reload. See [snapshot apply/recovery](config-snapshots.md) for the actual
authenticated apply workflow and current recovery limitations.

## Standalone Configuration Tester

The tester requires `--config` (or `FLUXHEIM_CONFIG`) and never starts the
gateway. A small [proxy example](../../examples/cli/proxy.toml) needs no running
origin for these commands:

```sh
fluxheim-config-tester --config examples/cli/proxy.toml --profile proxy --explain
fluxheim-config-tester --config examples/cli/proxy.toml --profile proxy \
  --no-runtime-paths --resolve-upstreams --runtime-cutover
```

| Option | Meaning and limit |
| --- | --- |
| `-c`, `--config FILE_OR_DIRECTORY` | Required input unless `FLUXHEIM_CONFIG` is set |
| `--profile NAME` | Additional policy filter, default `full`; see the matrix below |
| `--no-runtime-paths` | Skip process runtime-path inspection and runtime construction; still parse, merge and validate semantics/profile policy. This is not a bypass for all filesystem reads or config/include trust checks |
| `--check-tls-storage` | Run the explicit storage check, **even with** `--no-runtime-paths` |
| `--acme-targets` | Print configured renewal targets, issuers, challenge types and domains; no issuance. Requires an ACME-capable tester |
| `--resolve-upstreams` | Resolve configured proxy authorities; no connection or health request |
| `--explain` | Print config path, selected profile, vhost count and completed check markers |
| `--crypto` | Print crypto diagnostics for this tester build and config, not for a different server executable |
| `--runtime-cutover` | Print native plan, candidate and launch-plan diagnostic rows; not a strict readiness exit-status gate |

Unlike the main binary's top-level modes, the tester's diagnostic switches can
be combined. It validates the selected profile before printing diagnostics.
Without `--no-runtime-paths` it also performs compiled-module and runtime checks.
It ends with `config tester: ok` only if its selected operations return success.
However, a cutover report can contain `native-runtime-launch-plan-error` and
still finish successfully: the report was generated. Inspect its contents;
do not interpret the final line as proof that a listener plan is runnable.

DNS preview covers root proxy settings when there are no vhosts, vhost and
route proxy settings, and enabled legacy ACME-challenge proxy destinations.
It does not inventory every PHP, stream, UDP, collector or dynamic-discovery
destination. Numeric addresses work without DNS. A resolved address is not a
reachable server, trusted TLS peer or healthy application. Resolver failures
produce a nonzero result; the CLI exposes no separate DNS deadline, so impose
an outer process timeout in CI. Output reveals internal names and addresses.

### Profile Filters Are Not Target Builds

This is the **current tester filter**, not a release feature matrix:

| `--profile` value | Proxy | Static web | Cache | PHP |
| --- | --- | --- | --- | --- |
| `full` | Allowed | Allowed | Allowed | Rejected |
| `development` | Allowed | Allowed | Allowed | Allowed |
| `cache` | Allowed | Rejected | Allowed | Rejected |
| `proxy`, `load-balancer` | Allowed | Rejected | Rejected | Rejected |
| `web-php` | Rejected for vhost/route proxy; root exception below | Allowed | Rejected | Allowed |
| `fips-openssl`, `iso19790-openssl` | Allowed | Rejected | Rejected | Rejected |
| `fips-rustls`, `iso19790-rustls` | Allowed | Rejected | Rejected | Rejected |

The FIPS/ISO filters additionally require the named TLS backend and a required
FIPS or ISO mode in config. They do not switch the tester's compiled provider,
install a validated module or certify the deployment; see [FIPS guidance](fips.md).

**Current limitation:** these filters only cover selected modules,
not every capability of the target archive. There is no `php` or `wasm` profile
value. The legacy `web-php` filter rejects a vhost proxy even though the shipped
PHP package includes proxy support; the same filter currently accepts root
proxy settings. A development tester cannot prove a smaller target has every
configured feature. the local follow-up is queued to align the profile contract and
release feature graph. Until then, use the tester as an additional check and
always run `--validate-config` and live qualification with the **exact deployed
binary**, not just a profile name.

## Local Snapshot Commands

These commands use local disk; they are not admin HTTP requests. Supply a
private store and, for authenticated manifests, an integrity key:

```sh
fluxheim --config candidate.toml snapshot --store /var/lib/fluxheim/snapshots \
  --integrity-key-file /etc/fluxheim/secrets/snapshot.key --message 'candidate'
fluxheim snapshots --store /var/lib/fluxheim/snapshots \
  --integrity-key-file /etc/fluxheim/secrets/snapshot.key
```

| Command/options | Effect |
| --- | --- |
| `snapshot --store DIR [--integrity-key-file FILE] [--message TEXT]` | Capture validated effective config from disk and update the store pointer; not live apply |
| `rollback --store DIR [--integrity-key-file FILE] [--to ID]` | Move current to a verified target; default previous snapshot; not live rollback |
| `snapshots --store DIR [--integrity-key-file FILE]` | List IDs, status, current marker and notes |
| `snapshots... show ID` | Show snapshot metadata, integrity and config pathname |
| `snapshots... diff OLD NEW` | List changed top-level fields, not a line-by-line config diff |
| `snapshots... verify ID` | Report integrity; `unverified` is not authenticated |
| `snapshots... doctor` | Inspect store health; unhealthy report fails |
| `snapshots... prune [--keep N] [--older-than-days DAYS]` | Delete eligible history according to the store rules; no dry-run |

Put `--store` and `--integrity-key-file` before nested actions such as `show`.
Their environment alternatives are `FLUXHEIM_SNAPSHOT_STORE` and
`FLUXHEIM_SNAPSHOT_INTEGRITY_KEY_FILE`. These environment variables are CLI
defaults, not replacements for the running server's admin settings. The
[snapshot guide](config-snapshots.md) contains complete apply, rollback,
verification, retention and self-healing examples. Read it before pruning or
relying on automatic recovery.

## Cache Commands

Use the [cache operations guide](cache-operations.md) for a complete explicit
vhost configuration, actual warm/purge workflow and assertions. Root-only
cache preview and offline memory/bin inspection have documented limitations;
an offline CLI invocation is not the running server's memory cache.

```sh
fluxheim --config gateway.toml cache-key --host cache.example.test \
  --path /asset.png --method GET --expect-eligible
fluxheim --config gateway.toml cache-lookup --host cache.example.test \
  --path /asset.png --require-object --expect-tier disk
fluxheim --config gateway.toml cache-warm --listen 127.0.0.1:8080 \
  --host cache.example.test --path /asset.png --dry-run
```

`cache-key` predicts policy/key selection without requesting the origin;
`cache-lookup` inspects local stored metadata without printing response bodies;
`cache-warm` sends real requests unless `--dry-run` is present. Do not assume
lookup is a forensic read-only operation: opening/recovering stores and handling
expired entries can have filesystem effects. Warming uses its documented plain
HTTP transport; an HTTPS URL is not interchangeable with `--listen HOST:PORT`.

### Request Selection And Warming

| Option | Commands | Meaning |
| --- | --- | --- |
| `--host HOST` | All three | Route/key Host value; otherwise configured default vhost host |
| `--header 'Name: value'` | All three | Repeat for negotiated variants; avoid credentials in shell history/process arguments |
| `--path /path` | All three | Required once for key/lookup, repeatable for warm |
| `--method METHOD` | Key/lookup | Default `GET`; does not send a request |
| `--query QUERY` | Key/lookup | Separate query only when `--path` has none |
| `--listen IP:PORT` | Warm | Numeric socket destination, otherwise first configured listener |
| `--input FILE` | Warm | Additional lines `/path` or `host.example /path` |
| `--timeout-secs N` | Warm | Per-request socket timeout, default 10; not a whole-batch budget |
| `--max-targets N` | Warm | Path plus input target cap, default 256 |
| `--repeat N` | Warm | Requests per target, default 1 |
| `--fail-fast` | Warm | Stop at first failed request |
| `--dry-run` | Warm | Validate and print plan, no HTTP requests |
| `--allow-status CODE` | Warm | Repeat to accept additional statuses; 2xx/3xx accepted by default |
| `--cache-status-header NAME` | Warm | Header to inspect, default `x-cache-status` |
| `--expect-cache-status VALUE` | Warm | Repeat acceptable values, for example MISS and HIT |
| `--expect-cache-status-sequence MISS,HIT` | Warm | Expected per-repeat sequence; do not combine with the previous option |

### Key And Lookup Assertions

Assertions turn policy/metadata expectations into a nonzero result on mismatch.
Boolean switches below require true; there is no `--flag false` form. To inspect
false values, read the printed policy rather than passing a trailing `false`.

| Shared assertion | Expected value |
| --- | --- |
| `--expect-ineligible`, `--expect-reason TEXT` | Bypass status and bounded reason |
| `--expect-cache-lock-enabled` | Cache lock enabled |
| `--expect-cache-lock-wait-timeout-secs N` | Lock wait timeout |
| `--expect-cache-predictor-enabled` | Predictor enabled |
| `--expect-origin-protection-enabled` | Origin protection enabled |
| `--expect-origin-protection-max-concurrent-fills N` | Fill limit |
| `--expect-peer-fill-enabled` | Peer fill enabled |
| `--expect-peer-fill-peers N` | Peer count |
| `--expect-peer-fill-max-concurrent-requests N` | Peer request cap |
| `--expect-memory-tier-enabled`, `--expect-disk-tier-enabled` | Named tier enabled |
| `--expect-storage-tiers N` | Enabled tier count |
| `--expect-scope vhost`, `--expect-scope route` | Selected policy scope |
| `--expect-vhost NAME`, `--expect-route NAME` | Selected names |
| `--expect-namespace VALUE` | Cache namespace |
| `--expect-key-namespace VALUE` | Operator key namespace |
| `--expect-user-tag VALUE` | Purge user tag |

Key-only `--expect-eligible` requires cache eligibility. Lookup adds:

| Lookup assertion | Expected metadata |
| --- | --- |
| `--require-object`, `--expect-objects N` | Presence / exact matching object count |
| `--expect-freshness-state STATE` | Repeat `fresh`, `stale`, `expired` |
| `--expect-status CODE`, `--expect-tier TIER` | Repeat desired statuses / `memory`, `disk` |
| `--expect-fresh-ttl-secs N`, `--expect-body-bytes N` | Repeat TTL / stored body-size expectations |
| `--expect-header-name NAME`, `--expect-header 'Name: value'` | Repeat stored header requirements |
| `--expect-cache-tag TAG` | Repeat required tags |
| `--expect-purge-indexed` | At least one matching object is purge indexed |
| `--expect-serve-stale-if-error`, `--expect-serve-stale-while-revalidate` | Required stale-serving state |

See [cache operations](cache-operations.md) for matching semantics when several
objects/requirements are present. Metadata output may reveal URLs, queries,
cache tags and internal policy names. Keep it private even without body output.

### Generate An Encryption Key

`fluxheim cache-keygen` writes a fresh 256-bit hex secret to stdout. It does not
install or rotate the server's cache key. Redirect it into a **new** private
file, following [cache encryption](cache-encryption.md), rather than displaying
it or overwriting a key still protecting existing data. Key generation itself
does not require the cache runtime feature. Do not send its output to CI logs.

## Crypto And Certificate Tools

```sh
fluxheim crypto
fluxheim --config gateway.toml crypto
fluxheim-acme --config gateway.toml targets
fluxheim-acme --config gateway.toml status
```

Without `--config` or `FLUXHEIM_CONFIG`, `crypto` reports compile/provider
information without loading a discovered config. With config it also reports configuration intent,
using the loader without runtime-path checks. It is not a compliance certificate
or proof of a successful handshake.

`fluxheim --config gateway.toml acme-renew` performs one issuance/renewal pass.
`--force-renew` forces configured targets; hidden legacy `--all` is deprecated.
Neither is a dry-run. [Renewal](acme.md) and [account/recovery procedures](acme-recovery.md)
explain due policy, challenges, limits, storage and live activation.

`fluxheim acme-init ISSUER` writes local issuer configuration/secrets. See the
[issuer setup recipes](acme-accounts.md) before executing it:

| Initializer option | Meaning |
| --- | --- |
| `--email ADDRESS` | Account contact |
| `--kid-file FILE`, `--hmac-key-file FILE` | Paired EAB input files; both required together |
| `--terms-of-service-url HTTPS_URL`, `--accept-terms-of-service` | Paired explicit operator acceptance; never assume consent from an example |
| `--non-interactive` | Fail instead of asking for missing input |
| `--force` | Permit replacement of initializer output; not permission to ignore trust checks |
| `--no-systemd` | Do not create a systemd credential drop-in |
| `--output FILE` | Default `/etc/fluxheim/conf.d/acme.toml` |
| `--storage DIR` | Default `/var/lib/fluxheim/acme` |
| `--secrets-dir DIR` | Default `/etc/fluxheim/secrets` |
| `--systemd-dropin-dir DIR` | Default `/etc/systemd/system/fluxheim.service.d` |

Those defaults describe Linux packaging; supply appropriate paths and
`--no-systemd` where systemd is absent. Initialization/issuance is not performed
by the CLI guide test. Follow the separate staging-CA qualification procedure.

The companion `fluxheim-acme` has its own `--config`, help/version and commands:

| Command/options | Purpose |
| --- | --- |
| `targets` | Configured renewal targets, no issuance |
| `status [--vhost NAME]` | Certificate status/planning information |
| `renew [--vhost NAME] [--force-renew] [--no-reload]` | Issue/renew, optionally suppress explicit post-pass reload |
| `reload` | Ask the local certificate control socket to reload |
| `doctor [--online]` | Local diagnostics; opt into issuer network checks |
| `account-rollover --issuer NAME [--confirm]` | Plan or confirm account-key replacement |
| `account-deactivate --issuer NAME [--confirm]` | Plan or confirm account deactivation |
| `revoke --vhost NAME [--confirm]` | Plan or confirm certificate revocation |

Do not substitute account deactivation for certificate revocation. Scope,
confirmation, transport and recovery restrictions are documented in
[ACME accounts](acme-accounts.md) and [ACME recovery](acme-recovery.md).

## Automation And Troubleshooting

- Test the exit status, not whether stdout is empty. Quiet validation is empty
  on success; diagnostic commands print on success. Syntax errors and operation
  failures are nonzero; do not depend on one universal error-code number.
- Use argument arrays in automation, an explicit executable/config path, a
  process timeout and bounded private output retention. Do not evaluate output
  as shell commands. Never treat top-level validation flags as a dry-run prefix.
- A feature error means the chosen binary cannot perform that check/operation.
  A tester profile does not add features. Compare the deployed package and
  [feature reference](../reference/features.md).
- A path error may concern the file, any parent, symlinks, ownership or ACLs.
  Repair the deployment layout; do not bypass protection by running the live
  service as root. Recheck as the service user.
- A DNS success or `config tester: ok` is not a complete readiness test. Finish
  with actual listener, TLS, application, cache and collector smoke checks.

## Guide Qualification

```sh
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
cargo build --locked --no-default-features --features profile-development --bin fluxheim-config-tester
python3 scripts/test_cli_examples.py
python3 scripts/smoke_cli_examples.py --binary target/debug/fluxheim \
  --tester target/debug/fluxheim-config-tester
```

The harness uses isolated owner-private fixtures, argument arrays and bounded
subprocesses. It checks actual generated help against this option inventory,
quiet/printed validation, environment precedence, negative syntax/semantics,
combined tester diagnostics and the two current gaps. It deliberately does not
issue certificates, touch production stores, print generated secrets or claim
native-platform qualification on a platform where it was not executed.
