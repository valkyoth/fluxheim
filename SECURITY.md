# Security Policy

Fluxheim is security-sensitive infrastructure. Treat dependency, TLS, cache, and
request-routing changes as high-risk until tested.

## Routine Checks

Run these regularly and before releases:

```bash
scripts/checks.sh
scripts/release_checks.sh
cargo deny check
cargo deny check licenses
cargo audit
scripts/generate-sbom.sh
scripts/reproducible_build_check.sh
```

GitHub Actions run CI, and GitHub CodeQL default setup should be enabled in the
repository security settings. Keep only one active CodeQL configuration:
GitHub rejects SARIF uploads when default setup and an advanced workflow both
try to analyze the same repository.

The full release gate is documented in
[Release Checklist](docs/guides/release-checklist.md). Use it before publishing
artifacts, changing dependency versions, or changing TLS/cache/proxy behavior.
The Rust dependency threat model and review rules are documented in
[Rust Supply-Chain Security](docs/guides/supply-chain-security.md).

## Dependency Policy

The dependency policy lives in `deny.toml`. Unknown registries and git sources
are denied by default. License exceptions must be narrow, named, versioned, and
documented with the reason for acceptance.

Build scripts, procedural macros, `*-sys` crates, vendored native code, Cargo
aliases, CI workflow edits, and release script edits are treated as executable
supply-chain changes. Review them before merging dependency updates.

Reviewed advisory exceptions are allowed only when there is no compatible
upgrade and the affected API is not reachable in Fluxheim. Each exception must
be listed in the tool that reports it (`deny.toml` or `.cargo/audit.toml`), with
a removal condition.

Current reviewed dependency warning exceptions: none.

## Release Supply-Chain Evidence

Stable releases must publish SPDX and CycloneDX SBOM files generated from the
tagged source tree. The release notes must include SBOM checksums, source archive
checksums, binary checksums, container digests, and the signed tag verification
line.

Fluxheim also runs a local reproducible-build check for release candidates. The
check builds the release binary twice from separate target directories with the
same lockfile and compares the resulting executable hash. This is a practical
release-builder reproducibility gate, not a claim that every supported distro or
container builder is bit-for-bit reproducible across machines.

## TLS File Policy

On Unix deployments, private key files should be owner-only (`0600`) and ACME
storage directories should be owner-only (`0700`). Fluxheim's TLS storage helper
checks these permissions separately from config parsing so operators can validate
configuration before certificates are provisioned and then validate filesystem
state before startup or renewal.

Fluxheim's Unix filesystem trust checks inspect ownership, symlinks, and classic
mode bits. They do not parse POSIX extended ACLs yet. Regulated or multi-tenant
deployments should audit sensitive Fluxheim paths with platform tools such as
`getfacl`, keep parent directories private to the service user, and disable
swap/core dumps for processes that handle admin bearer tokens, EAB secrets, TLS
private keys, or cache encryption credentials. The process-local admin token
MAC key is generated at startup and intentionally remains resident for the
process lifetime, so high-assurance deployments should also disable core dumps,
avoid swap, and use service isolation that prevents `/proc/<pid>/mem` access.

### Fatal Termination And Memory Dumps

Fatal invariant failures and the fatal-output watchdog can abort the process.
An OS memory dump may contain secrets even though Fluxheim's finite fatal reason
records do not. `logging.crash_file` contains those reason records, not a memory
dump; disabling that option does not disable OS crash collection.

The packaged server and ACME systemd units set `LimitCORE=0` (both limits).
Shipped Compose examples set `ulimits.core.soft` and `hard` to zero; direct
Podman/Docker deployments must pass `--ulimit core=0:0`. These are launcher
settings, not properties baked into the image or enforced by the Rust binary.
Recreate containers or restart services after applying them. Existing/custom
deployments do not acquire the settings merely by pulling a new image.

On Linux, `RLIMIT_CORE=0` does **not** prevent a kernel-piped crash collector from
receiving process memory. Inspect `sysctl kernel.core_pattern` on the host,
including container hosts, and configure the actual collector not to retain or
process Fluxheim memory dumps. See the [Linux core documentation](https://man7.org/linux/man-pages/man5/core.5.html).

For hosts using systemd-coredump, an administrator may install a host-wide
`/etc/systemd/coredump.conf.d/90-no-memory-dumps.conf` containing:

```ini
[Coredump]
Storage=none
ProcessSizeMax=0
```

Both settings are needed: `Storage=none` alone can still allow temporary disk
storage for processing. This affects **all applications on the host**, preserves
a crash log entry, and does not remove previously collected dumps. Apply/reload
according to the installed systemd version and check for overriding drop-ins.
See [systemd's collector policy](https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html).
Fluxheim packaging intentionally does not change host-wide crash policy.
Other collectors, Windows Error Reporting/LocalDumps and macOS diagnostic tools
need their own operator-managed policy; Linux limits do not configure them.

Effective-limit tests prove the launcher limits, not absence of host collection,
privileged memory inspection, swap contents or previously retained dumps.

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

## Reporting

Do not publish exploitable security details before a fix is available. Open a
private security advisory or contact the maintainers directly once the project
has public repository security channels configured.
