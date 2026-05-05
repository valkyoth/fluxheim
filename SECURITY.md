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
```

The full release gate is documented in
[Release Checklist](docs/release-checklist.md). Use it before publishing
artifacts, changing dependency versions, or changing TLS/cache/proxy behavior.

## Dependency Policy

The dependency policy lives in `deny.toml`. Unknown registries and git sources
are denied by default. License exceptions must be narrow, named, versioned, and
documented with the reason for acceptance.

Reviewed advisory exceptions are allowed only when there is no compatible
upgrade and the affected API is not reachable in Fluxheim. Each exception must
be listed in both `deny.toml` and `.cargo/audit.toml`, with a removal condition.

## TLS File Policy

On Unix deployments, private key files should be owner-only (`0600`) and ACME
storage directories should be owner-only (`0700`). Fluxheim's TLS storage helper
checks these permissions separately from config parsing so operators can validate
configuration before certificates are provisioned and then validate filesystem
state before startup or renewal.

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

## Reporting

Do not publish exploitable security details before a fix is available. Open a
private security advisory or contact the maintainers directly once the project
has public repository security channels configured.
