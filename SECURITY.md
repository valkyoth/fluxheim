# Security Policy

Fluxheim is security-sensitive infrastructure. Treat dependency, TLS, cache, and
request-routing changes as high-risk until tested.

## Routine Checks

Run these regularly and before releases:

```bash
cargo deny check
cargo deny check licenses
cargo audit
```

## Dependency Policy

The dependency policy lives in `deny.toml`. Unknown registries and git sources
are denied by default. License exceptions must be narrow, named, versioned, and
documented with the reason for acceptance.

## Reporting

Do not publish exploitable security details before a fix is available. Open a
private security advisory or contact the maintainers directly once the project
has public repository security channels configured.
