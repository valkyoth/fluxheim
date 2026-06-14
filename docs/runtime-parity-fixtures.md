# Runtime Parity Fixtures

Status: `1.6.0` Pingora-exit baseline

The `1.6.x` line replaces the current Pingora runtime in stages. Before any
cutover, Fluxheim keeps an explicit inventory of fixtures and smoke scripts that
define current behavior. This is not the whole test suite; it is the minimum
release-gated parity surface that must stay visible while old and new runtime
paths coexist.

The machine-readable inventory is:

```text
docs/runtime-parity-fixtures.tsv
```

The inventory is validated by:

```bash
scripts/validate-runtime-fixtures.sh check
```

The gate checks that every listed script, config, directory, fixture, or
document still exists. Script entries must remain executable. Later `1.6.x`
cutover releases should add more entries before replacing a subsystem, not
after discovering a parity gap.

## How To Use

- Add a fixture before changing a runtime boundary.
- Keep fixtures focused on observable behavior, not implementation details.
- Prefer local deterministic scripts over external services unless the feature
  specifically needs a containerized dependency.
- Keep the inventory target column aligned with the `1.6.x` release where the
  fixture matters most.
- Do not delete or rename an inventory entry without updating the release notes
  and explaining what replaces the coverage.

## Relationship To Runtime Baseline

[Runtime Baseline](runtime-baseline.md) records build and dependency evidence.
This document records behavior fixtures. Both are required: dependency removal
without behavior parity is not a successful Pingora exit.
