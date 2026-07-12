# Fluxheim 1.7.9 Release Notes

Fluxheim 1.7.9 is the documentation and runnable-example parity release for
operators translating common F5 iRules, nginx Lua/OpenResty, HAProxy Lua/SPOE,
and VCL-style policy jobs into Fluxheim's typed WebAssembly policy ABI. It
provides capability mappings, not syntax or runtime compatibility with those
products.

## Added

- Add a checked-in F5 iRules-style route access policy and complete config
  fixture using Fluxheim's typed access-decision ABI.
- Add real listener coverage proving public requests reach origin, attached
  admin requests are denied before origin dispatch, and plugin traps fail
  closed.
- Add `scripts/smoke_wasm_policy_examples.sh` to `scripts/test_starter.py` and
  the opt-in Wasm release gate.

## Security

- Open private snapshot files with platform no-follow semantics before
  validating type and permissions from the opened descriptor. This removes a
  check-then-open race while retaining fail-closed symlink handling.
- Use the snapshot store's atomic writer and descriptor-based permission
  changes for corruption fixtures, keeping negative security tests realistic
  without normalizing raw path mutation patterns.

## In Progress

- Add checked-in plugins, configuration fixtures, operator documentation, and
  live HTTP tests for all four migration families.
- Keep every example bounded by configured symbolic IDs and deny arbitrary
  filesystem, network, secret, request-body, or cache-object access.
