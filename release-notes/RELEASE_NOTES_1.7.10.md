# Fluxheim 1.7.10 Release Notes

Fluxheim 1.7.10 is the stabilization and release-gate hardening release for
the 1.7 WebAssembly policy line. It turns the documented migration examples
into explicit operator-selectable and release-gated acceptance evidence while
keeping the typed policy ABI constrained.

## In Progress

- Expose focused `scripts/test_starter.py` entries for F5 iRules-style,
  nginx Lua/OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like Wasm policy
  examples.
- Keep focused and aggregate Wasm policy checks on one implementation path,
  and validate that the deep release gate requires the complete Wasm smoke.
- Audit every guest-controlled symbolic ID decoder for total, panic-free
  behavior over arbitrary integer inputs.

## Compatibility Boundary

- Fluxheim provides bounded capability mappings, not source-syntax or runtime
  compatibility with iRules, Lua/OpenResty, SPOE, or VCL.
- New host capabilities that require blocking I/O or third-party native
  callback code remain out of process until a killable, bounded IPC runner is
  designed and proven.
