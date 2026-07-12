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
- Add a checked-in nginx Lua/OpenResty-style header policy and complete config
  fixture. Live coverage proves the allow-listed origin request mutation,
  client response mutation, upstream-header removal, and fail-closed rejection
  of unknown mutation IDs.
- Add a checked-in HAProxy Lua/SPOE-style route policy and complete config
  fixture. Live coverage proves symbolic canary/mirror selection, unavailable
  branch rejection, selected-route policy enforcement, native load balancing,
  and managed-cookie persistence without exposing backend addresses.
- Promote the existing cache lookup/store WAT pair to the validated VCL-like
  parity example. The live smoke now proves pass, MISS/HIT, bounded variants,
  image-only TTL/tag/header metadata, expiry, tag purge, non-image isolation,
  and fail-closed invalid mutations.
- Add a deterministic policy builder that emits deployable `.wasm` files and
  `SHA256SUMS` under `target/wasm-policy-examples/`.
- Add one complete Wasm smoke shared by `scripts/test_starter.py` and the
  opt-in stable/deep release gate, fixing the launcher's previous multi-script
  command wiring.
- Add a standalone binary smoke using generated modules, exact digest pins, a
  private plugin root, file-based configuration, two local origins, and real
  HTTP traffic through every migration family.

## Fixed

- Stop attempting to initialize the native disk-cache backend for memory-only
  cache policies, avoiding an incorrect missing-path error at startup.

## Security

- ACME certificate installation now retains the exact trusted storage-boundary
  descriptor and reconciles every managed descendant to the selected UID/GID
  through descriptor-relative, no-symlink traversal. Restart repairs
  intermediate `0700 root:root` directories left by an interrupted root-run
  handoff, while outside-boundary targets fail before mutation. Linux also
  enforces `openat2(RESOLVE_NO_XDEV)` and other Unix platforms reject device-ID
  changes before ownership mutation, preventing reconciliation through nested
  mount points. The bind-mount regression is explicitly ignored in
  ordinary Rust runs and executed by CI and the deep release gate through a
  dedicated smoke using root-mapped user and private mount namespaces, without
  a privileged container. Hosts that disable user namespaces use a
  digest-pinned, network-isolated, read-only container with every capability
  dropped except the mount operation's required `SYS_ADMIN` capability. The
  regression requires the precise `EXDEV` result from Linux `RESOLVE_NO_XDEV`
  using the namespace's mapped identity, so a later ownership error cannot
  produce a false pass.
- Managed ACME account generation now creates P-256 material in zeroizing
  RustCrypto secret/document types before importing it into Ring and retaining
  the durable copy in `sanitization::SecretVec`, removing the transient
  non-zeroizing Ring PKCS#8 document.

- Open private snapshot files with platform no-follow semantics before
  validating type and permissions from the opened descriptor. This removes a
  check-then-open race while retaining fail-closed symlink handling.
- Use the snapshot store's atomic writer and descriptor-based permission
  changes for corruption fixtures, keeping negative security tests realistic
  without normalizing raw path mutation patterns.
- Use one no-follow parent-directory descriptor for Unix snapshot publication,
  with descriptor-relative temporary creation, create-new linking, replacement,
  cleanup, metadata checks, and directory synchronization. This prevents
  parent replacement from redirecting an in-progress atomic write.

## Compatibility Boundary

- The migration examples use Fluxheim's typed, bounded policy ABI; they do not
  execute iRules, Lua, SPOE, or VCL source directly.
- Every example remains bounded by configured symbolic IDs and denies arbitrary
  filesystem, network, secret, request-body, and cache-object access.
