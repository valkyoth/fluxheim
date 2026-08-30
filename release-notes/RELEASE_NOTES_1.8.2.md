# Fluxheim 1.8.2 Release Notes

Fluxheim 1.8.2 is the Windows portable-parity development line. It targets
native MSVC builds on both x86_64 and ARM64 Windows hosts while preserving the
same seven public profiles used by Linux and Apple Silicon macOS.

## Completed On Native x86_64 CI

- Build and execute unsigned `.zip` previews for `full`, `wasm`, `cache`,
  `proxy`, `load-balancer`, `php`, and `config-tester` with the native MSVC
  toolchain and deny Windows-target compiler warnings.
- Run the complete workspace suite plus live static, proxy, downstream and
  verified upstream TLS, memory and persistent storage-bin cache,
  load-balancer, integrity-authenticated snapshot create/list/rollback and
  doctor verification, admin, metrics, ACME storage, crash-restart recovery,
  CTRL_BREAK shutdown, and packaged-Wasm tests.
- Replace Unix-only filesystem, path, locking, shutdown, and
  certificate-storage assumptions with reviewed Windows-native behavior while
  retaining fail-closed owner, ACL, reparse-point, and exclusive-writer checks.
- Keep the Windows `php` profile on the shared FastCGI request path with
  external TCP pools. Managed PHP-FPM supervision remains Unix-only and is
  rejected during Windows configuration validation and runtime construction;
  a native Windows TCP FastCGI responder regression proves the supported path.
- Cross-check all seven public profiles for `aarch64-pc-windows-msvc` on the
  normal Windows CI host so target-specific compile failures surface before a
  native ARM64 release-builder run. This check does not execute ARM64 code and
  is not accepted as release evidence.
- Enforce confidential Windows ACLs for TLS, ACME, admin, metrics, snapshot,
  cache-encryption, peer-fill, and discovery credentials; new private files and
  directories receive protected DACLs before secret bytes are written.
- Open Windows static response files through retained directory handles with
  reparse traversal disabled, and reject untrusted writable cache, state,
  logging, configuration, ACME, and PHP-spool ancestors.
- Preserve Windows cache purge/refresh semantics with delete-sharing, bound
  cache reads across concurrent growth, make snapshot/ACME/cache directory
  flushes real, and use delete-on-close request-body spool files.
- Pin and record the manual review evidence for the exact
  `windows-permissions` dependency checksum and isolate first-party unsafe
  Windows path traversal in the narrowly scoped
  `fluxheim-windows-security` crate.

## Remaining Release Blocks

- Run the same workspace, seven-profile, live-runtime, archive, and packaged
  Wasm matrix on a native Windows ARM64 cloud builder.
- Produce exact-tag, architecture, checksum, test, and reproducibility evidence
  from dedicated native x86_64 and ARM64 Windows builders. Evidence records the
  Windows edition and build, and every executable in all seven ZIP profiles
  must launch and report the expected version. Planning-only output and the
  normal x86_64 CI result are not substitutes for exact-tag release evidence.
- Verify two clean archive builds are byte-identical on both dedicated builders
  before publishing either architecture.

The Unix/OpenSSL FIPS support shim remains excluded as an independent Windows
workspace package while staying covered by the dedicated Linux OpenSSL-FIPS
profiles.

These archives remain unsigned previews. Authenticode and installer work stays
deferred until company-backed publisher credentials are available.
