# Fluxheim 1.8.2 Release Notes

Fluxheim 1.8.2 is the Windows portable-parity development line. It targets
native x86_64 MSVC builds while preserving the same seven public profiles used
by Linux and Apple Silicon macOS. Windows ARM64 is deferred until sustainable
native build and test infrastructure is available.

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
- Evaluate Windows trust policy against retained target and ancestor handles,
  and create cache object and encryption-state temporary files relative to a
  validated parent before writing bytes.
- Make dedicated builder SSH provisioning global and account-scoped even when
  the vendor configuration ends in a `Match` block, and reject non-SSH, mixed,
  or duplicate tag signature formats before allowed-signers verification.
- Flush the load-balancer state file and containing directory after atomic
  replacement on Windows.
- Roll back newly created Windows files after a retained-parent ACL rejection
  through delete-capable handles, and surface any rollback failure explicitly.
- Bind the Windows filesystem-security audit to the complete reviewed
  first-party source boundary as well as the pinned ACL dependency checksum.
- Make the focused Wolfi, Alpine, Debian, and SUSE BCI PHP images
  self-contained managed
  PHP-FPM runtimes with one smoke-verified application extension contract,
  including MySQLi and its required MySQLnd module. The PHP image smoke rejects
  extension load warnings and executes a real request through each image.
- Replace `php-suse-micro` with `php-suse-bci`. The dedicated SUSE BCI PHP base
  provides an official PHP repository and matching PHP-FPM stack, while the
  pinned SL Micro base does not. Other SUSE Micro profiles remain supported,
  and Windows PHP continues to use external TCP FastCGI as documented.

## Remaining Release Blocks

- Produce exact-tag, architecture, checksum, test, and reproducibility evidence
  from a dedicated native x86_64 Windows builder. Evidence records the
  Windows edition and build, and every executable in all seven ZIP profiles
  must launch and report the expected version. Planning-only output and the
  normal x86_64 CI result are not substitutes for exact-tag release evidence.
- Verify two clean archive builds are byte-identical on the dedicated builder
  before publishing the x86_64 archives.

The Unix/OpenSSL FIPS support shim remains excluded as an independent Windows
workspace package while staying covered by the dedicated Linux OpenSSL-FIPS
profiles.

These archives remain unsigned previews. Authenticode and installer work stays
deferred until company-backed publisher credentials are available.
