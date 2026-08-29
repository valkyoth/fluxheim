# Fluxheim 1.8.2 Release Notes

Fluxheim 1.8.2 is the Windows portable-parity development line. It targets
native MSVC builds on both x86_64 and ARM64 Windows hosts while preserving the
same seven public profiles used by Linux and Apple Silicon macOS.

## In Progress

- Build unsigned `.zip` previews for `full`, `wasm`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` on both Windows architectures.
- Replace Unix-only filesystem, local-control, locking, shutdown, and
  certificate-storage assumptions with reviewed Windows-native behavior.
- Add native live static, proxy, TLS, cache, admin, load-balancer,
  observability, and packaged-Wasm tests before publishing Windows artifacts.
- Produce exact-tag, architecture, checksum, test, and reproducibility evidence
  from dedicated Windows builders. Planning-only output is not releasable.

These archives remain unsigned previews. Authenticode and installer work stays
deferred until company-backed publisher credentials are available.
