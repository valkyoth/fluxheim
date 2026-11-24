# ACME challenge ownership and restart

Run `cargo test --locked -p fluxheim-acme --all-features` for the order
and filesystem regressions. Native Linux, macOS arm64 and Windows x64 suites
exercise cancellation, timeout, competing owners, subsequent reuse of the same
token, partial TLS challenge cleanup and independent file failures. Fixtures
also check that a changed file and an unclaimed file are preserved and
unreachable, while other owned files are removed.

The packaged test (`sh scripts/check_acme_scope.sh`) uses a local Pebble
issuer. Seven runs stopped a disposable companion without running destructors:
before the account, order and authorization responses (no token published),
and before the challenge, ready-order, finalize and certificate responses
(live HTTP 200, then 404 while the token was still on disk). Each run restarted
the gateway against the same volume and confirmed that the owned files were
gone and the installed certificate was unchanged. This is an HTTP observation;
the native TLS-ALPN tests inspect challenge-store files, not a public CA or
live ALPN handshake.

For operating and upgrading a separate gateway and companion see
[Challenge Cleanup](../guides/acme-recovery.md#challenge-cleanup).
