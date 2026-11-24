# ACME certificate installation and activation

The packaged test (`sh scripts/check_acme_scope.sh`) built the full and PHP
Wolfi images and issued real certificates through a local Pebble CA. It
compared the disk leaf with the leaf from a fresh hostname-verified TLS
handshake, rather than treating successful issuance or a log as proof of
activation.

| Case | Observed result |
| --- | --- |
| Background renewal enabled for activation | Replacement installed and served on a new connection |
| Background install-only | Replacement installed; new connection still served the original |
| Companion forced renewal with `--no-reload` | Disk changed; served leaf did not |
| Explicit companion reload | New connection saw the staged leaf; established connection still served HTTP |
| Companion renewal with activation enabled | Newly issued leaf matched the live listener |
| Companion sharing storage but not the gateway socket | Nonzero exit after installation; old leaf remained live until explicit activation |
| Invalid replacement pair | Reload failed; a new connection still saw the last good leaf |

Native Linux, macOS arm64 and Windows x64 tests exercised background
install-only, absent handles, successful swap, established TLS sessions and
invalid replacement rollback using Rustls and loopback TCP. Native Windows
also rejected external socket activation. Linux and macOS exercised the
bounded Unix request/reply including a full accept queue, absent/refused
sockets, slow and silent peers, incomplete and oversized replies, and a
complete acknowledgement without EOF. OpenSSL generation and invalid-pair
reload tests passed on Linux. The packaged local-CA test ran on Linux;
the native handshake tests use locally generated certificates.

The removed configuration key is rejected for both boolean values in root
and fragment parsing. See the [migration guide](../guides/certificate-renewal.md#reload-migration).
