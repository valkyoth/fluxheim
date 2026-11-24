# Background ACME renewal retry

Before the correction, two immediate ticks on a missing certificate with
unaccepted issuer terms attempted issuance twice. The scheduler regression
uses the same failing issuance path and counts attempts. With a three-second
initial delay and an eight-second cap, failures at 0, 3, 9, 17 and 25 seconds
are attempted; intervening ticks are not. The clock is injected, not slept.

The native suites cover 32 configured vhosts, per-vhost success reset, worker
replacement, cancellation between attempts, an independent one-shot command,
overflow and configuration limits. ACME client tests passed on Linux (109,
one existing privileged mount test ignored), macOS arm64 (109), and Windows
x64 (92). The ACME-enabled Linux workspace suite and strict Clippy passed.

The packaged test in `sh scripts/check_acme_scope.sh` builds the full and PHP
Wolfi images. After normal HTTP-01 issuance via Pebble, the test adapter
refuses two directory requests for one issuer before forwarding requests again.
It checks the observed three- and six-second minimum gaps, independent
certificate installation for a second vhost, the unchanged original certificate
and an HTTP response over an established TLS connection during the fault.
It then checks that retrying installs a replacement. No public CA is contacted.

See the [operator retry policy](../guides/certificate-renewal.md#retry-policy)
for the seven-day configuration ceiling, tick cadence and process boundaries.
