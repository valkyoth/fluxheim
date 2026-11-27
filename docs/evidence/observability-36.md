# ACME account deactivation and recovery

The account outcome fixture uses a disposable key, a trusted loopback TLS
endpoint and the real ACME client. It distinguishes the fixture's account
state from what the companion observed. It checks the target and payload of
each request but is not a CA implementation or a signature verifier.

Build the debug companion first, then run the tests in the same target
directory. A build of the default profile in between can replace the companion
with one that does not have the ACME client.

```sh
cargo build --locked --no-default-features --features profile-web-server,acme-client --bin fluxheim-acme
cargo test --locked -p fluxheim-acme --all-features --lib account_outcome_contract -- --include-ignored
```

The cross-process test invokes separate companion processes against the same
protected storage. A rejected update followed by a valid status restores the
same account; an applied update followed by a broken reply requires a status
read before cleanup. A refused status read does neither. The library tests
also exercise cancellation during the request, lock contention, timeout,
malformed responses, redirects, unknown status and issuer mismatch.

No public CA or production credentials are used. For separate qualification
of ordinary registration, certificate issuance, renewal and revocation in
the packaged images, run `sh scripts/check_acme_scope.sh`.
