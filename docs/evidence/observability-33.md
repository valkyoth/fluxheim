# Certificate installation recovery

The ACME crate's recovery tests interrupt installation at persisted boundaries,
including between the two active-file replacements. They run recovery twice
and validate the selected certificate and key. Missing or changed recovery
inputs must leave the journal and the other active file untouched.

The packaged gateway smoke uses two real Pebble-issued leaves, reconstructs an
interrupted legacy rollback in its private container volume, runs offline doctor
twice and checks the exact TLS leaf before and after explicit activation.

Run `cargo test --locked -p fluxheim-acme --all-features` and
`sh scripts/check_acme_scope.sh`. These are logical crash-boundary tests,
not a claim of power-loss testing on every filesystem.
