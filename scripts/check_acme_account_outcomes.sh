#!/usr/bin/env sh
set -eu
cargo build --locked --no-default-features --features profile-web-server,acme-client --bin fluxheim-acme
test_name=tests::account_outcome_contract::native_companion_reconciles_account_outcomes_across_processes
if ! result=$(cargo test --locked -p fluxheim-acme --all-features --lib "$test_name" -- --exact --ignored); then
    printf '%s\n' "$result" >&2
    exit 1
fi
printf '%s\n' "$result"
printf '%s\n' "$result" | grep -Fq '1 passed; 0 failed'
