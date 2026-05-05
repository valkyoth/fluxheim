#!/usr/bin/env sh
set -eu

cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --no-default-features --features proxy,load-balancer
cargo test --no-default-features --features proxy,cache
cargo test --no-default-features --features cache
cargo test --no-default-features --features web
cargo test --no-default-features --features proxy,metrics
cargo test --no-default-features --features proxy,tls-rustls,acme
cargo check --no-default-features --features proxy,tls-rustls
cargo run --quiet -- --check-config --config examples/fluxheim.toml >/dev/null
cargo run --quiet -- --check-config --config examples/admin.toml >/dev/null
cargo run --quiet -- --check-config --config examples/vhosts.toml >/dev/null
cargo run --quiet -- --check-config --config examples/conf.d >/dev/null
cargo deny check
cargo audit
