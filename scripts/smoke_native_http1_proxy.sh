#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-server native_http1
cargo test --locked -p fluxheim-server native_proxy_forwards_downstream_request_to_upstream
cargo test --locked -p fluxheim-server native_proxy --features tls-rustls
cargo test --locked -p fluxheim-server native_proxy --no-default-features --features tls-openssl
scripts/smoke_graceful_drain.sh
scripts/smoke_systemd_socket_activation.sh
scripts/smoke_zero_downtime_upgrade.sh

echo "native HTTP/1 listener/proxy smoke passed"
