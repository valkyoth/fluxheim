#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-server native_http1

echo "native HTTP/1 listener/proxy smoke passed"
