#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")

echo "1.0 fixtures: validate representative gateway config set"
# Gateway fixtures use placeholder /srv roots and upstreams. Keep this as a
# static config check; deployment preflight uses --validate-config.
FIXTURES_TMP_DIR="$SMOKE_TMP_ROOT/fluxheim-1-0-fixtures-$$"
export FIXTURES_TMP_DIR
mkdir -p \
    "$FIXTURES_TMP_DIR/config" \
    "$FIXTURES_TMP_DIR/run/fluxheim" \
    "$FIXTURES_TMP_DIR/srv/fluxheim" \
    "$FIXTURES_TMP_DIR/srv/sites" \
    "$FIXTURES_TMP_DIR/var/cache/fluxheim" \
    "$FIXTURES_TMP_DIR/var/lib/fluxheim/acme" \
    "$FIXTURES_TMP_DIR/var/log/fluxheim"
trap 'rm -rf "$FIXTURES_TMP_DIR"' EXIT HUP INT TERM

cp -R examples/gateway-1-0/. "$FIXTURES_TMP_DIR/config"/
find "$FIXTURES_TMP_DIR/config" -type f -name '*.toml' -exec perl -0pi -e '
    s#/run/fluxheim#$ENV{FIXTURES_TMP_DIR}/run/fluxheim#g;
    s#/srv/fluxheim#$ENV{FIXTURES_TMP_DIR}/srv/fluxheim#g;
    s#/srv/sites#$ENV{FIXTURES_TMP_DIR}/srv/sites#g;
    s#/var/cache/fluxheim#$ENV{FIXTURES_TMP_DIR}/var/cache/fluxheim#g;
    s#/var/lib/fluxheim#$ENV{FIXTURES_TMP_DIR}/var/lib/fluxheim#g;
    s#/var/log/fluxheim#$ENV{FIXTURES_TMP_DIR}/var/log/fluxheim#g;
' {} +

cargo run --quiet --no-default-features --features profile-development \
    --bin fluxheim-config-tester -- \
    --config "$FIXTURES_TMP_DIR/config" \
    --profile development \
    --no-runtime-paths >/dev/null
echo "1.0 fixtures: ok"
