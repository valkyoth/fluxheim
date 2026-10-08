#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

expect_rejection() {
    # Match diagnostics independently of CI's forced terminal colors.
    if output=$(cargo check --color never --locked \
        --manifest-path "$ROOT_DIR/tools/http3-source-probe/Cargo.toml" \
        --no-default-features "$@" 2>&1); then
        echo 'HTTP/3 probe accepted an invalid crypto provider selection' >&2
        exit 1
    fi
    case "$output" in
        *'error: select exactly one probe crypto provider'*) ;;
        *)
            printf '%s\n' "$output" >&2
            echo 'HTTP/3 probe failed for an unexpected reason' >&2
            exit 1
            ;;
    esac
}

expect_rejection
expect_rejection --features ring,aws-lc
echo 'HTTP/3 probe provider rejection checks: ok'
