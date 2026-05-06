#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check)
        cargo_action="check"
        ;;
    release)
        cargo_action="build --release"
        ;;
    *)
        echo "usage: scripts/validate-tls-backends.sh [check|release]" >&2
        exit 2
        ;;
esac

run_tls_backend() {
    backend="$1"
    features="proxy,$backend"
    scripts/validate-features.sh "$features"
    echo "tls backend: $cargo_action --no-default-features --features $features"
    if [ "$backend" = "tls-boringssl" ]; then
        extra_args="$(bindgen_extra_clang_args)"
        if [ -n "$extra_args" ]; then
            BINDGEN_EXTRA_CLANG_ARGS="$extra_args" cargo $cargo_action --no-default-features --features "$features"
        else
            cargo $cargo_action --no-default-features --features "$features"
        fi
    else
        cargo $cargo_action --no-default-features --features "$features"
    fi
}

has_libclang() {
    if [ -n "${LIBCLANG_PATH:-}" ]; then
        return 0
    fi

    for candidate in \
        /usr/lib*/libclang*.so* \
        /usr/lib/*/libclang*.so* \
        /usr/lib*/llvm*/lib/libclang*.so* \
        /usr/lib/llvm*/lib/libclang*.so*
    do
        if [ -e "$candidate" ]; then
            return 0
        fi
    done

    return 1
}

bindgen_extra_clang_args() {
    if [ -n "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]; then
        printf '%s\n' "$BINDGEN_EXTRA_CLANG_ARGS"
        return 0
    fi

    args=""

    for include_dir in \
        /usr/lib*/clang/*/include \
        /usr/lib/clang/*/include
    do
        if [ -f "$include_dir/stddef.h" ]; then
            args="$args -isystem $include_dir"
            break
        fi
    done

    for include_dir in \
        /usr/lib*/gcc/*/*/include \
        /usr/lib/gcc/*/*/include
    do
        if [ -f "$include_dir/stddef.h" ]; then
            args="$args -isystem $include_dir"
            break
        fi
    done

    printf '%s\n' "${args# }"
}

run_tls_backend tls-rustls
run_tls_backend tls-openssl
run_tls_backend tls-s2n

if has_libclang; then
    run_tls_backend tls-boringssl
elif [ "${FLUXHEIM_REQUIRE_BORINGSSL:-0}" = "1" ]; then
    echo "tls backend: tls-boringssl requires libclang for bindgen; set LIBCLANG_PATH or install libclang" >&2
    exit 1
else
    echo "tls backend: skipping tls-boringssl because libclang is not available"
    echo "tls backend: set FLUXHEIM_REQUIRE_BORINGSSL=1 to make this a hard failure"
fi
