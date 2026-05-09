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
        clang_path="$(resolve_clang_path || true)"
        libclang_path="$(resolve_libclang_path || true)"
        if [ -z "$clang_path" ] && [ -z "$libclang_path" ] && [ -z "$extra_args" ]; then
            cargo $cargo_action --no-default-features --features "$features"
        else
            (
                if [ -n "$clang_path" ]; then
                    export CLANG_PATH="$clang_path"
                fi
                if [ -n "$libclang_path" ]; then
                    export LIBCLANG_PATH="$libclang_path"
                fi
                if [ -n "$extra_args" ]; then
                    export BINDGEN_EXTRA_CLANG_ARGS="$extra_args"
                fi
                cargo $cargo_action --no-default-features --features "$features"
            )
        fi
    else
        cargo $cargo_action --no-default-features --features "$features"
    fi
}

has_command() {
    command -v "$1" >/dev/null 2>&1
}

resolve_clang_path() {
    if [ -n "${CLANG_PATH:-}" ]; then
        printf '%s\n' "$CLANG_PATH"
        return 0
    fi
    if has_command clang; then
        command -v clang
        return 0
    fi

    for candidate in clang-22 clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 clang-14 clang-13; do
        if has_command "$candidate"; then
            command -v "$candidate"
            return 0
        fi
    done

    return 1
}

resolve_libclang_path() {
    if [ -n "${LIBCLANG_PATH:-}" ]; then
        printf '%s\n' "$LIBCLANG_PATH"
        return 0
    fi

    for candidate in \
        /usr/lib*/libclang.so* \
        /usr/lib/*/libclang.so* \
        /usr/lib*/llvm*/lib/libclang.so* \
        /usr/lib/llvm*/lib/libclang.so*
    do
        if [ -e "$candidate" ]; then
            dirname "$candidate"
            return 0
        fi
    done

    return 1
}

has_libclang() {
    resolve_libclang_path >/dev/null 2>&1
}

has_bindgen_toolchain() {
    if [ "${FLUXHEIM_REQUIRE_BORINGSSL:-0}" = "1" ]; then
        return 0
    fi

    if [ -n "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]; then
        return 0
    fi

    has_libclang || return 1
    resolve_clang_path >/dev/null 2>&1 || return 1

    return 0
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

if has_bindgen_toolchain; then
    run_tls_backend tls-boringssl
elif [ "${FLUXHEIM_REQUIRE_BORINGSSL:-0}" = "1" ]; then
    echo "tls backend: tls-boringssl requires a complete bindgen toolchain; set LIBCLANG_PATH/BINDGEN_EXTRA_CLANG_ARGS or install clang/libclang" >&2
    exit 1
else
    echo "tls backend: skipping tls-boringssl because a complete bindgen toolchain is not available"
    echo "tls backend: set FLUXHEIM_REQUIRE_BORINGSSL=1 to make this a hard failure"
fi
