#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if [ "$(uname -s)" != "Linux" ]; then
    echo "ACME mount-boundary smoke requires Linux" >&2
    exit 1
fi

test_name=acme_directory::tests::owned_directory_reconciliation_rejects_bind_mount
build_output=$(cargo test --locked -p fluxheim-acme --features acme-client \
    --no-run --message-format=json)
test_binary=$(printf '%s\n' "$build_output" \
    | sed -n 's/.*"executable":"\([^"]*\/fluxheim_acme-[^"]*\)".*/\1/p' \
    | tail -n 1)
if [ -z "$test_binary" ] || [ ! -x "$test_binary" ]; then
    echo "ACME mount-boundary smoke could not locate the compiled test binary" >&2
    exit 1
fi

run_in_user_namespace() {
    unshare --user --map-root-user --mount --propagation private --fork \
        "$test_binary" \
        --exact "$test_name" --ignored --nocapture
}

select_container_runtime() {
    runtime=${FLUXHEIM_ACME_MOUNT_TEST_RUNTIME:-}
    if [ -z "$runtime" ]; then
        if command -v podman >/dev/null 2>&1; then
            runtime=podman
        elif command -v docker >/dev/null 2>&1; then
            runtime=docker
        else
            echo "ACME ownership smoke requires Podman or Docker for its two-UID fixture" >&2
            exit 1
        fi
    fi
    case "$runtime" in
        podman | docker) ;;
        *)
            echo "unsupported ACME mount-boundary container runtime: $runtime" >&2
            exit 1
            ;;
    esac

    image=${FLUXHEIM_ACME_MOUNT_TEST_IMAGE:-docker.io/library/debian:13.3-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430}
}

run_ownership_test() {
    # A separate private tmpfs provides two UIDs without granting mount privileges.
    ownership_test=alpn_control::directory_tests::root_broker_refuses_foreign_owner_without_modifying_storage
    ownership_result=$("$runtime" run --rm --network none --read-only --cap-drop ALL \
        --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges \
        --pids-limit 64 --tmpfs /work:rw,nosuid,nodev,noexec,mode=0700,size=8m \
        --user 0:0 --workdir /work --entrypoint /fluxheim-acme-test \
        -v "$test_binary:/fluxheim-acme-test:ro,Z" "$image" --exact "$ownership_test" --ignored)
    printf '%s\n' "$ownership_result"
    printf '%s\n' "$ownership_result" | grep -Fq '1 passed; 0 failed'
}

run_in_constrained_container() {
    apparmor_option=
    if [ "$runtime" = docker ]; then
        # docker-default denies mount(2) independently of CAP_SYS_ADMIN.
        apparmor_option=--security-opt=apparmor=unconfined
    fi
    # apparmor_option is either empty or one fixed argument selected above.
    # shellcheck disable=SC2086
    "$runtime" run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        --cap-add SYS_ADMIN \
        --security-opt no-new-privileges \
        $apparmor_option \
        --pids-limit 64 \
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
        --user 0:0 \
        --workdir /tmp \
        --entrypoint /fluxheim-acme-test \
        -v "$test_binary:/fluxheim-acme-test:ro,Z" \
        "$image" \
        --exact "$test_name" --ignored --nocapture
}

mode=${FLUXHEIM_ACME_MOUNT_TEST_MODE:-auto}
case "$mode" in
    auto)
        if command -v unshare >/dev/null 2>&1 \
            && unshare --user --map-root-user --mount --propagation private --fork true \
                >/dev/null 2>&1; then
            backend=userns
        else
            echo "ACME mount-boundary smoke: user namespaces unavailable; using constrained container" >&2
            backend=container
        fi
        ;;
    userns)
        if ! command -v unshare >/dev/null 2>&1; then
            echo "ACME mount-boundary smoke requires util-linux unshare in userns mode" >&2
            exit 1
        fi
        backend=userns
        ;;
    container)
        backend=container
        ;;
    *)
        echo "unsupported ACME mount-boundary smoke mode: $mode" >&2
        exit 1
        ;;
esac

select_container_runtime
run_ownership_test
if [ "$backend" = userns ]; then
    mount_result=$(run_in_user_namespace)
else
    mount_result=$(run_in_constrained_container)
fi
printf '%s\n' "$mount_result"
printf '%s\n' "$mount_result" | grep -Fq '1 passed; 0 failed'
echo "ACME mount-boundary smoke passed"
