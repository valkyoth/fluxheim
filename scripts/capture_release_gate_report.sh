#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | release)
        ;;
    *)
        echo "usage: scripts/capture_release_gate_report.sh [check|release]" >&2
        exit 2
        ;;
esac

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
report_dir="release-reports/${timestamp}-${mode}"
mkdir -p "$report_dir"

summary="$report_dir/summary.txt"
git_status="$report_dir/git-status.txt"

{
    echo "Fluxheim release gate report"
    echo "Generated UTC: $timestamp"
    echo "Mode: $mode"
    echo "Deep gate: ${FLUXHEIM_CAPTURE_DEEP:-0}"
    echo "Git revision: $(git rev-parse --verify HEAD 2>/dev/null || echo unknown)"
    echo
    echo "Selected optional gate variables:"
    env | sort | grep '^FLUXHEIM_' || true
    echo
} >"$summary"

git status --short --branch >"$git_status" 2>&1 || true

if [ "${FLUXHEIM_CAPTURE_DEEP:-0}" = "1" ]; then
    gate_cmd="scripts/stable_release_deep_gate.sh"
    gate_log="$report_dir/stable_release_deep_gate.log"
else
    gate_cmd="scripts/stable_release_gate.sh"
    gate_log="$report_dir/stable_release_gate.log"
fi

{
    echo "Gate command: $gate_cmd $mode"
    echo "Gate log: $gate_log"
} >>"$summary"

set +e
"$gate_cmd" "$mode" >"$gate_log" 2>&1
status="$?"
set -e

{
    echo
    echo "Gate exit status: $status"
    echo "Report directory: $report_dir"
} >>"$summary"

if [ "$status" -eq 0 ]; then
    echo "release gate report: ok"
    echo "release gate report: $report_dir"
else
    echo "release gate report: failed with status $status" >&2
    echo "release gate report: $report_dir" >&2
fi

exit "$status"
