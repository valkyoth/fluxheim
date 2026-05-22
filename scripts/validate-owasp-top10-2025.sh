#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | run) ;;
    *)
        echo "usage: scripts/validate-owasp-top10-2025.sh [check|run]" >&2
        exit 2
        ;;
esac

require_file_contains() {
    file="$1"
    pattern="$2"
    label="$3"
    if ! grep -Eq "$pattern" "$file"; then
        echo "owasp baseline failed: missing $label in $file" >&2
        echo "pattern: $pattern" >&2
        exit 1
    fi
}

require_test() {
    name="$1"
    if ! printf '%s\n' "$test_list" | grep -E "(^|::)$name: test$" >/dev/null; then
        echo "owasp baseline failed: missing representative test: $name" >&2
        exit 1
    fi
}

run_test() {
    name="$1"
    echo "owasp baseline: running $name"
    cargo test --lib "$name"
}

echo "owasp baseline: static policy checks"
require_file_contains src/lib.rs '#!\[forbid\(unsafe_code\)\]' "unsafe-code ban"
require_file_contains Cargo.toml 'panic = "abort"' "release panic abort"
require_file_contains .github/workflows/ci.yml 'cargo deny check' "dependency policy gate"
require_file_contains .github/workflows/ci.yml 'cargo audit' "RustSec advisory gate"
require_file_contains .github/workflows/ci.yml 'scripts/generate-sbom.sh' "SBOM generation gate"
require_file_contains .github/workflows/ci.yml 'scripts/validate-fips-openssl.sh check' "FIPS-capable validation gate"
require_file_contains .github/workflows/ci.yml 'scripts/validate-fips-rustls.sh check' "rustls/AWS-LC FIPS-capable validation gate"
require_file_contains deny.toml 'allow-registry = \["https://github.com/rust-lang/crates.io-index"\]' "registry allow-list"
require_file_contains examples/fluxheim.toml 'x_content_type_options = "nosniff"' "example nosniff header"
require_file_contains examples/fluxheim.toml 'x_frame_options = "DENY"' "example frame policy"
require_file_contains examples/fluxheim.toml 'referrer_policy = "no-referrer"' "example referrer policy"
require_file_contains examples/fluxheim.toml 'deny_dotfiles = true' "example dotfile denial"
require_file_contains examples/fluxheim.toml '\[admin\]' "admin config example"
require_file_contains examples/admin.toml 'token_env = "FLUXHEIM_ADMIN_TOKEN"' "admin token source"
require_file_contains docs/fips.md 'FIPS PUB 140-3' "FIPS documentation"
require_file_contains docs/production-readiness.md 'FLUXHEIM_GATE_FIPS_OPENSSL=1' "release FIPS gate documentation"
require_file_contains docs/production-readiness.md 'profile-fips-rustls' "rustls/AWS-LC FIPS documentation"

echo "owasp baseline: collecting test inventory"
test_list="$(cargo test -- --list)"

echo "owasp baseline: checking representative regression tests"
while IFS='|' read -r category test_name; do
    [ -n "$category" ] || continue
    case "$category" in \#*) continue ;; esac
    require_test "$test_name"
done <<'EOF'
A01|rejects_dotfiles_by_default
A01|rejects_traversal
A01|status_endpoint_requires_bearer_token
A01|cache_purge_endpoint_requires_auth_and_purges_by_request_identity
A01|rejects_redirect_location_without_safe_host
A02|directory_listing_is_disabled_by_default
A02|applies_default_response_headers
A02|rejects_enabled_admin_without_auth
A02|rejects_remote_admin_listener_by_default
A03|parses_tls_fips_config_and_requires_fips_capable_build
A04|rejects_tls_fips_policy_with_chacha20_cipher
A04|rejects_tls_fips_policy_with_non_nist_group
A04|rejects_tls_storage_below_symlinked_directory
A04|permission_predicates_allow_only_owner_access
A05|rejects_invalid_generic_header_value
A05|rejects_php_param_control_character_value
A05|cache_warm_targets_reject_header_injection
A05|route_strip_prefix_rejects_traversal_suffixes
A05|dynamic_header_rendering_strips_control_characters_from_variables
A06|rejects_header_bytes_over_global_limit
A06|rejects_header_count_over_global_limit
A06|admin_json_response_is_size_bounded
A06|rejects_too_many_php_params
A06|streaming_body_limit_counter_saturates
A07|admin_token_file_has_size_limit
A07|bearer_token_comparison_checks_full_string
A07|admin_auth_throttle_locks_repeated_failures_by_source
A07|admin_auth_throttle_can_lock_globally
A08|rejects_snapshot_store_root_below_world_writable_directory
A08|rejects_symlinked_configs_directory
A08|reload_endpoint_rejects_process_upgrade_config
A08|expired_self_healing_validation_rolls_back_fail_closed
A09|json_log_record_escapes_fields
A09|access_log_json_escapes_values_and_omits_query_when_given_path
A09|access_log_request_id_generates_for_missing_or_invalid_value
A10|admin_error_response_clamps_oversized_messages
A10|conf_d_parse_error_reports_source_file
A10|path_inspection_error_mentions_permissions_and_service_user
A10|response_body_byte_counter_saturates
EOF

if [ "$mode" = "run" ]; then
    echo "owasp baseline: executing representative regression tests"
    while IFS='|' read -r category test_name; do
        [ -n "$category" ] || continue
        case "$category" in \#*) continue ;; esac
        run_test "$test_name"
    done <<'EOF'
A01|rejects_dotfiles_by_default
A01|rejects_traversal
A01|status_endpoint_requires_bearer_token
A01|cache_purge_endpoint_requires_auth_and_purges_by_request_identity
A01|rejects_redirect_location_without_safe_host
A02|directory_listing_is_disabled_by_default
A02|applies_default_response_headers
A02|rejects_enabled_admin_without_auth
A02|rejects_remote_admin_listener_by_default
A03|parses_tls_fips_config_and_requires_fips_capable_build
A04|rejects_tls_fips_policy_with_chacha20_cipher
A04|rejects_tls_fips_policy_with_non_nist_group
A04|rejects_tls_storage_below_symlinked_directory
A04|permission_predicates_allow_only_owner_access
A05|rejects_invalid_generic_header_value
A05|rejects_php_param_control_character_value
A05|cache_warm_targets_reject_header_injection
A05|route_strip_prefix_rejects_traversal_suffixes
A05|dynamic_header_rendering_strips_control_characters_from_variables
A06|rejects_header_bytes_over_global_limit
A06|rejects_header_count_over_global_limit
A06|admin_json_response_is_size_bounded
A06|rejects_too_many_php_params
A06|streaming_body_limit_counter_saturates
A07|admin_token_file_has_size_limit
A07|bearer_token_comparison_checks_full_string
A07|admin_auth_throttle_locks_repeated_failures_by_source
A07|admin_auth_throttle_can_lock_globally
A08|rejects_snapshot_store_root_below_world_writable_directory
A08|rejects_symlinked_configs_directory
A08|reload_endpoint_rejects_process_upgrade_config
A08|expired_self_healing_validation_rolls_back_fail_closed
A09|json_log_record_escapes_fields
A09|access_log_json_escapes_values_and_omits_query_when_given_path
A09|access_log_request_id_generates_for_missing_or_invalid_value
A10|admin_error_response_clamps_oversized_messages
A10|conf_d_parse_error_reports_source_file
A10|path_inspection_error_mentions_permissions_and_service_user
A10|response_body_byte_counter_saturates
EOF
fi

echo "owasp baseline: ok"
