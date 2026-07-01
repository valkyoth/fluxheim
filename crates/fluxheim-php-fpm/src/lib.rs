#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod managed_config;
mod managed_process;
#[cfg(unix)]
mod managed_spawn;
mod params;
mod policy;
mod pool;
mod request_body;
mod response;
mod response_stream;
mod script;

#[cfg(test)]
pub(crate) use self::managed_config::managed_php_fpm_instance_name_from_parts;
pub use self::managed_config::{
    managed_php_fpm_config, managed_php_fpm_instance_name, managed_php_fpm_path_env_from,
    managed_php_fpm_restart_backoff_secs,
};
pub use self::managed_process::{ManagedPhpFpmProcess, managed_php_fpm_from_config};
#[cfg(unix)]
pub use self::managed_spawn::ensure_managed_php_fpm_binary_spawn_safe;
pub use self::params::{
    php_content_type_param_value, php_custom_params, php_header_param_name, php_host_param,
    php_request_header_params, php_server_name_param, safe_php_header_name, safe_php_header_value,
    safe_php_param_value,
};
pub use self::policy::{
    PhpFpmEndpoint, PhpFpmTimeoutKind, php_fpm_effective_connect_timeout,
    php_fpm_effective_request_timeout, php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_status,
    php_fpm_timeout_error, php_fpm_timeout_kind,
};
pub use self::pool::{
    PhpFpmPool, PhpFpmPoolMetrics, execute_php_fpm_once, php_fpm_keepalive_pools_from_config,
};
#[cfg(unix)]
pub use self::request_body::create_php_request_body_spool_dir_sync;
pub use self::request_body::{
    PhpRequestBody, create_php_request_body_spool_file, ensure_php_request_body_spool_dir,
};
pub use self::response::{
    ParsedPhpResponse, parse_php_response, parse_php_status,
    php_origin_cache_policy_is_restrictive, php_response_headers_to_strip,
    php_should_intercept_error_status, php_static_offload_file_allowed,
    php_static_offload_uri_target, php_static_offload_x_sendfile_local_path,
    php_x_accel_expires_ttl_secs, split_first_colon, split_php_response, trim_ascii, trim_ascii_cr,
};
pub use self::response_stream::{collect_php_fpm_response_stream, push_php_fpm_stream_chunk};
pub use self::script::{
    PhpScriptName, php_fpm_path_translated, php_fpm_script_filename, php_script_name_denied,
    php_script_name_for_request, php_segment_has_allowed_extension,
    php_should_redirect_directory_index, php_static_file_script_name,
};

pub const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
pub const PHP_HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
pub const PHP_STATIC_OFFLOAD_RESPONSE_HEADERS: &[&str] = &["x-accel-redirect", "x-sendfile"];

#[cfg(test)]
mod tests_io_policy;
#[cfg(test)]
mod tests_params_script;
#[cfg(test)]
mod tests_response_config;
