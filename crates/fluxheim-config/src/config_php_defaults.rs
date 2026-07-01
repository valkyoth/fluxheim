use crate::config::ByteSize;
use crate::config_php::DEFAULT_PHP_MAX_IN_FLIGHT;

pub(crate) fn default_php_fpm_managed_workers() -> usize {
    4
}

pub(crate) fn default_php_fpm_managed_max_requests() -> usize {
    1000
}

pub(crate) fn default_php_fpm_slowlog_trace_depth() -> usize {
    20
}

pub(crate) fn default_php_index() -> String {
    "index.php".to_owned()
}

pub(crate) fn default_php_allowed_extensions() -> Vec<String> {
    vec!["php".to_owned()]
}

pub(crate) fn default_php_request_timeout_secs() -> u64 {
    30
}

pub(crate) fn default_php_max_in_flight() -> usize {
    DEFAULT_PHP_MAX_IN_FLIGHT
}

pub(crate) fn default_php_max_response_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024 * 1024)
}

pub(crate) fn default_php_max_response_header_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

pub(crate) fn default_php_stderr_max_bytes() -> ByteSize {
    ByteSize::from_bytes(2048)
}

pub(crate) fn default_php_fpm_pool_max_idle() -> usize {
    8
}

pub(crate) fn default_php_fpm_idle_timeout_secs() -> u64 {
    60
}

pub(crate) fn default_php_fpm_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

pub(crate) fn default_true() -> bool {
    true
}
