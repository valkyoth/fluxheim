use crate::config_proxy::{
    DEFAULT_PROXY_DOWNSTREAM_READ_TIMEOUT_SECS,
    DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS,
    DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS,
};

pub(super) const DEFAULT_UPSTREAM: &str = "127.0.0.1:3000";

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_upstream() -> String {
    DEFAULT_UPSTREAM.to_owned()
}

pub(super) fn default_proxy_downstream_read_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_READ_TIMEOUT_SECS)
}

pub(super) fn default_proxy_downstream_write_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS)
}

pub(super) fn default_proxy_downstream_total_response_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS)
}

pub(crate) fn default_upstream_priority_group_min_active() -> usize {
    1
}
