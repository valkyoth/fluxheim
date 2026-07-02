use crate::config::{ConfigError, validate_required_timeout_secs};

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_stream_connect_timeout_secs() -> u64 {
    5
}

pub const DEFAULT_STREAM_MAX_CONNECTIONS: usize = 1024;

pub(crate) fn default_stream_idle_timeout_secs() -> u64 {
    300
}

pub(crate) fn default_stream_max_connections() -> usize {
    DEFAULT_STREAM_MAX_CONNECTIONS
}

pub(crate) fn validate_stream_optional_timeout_secs(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_required_timeout_secs(field, value)?;
    }
    Ok(())
}
