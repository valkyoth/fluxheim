use crate::config_net::{http_authority_is_numeric_loopback, valid_http_authority};

pub(crate) fn fips_allowed_local_otlp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if invalid_http_endpoint_rest_without_len_limit(rest) {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    !path.is_empty() && http_authority_is_numeric_loopback(authority)
}

pub(crate) fn fips_allowed_local_auth_request_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if invalid_http_endpoint_rest(rest) {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    !path.is_empty() && http_authority_is_numeric_loopback(authority)
}

pub(crate) fn fips_allowed_local_mirror_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if invalid_http_endpoint_rest(rest) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    http_authority_is_numeric_loopback(authority)
}

pub(crate) fn valid_http_endpoint_url(endpoint: &str) -> bool {
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return false;
    };
    if invalid_http_endpoint_rest(rest) {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    !authority.is_empty() && !path.is_empty() && valid_http_authority(authority)
}

pub(crate) fn valid_http_base_url(endpoint: &str) -> bool {
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return false;
    };
    if invalid_http_endpoint_rest(rest) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty() && valid_http_authority(authority)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
pub(crate) fn valid_http_otlp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return false;
    };
    if invalid_http_endpoint_rest_without_len_limit(rest) {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty() || path.is_empty() {
        return false;
    }
    valid_http_authority(authority)
}

fn invalid_http_endpoint_rest(rest: &str) -> bool {
    rest.is_empty() || rest.len() > 2048 || invalid_http_endpoint_rest_without_len_limit(rest)
}

fn invalid_http_endpoint_rest_without_len_limit(rest: &str) -> bool {
    rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
}
