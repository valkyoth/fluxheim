use fluxheim_config::ResponseMetadataConfig;
use sha2::{Digest as _, Sha256};

use crate::{NativeHttp1Error, NativeHttp1Response};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeCacheStatus {
    pub(crate) status: String,
    pub(crate) reason: Option<String>,
}

impl NativeCacheStatus {
    pub(crate) fn new(status: &str, reason: Option<&str>) -> Self {
        Self {
            status: status.to_owned(),
            reason: reason.map(str::to_owned),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeProxyStatusError {
    ConnectionRefused,
    ConnectionTerminated,
    ConnectionTimeout,
    DestinationUnavailable,
    HttpProtocolError,
}

impl NativeProxyStatusError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionTerminated => "connection_terminated",
            Self::ConnectionTimeout => "connection_timeout",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::HttpProtocolError => "http_protocol_error",
        }
    }
}

pub(crate) fn native_proxy_status_error(error: &NativeHttp1Error) -> NativeProxyStatusError {
    match error {
        NativeHttp1Error::Parse(_) => NativeProxyStatusError::HttpProtocolError,
        NativeHttp1Error::Io(error) => match error.kind() {
            std::io::ErrorKind::ConnectionRefused => NativeProxyStatusError::ConnectionRefused,
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof => NativeProxyStatusError::ConnectionTerminated,
            std::io::ErrorKind::TimedOut => NativeProxyStatusError::ConnectionTimeout,
            std::io::ErrorKind::InvalidData => NativeProxyStatusError::HttpProtocolError,
            _ => NativeProxyStatusError::DestinationUnavailable,
        },
    }
}

pub(crate) fn apply_native_status_metadata(
    metadata: &ResponseMetadataConfig,
    response: &mut NativeHttp1Response,
) {
    let Some(identifier) = metadata.identifier.as_deref() else {
        return;
    };
    if metadata.cache_status
        && !response.cache_status_metadata_emitted()
        && let Some(cache_status) = response.cache_status()
        && let Some(value) = cache_status_value(identifier, cache_status)
    {
        response.push_header("cache-status", value);
        response.mark_cache_status_metadata_emitted();
    }
    if metadata.proxy_status
        && !response.proxy_status_metadata_emitted()
        && let Some(error) = response.proxy_status_error()
    {
        response.push_header(
            "proxy-status",
            format!("{identifier}; error={}", error.as_str()),
        );
        response.mark_proxy_status_metadata_emitted();
    }
}

pub(crate) fn apply_native_digest_metadata(
    metadata: &ResponseMetadataConfig,
    request_method: &str,
    response: &mut NativeHttp1Response,
) {
    if metadata.content_digest {
        let value = digest_field_value(response.body());
        response.remove_header("content-digest");
        response.push_header("content-digest", value);
    }
    if metadata.repr_digest {
        response.remove_header("repr-digest");
        if response_has_complete_selected_representation(request_method, response) {
            response.push_header("repr-digest", digest_field_value(response.body()));
        }
    }
}

fn cache_status_value(identifier: &str, status: &NativeCacheStatus) -> Option<String> {
    let handling = match status.status.as_str() {
        "HIT" => "hit",
        "STALE"
            if status
                .reason
                .as_deref()
                .is_some_and(|reason| matches!(reason, "upstream-error" | "upstream-status")) =>
        {
            "fwd=stale"
        }
        "STALE" => "hit",
        "MISS" => "fwd=uri-miss; stored",
        "REVALIDATED" => "fwd=stale; fwd-status=304; stored",
        "EXPIRED" => "fwd=stale",
        "BYPASS" => "fwd=bypass",
        _ => return None,
    };
    Some(format!("{identifier}; {handling}"))
}

fn response_has_complete_selected_representation(
    request_method: &str,
    response: &NativeHttp1Response,
) -> bool {
    request_method == "GET"
        && response.status() == 200
        && !response
            .headers()
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-range"))
        && response
            .content_length()
            .is_none_or(|length| length == response.body().len() as u64)
}

fn digest_field_value(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256=:{}:",
        base64_ng::STANDARD.encode_string_infallible(digest.as_slice())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_metadata() -> ResponseMetadataConfig {
        ResponseMetadataConfig {
            content_digest: true,
            repr_digest: true,
            ..ResponseMetadataConfig::default()
        }
    }

    fn header<'a>(response: &'a NativeHttp1Response, name: &str) -> Option<&'a str> {
        response.headers().iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }

    #[test]
    fn cache_status_uses_only_standard_low_cardinality_parameters() {
        let status = NativeCacheStatus::new("MISS", Some("internal-cache-reason"));
        assert_eq!(
            cache_status_value("edge", &status).as_deref(),
            Some("edge; fwd=uri-miss; stored")
        );
    }

    #[test]
    fn proxy_error_classification_does_not_expose_error_text() {
        let error = NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "secret backend address",
        ));
        assert_eq!(
            native_proxy_status_error(&error),
            NativeProxyStatusError::ConnectionRefused
        );
    }

    #[test]
    fn digest_uses_rfc_9530_sha256_dictionary_shape() {
        assert_eq!(
            digest_field_value(b"hello"),
            "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
        );
    }

    #[test]
    fn head_digests_empty_content_without_guessing_representation() {
        let mut response = NativeHttp1Response::new(200, "OK", Vec::new()).with_content_length(5);
        apply_native_digest_metadata(&digest_metadata(), "HEAD", &mut response);

        assert_eq!(
            header(&response, "content-digest"),
            Some("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
        );
        assert_eq!(header(&response, "repr-digest"), None);
    }

    #[test]
    fn range_digest_covers_content_without_guessing_full_representation() {
        let mut response = NativeHttp1Response::new(206, "Partial Content", b"ell".to_vec())
            .with_header("content-range", "bytes 1-3/5");
        apply_native_digest_metadata(&digest_metadata(), "GET", &mut response);

        assert_eq!(
            header(&response, "content-digest"),
            Some("sha-256=:uuqWUAmX/1zWz9Jlkql41rc9SAtK0z0AJJnPAEGsmZY=:")
        );
        assert_eq!(header(&response, "repr-digest"), None);
    }

    #[test]
    fn encoded_complete_response_digests_final_encoded_bytes() {
        let mut response = NativeHttp1Response::new(200, "OK", vec![1, 2, 3, 4])
            .with_header("content-encoding", "gzip");
        apply_native_digest_metadata(&digest_metadata(), "GET", &mut response);

        assert_eq!(
            header(&response, "content-digest"),
            Some("sha-256=:n2SnR+G5fxMfq7a0Rylsm28CAeefs8U1bmx36JtqgGo=:")
        );
        assert_eq!(
            header(&response, "repr-digest"),
            header(&response, "content-digest")
        );
    }

    #[test]
    fn status_metadata_is_emitted_once_when_policy_is_reapplied() {
        let metadata = ResponseMetadataConfig {
            identifier: Some("edge".to_owned()),
            cache_status: true,
            proxy_status: true,
            ..ResponseMetadataConfig::default()
        };
        let mut response = NativeHttp1Response::new(502, "Bad Gateway", Vec::new())
            .with_proxy_status_error(NativeProxyStatusError::ConnectionRefused);
        response.set_cache_status(NativeCacheStatus::new("BYPASS", None));

        apply_native_status_metadata(&metadata, &mut response);
        apply_native_status_metadata(&metadata, &mut response);

        assert_eq!(
            response
                .headers()
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("cache-status"))
                .count(),
            1
        );
        assert_eq!(
            response
                .headers()
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-status"))
                .count(),
            1
        );
    }
}
