use fluxheim_config::CacheConfig;

use crate::{NativeHttp1Request, NativeHttp1Response};

#[cfg(test)]
#[path = "native_http1_proxy_peer_context_tests.rs"]
mod tests;

pub(crate) const VERSION: &str = "x-fluxheim-peer-fill-version";
pub(crate) const CONTEXT: &str = "x-fluxheim-peer-fill-context";
pub(crate) const VARIANTS: &str = "x-fluxheim-peer-fill-vary";
pub(crate) const DATE: &str = "x-fluxheim-peer-fill-date";
const MAX_FIELDS: usize = 19;
const MAX_BYTES: usize = 8192;
const MAX_VALUES: usize = 64;

fn safe_field(name: &str) -> bool {
    name.len() <= 128
        && http::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
        && !fluxheim_headers::HOP_BY_HOP_REQUEST_HEADERS
            .iter()
            .any(|header| header.eq_ignore_ascii_case(name))
        && !matches!(
            name,
            "host"
                | "cookie"
                | "set-cookie"
                | "content-length"
                | "cache-control"
                | "range"
                | "forwarded"
                | "x-real-ip"
                | "traceparent"
                | "tracestate"
        )
        && !name.starts_with("x-fluxheim-")
        && !name.starts_with("x-forwarded-")
        && !name.starts_with("if-")
        && ![
            "auth",
            "token",
            "secret",
            "api-key",
            "apikey",
            "credential",
            "certificate",
        ]
        .iter()
        .any(|part| name.contains(part))
}

pub(crate) fn selected_fields(cache: &CacheConfig) -> Option<Vec<String>> {
    if cache.vary_request_headers.len() > 16 {
        return None;
    }
    let mut fields = vec![
        "accept".into(),
        "accept-encoding".into(),
        "accept-language".into(),
    ];
    for name in &cache.vary_request_headers {
        if name.len() > 128 {
            return None;
        }
        let name = name.to_ascii_lowercase();
        if !safe_field(&name) {
            return None;
        }
        fields.push(name);
    }
    fields.sort();
    fields.dedup();
    Some(fields)
}

fn single<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values.next()?.1.as_str();
    values.next().is_none().then_some(value)
}

fn declared_fields(value: &str) -> Option<Vec<&str>> {
    if value.len() > 2048 {
        return None;
    }
    let fields: Vec<_> = value.split(',').collect();
    if fields.len() > MAX_FIELDS
        || fields
            .iter()
            .any(|name| !safe_field(name) || *name != name.to_ascii_lowercase())
        || fields.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return None;
    }
    Some(fields)
}

// Lengths and occurrence counts keep missing, empty, and repeated fields distinct.
pub(crate) fn canonical_context(headers: &[(String, String)]) -> Option<Vec<u8>> {
    if single(headers, VERSION)? != "2" || single(headers, "cache-control")? != "only-if-cached" {
        return None;
    }
    let fields = declared_fields(single(headers, CONTEXT)?)?;
    for required in ["accept", "accept-encoding", "accept-language"] {
        if !fields.contains(&required) {
            return None;
        }
    }
    let mut bytes = Vec::new();
    append(&mut bytes, single(headers, "host")?.as_bytes())?;
    for field in fields {
        append(&mut bytes, field.as_bytes())?;
        let count = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(field))
            .count();
        if count > MAX_VALUES {
            return None;
        }
        append(&mut bytes, &(count as u64).to_be_bytes())?;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(field) {
                if value.trim_matches([' ', '\t']) != value
                    || value.bytes().any(|byte| byte < 32 || byte == 127)
                {
                    return None;
                }
                append(&mut bytes, value.as_bytes())?;
            }
        }
    }
    Some(bytes)
}

fn append(output: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    if value.len().saturating_add(8) > MAX_BYTES.saturating_sub(output.len()) {
        return None;
    }
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
    Some(())
}

pub(crate) fn prepare_response(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    cache: &CacheConfig,
) {
    response.remove_header(VERSION);
    response.remove_header(VARIANTS);
    response.remove_header(CONTEXT);
    response.remove_header(DATE);
    let Some(context) = canonical_context(&request.headers) else {
        return;
    };
    let headers = crate::native_http1_cache::native_response_header_map(response);
    let fields = match fluxheim_cache::cache_vary_policy(&headers, cache) {
        fluxheim_cache::VaryCachePolicy::None => Vec::new(),
        fluxheim_cache::VaryCachePolicy::Fields(fields) => fields,
        fluxheim_cache::VaryCachePolicy::Uncacheable(_) => return,
    };
    if fields.iter().any(|name| !safe_field(name)) {
        return;
    }
    response.push_header(VERSION, "2");
    response.push_header(VARIANTS, fields.join(","));
    response.push_header(CONTEXT, context_digest(&context));
    // HTTP/1 regenerates Date after signing; preserve cache freshness metadata
    // in the authenticated envelope and restore it only after verification.
    let date = single(response.headers(), "date")
        .map(str::to_owned)
        .unwrap_or_else(|| httpdate::fmt_http_date(std::time::SystemTime::now()));
    response.push_header(DATE, date);
}

fn context_digest(context: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    base64_ng::URL_SAFE_NO_PAD.encode_string_infallible(&Sha256::digest(context))
}

pub(crate) fn response_context_matches(
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
    cache: &CacheConfig,
) -> bool {
    let Some(context) = canonical_context(&request.headers) else {
        return false;
    };
    if single(response.headers(), VERSION) != Some("2")
        || single(response.headers(), CONTEXT) != Some(context_digest(&context).as_str())
        || !single(response.headers(), DATE)
            .is_some_and(|date| httpdate::parse_http_date(date).is_ok())
    {
        return false;
    }
    let Some(selected) = single(&request.headers, CONTEXT).and_then(declared_fields) else {
        return false;
    };
    let Some(declared) = single(response.headers(), VARIANTS) else {
        return false;
    };
    let fields = if declared.is_empty() {
        Vec::new()
    } else {
        let Some(fields) = declared_fields(declared) else {
            return false;
        };
        fields
    };
    let headers = crate::native_http1_cache::native_response_header_map(response);
    let required = match fluxheim_cache::cache_vary_policy(&headers, cache) {
        fluxheim_cache::VaryCachePolicy::None => Vec::new(),
        fluxheim_cache::VaryCachePolicy::Fields(fields) => fields,
        fluxheim_cache::VaryCachePolicy::Uncacheable(_) => return false,
    };
    fields.iter().all(|name| selected.contains(name))
        && required
            .iter()
            .all(|name| selected.contains(&name.as_str()))
}
