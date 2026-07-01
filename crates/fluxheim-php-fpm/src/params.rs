use super::MAX_PHP_PARAM_VALUE_BYTES;

pub fn safe_php_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub fn safe_php_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | 0x21..=0x7E))
}

pub fn safe_php_param_value(value: &str) -> bool {
    value.len() <= MAX_PHP_PARAM_VALUE_BYTES
        && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
}

pub fn php_header_param_name(name: &str) -> Option<String> {
    if name.eq_ignore_ascii_case("proxy")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
    {
        return None;
    }
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }

    let mut param = String::with_capacity("HTTP_".len() + name.len());
    param.push_str("HTTP_");
    for byte in name.bytes() {
        if byte == b'-' {
            param.push('_');
        } else {
            param.push((byte as char).to_ascii_uppercase());
        }
    }
    Some(param)
}

pub fn php_server_name_param(host: &str, fallback: &str) -> String {
    if safe_php_param_value(host) && !host.is_empty() {
        return host.to_owned();
    }
    if safe_php_param_value(fallback) && !fallback.is_empty() {
        return fallback.to_owned();
    }
    "localhost".to_owned()
}

pub fn php_request_header_params<'a, I>(headers: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut translated = std::collections::BTreeMap::<String, String>::new();
    for (name, value) in headers {
        let Some(param_name) = php_header_param_name(name) else {
            continue;
        };
        if !safe_php_param_value(value) {
            continue;
        }
        translated
            .entry(param_name)
            .and_modify(|existing| {
                let separator = if name.eq_ignore_ascii_case("cookie") {
                    "; "
                } else {
                    ", "
                };
                if existing
                    .len()
                    .saturating_add(separator.len())
                    .saturating_add(value.len())
                    <= MAX_PHP_PARAM_VALUE_BYTES
                {
                    existing.push_str(separator);
                    existing.push_str(value);
                }
            })
            .or_insert_with(|| value.to_owned());
    }
    translated.into_iter().collect()
}

pub fn php_host_param(host: &str) -> Option<(String, String)> {
    safe_php_param_value(host).then(|| ("HTTP_HOST".to_owned(), host.to_owned()))
}

pub fn php_content_type_param_value<'a, I>(values: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut result = String::new();
    for value in values {
        if !safe_php_param_value(value) {
            return String::new();
        }
        let next_len = if result.is_empty() {
            value.len()
        } else {
            result
                .len()
                .saturating_add(", ".len())
                .saturating_add(value.len())
        };
        if next_len > MAX_PHP_PARAM_VALUE_BYTES {
            return String::new();
        }
        if result.capacity() < next_len {
            result.reserve(next_len.saturating_sub(result.len()));
        }
        if !result.is_empty() {
            result.push_str(", ");
        }
        result.push_str(value);
    }
    result
}

pub fn php_custom_params<'a, I>(custom: I) -> (Vec<(String, String)>, Vec<String>)
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut accepted = Vec::new();
    let mut dropped = Vec::new();
    for (name, value) in custom {
        if fluxheim_config::protected_php_param_name(name) || !safe_php_param_value(value) {
            dropped.push(name.to_owned());
            continue;
        }
        accepted.push((name.to_owned(), value.to_owned()));
    }
    (accepted, dropped)
}
