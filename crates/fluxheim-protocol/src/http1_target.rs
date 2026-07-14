use crate::http1::Http1ParseError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1RequestTarget<'a> {
    Origin {
        raw: &'a str,
        path: &'a str,
        query: Option<&'a str>,
    },
    AbsoluteUri {
        raw: &'a str,
        scheme: &'a str,
        authority: Option<&'a str>,
        path: Option<&'a str>,
        query: Option<&'a str>,
    },
    Authority {
        raw: &'a str,
        port: u16,
    },
    Asterisk,
}

pub fn http1_request_target<'a>(
    method: &str,
    target: &'a str,
) -> Result<Http1RequestTarget<'a>, Http1ParseError> {
    if target.is_empty() || target_has_forbidden_byte(target) {
        return Err(Http1ParseError::InvalidRequestTarget);
    }

    if target == "*" {
        if method.eq_ignore_ascii_case("OPTIONS") {
            return Ok(Http1RequestTarget::Asterisk);
        }
        return Err(Http1ParseError::InvalidRequestTarget);
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        if target.starts_with('/') || target_contains_scheme_slashes(target) {
            return Err(Http1ParseError::InvalidRequestTarget);
        }
        let port = authority_form_port(target)?;
        validate_http1_authority(target)?;
        return Ok(Http1RequestTarget::Authority { raw: target, port });
    }

    if target.starts_with("//") {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    if target.starts_with('/') {
        let (path, query) = split_query(target)?;
        return Ok(Http1RequestTarget::Origin {
            raw: target,
            path,
            query,
        });
    }
    if let Some(colon) = target.find(':') {
        return parse_absolute_uri(target, colon);
    }
    Err(Http1ParseError::InvalidRequestTarget)
}

fn parse_absolute_uri(
    target: &str,
    colon: usize,
) -> Result<Http1RequestTarget<'_>, Http1ParseError> {
    let scheme = &target[..colon];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    let after_scheme = &target[colon + 1..];
    let after_slashes = after_scheme
        .strip_prefix("//")
        .ok_or(Http1ParseError::InvalidRequestTarget)?;
    let authority_end = find_path_or_query_start(after_slashes).unwrap_or(after_slashes.len());
    let authority = &after_slashes[..authority_end];
    validate_http1_authority(authority)?;
    let path_and_query = &after_slashes[authority_end..];
    let (path, query) = if path_and_query.is_empty() {
        (None, None)
    } else if let Some(query) = path_and_query.strip_prefix('?') {
        validate_query(query)?;
        (None, Some(query))
    } else {
        let (path, query) = split_query(path_and_query)?;
        (Some(path), query)
    };
    Ok(Http1RequestTarget::AbsoluteUri {
        raw: target,
        scheme,
        authority: Some(authority),
        path,
        query,
    })
}

fn split_query(value: &str) -> Result<(&str, Option<&str>), Http1ParseError> {
    let Some(index) = value.find('?') else {
        validate_path(value)?;
        return Ok((value, None));
    };
    let path = &value[..index];
    let query = &value[index + 1..];
    validate_path(path)?;
    validate_query(query)?;
    Ok((path, Some(query)))
}

fn validate_path(value: &str) -> Result<(), Http1ParseError> {
    if value.is_empty() {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    validate_uri_component(value, false)
}

fn validate_query(value: &str) -> Result<(), Http1ParseError> {
    validate_uri_component(value, true)
}

fn validate_uri_component(value: &str, query: bool) -> Result<(), Http1ParseError> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes
                .get(index + 1)
                .is_none_or(|byte| !byte.is_ascii_hexdigit())
                || bytes
                    .get(index + 2)
                    .is_none_or(|byte| !byte.is_ascii_hexdigit())
            {
                return Err(Http1ParseError::InvalidRequestTarget);
            }
            index += 3;
        } else if uri_component_byte_allowed(bytes[index], query) {
            index += 1;
        } else {
            return Err(Http1ParseError::InvalidRequestTarget);
        }
    }
    Ok(())
}

fn uri_component_byte_allowed(byte: u8, query: bool) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
        || query && byte == b'?'
}

pub(crate) fn validate_http1_authority(value: &str) -> Result<(), Http1ParseError> {
    if value.is_empty()
        || value.bytes().any(|byte| {
            matches!(
                byte,
                0x00..=0x20 | 0x7f..=0xff | b'/' | b'?' | b'#' | b'\\' | b'@' | b','
            )
        })
    {
        return Err(Http1ParseError::InvalidAuthority);
    }

    if let Some(bracketed) = value.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or(Http1ParseError::InvalidAuthority)?;
        let address = &bracketed[..close];
        address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| Http1ParseError::InvalidAuthority)?;
        let suffix = &bracketed[close + 1..];
        if suffix.is_empty() {
            return Ok(());
        }
        let port = suffix
            .strip_prefix(':')
            .ok_or(Http1ParseError::InvalidAuthority)?;
        return validate_authority_port(port);
    }

    if value.contains('[') || value.contains(']') || value.matches(':').count() > 1 {
        return Err(Http1ParseError::InvalidAuthority);
    }
    let (host, port) = value
        .split_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(Http1ParseError::InvalidAuthority);
    }
    if let Some(port) = port {
        validate_authority_port(port)?;
    }
    Ok(())
}

fn validate_authority_port(port: &str) -> Result<(), Http1ParseError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Http1ParseError::InvalidAuthority);
    }
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| Http1ParseError::InvalidAuthority)
}

fn authority_form_port(authority: &str) -> Result<u16, Http1ParseError> {
    let bytes = authority.as_bytes();
    let colon = if bytes.first() == Some(&b'[') {
        let close = bytes
            .iter()
            .position(|byte| *byte == b']')
            .ok_or(Http1ParseError::InvalidRequestTarget)?;
        if bytes.get(close + 1) != Some(&b':') {
            return Err(Http1ParseError::InvalidRequestTarget);
        }
        close + 1
    } else {
        let first = authority
            .find(':')
            .ok_or(Http1ParseError::InvalidRequestTarget)?;
        if authority[first + 1..].contains(':') {
            return Err(Http1ParseError::InvalidRequestTarget);
        }
        first
    };
    if colon == 0 || colon + 1 == bytes.len() {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    authority[colon + 1..]
        .parse::<u16>()
        .map_err(|_| Http1ParseError::InvalidRequestTarget)
}

fn find_path_or_query_start(value: &str) -> Option<usize> {
    value.bytes().position(|byte| matches!(byte, b'/' | b'?'))
}

fn target_has_forbidden_byte(value: &str) -> bool {
    !value.is_ascii() || value.bytes().any(|byte| matches!(byte, 0x00..=0x20 | 0x7f))
}

fn target_contains_scheme_slashes(target: &str) -> bool {
    target
        .find(':')
        .is_some_and(|colon| target.as_bytes().get(colon + 1) == Some(&b'/'))
}
