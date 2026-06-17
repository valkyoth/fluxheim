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
        validate_authority(target)?;
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
    if !valid_scheme(scheme) {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    let after_scheme = &target[colon + 1..];
    if let Some(after_slashes) = after_scheme.strip_prefix("//") {
        let authority_end = find_path_or_query_start(after_slashes).unwrap_or(after_slashes.len());
        let authority = &after_slashes[..authority_end];
        validate_authority(authority)?;
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
        return Ok(Http1RequestTarget::AbsoluteUri {
            raw: target,
            scheme,
            authority: Some(authority),
            path,
            query,
        });
    }

    Ok(Http1RequestTarget::AbsoluteUri {
        raw: target,
        scheme,
        authority: None,
        path: None,
        query: None,
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
    if value.is_empty() || value.as_bytes().contains(&b'#') || value.as_bytes().contains(&b'\\') {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    validate_percent_encoding(value)
}

fn validate_query(value: &str) -> Result<(), Http1ParseError> {
    if value.as_bytes().contains(&b'#') || value.as_bytes().contains(&b'\\') {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    validate_percent_encoding(value)
}

fn validate_percent_encoding(value: &str) -> Result<(), Http1ParseError> {
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
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn validate_authority(value: &str) -> Result<(), Http1ParseError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x20 | 0x7f | b'/' | b'?' | b'#' | b'\\'))
    {
        return Err(Http1ParseError::InvalidRequestTarget);
    }
    Ok(())
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
    value.bytes().any(|byte| matches!(byte, 0x00..=0x20 | 0x7f))
}

fn target_contains_scheme_slashes(target: &str) -> bool {
    target
        .find(':')
        .is_some_and(|colon| target.as_bytes().get(colon + 1) == Some(&b'/'))
}

fn valid_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}
