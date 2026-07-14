use crate::http1::{
    Http1HeadLimits, Http1Header, Http1ParseError, Http1Version, complete_head_len,
    parse_header_line,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http1ResponseHead<'a> {
    pub version: Http1Version,
    pub status: u16,
    pub reason: &'a str,
    pub headers: Vec<Http1Header<'a>>,
    pub head_len: usize,
}

pub fn parse_http1_response_head(
    input: &[u8],
    limits: Http1HeadLimits,
) -> Result<Option<Http1ResponseHead<'_>>, Http1ParseError> {
    let Some(head_len) = complete_head_len(input, limits.max_head_bytes)? else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&input[..head_len]).map_err(|_| Http1ParseError::InvalidUtf8)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(Http1ParseError::InvalidResponseLine)?;
    if status_line.len() > limits.max_start_line_bytes {
        return Err(Http1ParseError::StartLineTooLong);
    }
    let (version, status, reason) = parse_status_line(status_line)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.len() > limits.max_header_line_bytes {
            return Err(Http1ParseError::HeaderLineTooLong);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(Http1ParseError::ObsoleteLineFolding);
        }
        if headers.len() >= limits.max_header_count {
            return Err(Http1ParseError::HeaderCountExceeded);
        }
        headers.push(parse_header_line(line)?);
    }

    Ok(Some(Http1ResponseHead {
        version,
        status,
        reason,
        headers,
        head_len,
    }))
}

fn parse_status_line(line: &str) -> Result<(Http1Version, u16, &str), Http1ParseError> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(Http1ParseError::InvalidResponseLine)?;
    let status = parts.next().ok_or(Http1ParseError::InvalidResponseLine)?;
    let reason = parts.next().unwrap_or("");
    let version = match version {
        "HTTP/1.0" => Http1Version::Http10,
        "HTTP/1.1" => Http1Version::Http11,
        _ => return Err(Http1ParseError::UnsupportedVersion),
    };
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Http1ParseError::InvalidStatusCode);
    }
    let status = status
        .parse::<u16>()
        .map_err(|_| Http1ParseError::InvalidStatusCode)?;
    if !(100..=599).contains(&status) {
        return Err(Http1ParseError::InvalidStatusCode);
    }
    if reason
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff))
    {
        return Err(Http1ParseError::InvalidResponseLine);
    }
    Ok((version, status, reason))
}
