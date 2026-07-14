use std::collections::HashSet;

use crate::http_token_valid;
use crate::http1::{Http1Header, Http1ParseError, Http1Version};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1ConnectionDirective {
    Close,
    Persistent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Http1ConnectionOptions {
    options: HashSet<String>,
}

impl Http1ConnectionOptions {
    pub fn contains(&self, name: &str) -> bool {
        self.options.contains(&name.to_ascii_lowercase())
    }

    pub fn identifies_hop_by_hop_header(&self, name: &str) -> bool {
        self.contains(name)
            || [
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            ]
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
    }
}

pub fn http1_connection_directive(
    version: Http1Version,
    headers: &[Http1Header<'_>],
) -> Result<Http1ConnectionDirective, Http1ParseError> {
    let options = http1_connection_options(headers)?;
    if options.contains("close") {
        return Ok(Http1ConnectionDirective::Close);
    }
    if version == Http1Version::Http11 || options.contains("keep-alive") {
        Ok(Http1ConnectionDirective::Persistent)
    } else {
        Ok(Http1ConnectionDirective::Close)
    }
}

pub fn http1_connection_options(
    headers: &[Http1Header<'_>],
) -> Result<Http1ConnectionOptions, Http1ParseError> {
    let mut options = HashSet::new();
    for header in headers {
        if !header.name().eq_ignore_ascii_case("connection") {
            continue;
        }
        for token in header.value().split(',') {
            let token = token.trim();
            if !http_token_valid(token) {
                return Err(Http1ParseError::InvalidConnection);
            }
            options.insert(token.to_ascii_lowercase());
        }
    }
    Ok(Http1ConnectionOptions { options })
}
