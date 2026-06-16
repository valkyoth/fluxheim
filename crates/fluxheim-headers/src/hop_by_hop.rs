pub const HOP_BY_HOP_REQUEST_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HopByHopRequestHeaderPolicy {
    connection_listed_headers: Vec<String>,
    preserve_chunked_framing: bool,
}

impl HopByHopRequestHeaderPolicy {
    pub fn connection_listed_headers(&self) -> &[String] {
        &self.connection_listed_headers
    }

    pub const fn preserve_chunked_framing(&self) -> bool {
        self.preserve_chunked_framing
    }
}

pub fn hop_by_hop_request_header_policy<'a, 'b>(
    connection_values: impl IntoIterator<Item = &'a str>,
    transfer_encoding_values: impl IntoIterator<Item = &'b str>,
) -> HopByHopRequestHeaderPolicy {
    let connection_listed_headers = connection_values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| fluxheim_protocol::http_token_valid(value))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let terminal_transfer_coding = transfer_encoding_values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .last();
    let preserve_chunked_framing =
        terminal_transfer_coding.is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"));

    HopByHopRequestHeaderPolicy {
        connection_listed_headers,
        preserve_chunked_framing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_connection_listed_hop_by_hop_headers() {
        let policy =
            hop_by_hop_request_header_policy(["close, x-hop, bad/header"], std::iter::empty());

        assert_eq!(
            policy.connection_listed_headers(),
            &["close".to_string(), "x-hop".to_string()]
        );
    }

    #[test]
    fn preserves_only_terminal_chunked_transfer_encoding() {
        let policy =
            hop_by_hop_request_header_policy(std::iter::empty(), ["gzip, chunked", "br, deflate"]);
        assert!(!policy.preserve_chunked_framing());

        let policy = hop_by_hop_request_header_policy(std::iter::empty(), ["gzip", "br, chunked"]);
        assert!(policy.preserve_chunked_framing());
    }
}
