use fluxheim_protocol::http_token_valid;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{NativeHttp1Error, NativeHttp1Request};

pub(crate) async fn write_owned_proxy_headers<S>(
    stream: &mut S,
    request: &NativeHttp1Request,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let via = request
        .headers
        .iter()
        .filter(|(name, value)| {
            name.eq_ignore_ascii_case("via") && valid_upstream_request_header(name, value)
        })
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    stream
        .write_all(
            format!(
                "via: {}\r\n",
                fluxheim_protocol::append_fluxheim_via_value(&via)
            )
            .as_bytes(),
        )
        .await?;

    #[cfg(not(feature = "privacy-mode"))]
    if let Some(peer_addr) = request.peer_addr {
        stream
            .write_all(format!("x-forwarded-for: {}\r\n", peer_addr.ip()).as_bytes())
            .await?;
    }

    Ok(())
}

pub(crate) fn valid_upstream_request_header(name: &str, value: &str) -> bool {
    http_token_valid(name) && valid_upstream_header_value(value)
}

pub(crate) fn valid_upstream_header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff))
}
