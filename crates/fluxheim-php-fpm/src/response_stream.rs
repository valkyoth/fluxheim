use std::io;

pub async fn collect_php_fpm_response_stream<S>(
    mut stream: S,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response>
where
    S: fastcgi_client::StreamExt<
            Item = fastcgi_client::ClientResult<fastcgi_client::response::Content>,
        > + Unpin,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut total_bytes = 0_u64;
    while let Some(content) = stream.next().await {
        match content.map_err(|error| io::Error::other(error.to_string()))? {
            fastcgi_client::response::Content::Stdout(chunk) => {
                push_php_fpm_stream_chunk(
                    &mut stdout,
                    &chunk,
                    &mut total_bytes,
                    max_response_bytes,
                )?;
            }
            fastcgi_client::response::Content::Stderr(chunk) => {
                push_php_fpm_stream_chunk(
                    &mut stderr,
                    &chunk,
                    &mut total_bytes,
                    max_response_bytes,
                )?;
            }
        }
    }

    let mut response = fastcgi_client::Response::default();
    response.stdout = (!stdout.is_empty()).then_some(stdout);
    response.stderr = (!stderr.is_empty()).then_some(stderr);
    Ok(response)
}

pub fn push_php_fpm_stream_chunk(
    target: &mut Vec<u8>,
    chunk: &[u8],
    total_bytes: &mut u64,
    max_response_bytes: u64,
) -> io::Result<()> {
    let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
    let Some(next_total) = total_bytes.checked_add(chunk_len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    };
    if next_total > max_response_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    }
    *total_bytes = next_total;
    target.extend_from_slice(chunk);
    Ok(())
}
