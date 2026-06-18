use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) async fn read_request_head<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    request
}
