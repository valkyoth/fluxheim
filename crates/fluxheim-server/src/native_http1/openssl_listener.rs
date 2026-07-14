use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_openssl::SslStream;

use super::connection_tasks::NativeConnectionTasks;
use super::listener::connection_semaphore;
use super::{
    NativeHttp1Error, NativeHttp1Handler, NativeHttp1RequestContext, NativeHttp1TlsClientIdentity,
    NativeTlsHttp2Dispatch, serve_native_http1_connection_with_context, sha256_hex,
};
use crate::DownstreamHttp1Policy;

pub async fn serve_native_http1_openssl_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = connection_semaphore(policy)?;
    let mut connections = NativeConnectionTasks::new();
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS HTTP/1 connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                connections.spawn(async move {
                    let stream = match native_openssl_server_stream(&acceptor, stream) {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 OpenSSL stream setup failed; peer={peer_addr}; error={error}"
                            );
                            drop(permit);
                            return;
                        }
                    };
                    let mut stream = stream;
                    let handshake =
                        timeout(policy.tls_handshake_timeout(), std::pin::Pin::new(&mut stream).accept())
                            .await;
                    match handshake {
                        Ok(Ok(())) => {
                            let mut request_context = native_openssl_request_context(&stream);
                            request_context.local_addr = local_addr;
                            let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, policy, handler).await;
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
    drop(listener);
    connections.drain().await;
    Ok(())
}

pub async fn serve_native_http1_and_http2_openssl_listener<H, F>(
    listener: TcpListener,
    http1_policy: DownstreamHttp1Policy,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
    h2_dispatch: NativeTlsHttp2Dispatch,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = connection_semaphore(http1_policy)?;
    let mut connections = NativeConnectionTasks::new();
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        http1_policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                connections.spawn(async move {
                    let stream = match native_openssl_server_stream(&acceptor, stream) {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS OpenSSL stream setup failed; peer={peer_addr}; error={error}"
                            );
                            drop(permit);
                            return;
                        }
                    };
                    let mut stream = stream;
                    let handshake =
                        timeout(http1_policy.tls_handshake_timeout(), std::pin::Pin::new(&mut stream).accept())
                            .await;
                    match handshake {
                        Ok(Ok(())) => {
                            let mut request_context = native_openssl_request_context(&stream);
                            request_context.local_addr = local_addr;
                            match stream.ssl().selected_alpn_protocol() {
                                Some(b"h2") if h2_dispatch.http2_allowed => {
                                    let h2_handler = Arc::new(crate::NativeHttp2RouteAdapter::new(
                                        handler,
                                        Some(peer_addr),
                                        request_context,
                                    ));
                                    if let Err(error) = crate::serve_native_http2_connection(
                                        stream,
                                        h2_dispatch.policy,
                                        h2_handler,
                                    )
                                    .await
                                    {
                                        log::debug!(
                                            target: "fluxheim::native_http2",
                                            "HTTPS HTTP/2 connection failed; peer={peer_addr}; error={error}"
                                        );
                                    }
                                }
                                Some(b"http/1.1") | None if h2_dispatch.http1_allowed => {
                                    let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, http1_policy, handler).await;
                                }
                                selected => {
                                    log::debug!(
                                        target: "fluxheim::native_http1",
                                        "HTTPS connection negotiated unsupported ALPN; peer={peer_addr}; alpn={selected:?}"
                                    );
                                }
                            }
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                http1_policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
    drop(listener);
    connections.drain().await;
    Ok(())
}

fn native_openssl_server_stream(
    acceptor: &openssl::ssl::SslAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<SslStream<tokio::net::TcpStream>, openssl::error::ErrorStack> {
    let ssl = openssl::ssl::Ssl::new(acceptor.context())?;
    SslStream::new(ssl, stream)
}

fn native_openssl_request_context<S>(stream: &SslStream<S>) -> NativeHttp1RequestContext {
    let ssl = stream.ssl();
    let peer_certificate = ssl.peer_certificate();
    NativeHttp1RequestContext {
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: Some(NativeHttp1TlsClientIdentity {
            cipher: ssl.current_cipher().map(|cipher| cipher.name().to_owned()),
            version: Some(ssl.version_str().to_owned()),
            organization: peer_certificate
                .as_ref()
                .and_then(openssl_certificate_organization),
            serial_number: peer_certificate
                .as_ref()
                .and_then(openssl_certificate_serial),
            cert_sha256: peer_certificate
                .as_ref()
                .and_then(|certificate| certificate.to_der().ok())
                .map(|der| sha256_hex(&der)),
        }),
        geo_context: None,
    }
}

fn openssl_certificate_organization(certificate: &openssl::x509::X509) -> Option<String> {
    certificate
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
}

fn openssl_certificate_serial(certificate: &openssl::x509::X509) -> Option<String> {
    certificate
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|serial| serial.to_hex_str().ok())
        .map(|serial| serial.to_string())
}
