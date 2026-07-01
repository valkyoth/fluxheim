use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::{
    NativeHttp1Error, NativeHttp1Handler, NativeHttp1RequestContext, NativeHttp1TlsClientIdentity,
    NativeTlsHttp2Dispatch, serve_native_http1_connection_with_context, sha256_hex,
};
use crate::DownstreamHttp1Policy;

pub async fn serve_native_http1_rustls_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    tls_config: Arc<rustls::ServerConfig>,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
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
                tokio::spawn(async move {
                    let handshake = timeout(policy.tls_handshake_timeout(), acceptor.accept(stream)).await;
                    match handshake {
                        Ok(Ok(stream)) => {
                            let mut request_context = native_rustls_request_context(&stream);
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
}

pub async fn serve_native_http1_and_http2_rustls_listener<H, F>(
    listener: TcpListener,
    http1_policy: DownstreamHttp1Policy,
    tls_config: Arc<rustls::ServerConfig>,
    h2_dispatch: NativeTlsHttp2Dispatch,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(http1_policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
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
                tokio::spawn(async move {
                    let handshake = timeout(http1_policy.tls_handshake_timeout(), acceptor.accept(stream)).await;
                    match handshake {
                        Ok(Ok(stream)) => {
                            let mut request_context = native_rustls_request_context(&stream);
                            request_context.local_addr = local_addr;
                            match stream.get_ref().1.alpn_protocol() {
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
}

fn native_rustls_request_context<S>(
    stream: &tokio_rustls::server::TlsStream<S>,
) -> NativeHttp1RequestContext {
    let (_, connection) = stream.get_ref();
    NativeHttp1RequestContext {
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: Some(NativeHttp1TlsClientIdentity {
            cipher: connection
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite())),
            version: connection
                .protocol_version()
                .map(|version| format!("{version:?}")),
            organization: None,
            serial_number: None,
            cert_sha256: connection
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|certificate| sha256_hex(certificate.as_ref())),
        }),
        geo_context: None,
    }
}
