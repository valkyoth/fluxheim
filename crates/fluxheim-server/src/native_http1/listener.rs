use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use super::connection_tasks::NativeConnectionTasks;
use super::{
    NativeHttp1Error, NativeHttp1Handler, NativeHttp1RequestContext,
    serve_native_http1_connection_with_context, serve_native_http1_proxy_protocol_connection,
};
use crate::{DownstreamHttp1Policy, ProxyProtocolPolicy};

pub async fn serve_native_http1_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
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
                        "HTTP/1 connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                connections.spawn(async move {
                    let request_context = NativeHttp1RequestContext {
                        local_addr,
                        ..NativeHttp1RequestContext::default()
                    };
                    let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, policy, handler).await;
                    drop(permit);
                });
            }
        }
    }
    drop(listener);
    connections.drain().await;
    Ok(())
}

pub async fn serve_native_http1_listener_with_proxy_protocol<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    proxy_protocol: ProxyProtocolPolicy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
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
                        "HTTP/1 PROXY-protocol connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                let proxy_protocol = proxy_protocol.clone();
                connections.spawn(async move {
                    let result = serve_native_http1_proxy_protocol_connection(
                        stream,
                        peer_addr,
                        local_addr,
                        proxy_protocol,
                        policy,
                        handler,
                    )
                    .await;
                    if let Err(error) = result {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "HTTP/1 PROXY-protocol connection failed; peer={peer_addr}; error={error}"
                        );
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

#[cfg(unix)]
pub async fn serve_native_http1_unix_listener<H, F>(
    listener: UnixListener,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let mut connections = NativeConnectionTasks::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTP/1 Unix listener connection rejected: listener at capacity; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                connections.spawn(async move {
                    let request_context = NativeHttp1RequestContext::default();
                    let _ = serve_native_http1_connection_with_context(
                        stream,
                        None,
                        request_context,
                        policy,
                        handler,
                    )
                    .await;
                    drop(permit);
                });
            }
        }
    }
    drop(listener);
    connections.drain().await;
    Ok(())
}
