use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener as StdTcpListener};

use tokio::net::TcpListener;

use super::{NativeHttp1ProxyRuntimeError, NativeHttp1ProxyRuntimeListener};
use crate::{
    ListenerProtocol, NativeRuntimeLaunchListener, NativeRuntimeLaunchPlan, ServiceKind,
};

pub(super) async fn native_proxy_runtime_listeners(
    launch_plan: &NativeRuntimeLaunchPlan,
    inherited: Option<Vec<StdTcpListener>>,
) -> Result<Vec<NativeHttp1ProxyRuntimeListener>, NativeHttp1ProxyRuntimeError> {
    let planned = launch_plan
        .listeners()
        .iter()
        .filter(|listener| listener.service_kind() == ServiceKind::ProxyHttp)
        .collect::<Vec<_>>();
    for listener in &planned {
        if !matches!(
            listener.listener_protocol(),
            ListenerProtocol::Http | ListenerProtocol::Https
        ) {
            return Err(NativeHttp1ProxyRuntimeError::UnsupportedListener {
                protocol: listener.listener_protocol(),
                addr: listener.listener_addr(),
            });
        }
    }
    if planned.is_empty() {
        return Err(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener);
    }

    match inherited {
        Some(listeners) => adopt_inherited_listeners(&planned, listeners),
        None => bind_planned_listeners(&planned).await,
    }
}

async fn bind_planned_listeners(
    planned: &[&NativeRuntimeLaunchListener],
) -> Result<Vec<NativeHttp1ProxyRuntimeListener>, NativeHttp1ProxyRuntimeError> {
    let mut listeners = Vec::with_capacity(planned.len());
    for listener in planned {
        let addr = listener.listener_addr();
        let socket = TcpListener::bind(addr)
            .await
            .map_err(|source| NativeHttp1ProxyRuntimeError::Bind { addr, source })?;
        let local_addr = socket
            .local_addr()
            .map_err(|source| NativeHttp1ProxyRuntimeError::Bind { addr, source })?;
        listeners.push(runtime_listener(listener, local_addr, socket));
    }
    Ok(listeners)
}

fn adopt_inherited_listeners(
    planned: &[&NativeRuntimeLaunchListener],
    inherited: Vec<StdTcpListener>,
) -> Result<Vec<NativeHttp1ProxyRuntimeListener>, NativeHttp1ProxyRuntimeError> {
    if inherited.len() != planned.len() {
        return Err(NativeHttp1ProxyRuntimeError::InheritedListenerCount {
            expected: planned.len(),
            actual: inherited.len(),
        });
    }

    let mut by_addr = HashMap::with_capacity(inherited.len());
    for listener in inherited {
        let addr = listener
            .local_addr()
            .map_err(|source| NativeHttp1ProxyRuntimeError::InheritedListenerInspect { source })?;
        if by_addr.insert(addr, listener).is_some() {
            return Err(NativeHttp1ProxyRuntimeError::DuplicateInheritedListener { addr });
        }
    }

    let mut listeners = Vec::with_capacity(planned.len());
    for listener in planned {
        let addr = listener.listener_addr();
        let socket = by_addr
            .remove(&addr)
            .ok_or(NativeHttp1ProxyRuntimeError::MissingInheritedListener { addr })?;
        socket.set_nonblocking(true).map_err(|source| {
            NativeHttp1ProxyRuntimeError::InheritedListenerSetup { addr, source }
        })?;
        let socket = TcpListener::from_std(socket).map_err(|source| {
            NativeHttp1ProxyRuntimeError::InheritedListenerSetup { addr, source }
        })?;
        listeners.push(runtime_listener(listener, addr, socket));
    }
    if let Some(addr) = by_addr.into_keys().next() {
        return Err(NativeHttp1ProxyRuntimeError::UnexpectedInheritedListener { addr });
    }
    Ok(listeners)
}

fn runtime_listener(
    planned: &NativeRuntimeLaunchListener,
    local_addr: SocketAddr,
    listener: TcpListener,
) -> NativeHttp1ProxyRuntimeListener {
    NativeHttp1ProxyRuntimeListener {
        protocol: planned.listener_protocol(),
        proxy_protocol_enabled: planned.proxy_protocol_enabled(),
        planned_addr: planned.listener_addr(),
        local_addr,
        listener,
    }
}
