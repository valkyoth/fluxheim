use std::io;
use std::net::SocketAddr;

use super::{NativeHttp1ProxyListenerHandle, NativeHttp1ProxyRuntimeHandle};
use crate::NativeHttp1Error;

impl NativeHttp1ProxyRuntimeHandle {
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .map(|listener| listener.local_addr)
            .collect()
    }

    pub fn abort_all(&self) {
        for listener in &self.listeners {
            if let Some(handle) = &listener.handle {
                handle.abort();
            }
        }
    }

    pub async fn join(mut self) -> Vec<Result<(), NativeHttp1Error>> {
        let listeners = std::mem::take(&mut self.listeners);
        let mut results = Vec::with_capacity(listeners.len());
        for listener in listeners {
            match listener.join().await {
                None => {}
                Some(Ok(result)) => results.push(result),
                Some(Err(error)) if error.is_cancelled() => {}
                Some(Err(error)) => {
                    results.push(Err(NativeHttp1Error::Io(io::Error::other(error))));
                }
            }
        }
        results
    }
}

impl NativeHttp1ProxyListenerHandle {
    async fn join(
        mut self,
    ) -> Option<Result<Result<(), NativeHttp1Error>, tokio::task::JoinError>> {
        let handle = self.handle.as_mut()?;
        let result = handle.await;
        self.handle.take();
        Some(result)
    }
}

impl Drop for NativeHttp1ProxyListenerHandle {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

impl Drop for NativeHttp1ProxyRuntimeHandle {
    fn drop(&mut self) {
        for listener in &mut self.listeners {
            if let Some(handle) = &listener.handle {
                handle.abort();
            }
        }
    }
}
