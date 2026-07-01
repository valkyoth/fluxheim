use std::sync::atomic::Ordering;

use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::{NativeHttp1ConnectionStream, NativeHttp1Request};

impl NativeHttp1Proxy {
    pub(crate) async fn handle_static_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), crate::NativeHttp1Error> {
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        if total == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket proxy has no upstream",
            )
            .into());
        }
        let index = self.upstream_slots[start % total];
        self.upstreams[index]
            .websocket_tunnel(&request, prebuffered, stream)
            .await
    }

    #[cfg(feature = "load-balancer")]
    pub(crate) async fn handle_load_balanced_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), crate::NativeHttp1Error> {
        let Some(load_balancer) = &self.load_balancer else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer is not configured",
            )
            .into());
        };
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer did not select an upstream",
            )
            .into());
        };
        let authority = selected.authority();
        let dynamic_upstream = self
            .upstream_for_authority(&authority)
            .is_none()
            .then(|| self.dynamic_upstream_for_authority(&authority))
            .flatten();
        let Some(upstream) = self
            .upstream_for_authority(&authority)
            .or(dynamic_upstream.as_ref())
        else {
            if let Some(reporter) = selected.reporter() {
                reporter.record_failure();
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("native WebSocket selected upstream {authority} has no transport"),
            )
            .into());
        };
        let result = upstream
            .websocket_tunnel(&request, prebuffered, stream)
            .await;
        if let Some(reporter) = selected.reporter() {
            if result.is_ok() {
                reporter.record_status(101, None);
            } else {
                reporter.record_failure();
            }
        }
        result
    }
}
