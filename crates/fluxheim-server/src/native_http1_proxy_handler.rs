use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::native_http1_proxy::NativeHttp1Proxy;
#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::{
    NativeAuthRequestDecision, apply_native_auth_request_headers, native_auth_status_reason,
};
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::{
    native_request_has_valid_mirror_marker, strip_native_traffic_mirror_headers,
};
use crate::native_http1_proxy_peer_fill::strip_native_peer_fill_header;
use crate::native_http1_proxy_request::native_request_is_websocket_upgrade;
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::NativeWasmHooks;
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response,
};

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            self.handle_inner(
                request,
                #[cfg(feature = "wasm")]
                None,
            )
            .await
        })
    }

    fn request_body_timeout(&self, _request: &NativeHttp1Request) -> Option<Duration> {
        self.request_body_timeout
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.websocket && native_request_is_websocket_upgrade(request)
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        mut request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.request_headers.apply(&mut request, None);
            #[cfg(feature = "load-balancer")]
            if self.load_balancer.is_some() {
                return self
                    .handle_load_balanced_connection_takeover(request, prebuffered, stream)
                    .await;
            }
            self.handle_static_connection_takeover(request, prebuffered, stream)
                .await
        })
    }
}

impl NativeHttp1Proxy {
    #[cfg(feature = "wasm")]
    pub(crate) async fn handle_with_wasm_hooks(
        &self,
        request: NativeHttp1Request,
        wasm_hooks: &NativeWasmHooks,
    ) -> NativeHttp1Response {
        self.handle_inner(request, Some(wasm_hooks)).await
    }

    async fn handle_inner(
        &self,
        request: NativeHttp1Request,
        #[cfg(feature = "wasm")] wasm_hooks: Option<&NativeWasmHooks>,
    ) -> NativeHttp1Response {
        let mut request = request;
        #[cfg(feature = "auth-request")]
        if let Some(auth_request) = &self.auth_request {
            match auth_request.authorize(&request).await {
                Ok(NativeAuthRequestDecision::Allow { headers }) => {
                    apply_native_auth_request_headers(&mut request, &headers);
                }
                Ok(NativeAuthRequestDecision::Deny { status, body }) => {
                    return NativeHttp1Response::new(
                        status,
                        native_auth_status_reason(status),
                        body,
                    )
                    .close_connection();
                }
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::auth_request",
                        "native auth_request failed: {error}"
                    );
                    let (status, reason) = if error.kind() == std::io::ErrorKind::WouldBlock {
                        (503, "Service Unavailable")
                    } else {
                        (502, "Bad Gateway")
                    };
                    return NativeHttp1Response::new(
                        status,
                        reason,
                        b"auth_request failed\n".as_slice(),
                    )
                    .close_connection();
                }
            }
        }
        #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
        {
            let already_mirrored = native_request_has_valid_mirror_marker(&request);
            strip_native_traffic_mirror_headers(&mut request);
            if !already_mirrored && let Some(mirror) = &self.mirror {
                mirror.spawn_if_selected(&request);
            }
        }
        if self.rejects_invalid_authenticated_peer_fill(&request) {
            return NativeHttp1Response::new(
                403,
                "Forbidden",
                b"invalid peer-fill authentication\n".as_slice(),
            )
            .close_connection();
        }
        strip_native_peer_fill_header(&mut request);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        self.request_headers.apply(&mut request, None);
        #[cfg(feature = "load-balancer")]
        if self.load_balancer.is_some() {
            return self
                .handle_load_balanced(
                    request,
                    #[cfg(feature = "wasm")]
                    wasm_hooks,
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request.as_ref(),
                )
                .await;
        }
        self.handle_static_upstreams(
            request,
            #[cfg(feature = "wasm")]
            wasm_hooks,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_request.as_ref(),
        )
        .await
    }
}
