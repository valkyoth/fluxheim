use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};

use crate::{
    NativeHttp1Handler, NativeHttp1Request, NativeHttp1RequestContext, NativeHttp1Response,
    NativeHttp2Handler, NativeHttp2Request, NativeHttp2Response,
};

pub struct NativeHttp2RouteAdapter<H> {
    handler: Arc<H>,
    peer_addr: Option<SocketAddr>,
    context: NativeHttp1RequestContext,
}

impl<H> NativeHttp2RouteAdapter<H> {
    pub const fn new(
        handler: Arc<H>,
        peer_addr: Option<SocketAddr>,
        context: NativeHttp1RequestContext,
    ) -> Self {
        Self {
            handler,
            peer_addr,
            context,
        }
    }
}

impl<H> NativeHttp2Handler for NativeHttp2RouteAdapter<H>
where
    H: NativeHttp1Handler,
{
    fn handle<'a>(
        &'a self,
        request: NativeHttp2Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp2Response> + Send + 'a>> {
        Box::pin(async move {
            if request.trailers.is_some() {
                return native_http1_response_to_http2(NativeHttp1Response::new(
                    501,
                    "Not Implemented",
                    b"HTTP/2 request trailers are not wired into native proxy context\n",
                ));
            }
            let Some(mut request) =
                native_http2_request_to_http1(request, self.peer_addr, &self.context)
            else {
                return native_http1_response_to_http2(NativeHttp1Response::new(
                    400,
                    "Bad Request",
                    b"invalid HTTP/2 request header value\n",
                ));
            };
            self.handler.prepare_request_context(&mut request);
            if self.handler.handles_connection_takeover(&request) {
                return native_http1_response_to_http2(NativeHttp1Response::new(
                    501,
                    "Not Implemented",
                    b"HTTP/2 connection takeover is not supported\n",
                ));
            }
            native_http1_response_to_http2(self.handler.handle(request).await)
        })
    }
}

fn native_http2_request_to_http1(
    request: NativeHttp2Request,
    peer_addr: Option<SocketAddr>,
    context: &NativeHttp1RequestContext,
) -> Option<NativeHttp1Request> {
    let NativeHttp2Request {
        method,
        uri,
        headers,
        body,
        trailers: _,
    } = request;
    let mut owned_headers = Vec::with_capacity(headers.len().saturating_add(1));
    for (name, value) in &headers {
        let value = value.to_str().ok()?.to_owned();
        owned_headers.push((name.as_str().to_owned(), value));
    }
    if !owned_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
        && let Some(authority) = uri.authority()
    {
        owned_headers.push(("host".to_owned(), authority.as_str().to_owned()));
    }
    let target = uri
        .path_and_query()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    Some(NativeHttp1Request {
        method: method.as_str().to_owned(),
        peer_addr,
        local_addr: context.local_addr,
        effective_client_addr: context.effective_client_addr,
        downstream_tls: context.downstream_tls,
        tls_identity: context.tls_identity.clone(),
        geo_context: context.geo_context.clone(),
        target,
        version: fluxheim_protocol::Http1Version::Http11,
        headers: owned_headers,
        body: body.to_vec(),
    })
}

fn native_http1_response_to_http2(response: NativeHttp1Response) -> NativeHttp2Response {
    let status = match StatusCode::from_u16(response.status()) {
        Ok(status) => status,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut converted = NativeHttp2Response::new(status, Bytes::copy_from_slice(response.body()));
    for (name, value) in response.headers() {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if crate::native_http2_stack::prohibited_http2_response_header(&name) {
            continue;
        }
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        converted = converted.append_header(name, value);
    }
    converted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_adapter_maps_request_authority_and_duplicate_response_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("1"));
        let request = NativeHttp2Request {
            method: http::Method::POST,
            uri: "https://native.test/upload?x=1".parse().unwrap(),
            headers,
            body: zeroize::Zeroizing::new(b"body".to_vec()),
            trailers: None,
        };

        let converted = native_http2_request_to_http1(
            request,
            "127.0.0.1:12345".parse().ok(),
            &NativeHttp1RequestContext {
                downstream_tls: true,
                ..NativeHttp1RequestContext::default()
            },
        )
        .unwrap();

        assert_eq!(converted.method, "POST");
        assert_eq!(converted.target, "/upload?x=1");
        assert_eq!(converted.body, b"body");
        assert!(converted.downstream_tls);
        assert!(
            converted
                .headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("host") && value == "native.test")
        );

        let response = NativeHttp1Response::new(200, "OK", b"ok")
            .with_header("set-cookie", "a=1")
            .with_header("set-cookie", "b=2")
            .with_header("connection", "close");
        let converted = native_http1_response_to_http2(response);
        let cookies = converted
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        assert_eq!(cookies, vec!["a=1", "b=2"]);
        assert!(!converted.headers().contains_key("connection"));
    }
}
