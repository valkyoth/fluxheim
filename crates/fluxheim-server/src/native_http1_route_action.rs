use std::time::Duration;

#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;
#[cfg(feature = "acme")]
use crate::native_http1_route_acme::native_acme_http_01_response;
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
use crate::native_http1_route_redirect::{NativeHttp1RouteRedirect, redirect_response};
use crate::native_http1_route_rewrite::request_path_and_query;
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::NativeWasmHooks;
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler, NativeHttp1Proxy,
    NativeHttp1Request, NativeHttp1Response, NativeHttp1StaticWeb,
};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativeHttp1RouteAction {
    #[cfg(feature = "acme")]
    AcmeHttp01(NativeHttp1AcmeHttp01Store),
    #[cfg(feature = "php-fpm")]
    PhpFpm(Box<NativePhpFpmRoute>),
    Proxy(Box<NativeHttp1Proxy>),
    Redirect(NativeHttp1RouteRedirect),
    StaticWeb(Box<NativeHttp1StaticWeb>),
}

impl NativeHttp1RouteAction {
    pub(crate) fn proxy(&self) -> Option<&NativeHttp1Proxy> {
        match self {
            Self::Proxy(proxy) => Some(proxy.as_ref()),
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(_) => None,
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(_) => None,
            Self::Redirect(_) | Self::StaticWeb(_) => None,
        }
    }

    pub(crate) fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect(_))
    }

    pub(crate) fn is_static_web(&self) -> bool {
        matches!(self, Self::StaticWeb(_))
    }

    pub(crate) fn https_redirect_exempt(&self) -> bool {
        #[cfg(feature = "acme")]
        if matches!(self, Self::AcmeHttp01(_)) {
            return true;
        }
        false
    }

    pub(crate) fn request_body_timeout(&self) -> Option<Duration> {
        match self {
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(_) => None,
            Self::Proxy(proxy) => proxy.request_body_timeout(),
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(php) => Some(Duration::from_secs(php.request_timeout_secs())),
            Self::Redirect(_) | Self::StaticWeb(_) => None,
        }
    }

    pub(crate) async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        match self {
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(store) => native_acme_http_01_response(&request, store).await,
            Self::Proxy(proxy) => proxy.handle(request).await,
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(php) => php.handle(request).await,
            Self::Redirect(redirect) => redirect_response(&request, redirect),
            Self::StaticWeb(web) => {
                let Some((path, _)) = request_path_and_query(&request) else {
                    return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection();
                };
                web.handle(&request, &path)
            }
        }
    }

    #[cfg(feature = "wasm")]
    pub(crate) async fn handle_with_wasm_hooks(
        &self,
        request: NativeHttp1Request,
        hooks: &NativeWasmHooks,
    ) -> NativeHttp1Response {
        match self {
            Self::Proxy(proxy) => proxy.handle_with_wasm_hooks(request, hooks).await,
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(_) | Self::Redirect(_) | Self::StaticWeb(_) => {
                self.handle(request).await
            }
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(_) => self.handle(request).await,
            #[cfg(not(feature = "acme"))]
            Self::Redirect(_) | Self::StaticWeb(_) => self.handle(request).await,
        }
    }

    pub(crate) fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        match self {
            Self::Proxy(proxy) => proxy.handles_connection_takeover(request),
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(_) => false,
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(_) => false,
            Self::Redirect(_) | Self::StaticWeb(_) => false,
        }
    }

    pub(crate) async fn handle_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        match self {
            Self::Proxy(proxy) => {
                proxy
                    .handle_connection_takeover(request, prebuffered, stream)
                    .await
            }
            #[cfg(feature = "acme")]
            Self::AcmeHttp01(_) => reject_connection_takeover(stream).await,
            #[cfg(feature = "php-fpm")]
            Self::PhpFpm(_) => reject_connection_takeover(stream).await,
            Self::Redirect(_) | Self::StaticWeb(_) => reject_connection_takeover(stream).await,
        }
    }
}

async fn reject_connection_takeover(
    mut stream: NativeHttp1ConnectionStream,
) -> Result<(), NativeHttp1Error> {
    write_takeover_rejection(
        &mut stream,
        400,
        "Bad Request",
        b"unsupported upgrade target\n",
    )
    .await
}

pub(crate) async fn write_takeover_rejection<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), NativeHttp1Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Connection: close\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: text/plain\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

pub(crate) async fn write_takeover_limit_rejection<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), NativeHttp1Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Connection: close\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: text/plain\r\n\
                 Retry-After: 1\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
