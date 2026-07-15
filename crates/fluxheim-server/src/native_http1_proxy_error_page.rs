use crate::native_http1_proxy::NativeHttp1ProxyConfigError;
use crate::{
    NativeHttp1Request, NativeHttp1Response, NativeHttp1ResponseWritePolicy, NativeHttp1StaticWeb,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeHttp1ProxyErrorPage {
    status: u16,
    path: String,
    web: NativeHttp1StaticWeb,
}

pub(crate) fn native_error_pages_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Vec<NativeHttp1ProxyErrorPage>, NativeHttp1ProxyConfigError> {
    let mut pages = Vec::with_capacity(proxy.error_pages.len());
    for page in &proxy.error_pages {
        let web = NativeHttp1StaticWeb::from_config(&page.web)
            .map_err(|_| NativeHttp1ProxyConfigError::ErrorPages)?
            .ok_or(NativeHttp1ProxyConfigError::ErrorPages)?;
        pages.push(NativeHttp1ProxyErrorPage {
            status: page.status,
            path: page.path.clone(),
            web,
        });
    }
    Ok(pages)
}

pub(crate) async fn native_error_page_response(
    pages: &[NativeHttp1ProxyErrorPage],
    response_write_policy: NativeHttp1ResponseWritePolicy,
    request: &NativeHttp1Request,
    status: u16,
) -> Option<NativeHttp1Response> {
    let page = pages.iter().find(|page| page.status == status)?;
    page.web
        .handle_error_page_async(request, &page.path, status)
        .await
        .map(|response| response.with_write_policy(response_write_policy))
        .map(NativeHttp1Response::close_connection)
}

#[cfg(feature = "load-balancer")]
pub(crate) const fn native_proxy_status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}
