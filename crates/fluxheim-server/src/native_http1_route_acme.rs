use crate::native_http1_acme::{NativeHttp1AcmeHttp01Store, http_01_token_from_path};
use crate::native_http1_route_rewrite::request_path_and_query;
use crate::{NativeHttp1Request, NativeHttp1Response};

pub(crate) async fn native_acme_http_01_response(
    request: &NativeHttp1Request,
    store: &NativeHttp1AcmeHttp01Store,
) -> NativeHttp1Response {
    if request.method != "GET" && request.method != "HEAD" {
        return NativeHttp1Response::new(405, "Method Not Allowed", Vec::new())
            .with_header("Allow", "GET, HEAD")
            .with_content_length(0);
    }

    let Some((path, _)) = request_path_and_query(request) else {
        return NativeHttp1Response::new(400, "Bad Request", b"bad request\n").close_connection();
    };
    let Some(token) = http_01_token_from_path(&path).map(str::to_owned) else {
        return NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection();
    };
    let Ok(blocking_permit) = crate::blocking_work::try_acquire_request_blocking_work(
        crate::blocking_work::NativeBlockingWorkClass::Critical,
    ) else {
        return NativeHttp1Response::new(503, "Service Unavailable", b"service unavailable\n")
            .with_retry_after_secs(1)
            .close_connection();
    };

    let store = store.clone();
    let key_authorization = match tokio::task::spawn_blocking(move || {
        let _blocking_permit = blocking_permit;
        store.load_key_authorization(&token)
    })
    .await
    {
        Ok(Ok(Some(value))) => value,
        Ok(Ok(None)) => {
            return NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection();
        }
        Ok(Err(error)) => {
            log::error!("failed to load ACME HTTP-01 challenge token: {error}");
            return NativeHttp1Response::new(
                500,
                "Internal Server Error",
                b"internal server error\n",
            )
            .close_connection();
        }
        Err(error) => {
            log::error!("ACME HTTP-01 challenge token loader failed: {error}");
            return NativeHttp1Response::new(
                500,
                "Internal Server Error",
                b"internal server error\n",
            )
            .close_connection();
        }
    };

    let content_length = key_authorization.len() as u64;
    let body = if request.method == "HEAD" {
        Vec::new()
    } else {
        key_authorization.into_bytes()
    };

    NativeHttp1Response::new(200, "OK", body)
        .with_header("content-type", "text/plain")
        .with_header("cache-control", "no-store")
        .with_content_length(content_length)
}
