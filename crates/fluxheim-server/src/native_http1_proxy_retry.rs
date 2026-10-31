use fluxheim_load_balancer::SelectedUpstream;

use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::{NativeHttp1Error, NativeHttp1Request, NativeHttp1Response, NativeHttp1Upstream};

impl NativeHttp1Proxy {
    /// Only buffered application requests use this path. Tunnels and downstream
    /// streaming must not enter it after committing any response bytes.
    pub(crate) async fn send_load_balanced(
        &self,
        request: &mut NativeHttp1Request,
        mut selected: SelectedUpstream,
        max_body_bytes: Option<usize>,
    ) -> (
        SelectedUpstream,
        Result<NativeHttp1Response, NativeHttp1Error>,
    ) {
        let Some(pool) = &self.load_balancer else {
            return (selected, Err(missing_transport()));
        };
        let replayable = request.body.is_empty()
            && request.trailers.is_empty()
            && !request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("upgrade")
                    || (name.eq_ignore_ascii_case("connection")
                        && value
                            .split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case("upgrade")))
            });
        let mut retries = pool.retry_sequence(&request.method, replayable);
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|addr| addr.ip());
        // Config caps retries at ten, so eleven total distinct members suffice.
        let mut attempted = Vec::with_capacity(11);
        let Some(mut upstream) = self.retry_transport(&selected, max_body_bytes) else {
            if let Some(reporter) = selected.reporter() {
                reporter.record_failure();
            }
            return (selected, Err(missing_transport()));
        };
        loop {
            attempted.push(selected.address());
            let result = upstream.send(request).await;
            if let Some(reporter) = selected.reporter() {
                match &result {
                    Ok(response) => reporter
                        .record_status(response.status(), response.upstream_header_latency()),
                    Err(_) => reporter.record_failure(),
                };
            }
            let status = result.as_ref().ok().map(NativeHttp1Response::status);
            let Some(permit) = retries.reserve(status) else {
                return (selected, result);
            };
            // Release the old member's in-flight slot before selecting a new one.
            drop(selected.permit.take());
            let Some(next) = pool.select_excluding(request, client_ip, &attempted) else {
                return (selected, result);
            };
            let Some(next_upstream) = self.retry_transport(&next, max_body_bytes) else {
                return (selected, result);
            };
            drop(result);
            selected = next;
            upstream = next_upstream;
            permit.commit();
            // send() supplies one telemetry attempt, including its trace context.
        }
    }

    fn retry_transport(
        &self,
        selected: &SelectedUpstream,
        max_body_bytes: Option<usize>,
    ) -> Option<NativeHttp1Upstream> {
        let authority = selected.authority();
        let mut upstream = self
            .upstream_for_authority(&authority)
            .cloned()
            .or_else(|| self.dynamic_upstream_for_authority(&authority))?
            .without_transport_replay();
        if let Some(limit) = max_body_bytes {
            upstream = upstream.with_max_body_bytes(limit);
        }
        Some(upstream)
    }
}

fn missing_transport() -> NativeHttp1Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "load-balanced upstream transport unavailable",
    )
    .into()
}
