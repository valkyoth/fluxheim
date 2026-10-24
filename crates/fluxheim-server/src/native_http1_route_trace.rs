use crate::NativeHttp1Request;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeTracePropagation {
    enabled: bool,
    traceparent: bool,
}

impl NativeTracePropagation {
    pub(crate) const fn from_config(config: &fluxheim_config::TracingConfig) -> Self {
        Self {
            enabled: config.enabled,
            traceparent: config.traceparent,
        }
    }
}

pub(crate) fn apply_native_route_traceparent(
    request: &mut NativeHttp1Request,
    trace_propagation: NativeTracePropagation,
    trusted_peer: bool,
) {
    let context = crate::native_request_telemetry::current_trace().unwrap_or_else(|| {
        crate::native_request_telemetry::unique_header(request, "traceparent")
            .filter(|value| value.len() <= 55)
            .and_then(|value| {
                fluxheim_observability::TraceContext::parse_traceparent(value, trusted_peer)
            })
            .or_else(fluxheim_observability::TraceContext::generate)
    });
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("traceparent"));
    if !trace_propagation.enabled || !trace_propagation.traceparent {
        return;
    }
    if let Some(trace_context) = context {
        request
            .headers
            .push(("traceparent".to_owned(), trace_context.to_traceparent()));
    }
}
