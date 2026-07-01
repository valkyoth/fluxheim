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
    let inbound = request
        .headers
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case("traceparent") && !value.trim().is_empty())
        .map(|(_, value)| value.trim().to_owned());
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("traceparent"));
    if !trace_propagation.enabled || !trace_propagation.traceparent {
        return;
    }
    if let Some(trace_context) =
        fluxheim_observability::context_from_traceparent(inbound.as_deref(), trusted_peer)
    {
        request
            .headers
            .push(("traceparent".to_owned(), trace_context.to_traceparent()));
    }
}
