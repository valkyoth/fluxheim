use crate::DownstreamHttp2Policy;

const REQUIRED_HOOKS: [NativeHttp2SafetyHook; 9] = [
    NativeHttp2SafetyHook::HeaderListSize,
    NativeHttp2SafetyHook::HeaderFieldCount,
    NativeHttp2SafetyHook::ConcurrentStreamLimit,
    NativeHttp2SafetyHook::RequestBodyReadTimeout,
    NativeHttp2SafetyHook::HandlerExecutionTimeout,
    NativeHttp2SafetyHook::ResponseWriteLifetime,
    NativeHttp2SafetyHook::FlowControlWindowBounds,
    NativeHttp2SafetyHook::ResetFloodBound,
    NativeHttp2SafetyHook::TrailerAndGrpcPassThrough,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp2SafetyHook {
    HeaderListSize,
    HeaderFieldCount,
    ConcurrentStreamLimit,
    RequestBodyReadTimeout,
    HandlerExecutionTimeout,
    ResponseWriteLifetime,
    FlowControlWindowBounds,
    ResetFloodBound,
    TrailerAndGrpcPassThrough,
}

impl NativeHttp2SafetyHook {
    pub const fn name(self) -> &'static str {
        match self {
            Self::HeaderListSize => "header-list-size",
            Self::HeaderFieldCount => "header-field-count",
            Self::ConcurrentStreamLimit => "concurrent-stream-limit",
            Self::RequestBodyReadTimeout => "request-body-read-timeout",
            Self::HandlerExecutionTimeout => "handler-execution-timeout",
            Self::ResponseWriteLifetime => "response-write-lifetime",
            Self::FlowControlWindowBounds => "flow-control-window-bounds",
            Self::ResetFloodBound => "reset-flood-bound",
            Self::TrailerAndGrpcPassThrough => "trailer-and-grpc-pass-through",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp2SafetyStatus {
    Satisfied,
    Blocking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttp2SafetyReport {
    hook: NativeHttp2SafetyHook,
    status: NativeHttp2SafetyStatus,
    detail: &'static str,
}

impl NativeHttp2SafetyReport {
    const fn satisfied(hook: NativeHttp2SafetyHook, detail: &'static str) -> Self {
        Self {
            hook,
            status: NativeHttp2SafetyStatus::Satisfied,
            detail,
        }
    }

    pub const fn hook(&self) -> NativeHttp2SafetyHook {
        self.hook
    }

    pub const fn status(&self) -> NativeHttp2SafetyStatus {
        self.status
    }

    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp2Preview {
    downstream_policy: DownstreamHttp2Policy,
    reports: Vec<NativeHttp2SafetyReport>,
}

impl NativeHttp2Preview {
    pub fn from_downstream_policy(policy: DownstreamHttp2Policy) -> Self {
        Self {
            downstream_policy: policy,
            reports: vec![
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::HeaderListSize,
                    "DownstreamHttp2Policy sets max_header_list_size.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::HeaderFieldCount,
                    "native HTTP/2 enforces decoded header-count limits before routing and keeps decoded header-list bytes bounded by h2 max_header_list_size.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::ConcurrentStreamLimit,
                    "DownstreamHttp2Policy sets max_concurrent_streams.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::RequestBodyReadTimeout,
                    "native HTTP/2 stack probe wraps the full request-body drain in one absolute deadline.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::HandlerExecutionTimeout,
                    "native HTTP/2 handler execution is wrapped in one absolute deadline.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::ResponseWriteLifetime,
                    "native HTTP/2 response writes are wrapped in one absolute lifetime to prevent flow-control window holds.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::FlowControlWindowBounds,
                    "DownstreamHttp2Policy sets initial_window_size and max_send_buffer_size.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::ResetFloodBound,
                    "DownstreamHttp2Policy sets max_pending_accept_reset_streams.",
                ),
                NativeHttp2SafetyReport::satisfied(
                    NativeHttp2SafetyHook::TrailerAndGrpcPassThrough,
                    "native HTTP/2 request/response types preserve trailers, including gRPC status trailers.",
                ),
            ],
        }
    }

    pub const fn downstream_policy(&self) -> &DownstreamHttp2Policy {
        &self.downstream_policy
    }

    pub fn reports(&self) -> &[NativeHttp2SafetyReport] {
        &self.reports
    }

    pub fn required_hooks() -> &'static [NativeHttp2SafetyHook] {
        &REQUIRED_HOOKS
    }

    pub fn blocking_reports(&self) -> impl Iterator<Item = &NativeHttp2SafetyReport> {
        self.reports
            .iter()
            .filter(|report| report.status() == NativeHttp2SafetyStatus::Blocking)
    }

    pub fn is_cutover_ready(&self) -> bool {
        self.blocking_reports().next().is_none()
    }
}
