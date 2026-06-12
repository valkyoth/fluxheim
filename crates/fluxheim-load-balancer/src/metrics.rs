use std::sync::OnceLock;

type LoadBalancerEventRecorder = fn(&str, Option<&str>, Option<&str>, &str);

static LOAD_BALANCER_EVENT_RECORDER: OnceLock<LoadBalancerEventRecorder> = OnceLock::new();

pub fn set_load_balancer_event_recorder(recorder: LoadBalancerEventRecorder) {
    let _ = LOAD_BALANCER_EVENT_RECORDER.set(recorder);
}

pub(crate) fn record_load_balancer_event(
    vhost: &str,
    route: Option<&str>,
    member: Option<&str>,
    event: &str,
) {
    if let Some(recorder) = LOAD_BALANCER_EVENT_RECORDER.get() {
        recorder(vhost, route, member, event);
    }
}
