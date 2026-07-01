use super::NativeRuntimeLaunchPlan;
use crate::{ProxyProtocolPolicy, ServiceKind};

impl NativeRuntimeLaunchPlan {
    pub fn to_tsv(&self) -> String {
        let mut report = format!(
            "native-runtime-launch-plan\tstatus\tservices\tlisteners\tbackground_tasks\tproxy_protocol\n\
             native-runtime-launch-plan\tready\t{}\t{}\t{}\t{}\n",
            self.manifest.services().len(),
            self.listeners.len(),
            self.background_tasks.len(),
            proxy_protocol_label(&self.proxy_protocol),
        );
        report.push_str("native-runtime-launch-policy\tprotocol\tfield\tvalue\n");
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_body_bytes",
            self.downstream_http1.max_body_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_connections",
            self.downstream_http1.max_connections().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_head_bytes",
            self.downstream_http1.max_head_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_header_count",
            self.downstream_http1.max_header_count().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_header_line_bytes",
            self.downstream_http1.max_header_line_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_start_line_bytes",
            self.downstream_http1.max_start_line_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "request_body_timeout_ms",
            self.downstream_http1
                .request_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "request_head_timeout_ms",
            self.downstream_http1
                .request_head_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "tls_handshake_timeout_ms",
            self.downstream_http1
                .tls_handshake_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_header_list_size",
            self.downstream_http2.max_header_list_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_header_count",
            self.downstream_http2.max_header_count().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_uri_bytes",
            self.downstream_http2.max_uri_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_body_bytes",
            self.downstream_http2.max_body_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "request_body_timeout_ms",
            self.downstream_http2
                .request_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "response_body_timeout_ms",
            self.downstream_http2
                .response_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "handler_timeout_ms",
            self.downstream_http2
                .handler_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "response_write_lifetime_ms",
            self.downstream_http2
                .response_write_lifetime()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_concurrent_streams",
            self.downstream_http2.max_concurrent_streams().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "initial_window_size",
            self.downstream_http2.initial_window_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_frame_size",
            self.downstream_http2.max_frame_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_send_buffer_size",
            self.downstream_http2.max_send_buffer_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_pending_accept_reset_streams",
            self.downstream_http2
                .max_pending_accept_reset_streams()
                .to_string(),
        );
        report.push_str("native-runtime-launch-service-policy\tkind\tfield\tvalue\n");
        if self.manifest.service(ServiceKind::MetricsHttp).is_some() {
            push_launch_service_policy_row(
                &mut report,
                "MetricsHttp",
                "bearer_token_required",
                self.metrics_bearer_token_required.to_string(),
            );
        }
        report.push_str(
            "native-runtime-launch-listener\tkind\tname\tprotocol\taddress\tproxy_protocol\n",
        );
        for listener in &self.listeners {
            report.push_str("native-runtime-launch-listener\t");
            report.push_str(&format!("{:?}", listener.service_kind()));
            report.push('\t');
            report.push_str(&launch_tsv_field(listener.service_name()));
            report.push('\t');
            report.push_str(&format!("{:?}", listener.listener_protocol()));
            report.push('\t');
            report.push_str(&listener.listener_addr().to_string());
            report.push('\t');
            report.push_str(if listener.proxy_protocol_enabled() {
                "true"
            } else {
                "false"
            });
            report.push('\n');
        }
        report.push_str("native-runtime-launch-background-task\tkind\tname\tcritical\n");
        for task in &self.background_tasks {
            report.push_str("native-runtime-launch-background-task\t");
            report.push_str(&format!("{:?}", task.kind()));
            report.push('\t');
            report.push_str(&launch_tsv_field(task.name()));
            report.push('\t');
            report.push_str(if task.is_critical() { "true" } else { "false" });
            report.push('\n');
        }
        report
    }
}

fn push_launch_policy_row(report: &mut String, protocol: &str, field: &str, value: String) {
    report.push_str("native-runtime-launch-policy\t");
    report.push_str(protocol);
    report.push('\t');
    report.push_str(field);
    report.push('\t');
    report.push_str(&value);
    report.push('\n');
}

fn push_launch_service_policy_row(report: &mut String, kind: &str, field: &str, value: String) {
    report.push_str("native-runtime-launch-service-policy\t");
    report.push_str(kind);
    report.push('\t');
    report.push_str(field);
    report.push('\t');
    report.push_str(&value);
    report.push('\n');
}

fn proxy_protocol_label(proxy_protocol: &ProxyProtocolPolicy) -> &'static str {
    match proxy_protocol {
        ProxyProtocolPolicy::Off => "off",
        ProxyProtocolPolicy::V1 { .. } => "v1",
        ProxyProtocolPolicy::V2 { .. } => "v2",
    }
}

fn launch_tsv_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}
