use super::*;
use proptest::prelude::*;
use serde_json::Value;

fn permissive_policy() -> CapturePolicy {
    CapturePolicy {
        access_enabled: true,
        include_resource: true,
        include_request_id: true,
        include_trace_ids: true,
        privacy_mode: false,
    }
}

fn security() -> EventData {
    EventData::Security {
        reason: SecurityReason::AuthenticationRejected,
    }
}

fn capture(input: CorrelationInput<'_>, policy: CapturePolicy) -> StructuredEvent {
    StructuredEvent::capture(1, security(), None, input, policy, true).unwrap()
}

fn json(event: &StructuredEvent) -> Value {
    serde_json::from_slice(event.encode(EventFormat::Json).unwrap().as_bytes()).unwrap()
}

fn assert_wire_bounds(event: &StructuredEvent) {
    let canonical = json(event);
    assert!(field_count(&canonical) <= MAX_EVENT_FIELDS);
    assert_strings_bounded(&canonical);
    for format in [EventFormat::Json, EventFormat::Text] {
        let encoded = event.encode(format).unwrap();
        assert!(encoded.encoded_len() <= MAX_EVENT_BYTES);
        let bytes = encoded.as_bytes();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
        assert!(!bytes.contains(&b'\r'));
        let start = bytes.iter().position(|&b| b == b'{').unwrap();
        let value: Value = serde_json::from_slice(&bytes[start..]).unwrap();
        assert_eq!(value, canonical);
    }
}

fn field_count(value: &Value) -> usize {
    match value {
        Value::Object(fields) => fields.len() + fields.values().map(field_count).sum::<usize>(),
        Value::Array(values) => values.iter().map(field_count).sum(),
        _ => 0,
    }
}

fn assert_strings_bounded(value: &Value) {
    match value {
        Value::String(s) => assert!(serde_json::to_vec(s).unwrap().len() <= MAX_STRING_BYTES),
        Value::Object(fields) => {
            for v in fields.values() {
                assert_strings_bounded(v);
            }
        }
        Value::Array(values) => {
            for v in values {
                assert_strings_bounded(v);
            }
        }
        _ => (),
    }
}

#[test]
fn audit_envelope_matches_versioned_fixture() {
    let data = EventData::Audit {
        operation: AuditOperation::Rollback,
        outcome: AuditOutcome::Failed,
        actor: ActorClass::Automatic,
        revision: Some(7),
    };
    let event = StructuredEvent::capture(
        42,
        data,
        None,
        CorrelationInput::default(),
        CapturePolicy::default(),
        true,
    )
    .unwrap();
    let expected: Value = serde_json::from_str(
        &include_str!("../../../tests/fixtures/observability/structured-audit.json")
            .replace("PACKAGE_VERSION", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    assert_eq!(json(&event), expected);
    assert_wire_bounds(&event);
}

#[test]
fn access_switch_and_filter_do_not_conflate_security_with_access() {
    let access = EventData::Access {
        outcome: AccessOutcome::Completed,
        method: Method::GET,
        status: HttpStatus::new(200),
        duration_micros: 1,
        bytes_sent: 2,
        attempts: 1,
    };
    let policy = CapturePolicy::default();
    assert!(!policy.allows(access, true));
    for data in [
        security(),
        EventData::Error {
            reason: FailureReason::Rollback,
            attempt: None,
        },
        EventData::Audit {
            operation: AuditOperation::Reload,
            outcome: AuditOutcome::Succeeded,
            actor: ActorClass::AdminToken,
            revision: None,
        },
    ] {
        assert!(policy.allows(data, true));
        assert!(!policy.allows(data, false));
        assert!(
            StructuredEvent::capture(0, data, None, CorrelationInput::default(), policy, false)
                .is_none()
        );
    }
    assert_eq!(access.admission_class(), AdmissionClass::Ordinary);
    assert_eq!(security().admission_class(), AdmissionClass::Protected);
    assert!(
        !CapturePolicy {
            privacy_mode: true,
            ..permissive_policy()
        }
        .allows(access, true)
    );
    assert_eq!(
        permissive_policy().allows(access, true),
        !cfg!(feature = "privacy-mode")
    );
}

#[test]
fn privacy_mode_removes_resource_and_correlation_even_for_audit() {
    let resource = ResourceId {
        kind: ResourceKind::Route,
        generation: 1,
        index: 2,
    };
    let event = StructuredEvent::capture(
        0,
        security(),
        Some(resource),
        CorrelationInput {
            trusted: true,
            request_id: Some("secret-canary"),
            trace_id: Some("11111111111111111111111111111111"),
            span_id: Some("1111111111111111"),
        },
        CapturePolicy {
            privacy_mode: true,
            ..permissive_policy()
        },
        true,
    )
    .unwrap();
    let value = json(&event);
    assert!(value.get("resource").is_none());
    assert_eq!(value["correlation"], serde_json::json!({}));
    assert_eq!(value["redacted"], true);
    assert!(!format!("{event:?}").contains("secret-canary"));
    assert_wire_bounds(&event);
}

#[test]
fn default_and_untrusted_policies_never_copy_candidates() {
    for (trusted, policy) in [
        (true, CapturePolicy::default()),
        (false, permissive_policy()),
    ] {
        let input = CorrelationInput {
            trusted,
            request_id: Some("secret-canary"),
            trace_id: Some("11111111111111111111111111111111"),
            span_id: Some("1111111111111111"),
        };
        assert!(!format!("{input:?}").contains("secret-canary"));
        let event = capture(input, policy);
        assert_eq!(json(&event)["correlation"], serde_json::json!({}));
        assert_eq!(json(&event)["redacted"], true);
        assert!(!format!("{event:?}").contains("secret-canary"));
        assert_wire_bounds(&event);
    }
}

#[test]
fn secrets_controls_urls_and_unicode_are_not_rendered_as_ids() {
    for value in [
        "Authorization: Bearer secret-canary",
        "Cookie: secret-canary",
        "\r\nsecret-canary",
        "\u{001b}[31msecret-canary",
        "https://user:secret-canary@backend/?token=secret-canary",
        "\"secret-canary\":true",
        "\u{79d8}\u{5bc6}secret-canary",
        "\u{202e}secret-canary",
        "",
        "a\0b",
    ] {
        let event = capture(
            CorrelationInput {
                trusted: true,
                request_id: Some(value),
                trace_id: Some(value),
                span_id: Some(value),
            },
            permissive_policy(),
        );
        assert_eq!(json(&event)["correlation"], serde_json::json!({}));
        assert_eq!(json(&event)["redacted"], true);
        for format in [EventFormat::Json, EventFormat::Text] {
            let bytes = event.encode(format).unwrap();
            assert!(
                !std::str::from_utf8(bytes.as_bytes())
                    .unwrap()
                    .contains("secret-canary")
            );
        }
        assert_wire_bounds(&event);
    }
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn correlation_is_validated_without_slicing_untrusted_utf8_or_shortening_ids() {
    let request = "a".repeat(MAX_REQUEST_ID_BYTES);
    let event = capture(
        CorrelationInput {
            trusted: true,
            request_id: Some(&request),
            trace_id: Some("ABCDEF11111111111111111111111111"),
            span_id: Some("ABCDEF1111111111"),
        },
        permissive_policy(),
    );
    assert_eq!(json(&event)["correlation"]["request_id"], request);
    assert_eq!(
        json(&event)["correlation"]["trace_id"],
        "abcdef11111111111111111111111111"
    );
    assert_eq!(json(&event)["correlation"]["span_id"], "abcdef1111111111");
    assert_eq!(json(&event)["redacted"], false);
    for value in ["a".repeat(129), "secret-canary".repeat(100_000)] {
        let event = capture(
            CorrelationInput {
                trusted: true,
                request_id: Some(&value),
                ..CorrelationInput::default()
            },
            permissive_policy(),
        );
        assert_eq!(json(&event)["correlation"], serde_json::json!({}));
        assert_eq!(json(&event)["truncated"], true);
        assert_wire_bounds(&event);
    }
    for (trace, span) in [
        (
            Some("00000000000000000000000000000000"),
            Some("1111111111111111"),
        ),
        (
            Some("11111111111111111111111111111111"),
            Some("0000000000000000"),
        ),
        (Some("11111111111111111111111111111111"), None),
        (None, Some("1111111111111111")),
        (
            Some("\u{00e9}1111111111111111111111111111111"),
            Some("1111111111111111"),
        ),
    ] {
        let event = capture(
            CorrelationInput {
                trusted: true,
                trace_id: trace,
                span_id: span,
                ..CorrelationInput::default()
            },
            permissive_policy(),
        );
        assert_eq!(json(&event)["correlation"], serde_json::json!({}));
        assert_eq!(json(&event)["redacted"], true);
    }
}

#[test]
fn size_limit_includes_framing_and_newline_and_never_returns_partial_data() {
    let event = capture(CorrelationInput::default(), CapturePolicy::default());
    for format in [EventFormat::Json, EventFormat::Text] {
        let encoded = event.encode(format).unwrap();
        let len = encoded.encoded_len();
        assert_eq!(
            event.encode_with_limit(format, len).unwrap().as_bytes(),
            encoded.as_bytes()
        );
        for limit in [0, 1, len - 1] {
            assert_eq!(
                event.encode_with_limit(format, limit).unwrap_err(),
                EncodingError::SizeLimit
            );
        }
        assert!(
            event
                .encode_with_limit(format, usize::MAX)
                .unwrap()
                .encoded_len()
                <= MAX_EVENT_BYTES
        );
    }
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn optional_capture_choices_are_independent() {
    for request in [false, true] {
        for trace in [false, true] {
            for resource in [false, true] {
                let event = StructuredEvent::capture(
                    1,
                    security(),
                    Some(ResourceId {
                        kind: ResourceKind::Vhost,
                        generation: 9,
                        index: 4,
                    }),
                    CorrelationInput {
                        trusted: true,
                        request_id: Some("fh-local"),
                        trace_id: Some("11111111111111111111111111111111"),
                        span_id: Some("1111111111111111"),
                    },
                    CapturePolicy {
                        include_request_id: request,
                        include_trace_ids: trace,
                        include_resource: resource,
                        ..CapturePolicy::default()
                    },
                    true,
                )
                .unwrap();
                let value = json(&event);
                assert_eq!(value["correlation"].get("request_id").is_some(), request);
                assert_eq!(value["correlation"].get("trace_id").is_some(), trace);
                assert_eq!(value["correlation"].get("span_id").is_some(), trace);
                assert_eq!(value.get("resource").is_some(), resource);
                if resource {
                    assert_eq!(
                        value["resource"],
                        serde_json::json!({"kind":"vhost", "generation":9, "index":4})
                    );
                }
                assert_eq!(value["redacted"], !request || !trace || !resource);
                assert_wire_bounds(&event);
            }
        }
    }
}

#[test]
fn every_envelope_fits_when_all_optional_fields_and_numbers_are_maximal() {
    let variants = [
        EventData::Access {
            outcome: AccessOutcome::Failed,
            method: Method::CONNECT,
            status: HttpStatus::new(599),
            duration_micros: u64::MAX,
            bytes_sent: u64::MAX,
            attempts: u32::MAX,
        },
        EventData::Error {
            reason: FailureReason::CacheEncryption,
            attempt: Some(u32::MAX),
        },
        security(),
        EventData::Audit {
            operation: AuditOperation::CertificateRevocation,
            outcome: AuditOutcome::Rejected,
            actor: ActorClass::LocalOperations,
            revision: Some(u64::MAX),
        },
    ];
    for data in variants {
        assert!(data.message().len() <= MAX_MESSAGE_BYTES);
        let id = "a".repeat(128);
        let event = StructuredEvent::capture(
            u64::MAX,
            data,
            Some(ResourceId {
                kind: ResourceKind::AcmeIssuer,
                generation: u64::MAX,
                index: u32::MAX,
            }),
            CorrelationInput {
                trusted: true,
                request_id: Some(&id),
                trace_id: Some("11111111111111111111111111111111"),
                span_id: Some("1111111111111111"),
            },
            permissive_policy(),
            true,
        );
        if let Some(event) = event {
            assert_wire_bounds(&event);
        } else {
            assert!(cfg!(feature = "privacy-mode") && matches!(data, EventData::Access { .. }));
        }
    }
}

#[test]
fn status_and_method_inputs_are_finite() {
    for status in 0..=u16::MAX {
        assert_eq!(
            HttpStatus::new(status).is_some(),
            (100..=599).contains(&status)
        );
    }
    for method in ["GET /?secret=canary", "secret-canary", "", "get", "\r\nGET"] {
        assert_eq!(
            serde_json::to_value(Method::from_request(method)).unwrap(),
            "OTHER"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_inputs_keep_both_encoders_bounded(
        request in any::<String>(), trace in any::<String>(), span in any::<String>(),
        trusted in any::<bool>(), private in any::<bool>(), timestamp in any::<u64>()
    ) {
        let policy = CapturePolicy { privacy_mode: private, ..permissive_policy() };
        let event = StructuredEvent::capture(timestamp, security(), None,
            CorrelationInput { trusted, request_id: Some(&request), trace_id: Some(&trace), span_id: Some(&span) },
            policy, true).unwrap();
        assert_wire_bounds(&event);
        let value = json(&event);
        if !trusted || private || cfg!(feature = "privacy-mode") {
            prop_assert_eq!(&value["correlation"], &serde_json::json!({}));
        } else {
            if let Some(id) = value["correlation"]["request_id"].as_str() {
                prop_assert!(crate::access_log_request_id_valid(id));
                prop_assert_eq!(id, request);
            }
            if let Some(id) = value["correlation"]["trace_id"].as_str() {
                prop_assert!(valid_hex_id(id, 32));
                prop_assert!(valid_hex_id(value["correlation"]["span_id"].as_str().unwrap(), 16));
            }
        }
    }
}
