use std::time::UNIX_EPOCH;

#[cfg(feature = "proxy")]
use std::{fs, io};

use super::tests_support::static_file;
#[cfg(feature = "proxy")]
use super::tests_support::{TestDir, server};
use super::{
    ByteRangeParse, StaticRequestConditions, StaticResponseBody, parse_single_byte_range,
    plan_static_response,
};
#[cfg(feature = "proxy")]
use super::{ResolveResult, StaticFile};

#[test]
fn plans_static_etag_revalidation() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(42, Some(modified));
    let first = plan_static_response(&file, "GET", StaticRequestConditions::default());

    assert_eq!(first.status, 200);
    assert_eq!(first.content_length, Some(42));
    assert_eq!(first.response_body_bytes, 42);

    let revalidated = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_none_match: Some(&first.etag),
            ..StaticRequestConditions::default()
        },
    );

    assert_eq!(revalidated.status, 304);
    assert_eq!(revalidated.content_length, None);
    assert_eq!(revalidated.body, StaticResponseBody::None);
    assert_eq!(revalidated.response_body_bytes, 0);
}

#[test]
fn plans_static_modified_since_revalidation() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(42, Some(modified));
    let header = httpdate::fmt_http_date(modified);
    let plan = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_modified_since: Some(&header),
            ..StaticRequestConditions::default()
        },
    );

    assert_eq!(plan.status, 304);
    assert_eq!(plan.body, StaticResponseBody::None);
}

#[test]
fn plans_static_precondition_failures() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(42, Some(modified));
    let stale_date = httpdate::fmt_http_date(modified - std::time::Duration::from_secs(1));

    let if_match = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_match: Some("\"different\""),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(if_match.status, 412);
    assert_eq!(if_match.body, StaticResponseBody::None);
    assert_eq!(if_match.content_length, Some(0));

    let unmodified_since = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_unmodified_since: Some(&stale_date),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(unmodified_since.status, 412);
    assert_eq!(unmodified_since.body, StaticResponseBody::None);
    assert_eq!(unmodified_since.content_length, Some(0));
}

#[test]
fn wildcard_if_match_allows_existing_static_file() {
    let file = static_file(42, None);
    let plan = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_match: Some("*"),
            ..StaticRequestConditions::default()
        },
    );

    assert_eq!(plan.status, 200);
    assert_eq!(plan.body, StaticResponseBody::Full);
}

#[test]
fn if_match_takes_precedence_over_unmodified_since() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(42, Some(modified));
    let stale_date = httpdate::fmt_http_date(modified - std::time::Duration::from_secs(1));
    let plan = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_match: Some("*"),
            if_unmodified_since: Some(&stale_date),
            ..StaticRequestConditions::default()
        },
    );

    assert_eq!(plan.status, 200);
    assert_eq!(plan.body, StaticResponseBody::Full);
}

#[test]
fn plans_static_single_byte_ranges() {
    let file = static_file(100, None);

    let bounded = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            range: Some("bytes=10-19"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(bounded.status, 206);
    assert_eq!(
        bounded.body,
        StaticResponseBody::Range { start: 10, len: 10 }
    );
    assert_eq!(bounded.content_length, Some(10));
    assert_eq!(bounded.content_range.as_deref(), Some("bytes 10-19/100"));
    assert_eq!(bounded.response_body_bytes, 10);

    let suffix = plan_static_response(
        &file,
        "HEAD",
        StaticRequestConditions {
            range: Some("bytes=-5"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(suffix.status, 206);
    assert_eq!(suffix.body, StaticResponseBody::None);
    assert_eq!(suffix.content_length, Some(5));
    assert_eq!(suffix.response_body_bytes, 0);
}

#[test]
fn rejects_invalid_static_ranges() {
    assert_eq!(
        parse_single_byte_range("bytes=100-200", 100),
        ByteRangeParse::Unsatisfiable
    );
    assert_eq!(
        parse_single_byte_range("bytes=20-10", 100),
        ByteRangeParse::Unsatisfiable
    );
    assert_eq!(
        parse_single_byte_range("bytes=0-1,4-5", 100),
        ByteRangeParse::Ignore
    );
    assert_eq!(
        parse_single_byte_range("items=0-1", 100),
        ByteRangeParse::Unsatisfiable
    );

    let file = static_file(100, None);
    let plan = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            range: Some("bytes=100-200"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(plan.status, 416);
    assert_eq!(plan.content_length, Some(0));
    assert_eq!(plan.content_range.as_deref(), Some("bytes */100"));
    assert_eq!(plan.response_body_bytes, 0);
}

#[test]
fn ignores_satisfiable_multi_range_requests() {
    let file = static_file(100, None);
    let plan = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            range: Some("bytes=0-1,4-5"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(plan.status, 200);
    assert_eq!(plan.body, StaticResponseBody::Full);
    assert_eq!(plan.content_length, Some(100));
    assert_eq!(plan.content_range, None);
}

#[test]
fn request_cache_control_can_force_static_refresh() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(42, Some(modified));
    let first = plan_static_response(&file, "GET", StaticRequestConditions::default());

    let cache_control = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_none_match: Some(&first.etag),
            cache_control: Some("max-age = 0"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(cache_control.status, 200);
    assert_eq!(cache_control.body, StaticResponseBody::Full);

    let pragma = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            if_none_match: Some(&first.etag),
            pragma: Some("no-cache"),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(pragma.status, 200);
    assert_eq!(pragma.body, StaticResponseBody::Full);
}

#[test]
fn if_range_controls_static_range_responses() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = static_file(100, Some(modified));
    let fresh_date = httpdate::fmt_http_date(modified + std::time::Duration::from_secs(1));
    let stale_date = httpdate::fmt_http_date(modified - std::time::Duration::from_secs(1));

    let fresh = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            range: Some("bytes=10-19"),
            if_range: Some(&fresh_date),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(fresh.status, 206);
    assert_eq!(fresh.body, StaticResponseBody::Range { start: 10, len: 10 });

    let stale = plan_static_response(
        &file,
        "GET",
        StaticRequestConditions {
            range: Some("bytes=10-19"),
            if_range: Some(&stale_date),
            ..StaticRequestConditions::default()
        },
    );
    assert_eq!(stale.status, 200);
    assert_eq!(stale.body, StaticResponseBody::Full);
    assert_eq!(stale.content_range, None);
}

#[cfg(all(feature = "proxy", unix))]
#[test]
fn rejects_symlink_swap_before_static_body_read() {
    let root = TestDir::new("body-symlink-swap");
    let outside = TestDir::new("body-symlink-outside");
    fs::write(root.child("index.html"), "ok").unwrap();
    fs::write(outside.child("secret.txt"), "secret").unwrap();

    let server = server(root.path());
    let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
        panic!("expected static file")
    };
    let index = root.child("index.html");
    fs::remove_file(&index).unwrap();
    std::os::unix::fs::symlink(outside.child("secret.txt"), &index).unwrap();

    let error = super::read_static_response_body(&file, StaticResponseBody::Full).unwrap_err();

    assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidInput));
}

#[cfg(feature = "proxy")]
#[test]
fn reads_static_full_body_exactly() {
    let root = TestDir::new("body-full-exact");
    fs::write(root.child("index.html"), "ok").unwrap();

    let server = server(root.path());
    let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
        panic!("expected static file")
    };

    let body = super::read_static_response_body(&file, StaticResponseBody::Full).unwrap();

    assert_eq!(body, bytes::Bytes::from_static(b"ok"));
}

#[cfg(feature = "proxy")]
#[test]
fn refuses_static_full_body_over_buffer_limit() {
    let file = StaticFile {
        root: std::path::PathBuf::from("target"),
        path: std::path::PathBuf::from("target/fluxheim-too-large-static"),
        mime: "application/octet-stream".to_owned(),
        len: super::MAX_STATIC_BUFFERED_BODY_BYTES + 1,
        modified: None,
        #[cfg(unix)]
        device: 0,
        #[cfg(unix)]
        inode: 0,
    };

    let error = super::read_static_response_body(&file, StaticResponseBody::Full).unwrap_err();

    assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidInput));
}

#[cfg(all(feature = "proxy", unix))]
#[test]
fn rejects_same_size_replacement_before_static_body_read() {
    let root = TestDir::new("body-identity-change");
    fs::write(root.child("index.html"), "ok").unwrap();

    let server = server(root.path());
    let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
        panic!("expected static file")
    };
    fs::rename(root.child("index.html"), root.child("old-index.html")).unwrap();
    fs::write(root.child("index.html"), "no").unwrap();

    let error = super::read_static_response_body(&file, StaticResponseBody::Full).unwrap_err();

    assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidData));
}

#[cfg(feature = "proxy")]
#[test]
fn rejects_size_change_before_static_body_read() {
    let root = TestDir::new("body-size-change");
    fs::write(root.child("index.html"), "ok").unwrap();

    let server = server(root.path());
    let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
        panic!("expected static file")
    };
    fs::write(root.child("index.html"), "changed").unwrap();

    let error = super::read_static_response_body(&file, StaticResponseBody::Full).unwrap_err();

    assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidData));
}
