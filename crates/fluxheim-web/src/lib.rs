#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<DirectoryEntry>,
    pub local_time: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StaticResponseFile {
    pub len: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StaticResponsePlan {
    pub status: u16,
    pub body: StaticResponseBody,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
    pub etag: String,
    pub response_body_bytes: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StaticResponseBody {
    None,
    Full,
    Range { start: u64, len: u64 },
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct StaticResponseConditions<'a> {
    pub if_match: Option<&'a str>,
    pub if_unmodified_since: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub if_modified_since: Option<&'a str>,
    pub cache_refresh_forced: bool,
    pub range: Option<&'a str>,
    pub if_range: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ByteRangeParse {
    Single { start: u64, len: u64 },
    Unsatisfiable,
    Ignore,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SafeRelativePath {
    components: Vec<OsString>,
}

impl SafeRelativePath {
    pub fn push(&mut self, component: &str) {
        self.components.push(OsString::from(component));
    }

    pub fn as_path(&self) -> PathBuf {
        self.components.iter().collect()
    }

    pub fn from_path(path: &Path) -> Option<Self> {
        let mut safe = Self::default();
        for component in path.components() {
            match component {
                std::path::Component::Normal(component) => safe.components.push(component.into()),
                _ => return None,
            }
        }
        Some(safe)
    }

    pub fn from_rooted(root: &Path, candidate: &Path) -> Option<Self> {
        candidate.strip_prefix(root).ok().and_then(Self::from_path)
    }

    pub fn contains_component_starting_with(&self, prefix: char) -> bool {
        self.components.iter().any(|component| {
            component
                .to_str()
                .is_some_and(|component| component.starts_with(prefix))
        })
    }
}

pub fn plan_static_response(
    file: StaticResponseFile,
    method: &str,
    conditions: StaticResponseConditions<'_>,
) -> StaticResponsePlan {
    let etag = static_etag(file);

    if if_match_fails(conditions.if_match, &etag)
        || (conditions.if_match.is_none()
            && unmodified_since_fails(file.modified, conditions.if_unmodified_since))
    {
        return StaticResponsePlan {
            status: 412,
            body: StaticResponseBody::None,
            content_length: Some(0),
            content_range: None,
            etag,
            response_body_bytes: 0,
        };
    }

    if !conditions.cache_refresh_forced
        && (etag_not_modified(conditions.if_none_match, &etag)
            || (conditions.if_none_match.is_none()
                && modified_since_not_modified(file.modified, conditions.if_modified_since)))
    {
        return StaticResponsePlan {
            status: 304,
            body: StaticResponseBody::None,
            content_length: None,
            content_range: None,
            etag,
            response_body_bytes: 0,
        };
    }

    let range = conditions
        .range
        .filter(|_| if_range_allows_range(file.modified, &etag, conditions.if_range));

    if let Some(range) = range {
        return match parse_single_byte_range(range, file.len) {
            ByteRangeParse::Single { start, len } => StaticResponsePlan {
                status: 206,
                body: response_body(method, StaticResponseBody::Range { start, len }),
                content_length: Some(len),
                content_range: Some(format!(
                    "bytes {start}-{}/{}",
                    start.saturating_add(len).saturating_sub(1),
                    file.len
                )),
                etag,
                response_body_bytes: response_bytes(method, len),
            },
            ByteRangeParse::Unsatisfiable => StaticResponsePlan {
                status: 416,
                body: StaticResponseBody::None,
                content_length: Some(0),
                content_range: Some(format!("bytes */{}", file.len)),
                etag,
                response_body_bytes: 0,
            },
            ByteRangeParse::Ignore => full_static_response_plan(file, method, etag),
        };
    }

    full_static_response_plan(file, method, etag)
}

fn full_static_response_plan(
    file: StaticResponseFile,
    method: &str,
    etag: String,
) -> StaticResponsePlan {
    StaticResponsePlan {
        status: 200,
        body: response_body(method, StaticResponseBody::Full),
        content_length: Some(file.len),
        content_range: None,
        etag,
        response_body_bytes: response_bytes(method, file.len),
    }
}

fn response_body(method: &str, body: StaticResponseBody) -> StaticResponseBody {
    if method == "HEAD" {
        StaticResponseBody::None
    } else {
        body
    }
}

fn response_bytes(method: &str, bytes: u64) -> u64 {
    if method == "HEAD" { 0 } else { bytes }
}

fn static_etag(file: StaticResponseFile) -> String {
    let (seconds, nanos) = file
        .modified
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| (duration.as_secs(), duration.subsec_nanos()))
        .unwrap_or((0, 0));

    format!("W/\"{:x}-{seconds:x}-{nanos:x}\"", file.len)
}

fn etag_not_modified(if_none_match: Option<&str>, etag: &str) -> bool {
    let Some(value) = if_none_match else {
        return false;
    };

    value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || weak_etag_value(candidate) == weak_etag_value(etag))
}

fn weak_etag_value(value: &str) -> &str {
    value.strip_prefix("W/").unwrap_or(value)
}

fn if_match_fails(if_match: Option<&str>, etag: &str) -> bool {
    let Some(value) = if_match else {
        return false;
    };

    !value.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || (!candidate.starts_with("W/") && !etag.starts_with("W/") && candidate == etag)
    })
}

fn modified_since_not_modified(
    modified: Option<SystemTime>,
    if_modified_since: Option<&str>,
) -> bool {
    let (Some(modified), Some(if_modified_since)) = (modified, if_modified_since) else {
        return false;
    };
    let Ok(if_modified_since) = httpdate::parse_http_date(if_modified_since) else {
        return false;
    };

    let modified_seconds = modified
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let requested_seconds = if_modified_since
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    modified_seconds <= requested_seconds
}

fn unmodified_since_fails(modified: Option<SystemTime>, if_unmodified_since: Option<&str>) -> bool {
    let (Some(modified), Some(if_unmodified_since)) = (modified, if_unmodified_since) else {
        return false;
    };
    let Ok(if_unmodified_since) = httpdate::parse_http_date(if_unmodified_since) else {
        return false;
    };

    let modified_seconds = modified
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let requested_seconds = if_unmodified_since
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    modified_seconds > requested_seconds
}

fn if_range_allows_range(modified: Option<SystemTime>, etag: &str, if_range: Option<&str>) -> bool {
    let Some(if_range) = if_range.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };

    if if_range.starts_with('"') {
        return !etag.starts_with("W/") && if_range == etag;
    }

    modified_since_not_modified(modified, Some(if_range))
}

pub fn parse_single_byte_range(range: &str, file_len: u64) -> ByteRangeParse {
    let range = range.trim();
    let Some(range) = range.strip_prefix("bytes=") else {
        return ByteRangeParse::Unsatisfiable;
    };
    if range.contains(',') {
        return ByteRangeParse::Ignore;
    }
    if file_len == 0 {
        return ByteRangeParse::Unsatisfiable;
    }

    let Some((start, end)) = range.split_once('-') else {
        return ByteRangeParse::Unsatisfiable;
    };
    if start.is_empty() {
        let Ok(suffix_len) = end.parse::<u64>() else {
            return ByteRangeParse::Unsatisfiable;
        };
        if suffix_len == 0 {
            return ByteRangeParse::Unsatisfiable;
        }
        let len = suffix_len.min(file_len);
        return ByteRangeParse::Single {
            start: file_len - len,
            len,
        };
    }

    let Ok(start) = start.parse::<u64>() else {
        return ByteRangeParse::Unsatisfiable;
    };
    if start >= file_len {
        return ByteRangeParse::Unsatisfiable;
    }

    let end = if end.is_empty() {
        file_len - 1
    } else {
        match end.parse::<u64>() {
            Ok(end) => end.min(file_len - 1),
            Err(_) => return ByteRangeParse::Unsatisfiable,
        }
    };

    if end < start {
        return ByteRangeParse::Unsatisfiable;
    }

    ByteRangeParse::Single {
        start,
        len: end - start + 1,
    }
}

pub fn render_directory_listing(listing: &DirectoryListing) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of ");
    html.push_str(&html_escape(&listing.path));
    html.push_str("</title></head><body><h1>Index of ");
    html.push_str(&html_escape(&listing.path));
    html.push_str(
        "</h1><table><thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead><tbody>",
    );
    for entry in &listing.entries {
        let display_name = if entry.is_dir {
            format!("{}/", entry.name)
        } else {
            entry.name.clone()
        };
        let href = format!(
            "{}{}{}",
            listing.path,
            utf8_percent_encode(&entry.name, NON_ALPHANUMERIC),
            if entry.is_dir { "/" } else { "" }
        );
        html.push_str("<tr><td><a href=\"");
        html.push_str(&html_escape(&href));
        html.push_str("\">");
        html.push_str(&html_escape(&display_name));
        html.push_str("</a></td><td>");
        html.push_str(
            &entry
                .size
                .map(|size| size.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        );
        html.push_str("</td><td>");
        if let Some(modified) = entry.modified {
            html.push_str(&html_escape(&format_directory_listing_time(
                modified,
                listing.local_time,
            )));
        } else {
            html.push('-');
        }
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></body></html>");
    html
}

pub fn directory_listing_path(relative: &Path) -> String {
    let mut path = String::from("/");
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            continue;
        };
        if path.len() > 1 {
            path.push('/');
        }
        path.push_str(&segment.to_string_lossy());
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

pub fn configured_web_path_contains_symlink(path: &Path) -> io::Result<bool> {
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_) => {}
            std::path::Component::CurDir | std::path::Component::ParentDir => return Ok(true),
        }
    }

    let expected = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    match path.canonicalize() {
        Ok(canonical) => Ok(canonical != expected),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn format_directory_listing_time(modified: SystemTime, local_time: bool) -> String {
    if local_time {
        let local: chrono::DateTime<chrono::Local> = modified.into();
        return local.format("%Y-%m-%d %H:%M:%S %z").to_string();
    }

    httpdate::fmt_http_date(modified)
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::UNIX_EPOCH;

    use super::{
        ByteRangeParse, DirectoryEntry, DirectoryListing, SafeRelativePath, StaticResponseBody,
        StaticResponseConditions, StaticResponseFile, configured_web_path_contains_symlink,
        directory_listing_path, parse_single_byte_range, plan_static_response,
        render_directory_listing,
    };

    #[test]
    fn renders_escaped_directory_listing() {
        let listing = DirectoryListing {
            path: "/repo/<root>/".to_owned(),
            entries: vec![DirectoryEntry {
                name: "a&b.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: None,
            }],
            local_time: false,
        };

        let html = render_directory_listing(&listing);

        assert!(html.contains("Index of /repo/&lt;root&gt;/"));
        assert!(html.contains("a&amp;b.txt"));
    }

    #[test]
    fn directory_listing_local_time_uses_local_timestamp_shape() {
        let listing = DirectoryListing {
            path: "/".to_owned(),
            entries: vec![DirectoryEntry {
                name: "asset.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            }],
            local_time: true,
        };

        let html = render_directory_listing(&listing);

        assert!(
            html.contains("2023-11-14") || html.contains("2023-11-15"),
            "{html}"
        );
        assert!(!html.contains("GMT"));
    }

    #[test]
    fn safe_relative_path_rejects_non_normal_components() {
        assert!(SafeRelativePath::from_path(Path::new("assets/app.css")).is_some());
        assert!(SafeRelativePath::from_path(Path::new("../secret")).is_none());
        assert!(SafeRelativePath::from_path(Path::new("/absolute")).is_none());
    }

    #[test]
    fn safe_relative_path_detects_prefixed_components() {
        let path = SafeRelativePath::from_path(Path::new(".well-known/acme-challenge"))
            .expect("relative path should parse");

        assert!(path.contains_component_starting_with('.'));
    }

    #[test]
    fn formats_directory_listing_paths_with_trailing_slash() {
        assert_eq!(directory_listing_path(Path::new("")), "/");
        assert_eq!(
            directory_listing_path(Path::new("assets/css")),
            "/assets/css/"
        );
    }

    #[test]
    fn configured_web_path_rejects_dot_segments() {
        assert!(configured_web_path_contains_symlink(Path::new("assets/../public")).unwrap());
    }

    #[test]
    fn configured_web_path_allows_missing_plain_path() {
        let missing =
            std::env::temp_dir().join(format!("fluxheim-web-missing-{}", std::process::id()));

        assert!(!configured_web_path_contains_symlink(&missing).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn configured_web_path_detects_symlinked_parent() {
        let root = std::env::temp_dir().join(format!(
            "fluxheim-web-symlink-parent-{}",
            std::process::id()
        ));
        let real = root.join("real");
        let linked = root.join("linked");
        let public = linked.join("public");
        std::fs::create_dir_all(real.join("public")).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();

        assert!(configured_web_path_contains_symlink(&public).unwrap());

        let _ = std::fs::remove_file(linked);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_single_byte_ranges() {
        assert_eq!(
            parse_single_byte_range("bytes=10-19", 100),
            ByteRangeParse::Single { start: 10, len: 10 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=90-", 100),
            ByteRangeParse::Single { start: 90, len: 10 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=-5", 100),
            ByteRangeParse::Single { start: 95, len: 5 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=0-999", 10),
            ByteRangeParse::Single { start: 0, len: 10 }
        );
    }

    #[test]
    fn rejects_unsatisfiable_or_multi_ranges() {
        assert_eq!(
            parse_single_byte_range("bytes=100-101", 100),
            ByteRangeParse::Unsatisfiable
        );
        assert_eq!(
            parse_single_byte_range("bytes=0-1,2-3", 100),
            ByteRangeParse::Ignore
        );
        assert_eq!(
            parse_single_byte_range("items=0-1", 100),
            ByteRangeParse::Unsatisfiable
        );
    }

    #[test]
    fn plans_static_etag_revalidation() {
        let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let file = StaticResponseFile {
            len: 42,
            modified: Some(modified),
        };
        let first = plan_static_response(file, "GET", StaticResponseConditions::default());

        assert_eq!(first.status, 200);
        assert_eq!(first.content_length, Some(42));
        assert_eq!(first.response_body_bytes, 42);

        let revalidated = plan_static_response(
            file,
            "GET",
            StaticResponseConditions {
                if_none_match: Some(&first.etag),
                ..StaticResponseConditions::default()
            },
        );

        assert_eq!(revalidated.status, 304);
        assert_eq!(revalidated.content_length, None);
        assert_eq!(revalidated.body, StaticResponseBody::None);
        assert_eq!(revalidated.response_body_bytes, 0);
    }

    #[test]
    fn forced_refresh_ignores_static_revalidation() {
        let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let file = StaticResponseFile {
            len: 42,
            modified: Some(modified),
        };
        let first = plan_static_response(file, "GET", StaticResponseConditions::default());

        let refreshed = plan_static_response(
            file,
            "GET",
            StaticResponseConditions {
                if_none_match: Some(&first.etag),
                cache_refresh_forced: true,
                ..StaticResponseConditions::default()
            },
        );

        assert_eq!(refreshed.status, 200);
        assert_eq!(refreshed.body, StaticResponseBody::Full);
    }
}
