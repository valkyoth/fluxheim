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

mod directory_listing;

pub use directory_listing::{
    DirectoryEntry, DirectoryListing, directory_listing_path, render_directory_listing,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StaticResponseFile {
    pub len: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StaticCacheIdentity<'a> {
    pub path: &'a Path,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub device_inode: Option<(u64, u64)>,
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

pub fn static_cache_identity(identity: StaticCacheIdentity<'_>) -> String {
    let modified = identity
        .modified
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| format!("{}:{}", duration.as_secs(), duration.subsec_nanos()))
        .unwrap_or_else(|| "0:0".to_owned());

    if let Some((device, inode)) = identity.device_inode {
        format!(
            "{}:{}:{}:{}:{}",
            identity.path.display(),
            device,
            inode,
            identity.len,
            modified
        )
    } else {
        format!("{}:{}:{}", identity.path.display(), identity.len, modified)
    }
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

#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;
