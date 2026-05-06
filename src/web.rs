#[cfg(feature = "proxy")]
use std::fs::OpenOptions;
use std::io;
#[cfg(feature = "proxy")]
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use percent_encoding::percent_decode_str;

use crate::config::WebConfig;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(all(feature = "proxy", target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(all(feature = "proxy", target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(feature = "proxy")]
pub const MAX_STATIC_BUFFERED_BODY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StaticFileServer {
    root: PathBuf,
    index_files: Vec<String>,
    deny_dotfiles: bool,
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    cache_control: String,
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    expires: Option<String>,
}

impl StaticFileServer {
    pub fn from_config(config: &WebConfig) -> io::Result<Option<Self>> {
        let Some(root) = &config.root else {
            return Ok(None);
        };

        if configured_web_path_contains_symlink(root)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "web root must not be below a symlinked directory: {}",
                    root.display()
                ),
            ));
        }

        let root_metadata = std::fs::symlink_metadata(root)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("web root is not a real directory: {}", root.display()),
            ));
        }

        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("web root is not a directory: {}", root.display()),
            ));
        }

        Ok(Some(Self {
            root,
            index_files: config.index_files.clone(),
            deny_dotfiles: config.deny_dotfiles,
            cache_control: config.cache_control.clone(),
            expires: config.expires.clone(),
        }))
    }

    pub fn resolve(&self, request_path: &str) -> io::Result<ResolveResult> {
        let Some(relative_path) = self.relative_request_path(request_path)? else {
            return Ok(ResolveResult::Forbidden);
        };

        let candidate = self.root.join(relative_path);
        self.resolve_candidate(&candidate)
    }

    fn relative_request_path(&self, request_path: &str) -> io::Result<Option<PathBuf>> {
        if !request_path.starts_with('/') {
            return Ok(None);
        }

        let decoded = percent_decode_str(request_path)
            .decode_utf8()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        if decoded.contains('\0') {
            return Ok(None);
        }

        let mut relative = PathBuf::new();
        for segment in decoded.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }

            if segment == ".."
                || segment.contains('\\')
                || (self.deny_dotfiles && segment.starts_with('.'))
            {
                return Ok(None);
            }

            relative.push(segment);
        }

        Ok(Some(relative))
    }

    fn resolve_candidate(&self, candidate: &Path) -> io::Result<ResolveResult> {
        if path_contains_symlink(&self.root, candidate)? {
            return Ok(ResolveResult::NotFound);
        }

        let candidate_metadata = match candidate.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ResolveResult::NotFound);
            }
            Err(error) => return Err(error),
        };

        if candidate_metadata.is_dir() {
            for index in &self.index_files {
                let index_candidate = candidate.join(index);
                if let Some(file) = self.static_file(&index_candidate)? {
                    return Ok(ResolveResult::Found(file));
                }
            }

            return Ok(ResolveResult::NotFound);
        }

        match self.static_file(candidate)? {
            Some(file) => Ok(ResolveResult::Found(file)),
            None => Ok(ResolveResult::NotFound),
        }
    }

    fn static_file(&self, candidate: &Path) -> io::Result<Option<StaticFile>> {
        if path_contains_symlink(&self.root, candidate)? {
            return Ok(None);
        }

        let canonical = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        if !canonical.starts_with(&self.root) {
            return Ok(None);
        }

        let metadata = canonical.metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }

        let mime = mime_guess::from_path(&canonical)
            .first_or_octet_stream()
            .essence_str()
            .to_owned();

        Ok(Some(StaticFile {
            path: canonical,
            mime,
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }))
    }
}

fn path_contains_symlink(root: &Path, candidate: &Path) -> io::Result<bool> {
    let Ok(relative) = candidate.strip_prefix(root) else {
        return Ok(true);
    };

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn configured_web_path_contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolveResult {
    Found(StaticFile),
    NotFound,
    Forbidden,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StaticFile {
    pub path: PathBuf,
    pub mime: String,
    pub len: u64,
    pub modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
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
pub struct StaticRequestConditions<'a> {
    pub if_match: Option<&'a str>,
    pub if_unmodified_since: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub if_modified_since: Option<&'a str>,
    pub cache_control: Option<&'a str>,
    pub pragma: Option<&'a str>,
    pub range: Option<&'a str>,
    pub if_range: Option<&'a str>,
}

pub fn plan_static_response(
    file: &StaticFile,
    method: &str,
    conditions: StaticRequestConditions<'_>,
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

    if !crate::cache_headers::request_forces_cache_refresh(
        conditions.cache_control,
        conditions.pragma,
    ) && (etag_not_modified(conditions.if_none_match, &etag)
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
            Some((start, len)) => StaticResponsePlan {
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
            None => StaticResponsePlan {
                status: 416,
                body: StaticResponseBody::None,
                content_length: Some(0),
                content_range: Some(format!("bytes */{}", file.len)),
                etag,
                response_body_bytes: 0,
            },
        };
    }

    StaticResponsePlan {
        status: 200,
        body: response_body(method, StaticResponseBody::Full),
        content_length: Some(file.len),
        content_range: None,
        etag,
        response_body_bytes: response_bytes(method, file.len),
    }
}

#[cfg(all(feature = "web", feature = "proxy"))]
pub async fn serve_static_file(
    session: &mut pingora::proxy::Session,
    server: &StaticFileServer,
    file: &StaticFile,
    plan: &StaticResponsePlan,
    response_policy: &crate::config::ResponseHeaderPolicyConfig,
) -> pingora::Result<()> {
    use pingora::prelude::{InternalError, OrErr};

    let response = build_static_response_header(server, file, plan, response_policy)?;

    if matches!(plan.body, StaticResponseBody::None) {
        session
            .write_response_header(Box::new(response), true)
            .await?;
    } else {
        session
            .write_response_header(Box::new(response), false)
            .await?;
        let body = read_static_body(file, plan.body)
            .or_err(InternalError, "failed to read static file")?;
        session.write_response_body(Some(body), true).await?;
    }

    Ok(())
}

#[cfg(all(feature = "web", feature = "proxy"))]
fn build_static_response_header(
    server: &StaticFileServer,
    file: &StaticFile,
    plan: &StaticResponsePlan,
    response_policy: &crate::config::ResponseHeaderPolicyConfig,
) -> pingora::Result<pingora::http::ResponseHeader> {
    let mut response = pingora::http::ResponseHeader::build(plan.status, Some(9))?;
    response.insert_header("content-type", file.mime.as_str())?;
    if let Some(content_length) = plan.content_length {
        response.insert_header("content-length", content_length)?;
    }
    response.insert_header("cache-control", server.cache_control.as_str())?;
    response.insert_header("etag", plan.etag.as_str())?;
    response.insert_header("accept-ranges", "bytes")?;
    if let Some(expires) = server.expires.as_deref() {
        response.insert_header("expires", expires)?;
    }

    if let Some(modified) = file.modified {
        response.insert_header("last-modified", httpdate::fmt_http_date(modified))?;
    }
    if let Some(content_range) = plan.content_range.as_deref() {
        response.insert_header("content-range", content_range)?;
    }
    crate::headers::apply_response_policy(&mut response, response_policy)?;

    Ok(response)
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

fn static_etag(file: &StaticFile) -> String {
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

fn parse_single_byte_range(range: &str, file_len: u64) -> Option<(u64, u64)> {
    let range = range.trim();
    let range = range.strip_prefix("bytes=")?;
    if range.contains(',') || file_len == 0 {
        return None;
    }

    let (start, end) = range.split_once('-')?;
    if start.is_empty() {
        let suffix_len = end.parse::<u64>().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let len = suffix_len.min(file_len);
        return Some((file_len - len, len));
    }

    let start = start.parse::<u64>().ok()?;
    if start >= file_len {
        return None;
    }

    let end = if end.is_empty() {
        file_len - 1
    } else {
        end.parse::<u64>().ok()?.min(file_len - 1)
    };

    if end < start {
        return None;
    }

    Some((start, end - start + 1))
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

#[cfg(feature = "proxy")]
fn read_static_body(file: &StaticFile, body: StaticResponseBody) -> io::Result<bytes::Bytes> {
    match body {
        StaticResponseBody::None => Ok(bytes::Bytes::new()),
        StaticResponseBody::Full => {
            if file.len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "static file exceeds buffered response limit",
                ));
            }
            let mut reader = open_static_body_file(file)?;
            let capacity = usize::try_from(file.len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "static file too large")
            })?;
            let mut body = Vec::with_capacity(capacity);
            let mut bounded_reader = reader.by_ref().take(file.len.saturating_add(1));
            bounded_reader.read_to_end(&mut body)?;
            if body.len() as u64 != file.len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "static file changed during body read",
                ));
            }
            Ok(bytes::Bytes::from(body))
        }
        StaticResponseBody::Range { start, len } => {
            if len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "static range exceeds buffered response limit",
                ));
            }
            let len = usize::try_from(len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "static range too large")
            })?;
            let mut reader = open_static_body_file(file)?;
            reader.seek(io::SeekFrom::Start(start))?;
            let mut body = vec![0; len];
            reader.read_exact(&mut body)?;
            Ok(bytes::Bytes::from(body))
        }
    }
}

#[cfg(feature = "proxy")]
fn open_static_body_file(file: &StaticFile) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(&file.path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path is not a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);

    let file_handle = options.open(&file.path)?;
    let metadata = file_handle.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body handle is not a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.dev() != file.device || metadata.ino() != file.inode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "static file identity changed before body read",
        ));
    }
    if metadata.len() != file.len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "static file changed before body read",
        ));
    }

    Ok(file_handle)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::WebConfig;

    use super::{
        ResolveResult, StaticFile, StaticFileServer, StaticRequestConditions, StaticResponseBody,
        parse_single_byte_range, plan_static_response,
    };

    #[test]
    fn resolves_index_file() {
        let root = TestDir::new("index");
        fs::write(root.path().join("index.html"), "<h1>ok</h1>").unwrap();

        let server = server(root.path());
        let resolved = server.resolve("/").unwrap();

        assert!(matches!(resolved, ResolveResult::Found(file) if file.mime == "text/html"));
    }

    #[test]
    fn rejects_traversal() {
        let root = TestDir::new("traversal");
        fs::write(root.path().join("index.html"), "ok").unwrap();

        let server = server(root.path());

        assert_eq!(
            server.resolve("/../secret.txt").unwrap(),
            ResolveResult::Forbidden
        );
        assert_eq!(
            server.resolve("/%2e%2e/secret.txt").unwrap(),
            ResolveResult::Forbidden
        );
    }

    #[test]
    fn rejects_dotfiles_by_default() {
        let root = TestDir::new("dotfiles");
        fs::write(root.path().join(".env"), "secret").unwrap();

        let server = server(root.path());

        assert_eq!(server.resolve("/.env").unwrap(), ResolveResult::Forbidden);
    }

    #[test]
    fn stores_configured_static_cache_headers() {
        let root = TestDir::new("static-cache-headers");
        fs::write(root.path().join("index.html"), "ok").unwrap();

        let server = StaticFileServer::from_config(&WebConfig {
            root: Some(root.path().to_owned()),
            cache_control: "public, max-age=31536000, immutable".to_owned(),
            expires: Some("Wed, 21 Oct 2030 07:28:00 GMT".to_owned()),
            ..WebConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(server.cache_control, "public, max-age=31536000, immutable");
        assert_eq!(
            server.expires.as_deref(),
            Some("Wed, 21 Oct 2030 07:28:00 GMT")
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn builds_static_response_headers_from_config() {
        let root = TestDir::new("static-response-headers");
        fs::write(root.path().join("index.html"), "ok").unwrap();
        let server = StaticFileServer::from_config(&WebConfig {
            root: Some(root.path().to_owned()),
            cache_control: "public, max-age=31536000, immutable".to_owned(),
            expires: Some("Wed, 21 Oct 2030 07:28:00 GMT".to_owned()),
            ..WebConfig::default()
        })
        .unwrap()
        .unwrap();
        let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let file = static_file(2, Some(modified));
        let plan = plan_static_response(&file, "GET", StaticRequestConditions::default());

        let response = super::build_static_response_header(
            &server,
            &file,
            &plan,
            &crate::config::ResponseHeaderPolicyConfig::default(),
        )
        .unwrap();

        assert!(response.headers.get("server").is_none());
        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(
            response
                .headers
                .get("expires")
                .and_then(|value| value.to_str().ok()),
            Some("Wed, 21 Oct 2030 07:28:00 GMT")
        );
        assert_eq!(
            response
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("2")
        );
        assert!(response.headers.get("etag").is_some());
        assert!(response.headers.get("last-modified").is_some());
        assert_eq!(
            response
                .headers
                .get("accept-ranges")
                .and_then(|value| value.to_str().ok()),
            Some("bytes")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_static_root() {
        let target = TestDir::new("root-symlink-target");
        let root = std::env::temp_dir().join(format!(
            "fluxheim-web-test-root-symlink-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::os::unix::fs::symlink(target.path(), &root).unwrap();

        let error = StaticFileServer::from_config(&WebConfig {
            root: Some(root.clone()),
            index_files: vec!["index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_file(root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_static_root_below_symlinked_directory() {
        let dir = TestDir::new("root-parent-symlink");
        let real = dir.path().join("real");
        let linked = dir.path().join("linked");
        fs::create_dir_all(real.join("public")).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();

        let error = StaticFileServer::from_config(&WebConfig {
            root: Some(linked.join("public")),
            index_files: vec!["index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("symlinked directory"));
    }

    #[test]
    fn blocks_symlink_escape() {
        #[cfg(unix)]
        {
            let root = TestDir::new("symlink");
            let outside = TestDir::new("outside");
            fs::write(outside.path().join("secret.txt"), "secret").unwrap();
            std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.path().join("link"))
                .unwrap();

            let server = server(root.path());

            assert_eq!(server.resolve("/link").unwrap(), ResolveResult::NotFound);
        }
    }

    #[test]
    fn rejects_static_symlinks_inside_root() {
        #[cfg(unix)]
        {
            let root = TestDir::new("inside-symlink");
            fs::create_dir_all(root.path().join("real")).unwrap();
            fs::write(root.path().join("real").join("asset.txt"), "ok").unwrap();
            std::os::unix::fs::symlink(
                root.path().join("real").join("asset.txt"),
                root.path().join("asset-link.txt"),
            )
            .unwrap();
            std::os::unix::fs::symlink(root.path().join("real"), root.path().join("dir-link"))
                .unwrap();

            let server = server(root.path());

            assert_eq!(
                server.resolve("/asset-link.txt").unwrap(),
                ResolveResult::NotFound
            );
            assert_eq!(
                server.resolve("/dir-link/asset.txt").unwrap(),
                ResolveResult::NotFound
            );
        }
    }

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
        assert_eq!(parse_single_byte_range("bytes=100-200", 100), None);
        assert_eq!(parse_single_byte_range("bytes=20-10", 100), None);
        assert_eq!(parse_single_byte_range("bytes=0-1,4-5", 100), None);
        assert_eq!(parse_single_byte_range("items=0-1", 100), None);

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
        fs::write(root.path().join("index.html"), "ok").unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();

        let server = server(root.path());
        let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
            panic!("expected static file")
        };
        fs::remove_file(&file.path).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), &file.path).unwrap();

        let error = super::read_static_body(&file, StaticResponseBody::Full).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn reads_static_full_body_exactly() {
        let root = TestDir::new("body-full-exact");
        fs::write(root.path().join("index.html"), "ok").unwrap();

        let server = server(root.path());
        let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
            panic!("expected static file")
        };

        let body = super::read_static_body(&file, StaticResponseBody::Full).unwrap();

        assert_eq!(body, bytes::Bytes::from_static(b"ok"));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn refuses_static_full_body_over_buffer_limit() {
        let file = StaticFile {
            path: std::path::PathBuf::from("/tmp/fluxheim-too-large-static"),
            mime: "application/octet-stream".to_owned(),
            len: super::MAX_STATIC_BUFFERED_BODY_BYTES + 1,
            modified: None,
            #[cfg(unix)]
            device: 0,
            #[cfg(unix)]
            inode: 0,
        };

        let error = super::read_static_body(&file, StaticResponseBody::Full).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn rejects_same_size_replacement_before_static_body_read() {
        let root = TestDir::new("body-identity-change");
        fs::write(root.path().join("index.html"), "ok").unwrap();

        let server = server(root.path());
        let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
            panic!("expected static file")
        };
        fs::rename(&file.path, root.path().join("old-index.html")).unwrap();
        fs::write(&file.path, "no").unwrap();

        let error = super::read_static_body(&file, StaticResponseBody::Full).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn rejects_size_change_before_static_body_read() {
        let root = TestDir::new("body-size-change");
        fs::write(root.path().join("index.html"), "ok").unwrap();

        let server = server(root.path());
        let ResolveResult::Found(file) = server.resolve("/index.html").unwrap() else {
            panic!("expected static file")
        };
        fs::write(&file.path, "changed").unwrap();

        let error = super::read_static_body(&file, StaticResponseBody::Full).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fluxheim-web-test-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn server(root: &Path) -> StaticFileServer {
        StaticFileServer::from_config(&WebConfig {
            root: Some(root.to_owned()),
            index_files: vec!["index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        })
        .unwrap()
        .unwrap()
    }

    fn static_file(len: u64, modified: Option<SystemTime>) -> StaticFile {
        StaticFile {
            path: PathBuf::from("/tmp/fluxheim-static-test"),
            mime: "text/plain".to_owned(),
            len,
            modified,
            #[cfg(unix)]
            device: 0,
            #[cfg(unix)]
            inode: 0,
        }
    }
}
