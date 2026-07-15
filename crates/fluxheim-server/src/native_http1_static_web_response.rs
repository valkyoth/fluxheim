use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use fluxheim_cache::{request_cache_bypass_reason, request_cache_revalidation_requested};
use fluxheim_web::{
    DirectoryListing, SafeRelativePath, StaticResponseBody, StaticResponseConditions,
    StaticResponseFile, plan_static_response, render_directory_listing,
};

use crate::native_http1_cache::with_native_cache_status;
use crate::{NativeHttp1Request, NativeHttp1Response};

use super::{MAX_NATIVE_STATIC_BODY_BYTES, NativeHttp1StaticWeb, NativeStaticFile};

impl NativeHttp1StaticWeb {
    pub(super) fn file_response(
        &self,
        request: &NativeHttp1Request,
        file: &NativeStaticFile,
    ) -> NativeHttp1Response {
        self.file_response_with_status(request, file, static_conditions(request), None)
            .unwrap_or_else(|| {
                NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                    .close_connection()
            })
    }

    pub(super) fn cached_file_response(
        &self,
        request: &NativeHttp1Request,
        file: &NativeStaticFile,
    ) -> NativeHttp1Response {
        let Some(cache) = &self.cache else {
            return self.file_response(request, file);
        };
        let Some(key) = cache.static_key(request, file) else {
            return with_native_cache_status(
                self.file_response(request, file),
                &cache.config,
                "BYPASS",
                Some("static-ineligible"),
                None,
            );
        };
        if let Some(reason) = request_cache_bypass_reason(request, &cache.config) {
            return with_native_cache_status(
                self.file_response(request, file),
                &cache.config,
                "BYPASS",
                Some(reason),
                None,
            );
        }
        if !request_cache_revalidation_requested(request, &cache.config)
            && let Some(hit) = cache.get(&key)
        {
            return with_native_cache_status(
                hit.to_response(),
                &cache.config,
                "HIT",
                None,
                Some(hit.age_secs()),
            );
        }

        let response = self.file_response(request, file);
        let cache_status = if request_cache_revalidation_requested(request, &cache.config) {
            "REVALIDATED"
        } else {
            "MISS"
        };
        match cache.store(&key, &response) {
            Ok(()) => with_native_cache_status(response, &cache.config, cache_status, None, None),
            Err(reason) => {
                with_native_cache_status(response, &cache.config, "BYPASS", Some(reason), None)
            }
        }
    }

    pub(super) fn file_response_with_status(
        &self,
        request: &NativeHttp1Request,
        file: &NativeStaticFile,
        conditions: StaticResponseConditions<'_>,
        status_override: Option<u16>,
    ) -> Option<NativeHttp1Response> {
        let plan = plan_static_response(
            StaticResponseFile {
                len: file.len,
                modified: file.modified,
            },
            &request.method,
            conditions,
        );
        if plan.response_body_bytes > MAX_NATIVE_STATIC_BODY_BYTES {
            return Some(
                NativeHttp1Response::new(413, "Payload Too Large", b"static response too large\n")
                    .close_connection(),
            );
        }

        let body = match read_static_body(file, plan.body) {
            Ok(body) => body,
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "static file read failed: {error}");
                return None;
            }
        };

        let status = status_override.unwrap_or(plan.status);
        let mut response = NativeHttp1Response::new(status, static_reason(status), body)
            .with_header("content-type", file.mime)
            .with_header("cache-control", self.cache_control.clone())
            .with_header("etag", plan.etag)
            .with_header("accept-ranges", "bytes");
        if let Some(content_length) = plan.content_length {
            response = response.with_content_length(content_length);
        }
        if let Some(expires) = &self.expires {
            response = response.with_header("expires", expires.clone());
        }
        if let Some(modified) = file.modified {
            response = response.with_header("last-modified", httpdate::fmt_http_date(modified));
        }
        if let Some(content_range) = plan.content_range {
            response = response.with_header("content-range", content_range);
        }
        Some(response)
    }
}

pub(super) fn static_conditions(request: &NativeHttp1Request) -> StaticResponseConditions<'_> {
    StaticResponseConditions {
        if_match: request_header(request, "if-match"),
        if_unmodified_since: request_header(request, "if-unmodified-since"),
        if_none_match: request_header(request, "if-none-match"),
        if_modified_since: request_header(request, "if-modified-since"),
        cache_refresh_forced: request_forces_cache_refresh(request),
        range: request_header(request, "range"),
        if_range: request_header(request, "if-range"),
    }
}

pub(super) fn request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .map(String::as_str)
}

fn request_forces_cache_refresh(request: &NativeHttp1Request) -> bool {
    request_header(request, "pragma").is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|directive| directive.eq_ignore_ascii_case("no-cache"))
    }) || request_header(request, "cache-control").is_some_and(|value| {
        value.split(',').map(str::trim).any(|directive| {
            directive.eq_ignore_ascii_case("no-cache") || directive.eq_ignore_ascii_case("no-store")
        })
    })
}

fn read_static_body(file: &NativeStaticFile, body: StaticResponseBody) -> io::Result<Vec<u8>> {
    match body {
        StaticResponseBody::None => Ok(Vec::new()),
        StaticResponseBody::Full => {
            let capacity = usize::try_from(file.len)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "static file too large"))?;
            let mut reader = open_static_body_file(file)?;
            let mut body = Vec::with_capacity(capacity);
            let mut bounded_reader = reader.by_ref().take(file.len.saturating_add(1));
            bounded_reader.read_to_end(&mut body)?;
            if body.len() as u64 != file.len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "static file changed during body read",
                ));
            }
            Ok(body)
        }
        StaticResponseBody::Range { start, len } => {
            let len = usize::try_from(len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "static range too large")
            })?;
            let mut reader = open_static_body_file(file)?;
            reader.seek(io::SeekFrom::Start(start))?;
            let mut body = vec![0; len];
            reader.read_exact(&mut body)?;
            Ok(body)
        }
    }
}

fn open_static_body_file(file: &NativeStaticFile) -> io::Result<File> {
    let Some(relative) = SafeRelativePath::from_rooted(&file.root, &file.path) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path escaped web root",
        ));
    };
    if file.path != file.root.join(relative.as_path()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path contains a symlink",
        ));
    }
    let canonical = file.path.canonicalize()?;
    if !canonical.starts_with(&file.root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path escaped web root",
        ));
    }
    let opened = open_static_body_file_at_root(file, &relative.as_path())?;
    let metadata = opened.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path is not a regular file",
        ));
    }
    Ok(opened)
}

fn open_static_body_file_at_root(
    file: &NativeStaticFile,
    relative_path: &Path,
) -> io::Result<File> {
    let directory_flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC;
    let nofollow_directory_flags = directory_flags | rustix::fs::OFlags::NOFOLLOW;
    let file_flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;

    let mut directory = rustix::fs::open(
        &file.root,
        nofollow_directory_flags,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut components = relative_path.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path is not relative",
            ));
        };
        let name = Path::new(name);
        if components.peek().is_some() {
            directory = rustix::fs::openat(
                &directory,
                name,
                nofollow_directory_flags,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?;
        } else {
            let file = rustix::fs::openat(&directory, name, file_flags, rustix::fs::Mode::empty())
                .map_err(io::Error::from)?;
            return Ok(File::from(file));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "static body path is empty",
    ))
}

pub(super) fn directory_listing_response(
    request: &NativeHttp1Request,
    listing: &DirectoryListing,
) -> NativeHttp1Response {
    let body = render_directory_listing(listing);
    let content_length = body.len() as u64;
    let body = if request.method == "HEAD" {
        Vec::new()
    } else {
        body.into_bytes()
    };
    NativeHttp1Response::new(200, "OK", body)
        .with_content_length(content_length)
        .with_header("content-type", "text/html; charset=utf-8")
        .with_header("cache-control", "private, no-store")
}

pub(super) fn native_static_cache_expires_at(now: Instant, ttl: Duration) -> Option<Instant> {
    now.checked_add(ttl)
}

pub(super) fn static_web_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

fn static_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        304 => "Not Modified",
        412 => "Precondition Failed",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        416 => "Range Not Satisfiable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use tempfile::TempDir;

    use super::{native_static_cache_expires_at, open_static_body_file};
    use crate::NativeHttp1Response;
    use crate::native_http1_cache::{
        NativeMemoryCacheEntry, NativeMemoryCacheState, native_cache_entry_weight,
        prune_native_memory_cache,
    };
    use crate::native_http1_static_web::NativeStaticFile;

    #[test]
    fn static_cache_entry_weight_includes_entry_overhead() {
        let response = NativeHttp1Response::new(200, "OK", b"hello")
            .with_header("cache-control", "max-age=60");
        let raw_bytes = 5_u64 + "cache-control".len() as u64 + "max-age=60".len() as u64 + 4;

        let weight = native_cache_entry_weight("cache-key", &response, 5);

        assert!(weight >= raw_bytes + 256 + "cache-key".len() as u64 + "OK".len() as u64);
    }

    #[test]
    fn static_cache_expiry_rejects_unrepresentable_ttl() {
        assert!(native_static_cache_expires_at(Instant::now(), Duration::MAX).is_none());
    }

    #[test]
    fn prune_static_cache_removes_expired_and_oldest_entries() {
        let now = Instant::now();
        let mut state = NativeMemoryCacheState::default();
        state.objects.insert(
            "expired".to_owned(),
            cache_entry(
                now - Duration::from_secs(30),
                now - Duration::from_secs(1),
                100,
            ),
        );
        state.objects.insert(
            "old".to_owned(),
            cache_entry(
                now - Duration::from_secs(20),
                now + Duration::from_secs(60),
                100,
            ),
        );
        state.objects.insert(
            "new".to_owned(),
            cache_entry(
                now - Duration::from_secs(10),
                now + Duration::from_secs(60),
                100,
            ),
        );
        state.bytes = 300;

        prune_native_memory_cache(&mut state, 150);

        assert!(!state.objects.contains_key("expired"));
        assert!(!state.objects.contains_key("old"));
        assert!(state.objects.contains_key("new"));
        assert_eq!(state.bytes, 100);
    }

    fn cache_entry(stored_at: Instant, expires_at: Instant, weight: u64) -> NativeMemoryCacheEntry {
        NativeMemoryCacheEntry {
            status: 200,
            reason: "OK".to_owned(),
            headers: Vec::new(),
            content_length: Some(1),
            body: Arc::from(*b"x"),
            body_sha256: Arc::new(crate::native_http1_cache::native_cache_body_sha256(b"x")),
            expires_at,
            stale_while_revalidate_until: None,
            stale_if_error_until: None,
            stored_at,
            weight,
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_static_body_file_rejects_symlink_swapped_after_resolution() {
        let root = TempDir::new().unwrap();
        let asset = root.path().join("asset.txt");
        let outside = root.path().join("outside.txt");
        std::fs::write(&asset, b"safe").unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let file = NativeStaticFile {
            root: root_path.clone(),
            path: root_path.join("asset.txt"),
            mime: "text/plain; charset=utf-8",
            len: 4,
            modified: Some(SystemTime::UNIX_EPOCH),
            device: 0,
            inode: 0,
        };

        std::fs::remove_file(&asset).unwrap();
        std::os::unix::fs::symlink(&outside, &asset).unwrap();

        assert!(open_static_body_file(&file).is_err());
        root.close().unwrap();
    }
}
