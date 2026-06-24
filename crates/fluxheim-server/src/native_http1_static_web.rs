use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use fluxheim_cache::{
    CacheRequestView, StaticCacheRequest, request_cache_bypass_reason,
    request_cache_revalidation_requested, response_cache_admission_rejection,
    response_cache_control_max_age, static_cache_key,
};
use fluxheim_config::{CacheConfig, DirectoryListingConfig, WebConfig};
use fluxheim_web::{
    DirectoryEntry, DirectoryListing, SafeRelativePath, StaticCacheIdentity, StaticResponseBody,
    StaticResponseConditions, StaticResponseFile, configured_web_path_contains_symlink,
    directory_listing_path, plan_static_response, render_directory_listing, static_cache_identity,
};
use percent_encoding::percent_decode_str;

use crate::{NativeHttp1Request, NativeHttp1Response};

const MAX_DIRECTORY_LISTING_ENTRIES: usize = 4096;
const MAX_NATIVE_STATIC_BODY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1StaticWeb {
    root: PathBuf,
    index_files: Vec<String>,
    deny_dotfiles: bool,
    directory_listing: DirectoryListingConfig,
    cache_control: String,
    expires: Option<String>,
    cache: Option<NativeStaticMemoryCache>,
}

#[derive(Clone, Debug)]
struct NativeStaticMemoryCache {
    config: CacheConfig,
    max_bytes: u64,
    state: Arc<Mutex<NativeStaticMemoryCacheState>>,
}

impl Eq for NativeStaticMemoryCache {}

impl PartialEq for NativeStaticMemoryCache {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.max_bytes == other.max_bytes
    }
}

#[derive(Debug, Default)]
struct NativeStaticMemoryCacheState {
    objects: HashMap<String, NativeStaticCacheEntry>,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeStaticCacheEntry {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    content_length: Option<u64>,
    body: Arc<[u8]>,
    expires_at: Instant,
    stored_at: Instant,
    weight: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeStaticResolve {
    Found(NativeStaticFile),
    DirectoryListing(DirectoryListing),
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeStaticFile {
    root: PathBuf,
    path: PathBuf,
    mime: &'static str,
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl NativeHttp1StaticWeb {
    pub fn from_config(config: &WebConfig) -> io::Result<Option<Self>> {
        Self::from_config_with_cache(config, None)
    }

    pub fn from_config_with_cache(
        config: &WebConfig,
        cache: Option<&CacheConfig>,
    ) -> io::Result<Option<Self>> {
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

        let root_metadata = std::fs::symlink_metadata(root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("web root {}: {error}", root.display()),
            )
        })?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("web root is not a real directory: {}", root.display()),
            ));
        }

        let root = root.canonicalize().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("web root {}: {error}", root.display()),
            )
        })?;

        Ok(Some(Self {
            root,
            index_files: config.index_files.clone(),
            deny_dotfiles: config.deny_dotfiles,
            directory_listing: config.directory_listing.clone(),
            cache_control: config.cache_control.clone(),
            expires: config.expires.clone(),
            cache: cache.and_then(NativeStaticMemoryCache::from_config),
        }))
    }

    pub fn cache_supported(cache: &CacheConfig) -> bool {
        cache.enabled && cache.local_static && cache.memory.enabled && !cache.disk.enabled
    }

    pub fn handle(&self, request: &NativeHttp1Request, request_path: &str) -> NativeHttp1Response {
        if !static_web_method_allowed(&request.method) {
            return NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
                .with_header("allow", "GET, HEAD")
                .close_connection();
        }
        self.handle_static_request(request, request_path)
            .unwrap_or_else(|| {
                NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection()
            })
    }

    pub fn handle_optional(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
    ) -> Option<NativeHttp1Response> {
        if !static_web_method_allowed(&request.method) {
            return None;
        }
        self.handle_static_request(request, request_path)
    }

    fn handle_static_request(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
    ) -> Option<NativeHttp1Response> {
        match self.resolve(request_path) {
            Ok(NativeStaticResolve::Found(file)) => Some(self.cached_file_response(request, &file)),
            Ok(NativeStaticResolve::DirectoryListing(listing)) => {
                Some(directory_listing_response(request, &listing))
            }
            Ok(NativeStaticResolve::NotFound) => None,
            Ok(NativeStaticResolve::Forbidden) => {
                Some(NativeHttp1Response::new(403, "Forbidden", b"forbidden\n").close_connection())
            }
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "static web response failed: {error}");
                Some(
                    NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                        .close_connection(),
                )
            }
        }
    }

    pub fn handle_error_page(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        let file = match self.resolve(request_path) {
            Ok(NativeStaticResolve::Found(file)) => file,
            Ok(
                NativeStaticResolve::DirectoryListing(_)
                | NativeStaticResolve::NotFound
                | NativeStaticResolve::Forbidden,
            ) => return None,
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "static error page response failed: {error}"
                );
                return None;
            }
        };
        let plan = plan_static_response(
            StaticResponseFile {
                len: file.len,
                modified: file.modified,
            },
            &request.method,
            StaticResponseConditions::default(),
        );
        if plan.response_body_bytes > MAX_NATIVE_STATIC_BODY_BYTES {
            return None;
        }
        self.file_response_with_status(
            request,
            &file,
            StaticResponseConditions::default(),
            Some(status),
        )
    }

    fn resolve(&self, request_path: &str) -> io::Result<NativeStaticResolve> {
        let Some(relative_path) = self.relative_request_path(request_path)? else {
            return Ok(NativeStaticResolve::Forbidden);
        };
        self.resolve_relative_candidate(&relative_path)
    }

    fn relative_request_path(&self, request_path: &str) -> io::Result<Option<SafeRelativePath>> {
        if !request_path.starts_with('/') {
            return Ok(None);
        }

        let decoded = percent_decode_str(request_path)
            .decode_utf8()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if decoded.contains('\0') {
            return Ok(None);
        }

        let mut relative = SafeRelativePath::default();
        for segment in decoded.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".."
                || segment.contains('%')
                || segment.contains('\\')
                || (self.deny_dotfiles && segment.starts_with('.'))
            {
                return Ok(None);
            }
            relative.push(segment);
        }

        Ok(Some(relative))
    }

    fn resolve_relative_candidate(
        &self,
        relative: &SafeRelativePath,
    ) -> io::Result<NativeStaticResolve> {
        let candidate = self.root.join(relative.as_path());
        let canonical = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeStaticResolve::NotFound);
            }
            Err(error) => return Err(error),
        };

        if !canonical.starts_with(&self.root) || canonical != candidate {
            return Ok(NativeStaticResolve::NotFound);
        }

        let metadata = match canonical.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeStaticResolve::NotFound);
            }
            Err(error) => return Err(error),
        };

        if metadata.is_dir() {
            for index in &self.index_files {
                if let Some(file) = self.static_file(&canonical.join(index))? {
                    return Ok(NativeStaticResolve::Found(file));
                }
            }
            if self.directory_listing.enabled {
                return self.directory_listing(&canonical);
            }
            return Ok(NativeStaticResolve::NotFound);
        }

        Ok(match self.static_file(&candidate)? {
            Some(file) => NativeStaticResolve::Found(file),
            None => NativeStaticResolve::NotFound,
        })
    }

    fn static_file(&self, candidate: &Path) -> io::Result<Option<NativeStaticFile>> {
        let Some(relative) = SafeRelativePath::from_rooted(&self.root, candidate) else {
            return Ok(None);
        };
        let expected = self.root.join(relative.as_path());
        let canonical = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !canonical.starts_with(&self.root) || canonical != expected {
            return Ok(None);
        }

        let metadata = std::fs::symlink_metadata(&canonical)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(None);
        }
        #[cfg(unix)]
        let (device, inode) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };

        Ok(Some(NativeStaticFile {
            root: self.root.clone(),
            path: canonical.clone(),
            mime: content_type_for_path(&canonical),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device,
            #[cfg(unix)]
            inode,
        }))
    }

    fn directory_listing(&self, directory: &Path) -> io::Result<NativeStaticResolve> {
        let Some(relative) = SafeRelativePath::from_rooted(&self.root, directory) else {
            return Ok(NativeStaticResolve::NotFound);
        };
        if directory != self.root.join(relative.as_path()) {
            return Ok(NativeStaticResolve::NotFound);
        }

        let mut entries = Vec::new();
        for entry in std::fs::read_dir(directory)?.take(MAX_DIRECTORY_LISTING_ENTRIES + 1) {
            let entry = entry?;
            if entries.len() >= MAX_DIRECTORY_LISTING_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory listing entry limit exceeded",
                ));
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if self.deny_dotfiles && name.starts_with('.') {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                continue;
            }
            let metadata = entry.metadata()?;
            entries.push(DirectoryEntry {
                name: name.to_owned(),
                is_dir: file_type.is_dir(),
                size: file_type
                    .is_file()
                    .then_some(metadata.len())
                    .filter(|_| self.directory_listing.exact_size),
                modified: metadata.modified().ok(),
            });
        }
        entries.sort_by(|left, right| {
            right
                .is_dir
                .cmp(&left.is_dir)
                .then_with(|| left.name.cmp(&right.name))
        });
        let path = directory
            .strip_prefix(&self.root)
            .ok()
            .map(directory_listing_path)
            .unwrap_or_else(|| "/".to_owned());
        Ok(NativeStaticResolve::DirectoryListing(DirectoryListing {
            path,
            entries,
            local_time: self.directory_listing.local_time,
        }))
    }

    fn file_response(
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

    fn cached_file_response(
        &self,
        request: &NativeHttp1Request,
        file: &NativeStaticFile,
    ) -> NativeHttp1Response {
        let Some(cache) = &self.cache else {
            return self.file_response(request, file);
        };
        let Some(key) = cache.static_key(request, file) else {
            return self.file_response(request, file).with_static_cache_status(
                &cache.config,
                "BYPASS",
                Some("static-ineligible"),
                None,
            );
        };
        if let Some(reason) = request_cache_bypass_reason(request, &cache.config) {
            return self.file_response(request, file).with_static_cache_status(
                &cache.config,
                "BYPASS",
                Some(reason),
                None,
            );
        }
        if !request_cache_revalidation_requested(request, &cache.config)
            && let Some(hit) = cache.get(&key)
        {
            return hit.to_response().with_static_cache_status(
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
            Ok(()) => response.with_static_cache_status(&cache.config, cache_status, None, None),
            Err(reason) => {
                response.with_static_cache_status(&cache.config, "BYPASS", Some(reason), None)
            }
        }
    }

    fn file_response_with_status(
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

impl NativeStaticMemoryCache {
    fn from_config(config: &CacheConfig) -> Option<Self> {
        NativeHttp1StaticWeb::cache_supported(config).then(|| Self {
            config: config.clone(),
            max_bytes: config.memory.max_size_bytes.as_u64(),
            state: Arc::new(Mutex::new(NativeStaticMemoryCacheState::default())),
        })
    }

    fn static_key(&self, request: &NativeHttp1Request, file: &NativeStaticFile) -> Option<String> {
        let host = request_header(request, "host");
        static_cache_key(
            &self.config,
            &StaticCacheRequest {
                method: request.method(),
                host,
                path: request.path(),
                query: request.query(),
                file_identity: &file.cache_identity(),
            },
        )
        .map(|key| key.as_str().to_owned())
    }

    fn get(&self, key: &str) -> Option<NativeStaticCacheEntry> {
        let now = Instant::now();
        let mut state = lock_static_cache(&self.state);
        match state.objects.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.clone()),
            Some(entry) => {
                let weight = entry.weight;
                state.objects.remove(key);
                state.bytes = state.bytes.saturating_sub(weight);
                None
            }
            None => None,
        }
    }

    fn store(&self, key: &str, response: &NativeHttp1Response) -> Result<(), &'static str> {
        if response.status() != 200 {
            return Err("status-not-cacheable");
        }
        let body_len = response.body().len() as u64;
        if body_len == 0 {
            return Err("empty-body");
        }
        if body_len > self.config.max_object_bytes.as_u64() || body_len > self.max_bytes {
            return Err("object-too-large");
        }
        let headers = native_response_header_map(response);
        if let Some(reason) =
            response_cache_admission_rejection(response.status(), &headers, &self.config)
        {
            return Err(reason);
        }
        let Some(ttl) = static_cache_ttl(response.status(), &headers, &self.config) else {
            return Err("ttl-missing");
        };
        if ttl.is_zero() {
            return Err("ttl-zero");
        }

        let weight = static_cache_entry_weight(key, response, body_len);
        if weight > self.max_bytes {
            return Err("object-too-large");
        }
        let body: Arc<[u8]> = Arc::from(response.body().to_vec());
        let key = key.to_owned();
        let now = Instant::now();
        let entry = NativeStaticCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: response.headers().to_vec(),
            content_length: response.content_length(),
            body,
            expires_at: now + ttl,
            stored_at: now,
            weight,
        };
        let needs_prune = {
            let mut state = lock_static_cache(&self.state);
            if let Some(previous) = state.objects.remove(&key) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.bytes = state.bytes.saturating_add(weight);
            state.objects.insert(key, entry);
            state.bytes > self.max_bytes
        };
        if needs_prune {
            let mut state = lock_static_cache(&self.state);
            prune_static_cache(&mut state, self.max_bytes);
        }
        Ok(())
    }
}

impl NativeStaticCacheEntry {
    fn to_response(&self) -> NativeHttp1Response {
        let mut response =
            NativeHttp1Response::new(self.status, self.reason.clone(), self.body.to_vec());
        for (name, value) in &self.headers {
            response = response.with_header(name.clone(), value.clone());
        }
        if let Some(content_length) = self.content_length {
            response = response.with_content_length(content_length);
        }
        response
    }

    fn age_secs(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.stored_at)
            .as_secs()
    }
}

impl NativeStaticFile {
    fn cache_identity(&self) -> String {
        static_cache_identity(StaticCacheIdentity {
            path: &self.path,
            len: self.len,
            modified: self.modified,
            #[cfg(unix)]
            device_inode: Some((self.device, self.inode)),
            #[cfg(not(unix))]
            device_inode: None,
        })
    }
}

impl NativeHttp1Response {
    fn with_static_cache_status(
        mut self,
        cache: &CacheConfig,
        status: &str,
        reason: Option<&str>,
        age_secs: Option<u64>,
    ) -> Self {
        if let Some(header) = &cache.status_header {
            self.push_header(header.clone(), status.to_owned());
        }
        if let (Some(header), Some(reason)) = (&cache.status_reason_header, reason) {
            self.push_header(header.clone(), reason.to_owned());
        }
        if let Some(age_secs) = age_secs {
            self.push_header("age", age_secs.to_string());
        }
        self
    }
}

fn lock_static_cache(
    state: &Mutex<NativeStaticMemoryCacheState>,
) -> std::sync::MutexGuard<'_, NativeStaticMemoryCacheState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "static web memory cache mutex poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

fn static_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

fn static_cache_entry_weight(key: &str, response: &NativeHttp1Response, body_len: u64) -> u64 {
    const ENTRY_OVERHEAD: u64 = 256;

    response.headers().iter().fold(
        body_len
            .saturating_add(ENTRY_OVERHEAD)
            .saturating_add(key.len() as u64)
            .saturating_add(response.reason().len() as u64),
        |weight, (name, value)| {
            weight
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(4)
        },
    )
}

fn prune_static_cache(state: &mut NativeStaticMemoryCacheState, max_bytes: u64) {
    let now = Instant::now();
    let mut expired_bytes = 0_u64;
    state.objects.retain(|_, entry| {
        let keep = entry.expires_at > now;
        if !keep {
            expired_bytes = expired_bytes.saturating_add(entry.weight);
        }
        keep
    });
    state.bytes = state.bytes.saturating_sub(expired_bytes);

    if state.bytes > max_bytes {
        let mut by_age = state
            .objects
            .iter()
            .map(|(key, entry)| (entry.stored_at, key.clone()))
            .collect::<Vec<_>>();
        by_age.sort_unstable_by_key(|(stored_at, _)| *stored_at);
        for (_, key) in by_age {
            if state.bytes <= max_bytes {
                break;
            }
            if let Some(entry) = state.objects.remove(&key) {
                state.bytes = state.bytes.saturating_sub(entry.weight);
            }
        }
        if state.objects.is_empty() && state.bytes > max_bytes {
            state.bytes = 0;
        } else {
            let actual_bytes = state
                .objects
                .values()
                .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
            state.bytes = state.bytes.min(actual_bytes);
        }
    }
}

fn native_response_header_map(response: &NativeHttp1Response) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in response.headers() {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(content_length) = response.content_length()
        && let Ok(value) = http::HeaderValue::from_str(&content_length.to_string())
    {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
    headers
}

fn static_conditions(request: &NativeHttp1Request) -> StaticResponseConditions<'_> {
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

fn request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
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

fn directory_listing_response(
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

fn static_web_method_allowed(method: &str) -> bool {
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

fn content_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "css" => "text/css; charset=utf-8",
        "gif" => "image/gif",
        "html" | "htm" => "text/html; charset=utf-8",
        "ico" => "image/x-icon",
        "jpg" | "jpeg" => "image/jpeg",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use tempfile::TempDir;

    use super::{
        NativeStaticCacheEntry, NativeStaticFile, NativeStaticMemoryCacheState,
        open_static_body_file, prune_static_cache, static_cache_entry_weight,
    };
    use crate::NativeHttp1Response;

    #[test]
    fn static_cache_entry_weight_includes_entry_overhead() {
        let response = NativeHttp1Response::new(200, "OK", b"hello")
            .with_header("cache-control", "max-age=60");
        let raw_bytes = 5_u64 + "cache-control".len() as u64 + "max-age=60".len() as u64 + 4;

        let weight = static_cache_entry_weight("cache-key", &response, 5);

        assert!(weight >= raw_bytes + 256 + "cache-key".len() as u64 + "OK".len() as u64);
    }

    #[test]
    fn prune_static_cache_removes_expired_and_oldest_entries() {
        let now = Instant::now();
        let mut state = NativeStaticMemoryCacheState::default();
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

        prune_static_cache(&mut state, 150);

        assert!(!state.objects.contains_key("expired"));
        assert!(!state.objects.contains_key("old"));
        assert!(state.objects.contains_key("new"));
        assert_eq!(state.bytes, 100);
    }

    fn cache_entry(stored_at: Instant, expires_at: Instant, weight: u64) -> NativeStaticCacheEntry {
        NativeStaticCacheEntry {
            status: 200,
            reason: "OK".to_owned(),
            headers: Vec::new(),
            content_length: Some(1),
            body: Arc::from([b'x']),
            expires_at,
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
