use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use fluxheim_config::{DirectoryListingConfig, WebConfig};
use fluxheim_web::{
    DirectoryEntry, DirectoryListing, SafeRelativePath, StaticResponseBody,
    StaticResponseConditions, StaticResponseFile, configured_web_path_contains_symlink,
    directory_listing_path, plan_static_response, render_directory_listing,
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
}

impl NativeHttp1StaticWeb {
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
        }))
    }

    pub fn handle(&self, request: &NativeHttp1Request, request_path: &str) -> NativeHttp1Response {
        match self.resolve(request_path) {
            Ok(NativeStaticResolve::Found(file)) => self.file_response(request, &file),
            Ok(NativeStaticResolve::DirectoryListing(listing)) => {
                directory_listing_response(request, &listing)
            }
            Ok(NativeStaticResolve::NotFound) => {
                NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection()
            }
            Ok(NativeStaticResolve::Forbidden) => {
                NativeHttp1Response::new(403, "Forbidden", b"forbidden\n").close_connection()
            }
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "static web response failed: {error}");
                NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                    .close_connection()
            }
        }
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

        Ok(Some(NativeStaticFile {
            root: self.root.clone(),
            path: canonical.clone(),
            mime: content_type_for_path(&canonical),
            len: metadata.len(),
            modified: metadata.modified().ok(),
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
        let plan = plan_static_response(
            StaticResponseFile {
                len: file.len,
                modified: file.modified,
            },
            &request.method,
            static_conditions(request),
        );
        if plan.response_body_bytes > MAX_NATIVE_STATIC_BODY_BYTES {
            return NativeHttp1Response::new(
                413,
                "Payload Too Large",
                b"static response too large\n",
            )
            .close_connection();
        }

        let body = match read_static_body(file, plan.body) {
            Ok(body) => body,
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "static file read failed: {error}");
                return NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                    .close_connection();
            }
        };

        let mut response = NativeHttp1Response::new(plan.status, static_reason(plan.status), body)
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
        response
    }
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
    let metadata = std::fs::symlink_metadata(&canonical)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static body path is not a regular file",
        ));
    }
    File::open(canonical)
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

fn static_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        304 => "Not Modified",
        412 => "Precondition Failed",
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
