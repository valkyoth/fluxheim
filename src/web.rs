#[cfg(feature = "proxy")]
use std::fs::OpenOptions;
use std::io;
#[cfg(feature = "proxy")]
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use percent_encoding::percent_decode_str;

use crate::config::WebConfig;
#[cfg(feature = "proxy")]
use fluxheim_common::{FluxError, FluxResult};
use fluxheim_web::SafeRelativePath;
#[cfg(feature = "proxy")]
use fluxheim_web::StaticCacheIdentity;
use fluxheim_web::StaticResponseConditions;
pub use fluxheim_web::{
    ByteRangeParse, DirectoryEntry, DirectoryListing, StaticResponseBody, StaticResponseFile,
    StaticResponsePlan, configured_web_path_contains_symlink, directory_listing_path,
    parse_single_byte_range, render_directory_listing,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(all(feature = "proxy", unix))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(all(feature = "proxy", any(target_os = "linux", target_os = "android")))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(all(
    feature = "proxy",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    feature = "proxy",
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe file opening before building Fluxheim"
);

#[cfg(feature = "proxy")]
pub const MAX_STATIC_BUFFERED_BODY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StaticFileServer {
    root: PathBuf,
    index_files: Vec<String>,
    deny_dotfiles: bool,
    directory_listing: crate::config::DirectoryListingConfig,
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

        let root_metadata = match std::fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("web root does not exist: {}", root.display()),
                ));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("web root {}: {error}", root.display()),
                ));
            }
        };
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
            directory_listing: config.directory_listing.clone(),
            cache_control: config.cache_control.clone(),
            expires: config.expires.clone(),
        }))
    }

    pub fn resolve(&self, request_path: &str) -> io::Result<ResolveResult> {
        let Some(relative_path) = self.relative_request_path(request_path)? else {
            return Ok(ResolveResult::Forbidden);
        };

        self.resolve_relative_candidate(&relative_path)
    }

    #[cfg_attr(not(all(feature = "web", feature = "proxy")), allow(dead_code))]
    pub(crate) fn cache_control(&self) -> &str {
        &self.cache_control
    }

    #[cfg_attr(not(all(feature = "web", feature = "proxy")), allow(dead_code))]
    pub(crate) fn expires(&self) -> Option<&str> {
        self.expires.as_deref()
    }

    #[cfg(feature = "proxy")]
    pub fn resolve_rooted_file(&self, path: &Path) -> io::Result<ResolveResult> {
        if !path.is_absolute() {
            return Ok(ResolveResult::Forbidden);
        }
        let Some(relative_path) = SafeRelativePath::from_rooted(&self.root, path) else {
            return Ok(ResolveResult::Forbidden);
        };
        if self.deny_dotfiles && relative_path.contains_component_starting_with('.') {
            return Ok(ResolveResult::Forbidden);
        }

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

    fn resolve_relative_candidate(&self, relative: &SafeRelativePath) -> io::Result<ResolveResult> {
        let candidate = self.root.join(relative.as_path());
        let canonical = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ResolveResult::NotFound);
            }
            Err(error) => return Err(error),
        };

        if !canonical.starts_with(&self.root) || canonical != candidate {
            return Ok(ResolveResult::NotFound);
        }

        let candidate_metadata = match canonical.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ResolveResult::NotFound);
            }
            Err(error) => return Err(error),
        };

        if candidate_metadata.is_dir() {
            for index in &self.index_files {
                let index_candidate = canonical.join(index);
                if let Some(file) = self.static_file(&index_candidate)? {
                    return Ok(ResolveResult::Found(file));
                }
            }

            if self.directory_listing.enabled {
                return self.directory_listing(&canonical);
            }

            return Ok(ResolveResult::NotFound);
        }

        match self.static_file(&candidate)? {
            Some(file) => Ok(ResolveResult::Found(file)),
            None => Ok(ResolveResult::NotFound),
        }
    }

    fn static_file(&self, candidate: &Path) -> io::Result<Option<StaticFile>> {
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

        let metadata = canonical.metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }

        let mime = mime_guess::from_path(&canonical)
            .first_or_octet_stream()
            .essence_str()
            .to_owned();

        Ok(Some(StaticFile {
            root: self.root.clone(),
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

    fn directory_listing(&self, directory: &Path) -> io::Result<ResolveResult> {
        let Some(relative) = SafeRelativePath::from_rooted(&self.root, directory) else {
            return Ok(ResolveResult::NotFound);
        };
        if directory != self.root.join(relative.as_path()) {
            return Ok(ResolveResult::NotFound);
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
        Ok(ResolveResult::DirectoryListing(DirectoryListing {
            path,
            entries,
            local_time: self.directory_listing.local_time,
        }))
    }
}

const MAX_DIRECTORY_LISTING_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolveResult {
    Found(StaticFile),
    DirectoryListing(DirectoryListing),
    NotFound,
    Forbidden,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StaticFile {
    root: PathBuf,
    pub path: PathBuf,
    pub mime: String,
    pub len: u64,
    pub modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl StaticFile {
    #[cfg(feature = "proxy")]
    pub fn cache_identity(&self) -> String {
        #[cfg(unix)]
        let device_inode = Some((self.device, self.inode));
        #[cfg(not(unix))]
        let device_inode = None;

        fluxheim_web::static_cache_identity(StaticCacheIdentity {
            path: &self.path,
            len: self.len,
            modified: self.modified,
            device_inode,
        })
    }
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
    fluxheim_web::plan_static_response(
        StaticResponseFile {
            len: file.len,
            modified: file.modified,
        },
        method,
        StaticResponseConditions {
            if_match: conditions.if_match,
            if_unmodified_since: conditions.if_unmodified_since,
            if_none_match: conditions.if_none_match,
            if_modified_since: conditions.if_modified_since,
            cache_refresh_forced: fluxheim_cache::headers::request_forces_cache_refresh(
                conditions.cache_control,
                conditions.pragma,
            ),
            range: conditions.range,
            if_range: conditions.if_range,
        },
    )
}

#[cfg(feature = "proxy")]
pub(crate) fn read_static_response_body(
    file: &StaticFile,
    body: StaticResponseBody,
) -> FluxResult<bytes::Bytes> {
    match body {
        StaticResponseBody::None => Ok(bytes::Bytes::new()),
        StaticResponseBody::Full => {
            if file.len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(FluxError::io(
                    "static file exceeds buffered response limit",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "static file exceeds buffered response limit",
                    ),
                ));
            }
            let mut reader = open_static_body_file(file)?;
            let capacity = usize::try_from(file.len).map_err(|_| {
                FluxError::io(
                    "static file too large",
                    io::Error::new(io::ErrorKind::InvalidInput, "static file too large"),
                )
            })?;
            let mut body = Vec::with_capacity(capacity);
            let mut bounded_reader = reader.by_ref().take(file.len.saturating_add(1));
            bounded_reader
                .read_to_end(&mut body)
                .map_err(|error| FluxError::io("read static file body", error))?;
            if body.len() as u64 != file.len {
                return Err(FluxError::io(
                    "static file changed during body read",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "static file changed during body read",
                    ),
                ));
            }
            Ok(bytes::Bytes::from(body))
        }
        StaticResponseBody::Range { start, len } => {
            if len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(FluxError::io(
                    "static range exceeds buffered response limit",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "static range exceeds buffered response limit",
                    ),
                ));
            }
            let len = usize::try_from(len).map_err(|_| {
                FluxError::io(
                    "static range too large",
                    io::Error::new(io::ErrorKind::InvalidInput, "static range too large"),
                )
            })?;
            let mut reader = open_static_body_file(file)?;
            reader
                .seek(io::SeekFrom::Start(start))
                .map_err(|error| FluxError::io("seek static file body", error))?;
            let mut body = vec![0; len];
            reader
                .read_exact(&mut body)
                .map_err(|error| FluxError::io("read static range body", error))?;
            Ok(bytes::Bytes::from(body))
        }
    }
}

#[cfg(feature = "proxy")]
fn open_static_body_file(file: &StaticFile) -> FluxResult<std::fs::File> {
    let relative = SafeRelativePath::from_rooted(&file.root, &file.path).ok_or_else(|| {
        FluxError::io(
            "static body path escaped web root",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path escaped web root",
            ),
        )
    })?;
    if file.path != file.root.join(relative.as_path()) {
        return Err(FluxError::io(
            "static body path contains a symlink",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path contains a symlink",
            ),
        ));
    }

    let canonical = file
        .path
        .canonicalize()
        .map_err(|error| FluxError::io("canonicalize static body path", error))?;
    if !canonical.starts_with(&file.root) {
        return Err(FluxError::io(
            "static body path escaped web root",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path escaped web root",
            ),
        ));
    }

    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|error| FluxError::io("stat static body path", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FluxError::io(
            "static body path is not a regular file",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path is not a regular file",
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);

    let file_handle = options
        .open(&canonical)
        .map_err(|error| FluxError::io("open static body file", error))?;
    let metadata = file_handle
        .metadata()
        .map_err(|error| FluxError::io("stat static body handle", error))?;
    if !metadata.is_file() {
        return Err(FluxError::io(
            "static body handle is not a regular file",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body handle is not a regular file",
            ),
        ));
    }
    #[cfg(unix)]
    if metadata.dev() != file.device || metadata.ino() != file.inode {
        return Err(FluxError::io(
            "static file identity changed before body read",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "static file identity changed before body read",
            ),
        ));
    }
    if metadata.len() != file.len {
        return Err(FluxError::io(
            "static file changed before body read",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "static file changed before body read",
            ),
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
    use fluxheim_common::test_support::{safe_child_path, safe_relative_path, unique_temp_path};

    use super::{
        ByteRangeParse, ResolveResult, StaticFile, StaticFileServer, StaticRequestConditions,
        StaticResponseBody, parse_single_byte_range, plan_static_response,
    };

    #[test]
    fn resolves_index_file() {
        let root = TestDir::new("index");
        fs::write(root.child("index.html"), "<h1>ok</h1>").unwrap();

        let server = server(root.path());
        let resolved = server.resolve("/").unwrap();

        assert!(matches!(resolved, ResolveResult::Found(file) if file.mime == "text/html"));
    }

    #[test]
    fn rejects_traversal() {
        let root = TestDir::new("traversal");
        fs::write(root.child("index.html"), "ok").unwrap();

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
        fs::write(root.child(".env"), "secret").unwrap();

        let server = server(root.path());

        assert_eq!(server.resolve("/.env").unwrap(), ResolveResult::Forbidden);
    }

    #[test]
    fn directory_listing_is_disabled_by_default() {
        let root = TestDir::new("directory-listing-disabled");
        fs::write(root.child("asset.txt"), "ok").unwrap();

        let server = server(root.path());

        assert_eq!(server.resolve("/").unwrap(), ResolveResult::NotFound);
    }

    #[test]
    fn resolves_directory_listing_when_enabled() {
        let root = TestDir::new("directory-listing");
        fs::write(root.child("alpha.txt"), "hello").unwrap();
        fs::write(root.child(".secret"), "hidden").unwrap();
        fs::create_dir_all(root.child("nested")).unwrap();

        let server = StaticFileServer::from_config(&WebConfig {
            root: Some(root.path().to_owned()),
            directory_listing: crate::config::DirectoryListingConfig {
                enabled: true,
                exact_size: true,
                local_time: false,
            },
            ..WebConfig::default()
        })
        .unwrap()
        .unwrap();

        let ResolveResult::DirectoryListing(listing) = server.resolve("/").unwrap() else {
            panic!("expected directory listing")
        };

        assert_eq!(listing.path, "/");
        assert!(!listing.local_time);
        assert_eq!(
            listing
                .entries
                .iter()
                .map(|entry| (entry.name.as_str(), entry.is_dir, entry.size))
                .collect::<Vec<_>>(),
            vec![("nested", true, None), ("alpha.txt", false, Some(5))]
        );
    }

    #[test]
    fn renders_escaped_directory_listing() {
        let listing = super::DirectoryListing {
            path: "/repo/<root>/".to_owned(),
            entries: vec![super::DirectoryEntry {
                name: "a&b.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: None,
            }],
            local_time: false,
        };

        let html = super::render_directory_listing(&listing);

        assert!(html.contains("Index of /repo/&lt;root&gt;/"));
        assert!(html.contains("a&amp;b.txt"));
    }

    #[test]
    fn directory_listing_local_time_uses_local_timestamp_shape() {
        let listing = super::DirectoryListing {
            path: "/".to_owned(),
            entries: vec![super::DirectoryEntry {
                name: "asset.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            }],
            local_time: true,
        };

        let html = super::render_directory_listing(&listing);

        assert!(
            html.contains("2023-11-14") || html.contains("2023-11-15"),
            "{html}"
        );
        assert!(!html.contains("GMT"));
    }

    #[test]
    fn stores_configured_static_cache_headers() {
        let root = TestDir::new("static-cache-headers");
        fs::write(root.child("index.html"), "ok").unwrap();

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

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_static_root() {
        let target = TestDir::new("root-symlink-target");
        let root = unique_temp_path("web-root-symlink");
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

    #[test]
    fn rejects_missing_static_root() {
        let root = unique_temp_path("web-root-missing");

        let error = StaticFileServer::from_config(&WebConfig {
            root: Some(root.clone()),
            index_files: vec!["index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("web root does not exist"));
        assert!(error.to_string().contains(&root.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_static_root_below_symlinked_directory() {
        let dir = TestDir::new("root-parent-symlink");
        let real = dir.child("real");
        let linked = dir.child("linked");
        fs::create_dir_all(safe_child_path(&real, "public")).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();

        let error = StaticFileServer::from_config(&WebConfig {
            root: Some(safe_child_path(&linked, "public")),
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
            fs::write(outside.child("secret.txt"), "secret").unwrap();
            std::os::unix::fs::symlink(outside.child("secret.txt"), root.child("link")).unwrap();

            let server = server(root.path());

            assert_eq!(server.resolve("/link").unwrap(), ResolveResult::NotFound);
        }
    }

    #[test]
    fn rejects_static_symlinks_inside_root() {
        #[cfg(unix)]
        {
            let root = TestDir::new("inside-symlink");
            let real = root.child("real");
            fs::create_dir_all(&real).unwrap();
            fs::write(safe_child_path(&real, "asset.txt"), "ok").unwrap();
            std::os::unix::fs::symlink(
                safe_child_path(&real, "asset.txt"),
                root.child("asset-link.txt"),
            )
            .unwrap();
            std::os::unix::fs::symlink(&real, root.child("dir-link")).unwrap();

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

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = unique_temp_path(label);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn child(&self, name: &str) -> PathBuf {
            safe_relative_path(&self.path, name)
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
            root: PathBuf::from("target"),
            path: PathBuf::from("target/fluxheim-static-test"),
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
