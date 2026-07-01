use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use percent_encoding::percent_decode_str;

use crate::config::WebConfig;
use fluxheim_web::SafeRelativePath;
#[cfg(feature = "proxy")]
use fluxheim_web::StaticCacheIdentity;
use fluxheim_web::StaticResponseConditions;
pub use fluxheim_web::{
    ByteRangeParse, DirectoryEntry, DirectoryListing, StaticResponseBody, StaticResponseFile,
    StaticResponsePlan, configured_web_path_contains_symlink, directory_listing_path,
    parse_single_byte_range, render_directory_listing,
};

#[cfg(feature = "proxy")]
mod body_reader;
#[cfg(feature = "proxy")]
pub use body_reader::MAX_STATIC_BUFFERED_BODY_BYTES;
#[cfg(feature = "proxy")]
pub(crate) use body_reader::read_static_response_body;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

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

#[cfg(test)]
mod tests_resolution;
#[cfg(test)]
mod tests_response;
#[cfg(test)]
mod tests_support;
