use std::io;
use std::path::Path;

use fluxheim_web::{DirectoryEntry, SafeRelativePath, directory_listing_path};
use percent_encoding::percent_decode_str;

use super::{
    MAX_DIRECTORY_LISTING_ENTRIES, NativeHttp1StaticWeb, NativeStaticFile, NativeStaticResolve,
};

impl NativeHttp1StaticWeb {
    pub(super) fn resolve(&self, request_path: &str) -> io::Result<NativeStaticResolve> {
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
        Ok(NativeStaticResolve::DirectoryListing(
            fluxheim_web::DirectoryListing {
                path,
                entries,
                local_time: self.directory_listing.local_time,
            },
        ))
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
