use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use percent_encoding::percent_decode_str;

use crate::config::WebConfig;

#[derive(Debug, Clone)]
pub struct StaticFileServer {
    root: PathBuf,
    index_files: Vec<String>,
    deny_dotfiles: bool,
}

impl StaticFileServer {
    pub fn from_config(config: &WebConfig) -> io::Result<Option<Self>> {
        let Some(root) = &config.root else {
            return Ok(None);
        };

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
        if candidate.is_dir() {
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
        }))
    }
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
}

#[cfg(all(feature = "web", feature = "proxy"))]
pub async fn serve_static_file(
    session: &mut pingora::proxy::Session,
    file: &StaticFile,
    send_body: bool,
) -> pingora::Result<()> {
    use pingora::prelude::{InternalError, OrErr};

    let mut response = pingora::http::ResponseHeader::build(200, Some(6))?;
    response.insert_header("content-type", file.mime.as_str())?;
    response.insert_header("content-length", file.len)?;
    response.insert_header("cache-control", "public, max-age=60")?;
    response.insert_header("x-content-type-options", "nosniff")?;

    if let Some(modified) = file.modified {
        response.insert_header("last-modified", httpdate::fmt_http_date(modified))?;
    }

    if send_body {
        session
            .write_response_header(Box::new(response), false)
            .await?;
        let body = std::fs::read(&file.path).or_err(InternalError, "failed to read static file")?;
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
    } else {
        session
            .write_response_header(Box::new(response), true)
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::WebConfig;

    use super::{ResolveResult, StaticFileServer};

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
        })
        .unwrap()
        .unwrap()
    }
}
