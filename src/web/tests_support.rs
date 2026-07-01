use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use fluxheim_common::test_support::{safe_relative_path, unique_temp_path};

use super::{StaticFile, StaticFileServer};
use crate::config::WebConfig;

pub(super) struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub(super) fn new(label: &str) -> Self {
        let path = unique_temp_path(label);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn child(&self, name: &str) -> PathBuf {
        safe_relative_path(&self.path, name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(super) fn server(root: &Path) -> StaticFileServer {
    StaticFileServer::from_config(&WebConfig {
        root: Some(root.to_owned()),
        index_files: vec!["index.html".to_owned()],
        deny_dotfiles: true,
        ..WebConfig::default()
    })
    .unwrap()
    .unwrap()
}

pub(super) fn static_file(len: u64, modified: Option<SystemTime>) -> StaticFile {
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
