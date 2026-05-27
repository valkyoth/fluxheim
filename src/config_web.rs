use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_config_list_len};
use crate::config_header::validate_optional_header_value;
use crate::config_path::validate_path;

pub(crate) const MAX_WEB_INDEX_FILES: usize = 32;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_dotfiles: bool,
    #[serde(default)]
    pub directory_listing: DirectoryListingConfig,
    #[serde(default = "default_static_cache_control")]
    pub cache_control: String,
    #[serde(default)]
    pub expires: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            root: None,
            index_files: default_index_files(),
            deny_dotfiles: true,
            directory_listing: DirectoryListingConfig::default(),
            cache_control: default_static_cache_control(),
            expires: None,
        }
    }
}

impl WebConfig {
    pub fn enabled(&self) -> bool {
        self.root.is_some()
    }

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(root) = &mut self.root
            && root.is_relative()
        {
            *root = base_dir.join(&root);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if let Some(root) = &self.root
            && root.as_os_str().is_empty()
        {
            return Err(ConfigError::EmptyWebRoot);
        }
        validate_path("web.root", self.root.as_deref())?;
        self.directory_listing.validate()?;

        if self.index_files.is_empty() {
            return Err(ConfigError::EmptyIndexFiles);
        }
        validate_config_list_len(
            "web.index_files",
            self.index_files.len(),
            MAX_WEB_INDEX_FILES,
        )?;

        for index in &self.index_files {
            if index.trim().is_empty()
                || index.contains('/')
                || index.contains('\\')
                || index == "."
                || index == ".."
            {
                return Err(ConfigError::InvalidIndexFile {
                    file: index.clone(),
                });
            }
        }
        validate_optional_header_value("web.cache_control", Some(&self.cache_control))?;
        validate_optional_header_value("web.expires", self.expires.as_deref())?;

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryListingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub exact_size: bool,
    #[serde(default)]
    pub local_time: bool,
}

impl DirectoryListingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_owned()]
}

fn default_static_cache_control() -> String {
    "public, max-age=60".to_owned()
}

fn default_true() -> bool {
    true
}
