use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError, valid_credential_name, valid_http_token};
use crate::config_header::validate_header_name;
use crate::config_net::{http_authority_is_loopback, http_authority_is_numeric_loopback};
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_route::validate_route_path;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePurgerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_purger_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_cache_purger_limit")]
    pub limit: usize,
    #[serde(default = "default_cache_purger_batches")]
    pub batches: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePurgerConfigFragment {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    limit: Option<usize>,
    batches: Option<usize>,
}

impl Default for CachePurgerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_cache_purger_interval_secs(),
            limit: default_cache_purger_limit(),
            batches: default_cache_purger_batches(),
        }
    }
}

impl CachePurgerConfig {
    pub fn merge(&mut self, fragment: CachePurgerConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(interval_secs) = fragment.interval_secs {
            self.interval_secs = interval_secs;
        }
        if let Some(limit) = fragment.limit {
            self.limit = limit;
        }
        if let Some(batches) = fragment.batches {
            self.batches = batches;
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            #[cfg(not(feature = "cache"))]
            return Err(ConfigError::CachePurgerNotCompiled);
        }

        if self.interval_secs == 0 || self.interval_secs > 86_400 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.interval_secs",
                reason: "interval must be between 1 and 86400 seconds",
            });
        }
        if self.limit == 0 || self.limit > 100_000 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.limit",
                reason: "limit must be between 1 and 100000 indexed entries",
            });
        }
        if self.batches == 0 || self.batches > 100 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.batches",
                reason: "batches must be between 1 and 100",
            });
        }
        Ok(())
    }
}

fn default_cache_purger_interval_secs() -> u64 {
    300
}

fn default_cache_purger_limit() -> usize {
    512
}

fn default_cache_purger_batches() -> usize {
    1
}

fn default_true() -> bool {
    true
}
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachePreset {
    #[default]
    None,
    #[serde(rename = "wordpress")]
    WordPress,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default)]
    pub preset: CachePreset,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub local_static: bool,
    #[serde(default)]
    pub status_header: Option<String>,
    #[serde(default)]
    pub status_reason_header: Option<String>,
    #[serde(default)]
    pub hide_response_headers: Vec<String>,
    #[serde(default = "default_cache_tag_headers")]
    pub tag_headers: Vec<String>,
    #[serde(default)]
    pub no_store_response_headers: Vec<String>,
    #[serde(default)]
    pub no_store_response_header_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_path_prefixes: Vec<String>,
    #[serde(default)]
    pub bypass_path_exact: Vec<String>,
    #[serde(default)]
    pub bypass_request_headers: Vec<String>,
    #[serde(default)]
    pub bypass_request_header_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_cookie_names: Vec<String>,
    #[serde(default)]
    pub bypass_cookie_name_prefixes: Vec<String>,
    #[serde(default)]
    pub bypass_cookie_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_query_params: Vec<String>,
    #[serde(default)]
    pub bypass_query_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_query: bool,
    #[serde(default)]
    pub allow_client_cache_refresh: bool,
    #[serde(default)]
    pub vary_request_headers: Vec<String>,
    #[serde(default)]
    pub ignore_origin_cache_headers: bool,
    #[serde(default)]
    pub key_namespace: Option<String>,
    #[serde(default = "default_cache_key_parts")]
    pub key_parts: Vec<CacheKeyPart>,
    #[serde(default = "default_cache_min_uses")]
    pub min_uses: u32,
    #[serde(default)]
    pub pass_uncacheable_after: u32,
    #[serde(default)]
    pub range: CacheRangeConfig,
    #[serde(default)]
    pub status_ttls: BTreeMap<u16, u32>,
    #[serde(default)]
    pub default_status_ttl_secs: Option<u32>,
    #[serde(default)]
    pub stale_while_revalidate_secs: Option<u32>,
    #[serde(default)]
    pub stale_if_error_secs: Option<u32>,
    #[serde(default = "default_cache_stale_if_error_on")]
    pub stale_if_error_on: Vec<CacheStaleErrorKind>,
    #[serde(default)]
    pub stale_if_error_statuses: Vec<u16>,
    #[serde(default = "default_cache_include_query")]
    pub include_query: bool,
    #[serde(default = "default_cache_content_types")]
    pub content_types: Vec<String>,
    #[serde(default = "default_cache_static_extensions", alias = "extensions")]
    pub image_extensions: Vec<String>,
    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_cache_max_object_bytes")]
    pub max_object_bytes: ByteSize,
    #[serde(default)]
    pub memory: CacheMemoryConfig,
    #[serde(default)]
    pub disk: CacheDiskConfig,
    #[serde(default)]
    pub lock: CacheLockConfig,
    #[serde(default)]
    pub predictor: CachePredictorConfig,
    #[serde(default)]
    pub peer_fill: CachePeerFillConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfigFragment {
    preset: Option<CachePreset>,
    enabled: Option<bool>,
    local_static: Option<bool>,
    status_header: Option<String>,
    status_reason_header: Option<String>,
    hide_response_headers: Option<Vec<String>>,
    tag_headers: Option<Vec<String>>,
    no_store_response_headers: Option<Vec<String>>,
    no_store_response_header_values: Option<BTreeMap<String, String>>,
    bypass_path_prefixes: Option<Vec<String>>,
    bypass_path_exact: Option<Vec<String>>,
    bypass_request_headers: Option<Vec<String>>,
    bypass_request_header_values: Option<BTreeMap<String, String>>,
    bypass_cookie_names: Option<Vec<String>>,
    bypass_cookie_name_prefixes: Option<Vec<String>>,
    bypass_cookie_values: Option<BTreeMap<String, String>>,
    bypass_query_params: Option<Vec<String>>,
    bypass_query_values: Option<BTreeMap<String, String>>,
    bypass_query: Option<bool>,
    allow_client_cache_refresh: Option<bool>,
    vary_request_headers: Option<Vec<String>>,
    ignore_origin_cache_headers: Option<bool>,
    key_namespace: Option<String>,
    key_parts: Option<Vec<CacheKeyPart>>,
    min_uses: Option<u32>,
    pass_uncacheable_after: Option<u32>,
    range: Option<CacheRangeConfigFragment>,
    status_ttls: Option<BTreeMap<u16, u32>>,
    default_status_ttl_secs: Option<u32>,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
    stale_if_error_on: Option<Vec<CacheStaleErrorKind>>,
    stale_if_error_statuses: Option<Vec<u16>>,
    include_query: Option<bool>,
    content_types: Option<Vec<String>>,
    #[serde(alias = "extensions")]
    image_extensions: Option<Vec<String>>,
    methods: Option<Vec<String>>,
    max_object_bytes: Option<ByteSize>,
    memory: Option<CacheMemoryConfigFragment>,
    disk: Option<CacheDiskConfigFragment>,
    lock: Option<CacheLockConfigFragment>,
    predictor: Option<CachePredictorConfigFragment>,
    peer_fill: Option<CachePeerFillConfigFragment>,
}

const MAX_CACHE_HEADER_LIST_ENTRIES: usize = 64;
pub const MAX_CACHE_BYPASS_PATHS: usize = 128;
const MAX_CACHE_BYPASS_HEADERS: usize = 64;
pub const MAX_CACHE_BYPASS_COOKIES: usize = 128;
const MAX_CACHE_BYPASS_QUERY_PARAMS: usize = 128;
pub const MAX_CACHE_VARY_REQUEST_HEADERS: usize = 16;
const MAX_CACHE_KEY_PARTS: usize = 4;
pub const MAX_CACHE_CONTENT_TYPES: usize = 64;
pub const MAX_CACHE_IMAGE_EXTENSIONS: usize = 128;
pub const MAX_CACHE_METHODS: usize = 16;
pub const MAX_CACHE_STATUS_TTLS: usize = 128;
const MAX_CACHE_STALE_IF_ERROR_STATUSES: usize = 100;

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            preset: CachePreset::default(),
            enabled: false,
            local_static: false,
            status_header: None,
            status_reason_header: None,
            hide_response_headers: Vec::new(),
            tag_headers: default_cache_tag_headers(),
            no_store_response_headers: Vec::new(),
            no_store_response_header_values: BTreeMap::new(),
            bypass_path_prefixes: Vec::new(),
            bypass_path_exact: Vec::new(),
            bypass_request_headers: Vec::new(),
            bypass_request_header_values: BTreeMap::new(),
            bypass_cookie_names: Vec::new(),
            bypass_cookie_name_prefixes: Vec::new(),
            bypass_cookie_values: BTreeMap::new(),
            bypass_query_params: Vec::new(),
            bypass_query_values: BTreeMap::new(),
            bypass_query: false,
            allow_client_cache_refresh: false,
            vary_request_headers: Vec::new(),
            ignore_origin_cache_headers: false,
            key_namespace: None,
            key_parts: default_cache_key_parts(),
            min_uses: default_cache_min_uses(),
            pass_uncacheable_after: 0,
            range: CacheRangeConfig::default(),
            status_ttls: BTreeMap::new(),
            default_status_ttl_secs: None,
            stale_while_revalidate_secs: None,
            stale_if_error_secs: None,
            stale_if_error_on: default_cache_stale_if_error_on(),
            stale_if_error_statuses: Vec::new(),
            include_query: default_cache_include_query(),
            content_types: default_cache_content_types(),
            image_extensions: default_cache_static_extensions(),
            methods: default_cache_methods(),
            max_object_bytes: default_cache_max_object_bytes(),
            memory: CacheMemoryConfig::default(),
            disk: CacheDiskConfig::default(),
            lock: CacheLockConfig::default(),
            predictor: CachePredictorConfig::default(),
            peer_fill: CachePeerFillConfig::default(),
        }
    }
}

impl CacheConfig {
    pub fn merge(&mut self, fragment: CacheConfigFragment) {
        if let Some(preset) = fragment.preset {
            self.preset = preset;
        }
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(local_static) = fragment.local_static {
            self.local_static = local_static;
        }
        if let Some(status_header) = fragment.status_header {
            self.status_header = Some(status_header);
        }
        if let Some(status_reason_header) = fragment.status_reason_header {
            self.status_reason_header = Some(status_reason_header);
        }
        if let Some(headers) = fragment.hide_response_headers {
            self.hide_response_headers = headers;
        }
        if let Some(headers) = fragment.tag_headers {
            self.tag_headers = headers;
        }
        if let Some(headers) = fragment.no_store_response_headers {
            self.no_store_response_headers = headers;
        }
        if let Some(values) = fragment.no_store_response_header_values {
            self.no_store_response_header_values = values;
        }
        if let Some(paths) = fragment.bypass_path_prefixes {
            self.bypass_path_prefixes = paths;
        }
        if let Some(paths) = fragment.bypass_path_exact {
            self.bypass_path_exact = paths;
        }
        if let Some(headers) = fragment.bypass_request_headers {
            self.bypass_request_headers = headers;
        }
        if let Some(values) = fragment.bypass_request_header_values {
            self.bypass_request_header_values = values;
        }
        if let Some(cookies) = fragment.bypass_cookie_names {
            self.bypass_cookie_names = cookies;
        }
        if let Some(cookies) = fragment.bypass_cookie_name_prefixes {
            self.bypass_cookie_name_prefixes = cookies;
        }
        if let Some(values) = fragment.bypass_cookie_values {
            self.bypass_cookie_values = values;
        }
        if let Some(params) = fragment.bypass_query_params {
            self.bypass_query_params = params;
        }
        if let Some(values) = fragment.bypass_query_values {
            self.bypass_query_values = values;
        }
        if let Some(bypass_query) = fragment.bypass_query {
            self.bypass_query = bypass_query;
        }
        if let Some(allow) = fragment.allow_client_cache_refresh {
            self.allow_client_cache_refresh = allow;
        }
        if let Some(headers) = fragment.vary_request_headers {
            self.vary_request_headers = headers;
        }
        if let Some(ignore) = fragment.ignore_origin_cache_headers {
            self.ignore_origin_cache_headers = ignore;
        }
        if let Some(namespace) = fragment.key_namespace {
            self.key_namespace = Some(namespace);
        }
        if let Some(parts) = fragment.key_parts {
            self.key_parts = parts;
        }
        if let Some(min_uses) = fragment.min_uses {
            self.min_uses = min_uses;
        }
        if let Some(pass_uncacheable_after) = fragment.pass_uncacheable_after {
            self.pass_uncacheable_after = pass_uncacheable_after;
        }
        if let Some(range) = fragment.range {
            self.range.merge(range);
        }
        if let Some(ttls) = fragment.status_ttls {
            self.status_ttls = ttls;
        }
        if let Some(ttl) = fragment.default_status_ttl_secs {
            self.default_status_ttl_secs = Some(ttl);
        }
        if let Some(ttl) = fragment.stale_while_revalidate_secs {
            self.stale_while_revalidate_secs = Some(ttl);
        }
        if let Some(ttl) = fragment.stale_if_error_secs {
            self.stale_if_error_secs = Some(ttl);
        }
        if let Some(kinds) = fragment.stale_if_error_on {
            self.stale_if_error_on = kinds;
        }
        if let Some(statuses) = fragment.stale_if_error_statuses {
            self.stale_if_error_statuses = statuses;
        }
        if let Some(include_query) = fragment.include_query {
            self.include_query = include_query;
        }
        if let Some(content_types) = fragment.content_types {
            self.content_types = content_types;
        }
        if let Some(extensions) = fragment.image_extensions {
            self.image_extensions = extensions;
        }
        if let Some(methods) = fragment.methods {
            self.methods = methods;
        }
        if let Some(max_object_bytes) = fragment.max_object_bytes {
            self.max_object_bytes = max_object_bytes;
        }
        if let Some(memory) = fragment.memory {
            self.memory.merge(memory);
        }
        if let Some(disk) = fragment.disk {
            self.disk.merge(disk);
        }
        if let Some(lock) = fragment.lock {
            self.lock.merge(lock);
        }
        if let Some(predictor) = fragment.predictor {
            self.predictor.merge(predictor);
        }
        if let Some(peer_fill) = fragment.peer_fill {
            self.peer_fill.merge(peer_fill);
        }
    }

    #[cfg(any(feature = "cache", test))]
    pub fn with_presets(&self) -> Self {
        let mut config = self.clone();
        config.apply_preset_defaults();
        config
    }

    pub fn apply_preset_defaults(&mut self) {
        match self.preset {
            CachePreset::None => {}
            CachePreset::WordPress => self.apply_wordpress_preset_defaults(),
        }
    }

    fn apply_wordpress_preset_defaults(&mut self) {
        extend_unique(
            &mut self.bypass_path_prefixes,
            ["/wp-admin/", "/feed/"].map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_path_exact,
            [
                "/index.php",
                "/sitemap.xml",
                "/sitemap_index.xml",
                "/wp-app.php",
                "/wp-comments-popup.php",
                "/wp-comments-post.php",
                "/wp-cron.php",
                "/wp-links-opml.php",
                "/wp-locations.php",
                "/wp-login.php",
                "/wp-mail.php",
                "/wp-register.php",
                "/xmlrpc.php",
            ]
            .map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_query_params,
            ["preview"].map(str::to_owned),
        );
        self.bypass_query = true;
        extend_unique(
            &mut self.bypass_cookie_name_prefixes,
            [
                "comment_author_",
                "wordpress_",
                "wordpress_logged_in_",
                "wordpress_no_cache",
                "wordpress_sec_",
                "wp-postpass_",
            ]
            .map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_request_headers,
            ["authorization"].map(str::to_owned),
        );
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.disk.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        self.disk.encryption.resolve_relative_paths(base_dir);
    }

    pub fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        validate_cache_list_len(
            scope,
            "hide_response_headers",
            self.hide_response_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "tag_headers",
            self.tag_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "no_store_response_headers",
            self.no_store_response_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "no_store_response_header_values",
            self.no_store_response_header_values.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_path_prefixes",
            self.bypass_path_prefixes.len(),
            MAX_CACHE_BYPASS_PATHS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_path_exact",
            self.bypass_path_exact.len(),
            MAX_CACHE_BYPASS_PATHS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_request_headers",
            self.bypass_request_headers.len(),
            MAX_CACHE_BYPASS_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_request_header_values",
            self.bypass_request_header_values.len(),
            MAX_CACHE_BYPASS_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_names",
            self.bypass_cookie_names.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_name_prefixes",
            self.bypass_cookie_name_prefixes.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_values",
            self.bypass_cookie_values.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_query_params",
            self.bypass_query_params.len(),
            MAX_CACHE_BYPASS_QUERY_PARAMS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_query_values",
            self.bypass_query_values.len(),
            MAX_CACHE_BYPASS_QUERY_PARAMS,
        )?;
        validate_cache_list_len(
            scope,
            "vary_request_headers",
            self.vary_request_headers.len(),
            MAX_CACHE_VARY_REQUEST_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "status_ttls",
            self.status_ttls.len(),
            MAX_CACHE_STATUS_TTLS,
        )?;
        validate_cache_list_len(
            scope,
            "stale_if_error_statuses",
            self.stale_if_error_statuses.len(),
            MAX_CACHE_STALE_IF_ERROR_STATUSES,
        )?;
        validate_cache_list_len(
            scope,
            "content_types",
            self.content_types.len(),
            MAX_CACHE_CONTENT_TYPES,
        )?;
        validate_cache_list_len(
            scope,
            "image_extensions",
            self.image_extensions.len(),
            MAX_CACHE_IMAGE_EXTENSIONS,
        )?;
        validate_cache_list_len(scope, "methods", self.methods.len(), MAX_CACHE_METHODS)?;

        if let Some(status_header) = &self.status_header {
            validate_header_name(scope, status_header)?;
        }
        if let Some(status_reason_header) = &self.status_reason_header {
            validate_header_name(scope, status_reason_header)?;
        }
        for header in &self.hide_response_headers {
            validate_header_name(scope, header)?;
        }
        let mut seen_tag_headers = BTreeSet::new();
        for header in &self.tag_headers {
            validate_header_name(scope, header)?;
            let normalized = header.to_ascii_lowercase();
            if !seen_tag_headers.insert(normalized) {
                return Err(ConfigError::DuplicateCacheTagHeader {
                    scope,
                    header: header.clone(),
                });
            }
        }
        for header in &self.no_store_response_headers {
            validate_header_name(scope, header)?;
        }
        for (header, value) in &self.no_store_response_header_values {
            validate_header_name(scope, header)?;
            validate_cache_no_store_response_header_value(scope, header, value)?;
        }
        for path in &self.bypass_path_prefixes {
            validate_route_path(scope, path, true).map_err(|_| {
                ConfigError::InvalidCacheBypassPath {
                    scope,
                    path: path.clone(),
                }
            })?;
        }
        for path in &self.bypass_path_exact {
            validate_route_path(scope, path, false).map_err(|_| {
                ConfigError::InvalidCacheBypassPath {
                    scope,
                    path: path.clone(),
                }
            })?;
        }
        for header in &self.bypass_request_headers {
            validate_header_name(scope, header)?;
        }
        for (header, value) in &self.bypass_request_header_values {
            validate_header_name(scope, header)?;
            validate_cache_bypass_request_header_value(scope, header, value)?;
        }
        for cookie in &self.bypass_cookie_names {
            validate_cache_cookie_name(scope, cookie)?;
        }
        for cookie in &self.bypass_cookie_name_prefixes {
            validate_cache_cookie_name(scope, cookie)?;
        }
        for (cookie, value) in &self.bypass_cookie_values {
            validate_cache_cookie_name(scope, cookie)?;
            validate_cache_cookie_value(scope, cookie, value)?;
        }
        for param in &self.bypass_query_params {
            validate_cache_query_param(scope, param)?;
        }
        for (param, value) in &self.bypass_query_values {
            validate_cache_query_param(scope, param)?;
            validate_cache_query_value(scope, param, value)?;
        }
        for header in &self.vary_request_headers {
            validate_header_name(scope, header)?;
            if cache_sensitive_request_header(header) {
                return Err(ConfigError::InvalidCacheVaryRequestHeader {
                    scope,
                    header: header.clone(),
                });
            }
        }
        if let Some(namespace) = &self.key_namespace {
            validate_cache_key_namespace(scope, namespace)?;
        }
        if self.key_parts.is_empty() {
            return Err(ConfigError::EmptyCacheKeyParts { scope });
        }
        validate_cache_list_len(
            scope,
            "key_parts",
            self.key_parts.len(),
            MAX_CACHE_KEY_PARTS,
        )?;
        let mut seen_parts = BTreeSet::new();
        for part in &self.key_parts {
            if !seen_parts.insert(*part) {
                return Err(ConfigError::DuplicateCacheKeyPart { scope, part: *part });
            }
        }
        if !seen_parts.contains(&CacheKeyPart::Path) {
            return Err(ConfigError::MissingCacheKeyPath { scope });
        }
        if self.min_uses == 0 {
            return Err(ConfigError::InvalidCacheMinUses { scope });
        }
        for (status, ttl_secs) in &self.status_ttls {
            if !(100..=599).contains(status) || *ttl_secs == 0 {
                return Err(ConfigError::InvalidCacheStatusTtl {
                    scope,
                    status: *status,
                    ttl_secs: *ttl_secs,
                });
            }
        }
        if self.default_status_ttl_secs == Some(0) {
            return Err(ConfigError::InvalidCacheDefaultStatusTtl { scope });
        }
        if self.stale_if_error_secs == Some(0) {
            return Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope });
        }
        if self.stale_while_revalidate_secs == Some(0) {
            return Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope });
        }
        if self.stale_if_error_secs.is_some() && self.stale_if_error_on.is_empty() {
            return Err(ConfigError::EmptyCacheStaleIfErrorOn { scope });
        }
        for status in &self.stale_if_error_statuses {
            if !(500..=599).contains(status) {
                return Err(ConfigError::InvalidCacheStaleIfErrorStatus {
                    scope,
                    status: *status,
                });
            }
        }

        if self.content_types.is_empty() {
            return Err(ConfigError::EmptyCacheContentTypes { scope });
        }
        for content_type in &self.content_types {
            let content_type = content_type.trim();
            let Some((kind, subtype)) = content_type.split_once('/') else {
                return Err(ConfigError::InvalidCacheContentType {
                    scope,
                    content_type: content_type.to_owned(),
                });
            };
            if kind.is_empty()
                || subtype.is_empty()
                || kind == "*"
                || content_type.contains(';')
                || content_type.chars().any(char::is_whitespace)
                || content_type.chars().any(char::is_control)
                || (subtype.contains('*') && subtype != "*")
            {
                return Err(ConfigError::InvalidCacheContentType {
                    scope,
                    content_type: content_type.to_owned(),
                });
            }
        }

        if self.image_extensions.is_empty() {
            return Err(ConfigError::EmptyCacheImageExtensions { scope });
        }
        for extension in &self.image_extensions {
            let extension = extension.trim();
            if extension.is_empty()
                || extension.starts_with('.')
                || extension.contains('/')
                || extension.contains('\\')
                || extension.chars().any(char::is_whitespace)
            {
                return Err(ConfigError::InvalidCacheImageExtension {
                    scope,
                    extension: extension.to_owned(),
                });
            }
        }

        if self.methods.is_empty() {
            return Err(ConfigError::EmptyCacheMethods { scope });
        }
        for method in &self.methods {
            if !valid_http_token(method) || method.chars().any(char::is_lowercase) {
                return Err(ConfigError::InvalidCacheMethod {
                    scope,
                    method: method.clone(),
                });
            }
        }

        if self.max_object_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheMaxObjectBytes { scope });
        }

        self.range.validate(scope, self.max_object_bytes)?;
        self.lock.validate(scope)?;
        self.predictor.validate(scope)?;
        self.peer_fill.validate(scope)?;

        if self.enabled && !self.has_enabled_tier() {
            return Err(ConfigError::CacheEnabledWithoutStorageTier { scope });
        }
        if self.peer_fill.enabled && !self.enabled {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.enabled",
                reason: "peer fill requires the cache policy to be enabled",
            });
        }

        self.memory.validate(scope, self.max_object_bytes)?;
        self.disk.validate(scope, self.max_object_bytes)?;
        Ok(())
    }

    pub fn has_enabled_tier(&self) -> bool {
        self.memory.enabled || self.disk.enabled
    }
}

impl CacheConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(disk) = &mut self.disk {
            disk.resolve_relative_paths(base_dir);
        }
    }
}

pub fn validate_cache_compliance_internal_crypto(
    cache: &CacheConfig,
    scope: &'static str,
    require_disk_cache_encryption: bool,
) -> Result<(), ConfigError> {
    if !cache.disk.enabled {
        return Ok(());
    }

    if !cache.disk.encryption.enabled {
        if require_disk_cache_encryption {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: scope,
                reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
            });
        }
        log::warn!(
            "{scope}.disk.enabled is true in FIPS/ISO-required mode without disk cache encryption; cached response bodies are written at rest without a Fluxheim-managed encryption boundary"
        );
        return Ok(());
    }

    match cache.disk.encryption.provider {
        CacheDiskEncryptionProvider::Local => Err(ConfigError::InvalidCompliancePolicy {
            field: scope,
            reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
        }),
        CacheDiskEncryptionProvider::OpenbaoTransit => {
            let address = cache
                .disk
                .encryption
                .openbao
                .address
                .as_deref()
                .unwrap_or_default();
            if !fips_allowed_local_openbao_endpoint(address) {
                return Err(ConfigError::InvalidCompliancePolicy {
                    field: scope,
                    reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
                });
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_max_bytes")]
    pub max_bytes: ByteSize,
    #[serde(default)]
    pub slice: CacheRangeSliceConfig,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeConfigFragment {
    enabled: Option<bool>,
    max_bytes: Option<ByteSize>,
    slice: Option<CacheRangeSliceConfigFragment>,
}

impl Default for CacheRangeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: default_cache_range_max_bytes(),
            slice: CacheRangeSliceConfig::default(),
        }
    }
}

impl CacheRangeConfig {
    fn merge(&mut self, fragment: CacheRangeConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_bytes) = fragment.max_bytes {
            self.max_bytes = max_bytes;
        }
        if let Some(slice) = fragment.slice {
            self.slice.merge(slice);
        }
    }

    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if self.max_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must be greater than zero",
            });
        }
        if self.enabled && !self.slice.enabled && self.max_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed max_object_bytes",
            });
        }
        self.slice
            .validate(scope, self.enabled, self.max_bytes, max_object_bytes)?;
        Ok(())
    }
}

fn default_cache_range_max_bytes() -> ByteSize {
    ByteSize(8 * 1024 * 1024)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeSliceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_slice_size_bytes")]
    pub size_bytes: ByteSize,
    #[serde(default = "default_cache_range_slice_max_slices")]
    pub max_slices: u32,
    #[serde(default = "default_cache_range_slice_fill_missing")]
    pub fill_missing: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeSliceConfigFragment {
    enabled: Option<bool>,
    size_bytes: Option<ByteSize>,
    max_slices: Option<u32>,
    fill_missing: Option<bool>,
}

impl Default for CacheRangeSliceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size_bytes: default_cache_range_slice_size_bytes(),
            max_slices: default_cache_range_slice_max_slices(),
            fill_missing: default_cache_range_slice_fill_missing(),
        }
    }
}

impl CacheRangeSliceConfig {
    fn merge(&mut self, fragment: CacheRangeSliceConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(size_bytes) = fragment.size_bytes {
            self.size_bytes = size_bytes;
        }
        if let Some(max_slices) = fragment.max_slices {
            self.max_slices = max_slices;
        }
        if let Some(fill_missing) = fragment.fill_missing {
            self.fill_missing = fill_missing;
        }
    }

    fn validate(
        &self,
        scope: &'static str,
        range_enabled: bool,
        range_max_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !range_enabled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.enabled",
                reason: "slice caching requires range.enabled = true",
            });
        }
        if self.size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must be greater than zero",
            });
        }
        if self.size_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must not exceed max_object_bytes",
            });
        }
        if self.max_slices == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.max_slices",
                reason: "max slices must be greater than zero",
            });
        }
        let max_assembled = self
            .size_bytes
            .as_u64()
            .saturating_mul(u64::from(self.max_slices));
        if range_max_bytes.as_u64() > max_assembled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed range.slice.size_bytes * range.slice.max_slices",
            });
        }
        Ok(())
    }
}

fn default_cache_range_slice_size_bytes() -> ByteSize {
    ByteSize(1024 * 1024)
}

fn default_cache_range_slice_max_slices() -> u32 {
    128
}

fn default_cache_range_slice_fill_missing() -> bool {
    true
}

fn cache_sensitive_request_header(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization"
    )
}

fn validate_cache_query_param(scope: &'static str, param: &str) -> Result<(), ConfigError> {
    if param.is_empty()
        || param.len() > 128
        || param.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '=' | '#' | '?' | ';')
        })
    {
        return Err(ConfigError::InvalidCacheBypassQueryParam {
            scope,
            param: param.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_query_value(
    scope: &'static str,
    param: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '#' | ';'))
    {
        return Err(ConfigError::InvalidCacheBypassQueryValue {
            scope,
            param: param.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_bypass_request_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_no_store_response_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_cookie_name(scope: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 128 || !valid_cookie_name(name) {
        return Err(ConfigError::InvalidCacheBypassCookieName {
            scope,
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_cookie_value(
    scope: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.len() > 1024
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || matches!(byte, b';' | b','))
    {
        return Err(ConfigError::InvalidCacheBypassCookieValue {
            scope,
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn valid_cookie_name(value: &str) -> bool {
    value.bytes().all(|byte| {
        matches!(byte, 0x21 | 0x23..=0x27 | 0x2a..=0x2b | 0x2d..=0x2e | 0x30..=0x39 | 0x41..=0x5a | 0x5e..=0x7a | 0x7c | 0x7e)
    })
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKeyPart {
    Method,
    Host,
    Path,
    Query,
}

impl Display for CacheKeyPart {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => formatter.write_str("method"),
            Self::Host => formatter.write_str("host"),
            Self::Path => formatter.write_str("path"),
            Self::Query => formatter.write_str("query"),
        }
    }
}

pub fn extend_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn default_cache_key_parts() -> Vec<CacheKeyPart> {
    vec![
        CacheKeyPart::Method,
        CacheKeyPart::Host,
        CacheKeyPart::Path,
        CacheKeyPart::Query,
    ]
}

fn default_cache_tag_headers() -> Vec<String> {
    ["surrogate-key", "cache-tag", "x-cache-tags"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_cache_key_namespace(scope: &'static str, namespace: &str) -> Result<(), ConfigError> {
    if namespace.is_empty()
        || namespace.len() > 128
        || namespace
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':')))
    {
        return Err(ConfigError::InvalidCacheKeyNamespace {
            scope,
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheStaleErrorKind {
    Connect,
    Timeout,
    Read,
    Write,
    ConnectionClosed,
    HttpStatus,
    Protocol,
    Tls,
    Other,
}

fn default_cache_stale_if_error_on() -> Vec<CacheStaleErrorKind> {
    vec![
        CacheStaleErrorKind::Connect,
        CacheStaleErrorKind::Timeout,
        CacheStaleErrorKind::Read,
        CacheStaleErrorKind::Write,
        CacheStaleErrorKind::ConnectionClosed,
        CacheStaleErrorKind::HttpStatus,
        CacheStaleErrorKind::Protocol,
        CacheStaleErrorKind::Tls,
        CacheStaleErrorKind::Other,
    ]
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheLockConfig {
    #[serde(default = "default_cache_lock_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cache_lock_age_timeout_secs")]
    pub age_timeout_secs: u64,
    #[serde(default = "default_cache_lock_wait_timeout_secs")]
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheLockConfigFragment {
    enabled: Option<bool>,
    age_timeout_secs: Option<u64>,
    wait_timeout_secs: Option<u64>,
}

impl Default for CacheLockConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_lock_enabled(),
            age_timeout_secs: default_cache_lock_age_timeout_secs(),
            wait_timeout_secs: default_cache_lock_wait_timeout_secs(),
        }
    }
}

impl CacheLockConfig {
    fn merge(&mut self, fragment: CacheLockConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(age_timeout_secs) = fragment.age_timeout_secs {
            self.age_timeout_secs = age_timeout_secs;
        }
        if let Some(wait_timeout_secs) = fragment.wait_timeout_secs {
            self.wait_timeout_secs = wait_timeout_secs;
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.age_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.age_timeout_secs"),
            });
        }
        if self.wait_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.wait_timeout_secs"),
            });
        }
        Ok(())
    }
}

pub const CACHE_PREDICTOR_MAX_CAPACITY: usize = 1_048_576;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePredictorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_predictor_capacity")]
    pub capacity: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePredictorConfigFragment {
    enabled: Option<bool>,
    capacity: Option<usize>,
}

impl Default for CachePredictorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: default_cache_predictor_capacity(),
        }
    }
}

impl CachePredictorConfig {
    fn merge(&mut self, fragment: CachePredictorConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(capacity) = fragment.capacity {
            self.capacity = capacity;
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.enabled && (self.capacity == 0 || self.capacity > CACHE_PREDICTOR_MAX_CAPACITY) {
            return Err(ConfigError::InvalidCachePredictorCapacity { scope });
        }
        Ok(())
    }
}

fn default_cache_predictor_capacity() -> usize {
    65_536
}

const CACHE_PEER_FILL_MAX_PEERS: usize = 32;
const CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS: usize = 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerFillConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub peers: Vec<CachePeerConfig>,
    #[serde(default = "default_cache_peer_fill_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_cache_peer_fill_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default)]
    pub max_object_bytes: Option<ByteSize>,
    #[serde(default = "default_cache_peer_fill_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "default_true")]
    pub fail_open: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerFillConfigFragment {
    enabled: Option<bool>,
    peers: Option<Vec<CachePeerConfig>>,
    connect_timeout_secs: Option<u64>,
    read_timeout_secs: Option<u64>,
    max_object_bytes: Option<ByteSize>,
    max_concurrent_requests: Option<usize>,
    allow_insecure_http: Option<bool>,
    fail_open: Option<bool>,
}

impl Default for CachePeerFillConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: Vec::new(),
            connect_timeout_secs: default_cache_peer_fill_connect_timeout_secs(),
            read_timeout_secs: default_cache_peer_fill_read_timeout_secs(),
            max_object_bytes: None,
            max_concurrent_requests: default_cache_peer_fill_max_concurrent_requests(),
            allow_insecure_http: false,
            fail_open: true,
        }
    }
}

impl CachePeerFillConfig {
    fn merge(&mut self, fragment: CachePeerFillConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(peers) = fragment.peers {
            self.peers = peers;
        }
        if let Some(timeout_secs) = fragment.connect_timeout_secs {
            self.connect_timeout_secs = timeout_secs;
        }
        if let Some(timeout_secs) = fragment.read_timeout_secs {
            self.read_timeout_secs = timeout_secs;
        }
        if let Some(max_object_bytes) = fragment.max_object_bytes {
            self.max_object_bytes = Some(max_object_bytes);
        }
        if let Some(max_concurrent_requests) = fragment.max_concurrent_requests {
            self.max_concurrent_requests = max_concurrent_requests;
        }
        if let Some(allow_insecure_http) = fragment.allow_insecure_http {
            self.allow_insecure_http = allow_insecure_http;
        }
        if let Some(fail_open) = fragment.fail_open {
            self.fail_open = fail_open;
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        #[cfg(not(feature = "cache"))]
        if self.enabled {
            return Err(ConfigError::CachePeerFillNotCompiled);
        }

        if !self.enabled {
            return Ok(());
        }

        if self.peers.is_empty() || self.peers.len() > CACHE_PEER_FILL_MAX_PEERS {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.peers",
                reason: "peer fill requires between 1 and 32 peers",
            });
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 300 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.connect_timeout_secs",
                reason: "connect timeout must be between 1 and 300 seconds",
            });
        }
        if self.read_timeout_secs == 0 || self.read_timeout_secs > 3600 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.read_timeout_secs",
                reason: "read timeout must be between 1 and 3600 seconds",
            });
        }
        if self.max_object_bytes.is_some_and(|size| size.as_u64() == 0) {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_object_bytes",
                reason: "max object bytes must be greater than zero",
            });
        }
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS
        {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_concurrent_requests",
                reason: "max concurrent requests must be between 1 and 1024",
            });
        }

        let mut seen_names = BTreeSet::new();
        let mut seen_urls = BTreeSet::new();
        for peer in &self.peers {
            peer.validate(scope, self.allow_insecure_http)?;
            if !seen_names.insert(peer.name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerName {
                    scope,
                    name: peer.name.clone(),
                });
            }
            if !seen_urls.insert(peer.base_url.trim_end_matches('/').to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerUrl {
                    scope,
                    url: peer.base_url.clone(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerConfig {
    pub name: String,
    pub base_url: String,
}

impl CachePeerConfig {
    fn validate(&self, scope: &'static str, allow_insecure_http: bool) -> Result<(), ConfigError> {
        validate_cache_peer_name(scope, &self.name)?;
        validate_cache_peer_base_url(scope, &self.name, &self.base_url, allow_insecure_http)
    }
}

fn default_cache_peer_fill_connect_timeout_secs() -> u64 {
    2
}

fn default_cache_peer_fill_read_timeout_secs() -> u64 {
    10
}

fn default_cache_peer_fill_max_concurrent_requests() -> usize {
    64
}

fn validate_cache_peer_name(scope: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: name.to_owned(),
            reason: "peer name must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
        });
    }
    Ok(())
}

fn validate_cache_peer_base_url(
    scope: &'static str,
    peer: &str,
    base_url: &str,
    allow_insecure_http: bool,
) -> Result<(), ConfigError> {
    let base_url = base_url.trim();
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must start with https:// or http://",
        });
    };
    if !matches!(scheme, "https" | "http")
        || rest.is_empty()
        || base_url.len() > 2048
        || base_url.chars().any(char::is_whitespace)
        || base_url.chars().any(char::is_control)
        || base_url.contains('?')
        || base_url.contains('#')
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must be a safe HTTP(S) origin URL without query or fragment",
        });
    }

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.contains('@') || !valid_cache_peer_authority(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url authority must be a valid host:port or ip:port without userinfo",
        });
    }
    if !path.is_empty() && path != "/" {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must not include a path yet",
        });
    }
    if scheme == "http" && !allow_insecure_http && !cache_peer_authority_is_loopback(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
        });
    }

    Ok(())
}

fn valid_cache_peer_authority(authority: &str) -> bool {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let host = &authority[1..end];
        let tail = &authority[end + 1..];
        return !host.is_empty()
            && host.parse::<IpAddr>().is_ok()
            && tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|port| port != 0)
        && (host.parse::<IpAddr>().is_ok() || valid_cache_peer_hostname(host))
}

fn valid_cache_peer_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn cache_peer_authority_is_loopback(authority: &str) -> bool {
    http_authority_is_loopback(authority)
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMemoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_memory_max_size_bytes")]
    pub max_size_bytes: ByteSize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMemoryConfigFragment {
    enabled: Option<bool>,
    max_size_bytes: Option<ByteSize>,
}

impl Default for CacheMemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size_bytes: default_cache_memory_max_size_bytes(),
        }
    }
}

impl CacheMemoryConfig {
    fn merge(&mut self, fragment: CacheMemoryConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_size_bytes) = fragment.max_size_bytes {
            self.max_size_bytes = max_size_bytes;
        }
    }

    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.memory.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.memory"),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: CacheDiskBackend,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_cache_disk_max_size_bytes")]
    pub max_size_bytes: ByteSize,
    #[serde(default)]
    pub storage_bin: CacheDiskStorageBinConfig,
    #[serde(default)]
    pub encryption: CacheDiskEncryptionConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskConfigFragment {
    enabled: Option<bool>,
    backend: Option<CacheDiskBackend>,
    path: Option<PathBuf>,
    max_size_bytes: Option<ByteSize>,
    storage_bin: Option<CacheDiskStorageBinConfigFragment>,
    encryption: Option<CacheDiskEncryptionConfigFragment>,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskBackend {
    #[default]
    Filesystem,
    StorageBin,
}

impl Default for CacheDiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CacheDiskBackend::Filesystem,
            path: None,
            max_size_bytes: default_cache_disk_max_size_bytes(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        }
    }
}

impl CacheDiskConfig {
    fn merge(&mut self, fragment: CacheDiskConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(backend) = fragment.backend {
            self.backend = backend;
        }
        if let Some(path) = fragment.path {
            self.path = Some(path);
        }
        if let Some(max_size_bytes) = fragment.max_size_bytes {
            self.max_size_bytes = max_size_bytes;
        }
        if let Some(storage_bin) = fragment.storage_bin {
            self.storage_bin.merge(storage_bin);
        }
        if let Some(encryption) = fragment.encryption {
            self.encryption.merge(encryption);
        }
    }

    fn resolve_fragment_relative_paths(fragment: &mut CacheDiskConfigFragment, base_dir: &Path) {
        if let Some(path) = &mut fragment.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(encryption) = &mut fragment.encryption {
            encryption.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.backend == CacheDiskBackend::StorageBin {
            self.storage_bin
                .validate(scope, self.max_size_bytes, max_object_bytes)?;
        }
        self.encryption.validate(scope)?;

        let Some(path) = &self.path else {
            return Err(ConfigError::MissingCacheDiskPath { scope });
        };

        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyCacheDiskPath { scope });
        }
        let path_field = format!("{scope}.disk.path");
        validate_path(path_field.clone(), Some(path))?;
        validate_non_world_writable_parent(path_field, Some(path))?;

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.disk.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.disk"),
            });
        }

        Ok(())
    }
}

impl CacheDiskConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        CacheDiskConfig::resolve_fragment_relative_paths(self, base_dir);
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: CacheDiskEncryptionProvider,
    #[serde(default)]
    pub algorithm: CacheDiskEncryptionAlgorithm,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub key_credential: Option<String>,
    #[serde(default)]
    pub openbao: CacheDiskEncryptionOpenBaoConfig,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionConfigFragment {
    enabled: Option<bool>,
    provider: Option<CacheDiskEncryptionProvider>,
    algorithm: Option<CacheDiskEncryptionAlgorithm>,
    key_id: Option<String>,
    key_file: Option<PathBuf>,
    key_credential: Option<String>,
    openbao: Option<CacheDiskEncryptionOpenBaoConfigFragment>,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionProvider {
    #[default]
    Local,
    OpenbaoTransit,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionAlgorithm {
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
}

impl Default for CacheDiskEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: CacheDiskEncryptionProvider::Local,
            algorithm: CacheDiskEncryptionAlgorithm::Aes256Gcm,
            key_id: None,
            key_file: None,
            key_credential: None,
            openbao: CacheDiskEncryptionOpenBaoConfig::default(),
        }
    }
}

impl CacheDiskEncryptionConfig {
    fn merge(&mut self, fragment: CacheDiskEncryptionConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(provider) = fragment.provider {
            self.provider = provider;
        }
        if let Some(algorithm) = fragment.algorithm {
            self.algorithm = algorithm;
        }
        if let Some(key_id) = fragment.key_id {
            self.key_id = Some(key_id);
        }
        if let Some(key_file) = fragment.key_file {
            self.key_file = Some(key_file);
        }
        if let Some(key_credential) = fragment.key_credential {
            self.key_credential = Some(key_credential);
        }
        if let Some(openbao) = fragment.openbao {
            self.openbao.merge(openbao);
        }
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(key_file) = &mut self.key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        self.openbao.resolve_relative_paths(base_dir);
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        let key_file_field = format!("{scope}.disk.encryption.key_file");
        validate_path(key_file_field.clone(), self.key_file.as_deref())?;
        validate_non_world_writable_parent(key_file_field, self.key_file.as_deref())?;

        if let Some(key_id) = self.key_id.as_deref() {
            validate_cache_encryption_label(scope, "key_id", key_id)?;
        }
        if let Some(credential) = self.key_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "key_credential",
                credential: credential.to_owned(),
            });
        }

        self.openbao.validate(scope)?;

        if !self.enabled {
            return Ok(());
        }

        match self.provider {
            CacheDiskEncryptionProvider::Local => {
                if self.algorithm != CacheDiskEncryptionAlgorithm::Aes256Gcm {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.algorithm",
                        reason: "local provider currently supports only \"aes-256-gcm\"",
                    });
                }
                if self.openbao.is_configured() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.openbao",
                        reason: "openbao settings require provider = \"openbao-transit\"",
                    });
                }
                validate_cache_encryption_secret_choice(
                    scope,
                    "key",
                    self.key_file.as_ref(),
                    self.key_credential.as_deref(),
                )?;
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                if self.key_file.is_some() || self.key_credential.is_some() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.key",
                        reason: "local key sources require provider = \"local\"",
                    });
                }
                self.openbao.validate_enabled(scope)?;
            }
        }

        Ok(())
    }
}

impl CacheDiskEncryptionConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(key_file) = &mut self.key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        if let Some(openbao) = &mut self.openbao {
            openbao.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionOpenBaoConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub key_name: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub token_credential: Option<String>,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionOpenBaoConfigFragment {
    address: Option<String>,
    mount: Option<String>,
    key_name: Option<String>,
    token_file: Option<PathBuf>,
    token_credential: Option<String>,
}

impl CacheDiskEncryptionOpenBaoConfig {
    fn merge(&mut self, fragment: CacheDiskEncryptionOpenBaoConfigFragment) {
        if let Some(address) = fragment.address {
            self.address = Some(address);
        }
        if let Some(mount) = fragment.mount {
            self.mount = Some(mount);
        }
        if let Some(key_name) = fragment.key_name {
            self.key_name = Some(key_name);
        }
        if let Some(token_file) = fragment.token_file {
            self.token_file = Some(token_file);
        }
        if let Some(token_credential) = fragment.token_credential {
            self.token_credential = Some(token_credential);
        }
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
    }

    fn is_configured(&self) -> bool {
        self.address.is_some()
            || self.mount.is_some()
            || self.key_name.is_some()
            || self.token_file.is_some()
            || self.token_credential.is_some()
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if let Some(address) = self.address.as_deref()
            && invalid_cache_encryption_openbao_address(address)
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
            });
        }
        if let Some(mount) = self.mount.as_deref() {
            validate_cache_encryption_label(scope, "openbao.mount", mount)?;
        }
        if let Some(key_name) = self.key_name.as_deref() {
            validate_cache_encryption_label(scope, "openbao.key_name", key_name)?;
        }
        let token_file_field = format!("{scope}.disk.encryption.openbao.token_file");
        validate_path(token_file_field.clone(), self.token_file.as_deref())?;
        validate_non_world_writable_parent(token_file_field, self.token_file.as_deref())?;
        if let Some(credential) = self.token_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "openbao.token_credential",
                credential: credential.to_owned(),
            });
        }
        Ok(())
    }

    fn validate_enabled(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self
            .address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .mount
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.mount",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .key_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.key_name",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        validate_cache_encryption_secret_choice(
            scope,
            "openbao.token",
            self.token_file.as_ref(),
            self.token_credential.as_deref(),
        )
    }
}

impl CacheDiskEncryptionOpenBaoConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
    }
}

fn validate_cache_encryption_secret_choice(
    scope: &'static str,
    field: &'static str,
    file: Option<&PathBuf>,
    credential: Option<&str>,
) -> Result<(), ConfigError> {
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let credential = credential.map(str::trim).filter(|value| !value.is_empty());
    match (file.is_some(), credential.is_some()) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be read from a file or systemd/container credential",
        }),
        (true, true) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "cannot use more than one secret source",
        }),
    }
}

fn validate_cache_encryption_label(
    scope: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.contains("..")
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':')))
    {
        return Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be 1-128 safe ASCII label characters",
        });
    }
    Ok(())
}

fn invalid_cache_encryption_openbao_address(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(char::is_whitespace)
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        return true;
    }
    if value.starts_with("https://") {
        let rest = value.trim_start_matches("https://");
        let authority = rest.split('/').next().unwrap_or_default();
        return authority.is_empty();
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return true;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !openbao_plain_http_authority_is_loopback(authority)
}

fn openbao_plain_http_authority_is_loopback(authority: &str) -> bool {
    http_authority_is_numeric_loopback(authority)
}

pub fn fips_allowed_local_openbao_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _path)| authority);
    !authority.is_empty() && openbao_plain_http_authority_is_loopback(authority)
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskStorageBinConfig {
    #[serde(default = "default_cache_storage_bin_size_bytes")]
    pub bin_size_bytes: ByteSize,
    #[serde(default)]
    pub preallocate: bool,
    #[serde(default = "default_cache_storage_bin_max_open_bins")]
    pub max_open_bins: usize,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskStorageBinConfigFragment {
    bin_size_bytes: Option<ByteSize>,
    preallocate: Option<bool>,
    max_open_bins: Option<usize>,
}

impl Default for CacheDiskStorageBinConfig {
    fn default() -> Self {
        Self {
            bin_size_bytes: default_cache_storage_bin_size_bytes(),
            preallocate: false,
            max_open_bins: default_cache_storage_bin_max_open_bins(),
        }
    }
}

impl CacheDiskStorageBinConfig {
    fn merge(&mut self, fragment: CacheDiskStorageBinConfigFragment) {
        if let Some(bin_size_bytes) = fragment.bin_size_bytes {
            self.bin_size_bytes = bin_size_bytes;
        }
        if let Some(preallocate) = fragment.preallocate {
            self.preallocate = preallocate;
        }
        if let Some(max_open_bins) = fragment.max_open_bins {
            self.max_open_bins = max_open_bins;
        }
    }

    fn validate(
        &self,
        scope: &'static str,
        disk_max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        let field = format!("{scope}.disk.storage_bin.bin_size_bytes");
        if self.bin_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize { field });
        }
        if self.bin_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope });
        }
        if self.bin_size_bytes > disk_max_size_bytes {
            return Err(ConfigError::CacheStorageBinLargerThanDiskTier { scope });
        }
        if self.max_open_bins == 0 {
            return Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope });
        }
        Ok(())
    }
}
fn default_cache_include_query() -> bool {
    true
}

fn default_cache_min_uses() -> u32 {
    1
}

fn default_cache_lock_enabled() -> bool {
    true
}

fn default_cache_lock_age_timeout_secs() -> u64 {
    30
}

fn default_cache_lock_wait_timeout_secs() -> u64 {
    30
}

fn default_cache_content_types() -> Vec<String> {
    [
        "image/*",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/wasm",
        "font/*",
        "application/font-woff",
        "application/vnd.ms-fontobject",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_cache_static_extensions() -> Vec<String> {
    [
        "avif", "css", "eot", "gif", "ico", "jpeg", "jpg", "js", "mjs", "otf", "png", "svg", "ttf",
        "wasm", "webp", "woff", "woff2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_cache_methods() -> Vec<String> {
    ["GET", "HEAD"].into_iter().map(str::to_owned).collect()
}

fn default_cache_max_object_bytes() -> ByteSize {
    ByteSize::from_bytes(32 * 1024 * 1024)
}

fn default_cache_memory_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(1024 * 1024 * 1024)
}

fn default_cache_disk_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(10 * 1024 * 1024 * 1024)
}

fn default_cache_storage_bin_size_bytes() -> ByteSize {
    ByteSize::from_bytes(256 * 1024 * 1024)
}

fn default_cache_storage_bin_max_open_bins() -> usize {
    16
}
fn validate_cache_list_len(
    scope: &'static str,
    field: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidCacheListLength { scope, field, max });
    }
    Ok(())
}
