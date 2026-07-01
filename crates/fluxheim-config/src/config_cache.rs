use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};
use crate::config_cache_controls::{
    CacheLockConfig, CacheLockConfigFragment, CacheOriginProtectionConfig,
    CacheOriginProtectionConfigFragment, CachePredictorConfig, CachePredictorConfigFragment,
};
use crate::config_cache_disk::{CacheDiskConfig, CacheDiskConfigFragment};
use crate::config_cache_encryption::{
    CacheDiskEncryptionProvider, fips_allowed_local_openbao_endpoint,
};
use crate::config_cache_memory::{CacheMemoryConfig, CacheMemoryConfigFragment};
use crate::config_cache_peer::{CachePeerFillConfig, CachePeerFillConfigFragment};
use crate::config_cache_policy::{
    CacheKeyPart, CacheStaleErrorKind, default_cache_content_types, default_cache_include_query,
    default_cache_key_parts, default_cache_max_object_bytes, default_cache_methods,
    default_cache_min_uses, default_cache_stale_if_error_on, default_cache_static_extensions,
    default_cache_tag_headers, extend_unique,
};
use crate::config_cache_range::{CacheRangeConfig, CacheRangeConfigFragment};
use crate::config_cache_validate::validate_cache_config;

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
    pub origin_protection: CacheOriginProtectionConfig,
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
    origin_protection: Option<CacheOriginProtectionConfigFragment>,
    peer_fill: Option<CachePeerFillConfigFragment>,
}

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
            origin_protection: CacheOriginProtectionConfig::default(),
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
        if let Some(origin_protection) = fragment.origin_protection {
            self.origin_protection.merge(origin_protection);
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
        self.peer_fill.resolve_relative_paths(base_dir);
    }

    pub fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        validate_cache_config(self, scope)
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
        if let Some(peer_fill) = &mut self.peer_fill {
            peer_fill.resolve_relative_paths(base_dir);
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
