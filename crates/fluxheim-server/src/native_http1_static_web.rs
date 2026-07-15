use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use fluxheim_cache::{
    CacheRequestView, StaticCacheRequest, response_cache_admission_rejection, static_cache_key,
};
use fluxheim_config::{CacheConfig, DirectoryListingConfig, WebConfig};
use fluxheim_web::{
    DirectoryListing, StaticCacheIdentity, StaticResponseConditions, StaticResponseFile,
    configured_web_path_contains_symlink, plan_static_response, static_cache_identity,
};

use crate::blocking_work::{NativeBlockingWorkClass, try_acquire_request_blocking_work};
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, NativeMemoryCacheState, lock_native_memory_cache,
    native_cache_body_sha256, native_cache_entry_weight, native_cache_ttl,
    native_response_header_map, prune_native_memory_cache,
};
#[cfg(feature = "php-fpm")]
use crate::native_http1_php::{NativePhpScriptResolution, NativePhpScriptResolve};
use crate::response_retention::acquire_static_response_retention;
use crate::{NativeHttp1Request, NativeHttp1Response};

#[path = "native_http1_static_web_resolve.rs"]
mod resolve;
#[path = "native_http1_static_web_response.rs"]
mod response;

use response::{
    directory_listing_response, native_static_cache_expires_at, request_header, static_conditions,
    static_web_method_allowed,
};

const MAX_DIRECTORY_LISTING_ENTRIES: usize = 4096;
const MAX_NATIVE_STATIC_BODY_BYTES: u64 = 64 * 1024 * 1024;

fn static_response_capacity_unavailable() -> NativeHttp1Response {
    NativeHttp1Response::new(
        503,
        "Service Unavailable",
        b"static response capacity unavailable\n",
    )
    .with_retry_after_secs(1)
    .close_connection()
}

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

type NativeStaticMemoryCacheState = NativeMemoryCacheState;

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

    pub async fn handle_async(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
    ) -> NativeHttp1Response {
        if !static_web_method_allowed(&request.method) {
            return self.handle(request, request_path);
        }
        self.handle_optional_async(request, request_path)
            .await
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

    pub async fn handle_optional_async(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
    ) -> Option<NativeHttp1Response> {
        if !static_web_method_allowed(&request.method) {
            return None;
        }
        let resolved = match self.resolve_async(request_path).await {
            Ok(resolved) => resolved,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Some(static_response_capacity_unavailable());
            }
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "static web response failed: {error}");
                return Some(
                    NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                        .close_connection(),
                );
            }
        };
        match resolved {
            NativeStaticResolve::Found(file) => {
                let bytes = self.file_response_reservation_bytes(
                    request,
                    &file,
                    static_conditions(request),
                    true,
                )?;
                let Ok(retention) = acquire_static_response_retention(bytes).await else {
                    return Some(static_response_capacity_unavailable());
                };
                let Ok(blocking_permit) =
                    try_acquire_request_blocking_work(NativeBlockingWorkClass::Static)
                else {
                    return Some(static_response_capacity_unavailable());
                };
                let web = self.clone();
                let request = request.metadata_snapshot();
                match tokio::task::spawn_blocking(move || {
                    let _blocking_permit = blocking_permit;
                    web.cached_file_response(&request, &file)
                })
                .await
                {
                    Ok(response) => Some(response.with_retention(retention)),
                    Err(error) => {
                        log::error!(target: "fluxheim::native_http1", "static response task failed: {error}");
                        Some(
                            NativeHttp1Response::new(
                                500,
                                "Internal Server Error",
                                b"internal error\n",
                            )
                            .close_connection(),
                        )
                    }
                }
            }
            NativeStaticResolve::DirectoryListing(listing) => {
                let Ok(retention) =
                    acquire_static_response_retention(MAX_NATIVE_STATIC_BODY_BYTES as usize).await
                else {
                    return Some(static_response_capacity_unavailable());
                };
                let Ok(blocking_permit) =
                    try_acquire_request_blocking_work(NativeBlockingWorkClass::Static)
                else {
                    return Some(static_response_capacity_unavailable());
                };
                let request = request.metadata_snapshot();
                match tokio::task::spawn_blocking(move || {
                    let _blocking_permit = blocking_permit;
                    directory_listing_response(&request, &listing)
                })
                .await
                {
                    Ok(response) => Some(response.with_retention(retention)),
                    Err(error) => {
                        log::error!(target: "fluxheim::native_http1", "static directory response task failed: {error}");
                        Some(
                            NativeHttp1Response::new(
                                500,
                                "Internal Server Error",
                                b"internal error\n",
                            )
                            .close_connection(),
                        )
                    }
                }
            }
            NativeStaticResolve::NotFound => None,
            NativeStaticResolve::Forbidden => {
                Some(NativeHttp1Response::new(403, "Forbidden", b"forbidden\n").close_connection())
            }
        }
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

    pub async fn handle_error_page_async(
        &self,
        request: &NativeHttp1Request,
        request_path: &str,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        let resolved = self.resolve_async(request_path).await.ok()?;
        let NativeStaticResolve::Found(file) = resolved else {
            return None;
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
        let bytes = self.file_response_reservation_bytes(
            request,
            &file,
            StaticResponseConditions::default(),
            false,
        )?;
        let retention = acquire_static_response_retention(bytes).await.ok()?;
        let blocking_permit =
            try_acquire_request_blocking_work(NativeBlockingWorkClass::Static).ok()?;
        let web = self.clone();
        let request = request.metadata_snapshot();
        let response = tokio::task::spawn_blocking(move || {
            let _blocking_permit = blocking_permit;
            web.file_response_with_status(
                &request,
                &file,
                StaticResponseConditions::default(),
                Some(status),
            )
        })
        .await
        .ok()
        .flatten()?;
        Some(response.with_retention(retention))
    }

    async fn resolve_async(&self, request_path: &str) -> io::Result<NativeStaticResolve> {
        let blocking_permit = try_acquire_request_blocking_work(NativeBlockingWorkClass::Static)?;
        let web = self.clone();
        let request_path = request_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let _blocking_permit = blocking_permit;
            web.resolve(&request_path)
        })
        .await
        .map_err(|error| io::Error::other(format!("static resolution task failed: {error}")))?
    }

    fn file_response_reservation_bytes(
        &self,
        request: &NativeHttp1Request,
        file: &NativeStaticFile,
        conditions: StaticResponseConditions<'_>,
        allow_cache_store: bool,
    ) -> Option<usize> {
        let plan = plan_static_response(
            StaticResponseFile {
                len: file.len,
                modified: file.modified,
            },
            &request.method,
            conditions,
        );
        let Ok(bytes) = usize::try_from(plan.response_body_bytes) else {
            return Some(1);
        };
        if bytes > MAX_NATIVE_STATIC_BODY_BYTES as usize {
            return Some(1);
        }
        if allow_cache_store && self.cache.is_some() {
            bytes.checked_mul(2)
        } else {
            Some(bytes)
        }
    }

    #[cfg(feature = "php-fpm")]
    #[allow(
        dead_code,
        reason = "native PHP-FPM script resolution is staged before route runtime wiring"
    )]
    pub(crate) fn resolve_php_script(
        &self,
        php: &fluxheim_config::PhpConfig,
        request_path: &str,
        decline_existing_static: bool,
    ) -> io::Result<NativePhpScriptResolve> {
        let Some(parsed_script) = fluxheim_php_fpm::php_script_name_for_request(
            request_path,
            &php.index,
            php.path_info,
            &php.allowed_extensions,
        ) else {
            return Ok(NativePhpScriptResolve::Forbidden);
        };
        if fluxheim_php_fpm::php_script_name_denied(
            &php.deny_path_prefixes,
            &parsed_script.script_name,
        ) {
            return Ok(NativePhpScriptResolve::Forbidden);
        }

        if !parsed_script.explicit_php {
            match self.resolve(request_path)? {
                NativeStaticResolve::Found(file) => {
                    if let Some(script_name) = fluxheim_php_fpm::php_static_file_script_name(
                        &self.root,
                        &file.path,
                        &php.allowed_extensions,
                    ) {
                        if fluxheim_php_fpm::php_should_redirect_directory_index(
                            request_path,
                            &script_name,
                            &php.index,
                        ) {
                            return Ok(NativePhpScriptResolve::RedirectDirectorySlash);
                        }
                        if fluxheim_php_fpm::php_script_name_denied(
                            &php.deny_path_prefixes,
                            &script_name,
                        ) {
                            return Ok(NativePhpScriptResolve::Forbidden);
                        }
                        return Ok(NativePhpScriptResolve::Execute(NativePhpScriptResolution {
                            local_path: file.path,
                            script_name,
                            path_info: parsed_script.path_info,
                        }));
                    }
                    if decline_existing_static {
                        return Ok(NativePhpScriptResolve::Decline);
                    }
                }
                NativeStaticResolve::Forbidden => return Ok(NativePhpScriptResolve::Forbidden),
                NativeStaticResolve::NotFound | NativeStaticResolve::DirectoryListing(_) => {}
            }
            if php.try_files == fluxheim_config::PhpTryFilesMode::Strict {
                return Ok(NativePhpScriptResolve::NotFound);
            }
        }

        match self.resolve(&parsed_script.script_name)? {
            NativeStaticResolve::Found(file) => {
                let Some(script_name) = fluxheim_php_fpm::php_static_file_script_name(
                    &self.root,
                    &file.path,
                    &php.allowed_extensions,
                ) else {
                    return Ok(NativePhpScriptResolve::Forbidden);
                };
                if fluxheim_php_fpm::php_script_name_denied(&php.deny_path_prefixes, &script_name) {
                    return Ok(NativePhpScriptResolve::Forbidden);
                }
                Ok(NativePhpScriptResolve::Execute(NativePhpScriptResolution {
                    local_path: file.path,
                    script_name,
                    path_info: parsed_script.path_info,
                }))
            }
            NativeStaticResolve::Forbidden => Ok(NativePhpScriptResolve::Forbidden),
            NativeStaticResolve::NotFound | NativeStaticResolve::DirectoryListing(_) => {
                Ok(NativePhpScriptResolve::NotFound)
            }
        }
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

    fn get(&self, key: &str) -> Option<NativeMemoryCacheEntry> {
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
        let Some(ttl) = native_cache_ttl(response.status(), &headers, &self.config) else {
            return Err("ttl-missing");
        };
        if ttl.is_zero() {
            return Err("ttl-zero");
        }

        let weight = native_cache_entry_weight(key, response, body_len);
        if weight > self.max_bytes {
            return Err("object-too-large");
        }
        let body: Arc<[u8]> = Arc::from(response.body().to_vec());
        let key = key.to_owned();
        let now = Instant::now();
        let Some(expires_at) = native_static_cache_expires_at(now, ttl) else {
            return Err("ttl-overflow");
        };
        let entry = NativeMemoryCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: response.headers().to_vec(),
            content_length: response.content_length(),
            body,
            body_sha256: Arc::new(native_cache_body_sha256(response.body())),
            expires_at,
            stale_while_revalidate_until: None,
            stale_if_error_until: None,
            stale_reuse_forbidden: false,
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
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
        Ok(())
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

fn lock_static_cache(
    state: &Mutex<NativeStaticMemoryCacheState>,
) -> std::sync::MutexGuard<'_, NativeStaticMemoryCacheState> {
    lock_native_memory_cache(state, "static web")
}
