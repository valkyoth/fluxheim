use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use tokio::sync::Semaphore;

mod paths;

use crate::native_http1_php::{
    NativePhpResponsePlan, NativePhpScriptResolve, native_php_execute_fpm, native_php_request_body,
    native_php_request_plan,
};
use crate::native_http1_route_proxy::NativeHttp1RouteProxyConfigError;
use crate::native_http1_route_rewrite::request_path_and_query;
use crate::{
    NativeHttp1ProxyConfigError, NativeHttp1Request, NativeHttp1Response, NativeHttp1StaticWeb,
};
use paths::{native_php_fpm_root, native_php_root};

#[derive(Clone, Debug)]
pub(crate) struct NativePhpFpmRoute {
    config: fluxheim_config::PhpConfig,
    root: PathBuf,
    fpm_root: PathBuf,
    files: NativeHttp1StaticWeb,
    error_pages: Vec<NativePhpErrorPage>,
    vhost_name: String,
    _managed_fpm: Option<Arc<fluxheim_php_fpm::ManagedPhpFpmProcess>>,
    pools: Vec<Arc<fluxheim_php_fpm::PhpFpmPool>>,
    next_endpoint: Arc<AtomicUsize>,
    in_flight: Arc<Semaphore>,
}

impl PartialEq for NativePhpFpmRoute {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.root == other.root
            && self.fpm_root == other.fpm_root
            && self.files == other.files
            && self.error_pages == other.error_pages
            && self.vhost_name == other.vhost_name
    }
}

impl Eq for NativePhpFpmRoute {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativePhpErrorPage {
    status: u16,
    path: String,
    web: NativeHttp1StaticWeb,
}

impl NativePhpFpmRoute {
    pub(crate) fn from_config(
        scope: impl std::fmt::Display,
        vhost_name: &str,
        metric_pool: &str,
        config: &fluxheim_config::PhpConfig,
    ) -> Result<Option<Self>, NativeHttp1RouteProxyConfigError> {
        if !config.enabled {
            return Ok(None);
        }
        let scope = scope.to_string();
        let root = native_php_root(&scope, config).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let fpm_root = native_php_fpm_root(&scope, config, &root).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let files = NativeHttp1StaticWeb::from_config(&fluxheim_config::WebConfig {
            root: Some(root.clone()),
            index_files: vec![config.index.clone()],
            deny_dotfiles: true,
            directory_listing: fluxheim_config::DirectoryListingConfig::default(),
            cache_control: "private, no-store".to_owned(),
            expires: None,
        })
        .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        .ok_or(NativeHttp1RouteProxyConfigError::StaticWeb)?;
        let error_pages = native_php_error_pages_from_config(config).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let mut runtime_config = config.clone();
        let managed_fpm =
            fluxheim_php_fpm::managed_php_fpm_from_config(&scope, metric_pool, &mut runtime_config)
                .map_err(|error| {
                    log::error!(
                        target: "fluxheim::php_fpm",
                        "{scope}: managed PHP-FPM startup failed: {error}"
                    );
                    NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
                })?;
        let pools = fluxheim_php_fpm::php_fpm_keepalive_pools_from_config(
            &runtime_config,
            vhost_name,
            metric_pool,
            fluxheim_php_fpm::PhpFpmPoolMetrics::default(),
        );
        runtime_config.fpm.mode = fluxheim_config::PhpFpmMode::External;
        Ok(Some(Self {
            config: runtime_config,
            root,
            fpm_root,
            files,
            error_pages,
            vhost_name: vhost_name.to_owned(),
            _managed_fpm: managed_fpm,
            pools,
            next_endpoint: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
        }))
    }

    pub(crate) const fn request_timeout_secs(&self) -> u64 {
        self.config.request_timeout_secs
    }

    pub(crate) async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        if !native_php_method_allowed(&request.method) {
            return NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
                .with_header("allow", "GET, HEAD, POST")
                .close_connection();
        }
        let Some((path, _)) = request_path_and_query(&request) else {
            return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                .close_connection();
        };
        let resolved = self.files.resolve_php_script(&self.config, &path, true);
        self.handle_resolved(request, path, resolved).await
    }

    pub(crate) async fn handle_resolved(
        &self,
        request: NativeHttp1Request,
        path: String,
        resolved: io::Result<NativePhpScriptResolve>,
    ) -> NativeHttp1Response {
        let script = match resolved {
            Ok(NativePhpScriptResolve::Execute(script)) => script,
            Ok(NativePhpScriptResolve::RedirectDirectorySlash) => {
                return NativeHttp1Response::new(308, "Permanent Redirect", Vec::new())
                    .with_header("location", format!("{path}/"))
                    .close_connection();
            }
            Ok(NativePhpScriptResolve::Decline | NativePhpScriptResolve::NotFound) => {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            Ok(NativePhpScriptResolve::Forbidden) => {
                return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                    .close_connection();
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm script resolution failed: {error}"
                );
                return NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                    .close_connection();
            }
        };
        let Ok(_permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            return NativeHttp1Response::new(503, "Service Unavailable", b"php busy\n")
                .with_retry_after_secs(1)
                .close_connection();
        };
        let body = match native_php_request_body(&request, &self.config).await {
            Ok(body) if self.config.pass_request_body => body,
            Ok(_) => fluxheim_php_fpm::PhpRequestBody::memory(Vec::new()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                return NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                    .close_connection();
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm request body planning failed: {error}"
                );
                return NativeHttp1Response::new(502, "Bad Gateway", b"php-fpm failed\n")
                    .close_connection();
            }
        };
        let server_port = native_php_server_port(&self.config, &request);
        let plan = match native_php_request_plan(
            &request,
            &self.config,
            &self.root,
            &self.fpm_root,
            &script.local_path,
            &self.vhost_name,
            &server_port,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native php-fpm request plan rejected request: {error}"
                );
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            }
        };
        match native_php_execute_fpm(
            &self.config,
            &plan,
            body,
            &self.pools,
            self.next_endpoint.as_ref(),
        )
        .await
        {
            Ok(NativePhpResponsePlan {
                response,
                intercept_status: None,
            }) => response,
            Ok(NativePhpResponsePlan {
                response,
                intercept_status: Some(status),
            }) => self
                .error_page_response(&request, status)
                .unwrap_or(response),
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "native php-fpm request failed: {error}");
                NativeHttp1Response::new(502, "Bad Gateway", b"php-fpm failed\n").close_connection()
            }
        }
    }

    pub(crate) fn resolve_for_fallback(
        &self,
        path: &str,
    ) -> Option<io::Result<NativePhpScriptResolve>> {
        let resolved = self.files.resolve_php_script(&self.config, path, true);
        match &resolved {
            Ok(
                NativePhpScriptResolve::Execute(_)
                | NativePhpScriptResolve::RedirectDirectorySlash
                | NativePhpScriptResolve::Forbidden,
            ) => Some(resolved),
            Ok(NativePhpScriptResolve::Decline | NativePhpScriptResolve::NotFound) => None,
            Err(error) if self.resolution_error_requires_php_fail_closed(path) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm script pre-resolution failed; routing to php-fpm fail-closed path: {error}"
                );
                Some(resolved)
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm front-controller pre-resolution failed; deferring to static fallback before php-fpm: {error}"
                );
                None
            }
        }
    }

    fn resolution_error_requires_php_fail_closed(&self, path: &str) -> bool {
        let Some(parsed_script) = fluxheim_php_fpm::php_script_name_for_request(
            path,
            &self.config.index,
            self.config.path_info,
            &self.config.allowed_extensions,
        ) else {
            return true;
        };
        parsed_script.explicit_php
            || fluxheim_php_fpm::php_script_name_denied(
                &self.config.deny_path_prefixes,
                &parsed_script.script_name,
            )
    }

    fn error_page_response(
        &self,
        request: &NativeHttp1Request,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        self.error_pages
            .iter()
            .find(|page| page.status == status)
            .and_then(|page| page.web.handle_error_page(request, &page.path, status))
            .map(NativeHttp1Response::close_connection)
    }
}

fn native_php_error_pages_from_config(
    config: &fluxheim_config::PhpConfig,
) -> Result<Vec<NativePhpErrorPage>, NativeHttp1ProxyConfigError> {
    let mut pages = Vec::with_capacity(config.error_pages.len());
    for page in &config.error_pages {
        let web = NativeHttp1StaticWeb::from_config(&page.web)
            .map_err(|_| NativeHttp1ProxyConfigError::ErrorPages)?
            .ok_or(NativeHttp1ProxyConfigError::ErrorPages)?;
        pages.push(NativePhpErrorPage {
            status: page.status,
            path: page.path.clone(),
            web,
        });
    }
    Ok(pages)
}

fn native_php_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "POST")
}

fn native_php_server_port(
    config: &fluxheim_config::PhpConfig,
    request: &NativeHttp1Request,
) -> String {
    config
        .server_port
        .or_else(|| native_php_request_host(request).and_then(native_php_explicit_authority_port))
        .unwrap_or(if request.downstream_tls { 443 } else { 80 })
        .to_string()
}

fn native_php_request_host(request: &NativeHttp1Request) -> Option<&str> {
    request.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("host")
            .then_some(value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn native_php_explicit_authority_port(authority: &str) -> Option<u16> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (_, after_host) = rest.split_once(']')?;
        return after_host.strip_prefix(':')?.parse().ok();
    }
    let (_, port) = authority.rsplit_once(':')?;
    port.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn php_fallback_handle_uses_pre_resolved_script_result() {
        let root = tempfile::TempDir::new().expect("create php root");
        let script = root.path().join("index.php");
        std::fs::write(&script, b"<?php echo 'ok';").expect("write php script");
        let php = test_php_route(root.path());
        let request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/index.php".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![("host".to_owned(), "test.local".to_owned())],
            body: zeroize::Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };

        let response = php
            .handle_resolved(
                request,
                "/index.php".to_owned(),
                Ok(NativePhpScriptResolve::Forbidden),
            )
            .await;

        assert_eq!(response.status(), 403);
    }

    #[cfg(unix)]
    #[test]
    fn php_fallback_defers_non_php_resolution_errors_to_static() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::TempDir::new().expect("create php root");
        std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';")
            .expect("write index script");
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).expect("create locked dir");
        std::fs::write(locked.join("asset.txt"), b"asset").expect("write static asset");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock dir");
        let php = test_php_route(root.path());

        let resolved = php.resolve_for_fallback("/locked/asset.txt");

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock dir");
        assert!(resolved.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn php_fallback_routes_explicit_php_resolution_errors_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::TempDir::new().expect("create php root");
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).expect("create locked dir");
        std::fs::write(locked.join("secret.php"), b"<?php echo 'secret';")
            .expect("write php script");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock dir");
        let php = test_php_route(root.path());

        let resolved = php.resolve_for_fallback("/locked/secret.php");

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock dir");
        assert!(matches!(resolved, Some(Err(_))));
    }

    fn test_php_route(root: &Path) -> NativePhpFpmRoute {
        let files = NativeHttp1StaticWeb::from_config(&fluxheim_config::WebConfig {
            root: Some(root.to_path_buf()),
            index_files: vec!["index.php".to_owned()],
            deny_dotfiles: true,
            directory_listing: fluxheim_config::DirectoryListingConfig::default(),
            cache_control: "private, no-store".to_owned(),
            expires: None,
        })
        .expect("build static resolver")
        .expect("static resolver enabled");
        NativePhpFpmRoute {
            config: fluxheim_config::PhpConfig {
                enabled: true,
                root: Some(root.to_path_buf()),
                ..Default::default()
            },
            root: root.to_path_buf(),
            fpm_root: root.to_path_buf(),
            files,
            error_pages: Vec::new(),
            vhost_name: "test.local".to_owned(),
            _managed_fpm: None,
            pools: Vec::new(),
            next_endpoint: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(Semaphore::new(1)),
        }
    }
}
