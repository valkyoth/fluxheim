use crate::{NativeHttp1Proxy, NativeHttp1Request, NativeHttp1Upstream};

pub(super) fn write_native_proxy_cache_secret(path: &std::path::Path, contents: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write as _;

        let mut file = fluxheim_config::fs_trust::open_or_create_confidential_file(path).unwrap();
        file.set_len(0).unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
    }
    #[cfg(not(windows))]
    std::fs::write(path, contents).unwrap();
}

pub(super) fn proxy_for(upstream: std::net::SocketAddr) -> NativeHttp1Proxy {
    NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
}

pub(super) fn native_proxy_memory_cache_config() -> fluxheim_config::CacheConfig {
    fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".to_owned()),
        status_reason_header: Some("x-cache-reason".to_owned()),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn native_proxy_disk_cache_config(
    root: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_memory_cache_config();
    cache.memory.enabled = false;
    cache.disk.enabled = true;
    cache.disk.path = Some(root);
    cache.disk.max_size_bytes = fluxheim_config::ByteSize::from_bytes(1024 * 1024);
    cache
}

pub(super) fn native_proxy_encrypted_disk_cache_config(
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_disk_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.key_file = Some(key_file);
    cache
}

pub(super) fn native_proxy_storage_bin_cache_config(
    root: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_disk_cache_config(root);
    cache.disk.backend = fluxheim_config::CacheDiskBackend::StorageBin;
    cache.disk.storage_bin.bin_size_bytes = fluxheim_config::ByteSize::from_bytes(64 * 1024);
    cache
}

pub(super) fn native_proxy_encrypted_storage_bin_cache_config(
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_storage_bin_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.key_file = Some(key_file);
    cache
}

#[cfg(feature = "openbao-cache-encryption")]
pub(super) fn native_proxy_openbao_storage_bin_cache_config(
    root: std::path::PathBuf,
    address: String,
    token_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_storage_bin_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.provider = fluxheim_config::CacheDiskEncryptionProvider::OpenbaoTransit;
    cache.disk.encryption.key_id = Some("native-openbao-v1".to_owned());
    cache.disk.encryption.openbao.address = Some(address);
    cache.disk.encryption.openbao.mount = Some("transit/cache".to_owned());
    cache.disk.encryption.openbao.key_name = Some("native-key".to_owned());
    cache.disk.encryption.openbao.token_file = Some(token_file);
    cache
}

pub(super) fn native_proxy_tiered_cache_config(
    root: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_memory_cache_config();
    cache.disk.enabled = true;
    cache.disk.path = Some(root);
    cache.disk.max_size_bytes = fluxheim_config::ByteSize::from_bytes(1024 * 1024);
    cache
}

pub(super) fn route_test_request(path: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: path.to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "route.test".to_owned())],
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

pub(super) fn response_header(response: &str, name: &str) -> Option<String> {
    let expected = name.to_ascii_lowercase();
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(&expected)
            .then(|| value.trim().to_owned())
    })
}

pub(super) fn response_header_values(response: &str, name: &str) -> Vec<String> {
    response
        .lines()
        .filter_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .collect()
}

pub(super) fn native_route_proxy_test_vhost() -> fluxheim_config::VhostConfig {
    fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: fluxheim_config::ProxyConfig::disabled(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }
}

pub(super) fn native_route_proxy_test_route() -> fluxheim_config::RouteConfig {
    fluxheim_config::RouteConfig {
        name: "route".to_owned(),
        path_exact: Some("/route".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example{uri}".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    }
}
