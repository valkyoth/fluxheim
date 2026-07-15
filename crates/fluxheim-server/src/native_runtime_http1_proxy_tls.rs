#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
use std::sync::Arc;

#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
use fluxheim_config::{Config, TlsAlpnPolicy};

#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
use super::NativeHttp1ProxyRuntimeError;

#[cfg(feature = "tls-rustls-backend")]
const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

#[cfg(feature = "tls-rustls-backend")]
pub(super) fn native_rustls_server_config(
    config: &Config,
) -> Result<
    (
        Arc<rustls::ServerConfig>,
        Arc<fluxheim_tls::RustlsDownstreamCertificateResolver>,
    ),
    NativeHttp1ProxyRuntimeError,
> {
    let plan = native_downstream_tls_listener_plan(config)
        .map_err(NativeHttp1ProxyRuntimeError::TlsPlan)?
        .ok_or(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener)?;
    let resolver = Arc::new(
        fluxheim_tls::RustlsDownstreamCertificateResolver::new(plan.selector())
            .map_err(NativeHttp1ProxyRuntimeError::RustlsCertificate)?,
    );
    let acme_tls_alpn_protocol = plan
        .acme_tls_alpn_enabled()
        .then_some(ACME_TLS_ALPN_PROTOCOL);
    let server_config = fluxheim_tls::build_rustls_downstream_server_config(
        &config.tls,
        resolver.clone(),
        acme_tls_alpn_protocol,
    )
    .map(Arc::new)
    .map_err(NativeHttp1ProxyRuntimeError::RustlsServerConfig)?;
    Ok((server_config, resolver))
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub(super) fn native_openssl_acceptor(
    config: &Config,
) -> Result<
    (
        Arc<openssl::ssl::SslAcceptor>,
        Option<Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>>,
    ),
    NativeHttp1ProxyRuntimeError,
> {
    let plan = native_downstream_tls_listener_plan(config)
        .map_err(NativeHttp1ProxyRuntimeError::TlsPlan)?
        .ok_or(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener)?;
    let selector = plan.selector();
    let default_certificate = selector.certificate_for_sni(None);
    if plan.requires_certificate_resolver() {
        let store = Arc::new(
            fluxheim_tls::OpenSslDownstreamCertificateStore::new(selector, &config.tls, None)
                .map_err(NativeHttp1ProxyRuntimeError::OpenSslCertificateStore)?,
        );
        let acceptor = fluxheim_tls::build_openssl_downstream_acceptor_with_sni_store(
            &config.tls,
            default_certificate,
            store.clone(),
        )
        .map(Arc::new)
        .map_err(NativeHttp1ProxyRuntimeError::OpenSslAcceptor)?;
        return Ok((acceptor, Some(store)));
    }
    let acceptor =
        fluxheim_tls::build_openssl_downstream_acceptor(&config.tls, default_certificate)
            .map(Arc::new)
            .map_err(NativeHttp1ProxyRuntimeError::OpenSslAcceptor)?;
    Ok((acceptor, None))
}

#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
fn native_downstream_tls_listener_plan(
    config: &Config,
) -> Result<Option<fluxheim_tls::DownstreamTlsListenerPlan>, fluxheim_tls::DownstreamTlsPlanError> {
    fluxheim_tls::DownstreamTlsListenerPlan::from_config_with_acme_resolver(
        config,
        native_managed_acme_certificate_source,
    )
}

#[cfg(all(
    any(
        feature = "tls-rustls-backend",
        all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
    ),
    feature = "acme"
))]
fn native_managed_acme_certificate_source(
    config: &Config,
    vhost: &fluxheim_config::VhostConfig,
) -> Option<fluxheim_tls::DownstreamCertificateSource> {
    if !config.tls.acme.enabled {
        return None;
    }
    let storage = config.tls.acme.storage.as_deref()?;
    let owner = if vhost.tls.enabled && vhost.tls.acme.enabled {
        vhost.name.as_str()
    } else {
        fluxheim_tls::shared_managed_acme_certificate_owner(config, vhost)?
    };

    Some(fluxheim_tls::DownstreamCertificateSource {
        certificate: crate::native_http1_acme::native_managed_certificate_config(storage, owner),
        managed_acme: true,
    })
}

#[cfg(all(
    any(
        feature = "tls-rustls-backend",
        all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
    ),
    not(feature = "acme")
))]
fn native_managed_acme_certificate_source(
    _config: &Config,
    _vhost: &fluxheim_config::VhostConfig,
) -> Option<fluxheim_tls::DownstreamCertificateSource> {
    None
}

#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
pub(super) const fn native_tls_alpn_protocols(policy: TlsAlpnPolicy) -> (bool, bool) {
    match policy {
        TlsAlpnPolicy::Http1 => (true, false),
        TlsAlpnPolicy::Http2 => (false, true),
        TlsAlpnPolicy::Http1AndHttp2 => (true, true),
    }
}
