#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod listener;
#[cfg(feature = "tls-openssl")]
mod openssl_server_config;
mod policy;
mod provider;
#[cfg(feature = "tls-rustls-backend")]
mod rustls_resolver;
#[cfg(feature = "tls-rustls-backend")]
mod rustls_server_config;
#[cfg(test)]
mod test_certificates;
#[cfg(any(feature = "tls-openssl", feature = "tls-rustls-backend"))]
mod tls_input;

pub use listener::{
    DownstreamCertificateSelector, DownstreamCertificateSource, DownstreamTlsListenerPlan,
    DownstreamTlsPlanError, shared_managed_acme_certificate_owner,
};
#[cfg(feature = "tls-openssl")]
pub use openssl_server_config::{
    OpenSslDownstreamAcceptorError, OpenSslDownstreamCertificateStore,
    OpenSslDownstreamCertificateStoreError, build_openssl_downstream_acceptor,
    build_openssl_downstream_acceptor_with_sni_store,
};
pub use policy::{openssl_cipher_lists, openssl_curve_list, rustls_alpn_protocols};
#[cfg(feature = "tls-rustls-backend")]
pub use policy::{rustls_cipher_suite, rustls_kx_group};
#[cfg(feature = "tls-openssl-fips")]
pub use provider::{
    OpenSslFipsStatus, activate_openssl_fips_provider, probe_openssl_fips_provider,
};
#[cfg(feature = "tls-rustls-fips")]
pub use provider::{RustlsFipsStatus, probe_rustls_fips_provider};
pub use provider::{TlsRuntimeError, validate_fips_runtime_config};
#[cfg(feature = "tls-rustls-backend")]
pub use provider::{install_rustls_crypto_provider, rustls_crypto_provider};
#[cfg(feature = "tls-rustls-backend")]
pub use rustls_resolver::{
    RustlsDownstreamCertificateError, RustlsDownstreamCertificateResolver,
    RustlsTlsAlpnCertificateStore, load_rustls_certified_key_from_paths,
    set_pending_managed_certificate_recorder,
};
#[cfg(feature = "tls-rustls-backend")]
pub use rustls_server_config::{
    RustlsDownstreamServerConfigError, build_rustls_downstream_server_config,
};
