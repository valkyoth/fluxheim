#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod listener;
mod policy;
mod provider;
#[cfg(feature = "tls-rustls-backend")]
mod rustls_resolver;

pub use listener::{
    DownstreamCertificateSelector, DownstreamCertificateSource, DownstreamTlsListenerPlan,
    DownstreamTlsPlanError, shared_managed_acme_certificate_owner,
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
    RustlsTlsAlpnCertificateLoader, load_rustls_certified_key_from_paths,
    set_pending_managed_certificate_recorder,
};
