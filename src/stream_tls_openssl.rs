use std::net::IpAddr;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config_net::upstream_host;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVersion};
use openssl::x509::{X509, store::X509StoreBuilder};
use sanitization::SecretVec;

use crate::config::StreamRouteConfig;
use crate::upstream_tls::{read_upstream_tls_file, read_upstream_tls_secret_file};

const OPENSSL_STREAM_UPSTREAM_TLS12_CIPHERS: &str = concat!(
    "ECDHE-ECDSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES128-GCM-SHA256",
);

const OPENSSL_STREAM_UPSTREAM_TLS13_CIPHERS: &str =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

pub(super) fn build_openssl_connector(route: &StreamRouteConfig) -> FluxResult<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|error| {
        FluxError::invalid_input(format!(
            "stream upstream TLS connector setup failed: {error}"
        ))
    })?;
    configure_openssl_stream_tls_baseline(&mut builder)?;
    if let Some(ca_path) = route.upstream_ca_path.as_deref() {
        let contents = read_upstream_tls_file(ca_path)
            .map_err(|error| FluxError::io("read stream upstream TLS CA bundle", error))?;
        let certs = X509::stack_from_pem(&contents).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream CA bundle {}: {error}",
                ca_path.display()
            ))
        })?;
        if certs.is_empty() {
            return Err(FluxError::invalid_input(format!(
                "upstream CA bundle {} contains no certificates",
                ca_path.display()
            )));
        }
        let mut store = X509StoreBuilder::new().map_err(|error| {
            FluxError::invalid_input(format!(
                "stream upstream TLS trust store setup failed: {error}"
            ))
        })?;
        for cert in certs {
            store.add_cert(cert).map_err(|error| {
                FluxError::invalid_input(format!(
                    "failed to add upstream CA bundle {}: {error}",
                    ca_path.display()
                ))
            })?;
        }
        builder.set_cert_store(store.build());
    } else {
        builder.set_default_verify_paths().map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to load default stream upstream TLS trust roots: {error}"
            ))
        })?;
    }

    if let (Some(cert_path), Some(key_path)) = (
        route.upstream_client_cert_path.as_deref(),
        route.upstream_client_key_path.as_deref(),
    ) {
        let cert_contents = read_upstream_tls_file(cert_path)
            .map_err(|error| FluxError::io("read stream upstream TLS client certificate", error))?;
        let key_contents = SecretVec::from_vec(
            read_upstream_tls_secret_file(key_path)
                .map_err(|error| FluxError::io("read stream upstream TLS private key", error))?,
        );
        let certs = X509::stack_from_pem(&cert_contents).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ))
        })?;
        let Some((leaf, intermediates)) = certs.split_first() else {
            return Err(FluxError::invalid_input(format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            )));
        };
        let key = key_contents
            .with_secret(PKey::private_key_from_pem)
            .map_err(|error| {
                FluxError::invalid_input(format!(
                    "failed to parse upstream client private key {}: {error}",
                    key_path.display()
                ))
            })?;
        builder.set_certificate(leaf).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure upstream client certificate {}: {error}",
                cert_path.display()
            ))
        })?;
        for cert in intermediates {
            builder
                .add_extra_chain_cert(cert.clone())
                .map_err(|error| {
                    FluxError::invalid_input(format!(
                        "failed to configure upstream client certificate chain {}: {error}",
                        cert_path.display()
                    ))
                })?;
        }
        builder.set_private_key(&key).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure upstream client private key {}: {error}",
                key_path.display()
            ))
        })?;
    }

    Ok(builder.build())
}

fn configure_openssl_stream_tls_baseline(builder: &mut SslConnectorBuilder) -> FluxResult<()> {
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to set stream upstream TLS minimum version: {error}"
            ))
        })?;
    builder
        .set_cipher_list(OPENSSL_STREAM_UPSTREAM_TLS12_CIPHERS)
        .map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure stream upstream TLS cipher list: {error}"
            ))
        })?;
    builder
        .set_ciphersuites(OPENSSL_STREAM_UPSTREAM_TLS13_CIPHERS)
        .map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure stream upstream TLS 1.3 ciphersuites: {error}"
            ))
        })?;
    Ok(())
}

pub(super) fn stream_upstream_tls_sni(
    configured: Option<&str>,
    upstream_authority: &str,
) -> String {
    configured
        .map(str::to_owned)
        .or_else(|| {
            let host = upstream_host(upstream_authority)?;
            host.parse::<IpAddr>().is_err().then_some(host)
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{configure_openssl_stream_tls_baseline, stream_upstream_tls_sni};
    use openssl::ssl::{SslConnector, SslMethod, SslVersion};

    #[test]
    fn openssl_sni_derives_only_dns_hosts() {
        assert_eq!(
            stream_upstream_tls_sni(None, "backend.example.test:443"),
            "backend.example.test"
        );
        assert_eq!(stream_upstream_tls_sni(None, "127.0.0.1:443"), "");
        assert_eq!(
            stream_upstream_tls_sni(Some("configured.example.test"), "127.0.0.1:443"),
            "configured.example.test"
        );
    }

    #[test]
    fn openssl_stream_tls_baseline_sets_tls12_minimum() {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        configure_openssl_stream_tls_baseline(&mut builder).unwrap();

        assert_eq!(builder.min_proto_version(), Some(SslVersion::TLS1_2));
    }
}
