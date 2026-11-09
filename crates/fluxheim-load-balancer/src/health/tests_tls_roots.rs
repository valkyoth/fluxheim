use super::*;

impl FluxTcpHealthCheckTls {
    pub(in crate::health) fn trust_fixture_certificate(&mut self, certificate: &[u8], grpc: bool) {
        #[cfg(feature = "tls-rustls-backend")]
        {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    certificate.to_vec(),
                ))
                .unwrap();
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![if grpc {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }];
            self.config = Arc::new(config);
        }
        #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
        {
            let mut builder =
                openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
            let mut roots = openssl::x509::store::X509StoreBuilder::new().unwrap();
            roots
                .add_cert(openssl::x509::X509::from_der(certificate).unwrap())
                .unwrap();
            builder.set_cert_store(roots.build());
            builder
                .set_alpn_protos(if grpc { b"\x02h2" } else { b"\x08http/1.1" })
                .unwrap();
            self.connector = builder.build();
        }
    }
}
