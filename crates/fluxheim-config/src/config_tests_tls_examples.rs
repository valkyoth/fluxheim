use crate::{Config, TlsClientAuthMode, TlsPolicyProfile, TlsProtocolVersion};

#[test]
fn downstream_tls_guide_examples_validate_without_plaintext_exposure() {
    for source in [
        include_str!("../../../examples/tls/static.toml"),
        include_str!("../../../examples/tls/sni.toml"),
        include_str!("../../../examples/tls/mtls.toml"),
        include_str!("../../../examples/access/mtls.toml"),
    ] {
        let root = super::super::secure_test_dir("tls-guide");
        let mut config: Config = toml::from_str(source).unwrap();
        for certificate in &mut config.tls.certificates {
            certificate.resolve_relative_paths(&root);
        }
        if let Some(path) = &mut config.tls.client_auth.ca_path {
            *path = root.join(&*path);
        }
        for vhost in &mut config.vhosts {
            vhost.tls.resolve_relative_paths(&root);
            vhost.web.root = Some(root.join("site"));
        }
        config.validate().unwrap();
        assert!(config.server.listen.is_empty());
        assert_eq!(config.server.tls_listen, ["127.0.0.1:8443"]);
        assert!(config.tls.enabled);
        assert_eq!(
            config.tls.effective_min_protocol(),
            TlsProtocolVersion::Tls12
        );
        config.tls.profile = TlsPolicyProfile::Modern;
        config.validate().unwrap();
        assert_eq!(
            config.tls.effective_min_protocol(),
            TlsProtocolVersion::Tls13
        );
        config.tls.min_protocol = Some(TlsProtocolVersion::Tls12);
        assert!(config.validate().is_err());
        config.tls.min_protocol = None;
        if config.tls.client_auth.mode == TlsClientAuthMode::Required {
            config.tls.client_auth.mode = TlsClientAuthMode::Optional;
            config.validate().unwrap();
            config.tls.client_auth.ca_path = None;
            assert!(config.validate().is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
