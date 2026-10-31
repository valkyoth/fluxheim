use crate::Config;

#[test]
fn upstream_tls_guide_examples_validate_and_reject_unsafe_combinations() {
    for source in [
        include_str!("../../../examples/tls/upstream.toml"),
        include_str!("../../../examples/tls/upstream-mtls.toml"),
    ] {
        let root = super::super::secure_test_dir("upstream-tls-guide");
        let mut config: Config = toml::from_str(source).unwrap();
        let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
        let proxy = &mut config.vhosts[0].proxy;
        proxy.resolve_relative_paths(&root);
        assert!(proxy.upstream_tls);
        assert!(proxy.upstream_verify_cert && proxy.upstream_verify_hostname);
        config.validate().unwrap();

        let mut invalid = config.clone();
        invalid.vhosts[0].proxy.upstream_sni = None;
        assert!(
            invalid.validate().is_err(),
            "IP origin requires an identity"
        );
        let mut invalid = config.clone();
        invalid.vhosts[0].proxy.upstream_tls = false;
        assert!(invalid.validate().is_err(), "trust files need TLS");
        let mut invalid = config.clone();
        invalid.vhosts[0].proxy.upstream_verify_cert = false;
        assert!(invalid.validate().is_err());
        invalid.vhosts[0].proxy.upstream_verify_hostname = false;
        assert!(
            invalid.validate().is_err(),
            "custom roots need verification"
        );
        if config.vhosts[0].proxy.upstream_client_cert_path.is_some() {
            let mut invalid = config.clone();
            invalid.vhosts[0].proxy.upstream_client_key_path = None;
            assert!(invalid.validate().is_err(), "client pair must be complete");
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
