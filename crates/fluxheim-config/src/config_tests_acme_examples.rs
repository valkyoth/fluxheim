use super::*;

const HTTP: &str = include_str!("../../../examples/acme-http-01.toml");

fn recipe(source: &str, root: &Path) -> Config {
    let mut config: Config = toml::from_str(source).unwrap();
    config.tls.acme.storage = Some(root.join("acme"));
    for vhost in &mut config.vhosts {
        vhost.web.root = Some(root.to_owned());
    }
    config
}

#[test]
fn acme_guide_templates_validate_without_implied_terms_acceptance() {
    for source in [HTTP, include_str!("../../../examples/acme-actalis.toml")] {
        let root = secure_test_dir("acme-guide-template");
        let config = recipe(source, &root);
        config.validate().unwrap();
        config
            .validate_for_scope(crate::ValidationScope::Acme)
            .unwrap();
        assert_eq!(config.server.tls_listen.len(), 1);
        assert_eq!(config.tls.acme.issuers.len(), 1);
        assert!(!config.tls.acme.issuers[0].terms_of_service_agreed);
        assert!(config.vhosts[0].tls.acme.enabled);
        assert_eq!(config.vhosts[0].hosts, config.vhosts[0].tls.acme.domains);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn acme_guide_alpn_requires_tls_listener_and_rustls() {
    let root = secure_test_dir("acme-guide-alpn");
    let mut config = recipe(HTTP, &root);
    config.tls.acme.challenge = crate::AcmeChallenge::TlsAlpn01;
    config.validate().unwrap();
    config.server.tls_listen.clear();
    assert!(config.validate().is_err());
    config.server.tls_listen = vec!["127.0.0.1:8443".parse().unwrap()];
    config.tls.backend = crate::TlsBackend::Openssl;
    assert!(config.validate().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn acme_guide_explicit_issuer_list_replaces_builtins() {
    let root = secure_test_dir("acme-guide-issuer");
    let mut config = recipe(HTTP, &root);
    assert_eq!(config.tls.acme.issuers[0].name, "letsencrypt-staging");
    config.tls.acme.default_issuer = "letsencrypt".to_owned();
    assert!(config.validate().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn acme_account_guide_fragments_validate_with_each_eab_source() {
    let guide = include_str!("../../../docs/guides/acme-accounts.md");
    let fragments: Vec<toml::Value> = guide
        .split("```toml\n")
        .skip(1)
        .map(|section| toml::from_str(section.split_once("```").unwrap().0).unwrap())
        .collect();
    assert_eq!(fragments.len(), 4, "update coverage for new guide examples");
    let root = secure_test_dir("acme-account-guide");
    let mut config = recipe(HTTP, &root);
    config.tls.acme = fragments[0]["tls"]["acme"].clone().try_into().unwrap();
    config.tls.acme.storage = Some(root.join("state"));
    config.vhosts[0].tls.acme = fragments[0]["vhosts"]["tls"]["acme"]
        .clone()
        .try_into()
        .unwrap();
    config.vhosts[0].hosts = config.vhosts[0].tls.acme.domains.clone();
    config.validate().unwrap();
    assert!(!config.tls.acme.issuers[0].terms_of_service_agreed);
    for fragment in &fragments[1..] {
        let mut eab: crate::AcmeExternalAccountBindingConfig =
            fragment["tls"]["acme"]["issuers"]["eab"]
                .clone()
                .try_into()
                .unwrap();
        // Relocate deployment-specific paths without changing source selection.
        if eab.key_id_file.is_some() {
            eab.key_id_file = Some(root.join("kid"));
            eab.hmac_key_file = Some(root.join("hmac"));
        }
        config.tls.acme.issuers[0].eab = Some(eab);
        config.validate().unwrap();
        config
            .validate_for_scope(crate::ValidationScope::Acme)
            .unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn acme_guide_terms_require_url_and_sources_are_exclusive() {
    let root = secure_test_dir("acme-guide-terms");
    let mut config = recipe(HTTP, &root);
    let issuer = &mut config.tls.acme.issuers[0];
    issuer.terms_of_service_agreed = true;
    assert!(config.validate().is_err());
    config.tls.acme.issuers[0].terms_of_service_url =
        Some("https://issuer.example.test/reviewed-terms".to_owned());
    config.validate().unwrap();
    let mut eab = crate::AcmeExternalAccountBindingConfig {
        key_id_env: Some("GUIDE_EAB_KID".to_owned()),
        hmac_key_env: Some("GUIDE_EAB_HMAC_KEY".to_owned()),
        key_id_file: None,
        key_id_credential: None,
        hmac_key_file: None,
        hmac_key_credential: None,
    };
    config.tls.acme.issuers[0].eab = Some(eab.clone());
    config.validate().unwrap();
    eab.key_id_file = Some(root.join("kid"));
    config.tls.acme.issuers[0].eab = Some(eab);
    assert!(config.validate().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn acme_guide_forwarder_is_redirect_exempt_and_preserves_timeouts() {
    let forwarder: crate::VhostAcmeChallengeConfig = toml::from_str(
        r#"
enabled = true
upstream = "127.0.0.1:8090"
connect_timeout_secs = 5
read_timeout_secs = 10
send_timeout_secs = 10
"#,
    )
    .unwrap();
    forwarder.validate("guide").unwrap();
    let route = forwarder.route_config().unwrap();
    assert!(route.https_redirect_exempt);
    assert_eq!(
        route.path_prefix.as_deref(),
        Some("/.well-known/acme-challenge/")
    );
    let proxy = route.proxy.unwrap();
    assert_eq!(proxy.upstream.as_deref(), Some("127.0.0.1:8090"));
    assert_eq!(proxy.connect_timeout_secs, Some(5));
    assert_eq!(proxy.read_timeout_secs, Some(10));
    assert_eq!(proxy.send_timeout_secs, Some(10));
}
