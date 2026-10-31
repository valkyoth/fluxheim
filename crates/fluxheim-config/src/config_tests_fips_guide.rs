use super::*;

const GUIDE: &str = include_str!("../../../docs/guides/fips.md");
const EXAMPLE: &str = include_str!("../../../examples/fips/proxy.toml");
const CAPABLE: bool = cfg!(any(
    feature = "tls-openssl-fips",
    feature = "tls-rustls-fips"
));

fn backend() -> &'static str {
    if cfg!(feature = "tls-openssl-fips") {
        "openssl"
    } else {
        "rustls"
    }
}

fn snippet(prefix: &str) -> &str {
    GUIDE
        .split("```toml\n")
        .skip(1)
        .map(|block| block.split("```").next().unwrap())
        .find(|block| block.starts_with(prefix))
        .unwrap()
}

fn policy() -> Config {
    toml::from_str(&snippet("[tls]\n").replace(
        "backend = \"openssl\"",
        &format!("backend = {:?}", backend()),
    ))
    .unwrap()
}

#[test]
fn fips_guide_complete_example_resolves_private_paths_and_matches_build() {
    let dir = TestDir::new("fips-guide-example");
    fs::create_dir(dir.child("certs")).unwrap();
    // Configuration validation checks paths; real PEM/provider/TLS proof is separate.
    for name in ["server.pem", "server-key.pem", "origin-ca.pem"] {
        fs::write(
            dir.child(&format!("certs/{name}")),
            b"path-validation-fixture",
        )
        .unwrap();
    }
    fs::write(
        dir.child("proxy.toml"),
        EXAMPLE.replace(
            "backend = \"openssl\"",
            &format!("backend = {:?}", backend()),
        ),
    )
    .unwrap();
    let result = Config::load(Some(&dir.child("proxy.toml")));
    if !CAPABLE {
        assert!(result.is_err());
        return;
    }
    let config = result.unwrap();
    assert!(config.server.listen.is_empty());
    assert_eq!(config.server.tls_listen, ["127.0.0.1:8443"]);
    assert_eq!(
        config.tls.certificates[0].key_path,
        dir.child("certs/server-key.pem")
    );
    let proxy = &config.vhosts[0].proxy;
    assert!(proxy.upstream_tls && proxy.upstream_verify_cert && proxy.upstream_verify_hostname);
    assert_eq!(
        proxy.upstream_ca_path,
        Some(dir.child("certs/origin-ca.pem"))
    );
    assert!(!config.cache.enabled && !config.admin.enabled && !config.tls.acme.enabled);
}

#[test]
fn fips_guide_flags_are_opt_in_and_aliases_share_enforcement() {
    let defaults = Config::default().tls;
    assert!(!defaults.fips.required && !defaults.iso19790.required);
    assert!(!defaults.fips.require_disk_cache_encryption);
    assert!(!defaults.iso19790.require_disk_cache_encryption);
    for (fips, iso) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut config = policy();
        config.tls.fips.required = fips;
        config.tls.iso19790.required = iso;
        config.tls.fips.require_disk_cache_encryption = true;
        config.tls.iso19790.require_disk_cache_encryption = true;
        assert_eq!(config.tls.compliance_mode().required(), fips || iso);
        assert_eq!(config.tls.validate().is_ok(), CAPABLE || !(fips || iso));
        config.tls.enabled = false;
        assert_eq!(config.tls.validate().is_ok(), CAPABLE || !(fips || iso));
    }
}

#[test]
fn fips_guide_rejects_implicit_algorithms_and_nonexistent_profile() {
    let mut config = policy();
    config.tls.curve_preferences.clear();
    assert!(matches!(
        config.tls.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.curve_preferences",
            ..
        })
    ));
    let mut config = policy();
    config.tls.cipher_suites.clear();
    assert!(matches!(
        config.tls.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            ..
        })
    ));
    for field in ["profile = \"fips\"", "compliance_mode = \"fips\""] {
        assert!(toml::from_str::<Config>(&format!("[tls]\n{field}")).is_err());
    }
}

#[test]
fn fips_guide_tls12_suites_require_tls12_policy() {
    let suites: toml::Value = toml::from_str(snippet("cipher_suites = [\n")).unwrap();
    let mut config = policy();
    config.tls.cipher_suites = suites["cipher_suites"].clone().try_into().unwrap();
    assert_eq!(config.tls.cipher_suites.len(), 6);
    assert!(config.tls.validate().is_err());
    config.tls.profile = TlsPolicyProfile::Intermediate;
    config.tls.min_protocol = Some(TlsProtocolVersion::Tls12);
    assert_eq!(config.tls.validate().is_ok(), CAPABLE);
}

#[test]
#[cfg(any(feature = "tls-openssl-fips", feature = "tls-rustls-fips"))]
fn fips_guide_required_mtls_needs_a_crl() {
    let root = TestDir::new("fips-guide-mtls");
    let mut config = policy();
    let client: Config = toml::from_str(snippet("[tls.client_auth]\n")).unwrap();
    config.tls.client_auth = client.tls.client_auth;
    config.tls.client_auth.ca_path = Some(root.child("client-ca.pem"));
    config.tls.client_auth.crl_path = Some(root.child("client-crls.pem"));
    config.tls.validate().unwrap();
    config.tls.client_auth.crl_path = None;
    assert!(matches!(
        config.tls.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.client_auth.crl_path",
            ..
        })
    ));
}

#[test]
#[cfg(any(feature = "tls-openssl-fips", feature = "tls-rustls-fips"))]
fn fips_guide_disk_flags_apply_only_in_required_mode() {
    let root = TestDir::new("fips-guide-cache");
    let mut config = policy();
    let cache: Config = toml::from_str(snippet("[cache]\n")).unwrap();
    config.cache = cache.cache;
    config.cache.disk.path = Some(root.child("cache"));
    config.validate().unwrap();
    config.cache.disk.encryption.enabled = false;
    config.validate().unwrap();
    for (fips, iso) in [(true, false), (false, true), (true, true)] {
        config.tls.fips.require_disk_cache_encryption = fips;
        config.tls.iso19790.require_disk_cache_encryption = iso;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidCompliancePolicy { field: "cache", .. })
        ));
    }
    config.tls.fips.required = false;
    config.validate().unwrap();
    config.tls.iso19790.required = true;
    assert!(config.validate().is_err());
    config.cache.disk.enabled = false;
    config.cache.memory.enabled = true;
    config.validate().unwrap();
}

#[test]
#[cfg(all(
    any(feature = "tls-openssl-fips", feature = "tls-rustls-fips"),
    feature = "metrics-otlp",
    feature = "otel-otlp",
    feature = "otel-tracing",
    not(feature = "privacy-mode")
))]
fn fips_guide_collectors_accept_loopback_but_not_https_or_bearer() {
    let local: Config = toml::from_str(snippet("[metrics]\n")).unwrap();
    let mut config = policy();
    config.metrics = local.metrics;
    config.tracing = local.tracing;
    config.validate().unwrap();
    for traces in [false, true] {
        let mut remote = config.clone();
        if traces {
            remote.tracing.otlp.endpoint = "https://collector.example.test/v1/traces".into();
        } else {
            remote.metrics.otlp.endpoint = "https://collector.example.test/v1/metrics".into();
        }
        assert!(matches!(
            remote.validate(),
            Err(ConfigError::InvalidCompliancePolicy { .. })
        ));
        let mut token = config.clone();
        if traces {
            token.tracing.otlp.bearer_token_file = Some("not-read-token".into());
        } else {
            token.metrics.otlp.bearer_token_file = Some("not-read-token".into());
        }
        assert!(
            token
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requires HTTPS")
        );
    }
}
