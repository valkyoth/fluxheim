use super::super::*;

#[test]
fn parses_tls_acme_config_with_actalis_eab() {
    let storage = secure_test_dir("config-actalis-acme");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            default_issuer = "actalis"
            challenge = "http-01"
            automation = "external"

            [tls.acme.renewal]
            enabled = true
            renew_before_secs = 2592000
            renew_after = 2026-06-01T00:00:00Z
            check_interval_secs = 3600
            retry_initial_secs = 300
            retry_max_secs = 86400
            reload_after_renewal = true
            zero_downtime_reload = true

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(config.tls.enabled);
    assert_eq!(config.tls.backend, super::super::super::TlsBackend::Rustls);
    assert!(config.tls.acme.enabled);
    assert_eq!(config.tls.acme.storage, Some(storage));
    assert_eq!(config.tls.acme.default_issuer, "actalis");
    assert_eq!(
        config.tls.acme.challenge,
        super::super::super::AcmeChallenge::Http01
    );
    assert_eq!(
        config.tls.acme.automation,
        super::super::super::AcmeAutomationMode::External
    );
    assert_eq!(config.tls.acme.renewal.renew_before_secs, 2_592_000);
    assert!(config.tls.acme.renewal.renew_after.is_some());
    config.validate().unwrap();
}

#[test]
fn accepts_tls_alpn_acme_with_rustls_tls_listener() {
    let storage = secure_test_dir("config-tls-alpn-acme");
    let certificate_dir = secure_test_dir("config-tls-alpn-certificate");
    let cert_path = safe_child_path(&certificate_dir, "localhost-cert.pem");
    let key_path = safe_child_path(&certificate_dir, "localhost-key.pem");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [tls]
            enabled = true
            backend = "rustls"

            [[tls.certificates]]
            cert_path = '{}'
            key_path = '{}'

            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
        cert_path.display(),
        key_path.display(),
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.tls.acme.challenge,
        super::super::super::AcmeChallenge::TlsAlpn01
    );
    config.validate().unwrap();
}

#[test]
fn rejects_tls_alpn_acme_without_tls_listener() {
    let storage = secure_test_dir("config-tls-alpn-no-listener");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.acme.challenge",
            ..
        })
    ));
}

#[test]
fn parses_tls_policy_config() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            profile = "modern"
            min_protocol = "tls1.3"
            alpn = "http2"
            curve_preferences = ["X25519", "CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
            "#,
    )
    .unwrap();

    assert_eq!(config.tls.profile, TlsPolicyProfile::Modern);
    assert_eq!(
        config.tls.effective_min_protocol(),
        TlsProtocolVersion::Tls13
    );
    assert_eq!(config.tls.effective_alpn(), TlsAlpnPolicy::Http2);
    assert_eq!(
        config.tls.effective_curve_preferences(),
        [
            TlsCurvePreference::X25519,
            TlsCurvePreference::P256,
            TlsCurvePreference::P384
        ]
    );
    assert_eq!(
        config.tls.effective_cipher_suites(),
        [
            TlsCipherSuite::Tls13Aes256GcmSha384,
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256
        ]
    );
    config.validate().unwrap();
}

#[test]
fn parses_tls_fips_config_and_requires_fips_capable_build() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert!(config.tls.fips.required);
    assert_eq!(config.tls.compliance_mode().label(), "FIPS 140-3");

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.fips.required",
            reason: "FIPS-required mode requires a FIPS-capable TLS backend feature such as tls-rustls-fips or tls-openssl-fips; see docs/fips.md",
        })
    );

    #[cfg(feature = "tls-openssl-fips")]
    assert_eq!(config.validate(), Ok(()));

    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
        })
    );
}

#[test]
fn parses_tls_iso19790_config_as_required_compliance_alias() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.iso19790]
            required = true
            "#,
    )
    .unwrap();

    assert!(config.tls.iso19790.required);
    assert_eq!(config.tls.compliance_mode().label(), "ISO/IEC 19790");

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.iso19790.required",
            reason: "ISO/IEC 19790-required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790; see docs/fips.md",
        })
    );

    #[cfg(feature = "tls-openssl-fips")]
    assert_eq!(config.validate(), Ok(()));

    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.iso19790.required requires a configured backend supported by this FIPS/ISO-capable build",
        })
    );
}

#[test]
#[cfg(any(
    all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")),
    all(feature = "tls-openssl-fips", not(feature = "tls-rustls-fips"))
))]
fn rejects_tls_fips_policy_with_unsupported_backend_for_build() {
    #[cfg(feature = "tls-openssl-fips")]
    let backend = "rustls";
    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    let backend = "openssl";
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
        })
    );
}

#[test]
fn rejects_tls_fips_policy_with_non_nist_group() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            curve_preferences = ["X25519", "CurveP256"]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.curve_preferences",
            reason: "tls.fips.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more",
        })
    );
}

#[test]
fn rejects_tls_fips_policy_with_chacha20_cipher() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            reason: "tls.fips.required rejects non-FIPS cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider",
        })
    );
}
