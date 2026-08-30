#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
use super::super::*;

#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_capable_backend_for_tests() -> &'static str {
    #[cfg(feature = "tls-openssl-fips")]
    {
        "openssl"
    }
    #[cfg(all(not(feature = "tls-openssl-fips"), feature = "tls-rustls-fips"))]
    {
        "rustls"
    }
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_accepts_provider_backed_admin_auth() {
    let snapshot_store = secure_test_dir("config-fips-admin-snapshot-store");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = '{}'

            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#,
        snapshot_store.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_managed_acme_internal_crypto() {
    let storage = secure_test_dir("config-fips-managed-acme");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "tls.acme.enabled",
            reason: "FIPS/ISO-required mode currently rejects managed ACME because account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate generation are not fully routed through the selected validated provider; use externally issued static certificates or an externally evidenced renewal process for the FIPS evidence boundary",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_can_require_disk_cache_encryption() {
    let root = secure_test_dir("config-fips-require-disk-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            require_disk_cache_encryption = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = '{}'
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_local_cache_encryption() {
    let root = secure_test_dir("config-fips-local-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = '{}'

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_allows_openbao_transit_cache_encryption_boundary() {
    let root = secure_test_dir("config-fips-openbao-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = '{}'

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://127.0.0.1:8200"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_remote_openbao_transit_cache_encryption_boundary() {
    let root = secure_test_dir("config-fips-remote-openbao-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = '{}'

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
        })
    );
}

#[test]
fn fips_otlp_local_collector_exception_accepts_loopback_http_only() {
    assert!(super::super::super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://localhost/v1/traces"
    ));
    assert!(super::super::super::fips_allowed_local_otlp_endpoint(
        "http://[::1]:4318/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "https://127.0.0.1:4318/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://collector.example.test/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://[::1]example.test/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:0/v1/traces"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces?debug=true"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces#fragment"
    ));
    assert!(!super::super::super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces\n"
    ));
}

#[test]
fn fips_openbao_endpoint_accepts_numeric_loopback_http_only() {
    assert!(super::super::super::fips_allowed_local_openbao_endpoint(
        "http://127.0.0.1:8200"
    ));
    assert!(super::super::super::fips_allowed_local_openbao_endpoint(
        "http://[::1]:8200"
    ));
    assert!(!super::super::super::fips_allowed_local_openbao_endpoint(
        "http://localhost:8200"
    ));
    assert!(!super::super::super::fips_allowed_local_openbao_endpoint(
        "https://127.0.0.1:8200"
    ));
    assert!(!super::super::super::fips_allowed_local_openbao_endpoint(
        "https://openbao.internal.example"
    ));
    assert!(!super::super::super::fips_allowed_local_openbao_endpoint(
        "http://[::1]attacker.example.test"
    ));
}

#[test]
fn fips_auth_request_endpoint_accepts_numeric_loopback_http_only() {
    assert!(
        super::super::super::fips_allowed_local_auth_request_endpoint("http://127.0.0.1:4180/auth")
    );
    assert!(
        super::super::super::fips_allowed_local_auth_request_endpoint("http://[::1]:4180/auth")
    );
    assert!(
        !super::super::super::fips_allowed_local_auth_request_endpoint("http://127.0.0.1:4180")
    );
    assert!(
        !super::super::super::fips_allowed_local_auth_request_endpoint(
            "http://localhost:4180/auth"
        )
    );
    assert!(
        !super::super::super::fips_allowed_local_auth_request_endpoint(
            "https://127.0.0.1:4180/auth"
        )
    );
    assert!(
        !super::super::super::fips_allowed_local_auth_request_endpoint(
            "http://[::1]attacker.example.test/auth"
        )
    );
}

#[test]
fn fips_mirror_endpoint_accepts_numeric_loopback_http_only() {
    assert!(super::super::super::fips_allowed_local_mirror_endpoint(
        "http://127.0.0.1:9000"
    ));
    assert!(super::super::super::fips_allowed_local_mirror_endpoint(
        "http://[::1]:9000/shadow"
    ));
    assert!(!super::super::super::fips_allowed_local_mirror_endpoint(
        "http://localhost:9000"
    ));
    assert!(!super::super::super::fips_allowed_local_mirror_endpoint(
        "https://127.0.0.1:9000"
    ));
    assert!(!super::super::super::fips_allowed_local_mirror_endpoint(
        "http://[::1]attacker.example.test"
    ));
}
