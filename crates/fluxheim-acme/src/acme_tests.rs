use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use fluxheim_config::{
    AcmeConfig, AcmeExternalAccountBindingConfig, AcmeIssuerConfig, CacheConfig, Config,
    ProxyConfig, TlsConfig, VhostAcmeConfig, VhostConfig, VhostTlsConfig, WebConfig,
};

use super::{
    AcmeAccountStoreError, AcmeCertificateInstallError, AcmeHttp01Challenge,
    AcmeHttp01ChallengeStore, AcmeIssuedCertificate, AcmePreparedHttp01Order, AcmeRenewalError,
    AcmeSecretLoadError, CertificateObservation, MAX_ACCOUNT_CREDENTIALS_BYTES,
    MAX_EAB_SECRET_BYTES, account_credentials_path, acme_client_error_message_with_http_01_context,
    execute_renewal, http_01_token_from_path, install_managed_certificate,
    load_account_credentials, load_certificate_not_after, load_external_account_binding,
    managed_certificate_paths, next_retry_at, observe_configured_certificates, plan_renewal_queue,
    remove_account_credentials, renewal_targets, store_account_credentials,
    toml_offset_datetime_to_system_time,
};
#[cfg(feature = "acme-client")]
use super::{
    AcmeCertificatePaths, AcmeInstantClientError, AcmeTlsAlpn01ChallengeStore, decode_eab_hmac_key,
    recover_managed_certificate_transaction, renew_selected_instant_acme_targets,
    tls_alpn_01_certificate,
};
use proptest::prelude::*;

#[cfg(feature = "acme-client")]
#[path = "acme_tests_lifecycle.rs"]
mod lifecycle;
#[path = "acme_tests_plan.rs"]
mod plan;
#[path = "acme_tests_renewal.rs"]
mod renewal;
#[path = "acme_tests_storage.rs"]
mod storage;

fn acme_config_with_vhosts(vhosts: Vec<VhostConfig>) -> Config {
    Config {
        tls: TlsConfig {
            enabled: true,
            acme: AcmeConfig {
                enabled: true,
                storage: Some(PathBuf::from("/var/lib/fluxheim/acme")),
                ..AcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        vhosts,
        ..Config::default()
    }
}

fn managed_vhost(name: &str) -> VhostConfig {
    VhostConfig {
        name: name.to_owned(),
        hosts: vec![format!("{name}.test")],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        acme_challenge: fluxheim_config::VhostAcmeChallengeConfig::default(),
        redirect: fluxheim_config::VhostRedirectConfig::default(),
        tls: VhostTlsConfig {
            enabled: true,
            acme: VhostAcmeConfig {
                enabled: true,
                issuer: None,
                domains: Vec::new(),
            },
            certificate: None,
        },
        proxy: ProxyConfig::default(),
        cache: CacheConfig::default(),
        compression: None,
        headers: fluxheim_config::VhostHeaderPolicyConfig::default(),
        php: fluxheim_config::PhpConfig::default(),
        web: WebConfig::default(),
        routes: Vec::new(),
    }
}

fn eab_file_issuer(key_id: &std::path::Path, hmac_key: &std::path::Path) -> AcmeIssuerConfig {
    AcmeIssuerConfig {
        name: "actalis".to_owned(),
        directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
        terms_of_service_agreed: false,
        terms_of_service_url: None,
        allow_unadvertised_terms_of_service: false,
        ca_bundle_file: None,
        eab: Some(AcmeExternalAccountBindingConfig {
            key_id_env: None,
            key_id_file: Some(key_id.to_path_buf()),
            key_id_credential: None,
            hmac_key_env: None,
            hmac_key_file: Some(hmac_key.to_path_buf()),
            hmac_key_credential: None,
        }),
    }
}

fn test_certificate_pem() -> &'static [u8] {
    test_issued_material().0.as_bytes()
}

fn valid_leaf_certificate_pem() -> &'static [u8] {
    include_bytes!("../../../tests/fixtures/tls/localhost-cert.pem")
}

fn test_private_key_pem() -> &'static [u8] {
    test_issued_material().1.as_bytes()
}

fn test_issued_material() -> &'static (String, String) {
    static MATERIAL: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    MATERIAL.get_or_init(|| {
        let certified = rcgen::generate_simple_self_signed(["example.test".to_owned()]).unwrap();
        (certified.cert.pem(), certified.signing_key.serialize_pem())
    })
}

fn issued_material_for(domains: &[&str]) -> (String, String) {
    let certified = rcgen::generate_simple_self_signed(
        domains
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    (certified.cert.pem(), certified.signing_key.serialize_pem())
}

fn test_account_credentials() -> instant_acme::AccountCredentials {
    serde_json::from_str(test_account_credentials_json()).unwrap()
}

fn test_account_credentials_json() -> &'static str {
    r#"{"id":"https://acme.example.test/acct/1","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","directory":"https://acme.example.test/directory"}"#
}

struct FakeAcmeIssuerClient {
    prepare_calls: usize,
    finalize_calls: usize,
    fail_finalize: bool,
}

impl FakeAcmeIssuerClient {
    fn new() -> Self {
        Self {
            prepare_calls: 0,
            finalize_calls: 0,
            fail_finalize: false,
        }
    }
}

impl super::AcmeIssuerClient for FakeAcmeIssuerClient {
    type Error = &'static str;

    fn prepare_http_01_order(
        &mut self,
        request: super::AcmeIssueRequest<'_>,
    ) -> Result<AcmePreparedHttp01Order, Self::Error> {
        self.prepare_calls += 1;
        assert_eq!(request.target.vhost_name, "example");
        assert_eq!(
            request.issuer_directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );

        Ok(AcmePreparedHttp01Order {
            challenges: vec![AcmeHttp01Challenge {
                token: "token_123".to_owned(),
                key_authorization: "token_123.thumbprint".to_owned(),
            }],
        })
    }

    fn finalize_http_01_order(
        &mut self,
        _order: &AcmePreparedHttp01Order,
        challenge_store: &AcmeHttp01ChallengeStore,
    ) -> Result<AcmeIssuedCertificate, Self::Error> {
        self.finalize_calls += 1;
        assert_eq!(
            challenge_store
                .load_key_authorization("token_123")
                .map_err(|_| "challenge read failed")?,
            Some("token_123.thumbprint".to_owned())
        );
        if self.fail_finalize {
            return Err("finalize failed");
        }

        Ok(AcmeIssuedCertificate {
            fullchain_pem: test_certificate_pem().to_vec(),
            private_key_pem: sanitization::SecretVec::from_slice(test_private_key_pem()),
        })
    }
}
