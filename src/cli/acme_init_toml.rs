use std::error::Error;
use std::path::Path;

use super::AcmeInitIssuer;

impl AcmeInitIssuer {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Actalis => "actalis",
            Self::Letsencrypt => "letsencrypt",
            Self::LetsencryptStaging => "letsencrypt-staging",
        }
    }

    fn directory_url(self) -> &'static str {
        match self {
            Self::Actalis => "https://acme-api.actalis.com/acme/directory",
            Self::Letsencrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Self::LetsencryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }

    pub(super) fn requires_eab(self) -> bool {
        matches!(self, Self::Actalis)
    }
}

#[derive(serde::Serialize)]
struct AcmeInitToml {
    tls: AcmeInitTlsToml,
}

#[derive(serde::Serialize)]
struct AcmeInitTlsToml {
    acme: AcmeInitAcmeToml,
}

#[derive(serde::Serialize)]
struct AcmeInitAcmeToml {
    enabled: bool,
    storage: String,
    contact_email: String,
    default_issuer: String,
    challenge: String,
    automation: String,
    renewal: AcmeInitRenewalToml,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    issuers: Vec<AcmeInitIssuerToml>,
}

#[derive(serde::Serialize)]
struct AcmeInitRenewalToml {
    enabled: bool,
    renew_before_secs: u64,
    check_interval_secs: u64,
    retry_initial_secs: u64,
    retry_max_secs: u64,
    reload_after_renewal: bool,
    zero_downtime_reload: bool,
}

#[derive(serde::Serialize)]
struct AcmeInitIssuerToml {
    name: String,
    directory_url: String,
    eab: AcmeInitEabToml,
}

#[derive(serde::Serialize)]
struct AcmeInitEabToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_credential: Option<String>,
}

pub(super) fn build_acme_init_toml(
    issuer: AcmeInitIssuer,
    email: &str,
    storage: &Path,
    secrets_dir: &Path,
    use_systemd_credentials: bool,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let issuers = if issuer.requires_eab() {
        let eab = if use_systemd_credentials {
            AcmeInitEabToml {
                key_id_file: None,
                key_id_credential: Some("actalis-eab-kid".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: Some("actalis-eab-hmac-key".to_owned()),
            }
        } else {
            AcmeInitEabToml {
                key_id_file: Some(secrets_dir.join("actalis-eab-kid").display().to_string()),
                key_id_credential: None,
                hmac_key_file: Some(
                    secrets_dir
                        .join("actalis-eab-hmac-key")
                        .display()
                        .to_string(),
                ),
                hmac_key_credential: None,
            }
        };
        vec![AcmeInitIssuerToml {
            name: issuer.name().to_owned(),
            directory_url: issuer.directory_url().to_owned(),
            eab,
        }]
    } else {
        Vec::new()
    };

    let toml = AcmeInitToml {
        tls: AcmeInitTlsToml {
            acme: AcmeInitAcmeToml {
                enabled: true,
                storage: storage.display().to_string(),
                contact_email: email.to_owned(),
                default_issuer: issuer.name().to_owned(),
                challenge: "http-01".to_owned(),
                automation: if use_systemd_credentials {
                    "external".to_owned()
                } else {
                    "background".to_owned()
                },
                renewal: AcmeInitRenewalToml {
                    enabled: true,
                    renew_before_secs: 2_592_000,
                    check_interval_secs: 3_600,
                    retry_initial_secs: 300,
                    retry_max_secs: 86_400,
                    reload_after_renewal: true,
                    zero_downtime_reload: true,
                },
                issuers,
            },
        },
    };
    Ok(toml::to_string_pretty(&toml)?)
}
