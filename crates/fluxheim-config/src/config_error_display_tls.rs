use std::fmt::Formatter;

use super::kind::ConfigError;

pub(super) fn format_tls_error(
    error: &ConfigError,
    formatter: &mut Formatter<'_>,
) -> std::fmt::Result {
    match error {
        ConfigError::EmptyTlsCertificatePath { scope } => {
            write!(formatter, "{scope}.cert_path cannot be empty")
        }
        ConfigError::EmptyTlsKeyPath { scope } => {
            write!(formatter, "{scope}.key_path cannot be empty")
        }
        ConfigError::TlsEnabledWithoutCertificateSource { scope } => write!(
            formatter,
            "{scope}.enabled requires a static certificate or ACME"
        ),
        ConfigError::InvalidTlsPolicy { field, reason } => {
            write!(formatter, "{field} is invalid: {reason}")
        }
        ConfigError::TlsListenerWithoutTls => {
            write!(formatter, "server.tls_listen requires tls.enabled = true")
        }
        ConfigError::TlsListenerWithoutStaticCertificate => write!(
            formatter,
            "server.tls_listen requires a global certificate or a static/ACME certificate source on server.default_vhost"
        ),
        ConfigError::MissingAcmeStorage => {
            write!(
                formatter,
                "tls.acme.storage is required when ACME is enabled"
            )
        }
        ConfigError::EmptyAcmeStorage => write!(formatter, "tls.acme.storage cannot be empty"),
        ConfigError::InvalidAcmeContactEmail => {
            write!(
                formatter,
                "tls.acme.contact_email must be a valid email address when ACME is enabled"
            )
        }
        ConfigError::UnsupportedAcmeChallenge { challenge } => write!(
            formatter,
            "tls.acme.challenge {challenge:?} is not supported for managed ACME yet; use \"http-01\" or \"tls-alpn-01\""
        ),
        ConfigError::InvalidAcmeRenewalDuration { field } => {
            write!(formatter, "{field} must be greater than zero")
        }
        ConfigError::InvalidAcmeRenewAfterDatetime => write!(
            formatter,
            "tls.acme.renewal.renew_after must be a full TOML offset datetime"
        ),
        ConfigError::AcmeRenewalRetryInitialExceedsMax => write!(
            formatter,
            "tls.acme.renewal.retry_initial_secs cannot exceed retry_max_secs"
        ),
        ConfigError::EmptyAcmeIssuerName { scope } => write!(formatter, "{scope} cannot be empty"),
        ConfigError::DuplicateAcmeIssuerName { name } => {
            write!(formatter, "duplicate ACME issuer {name:?}")
        }
        ConfigError::UnknownAcmeIssuer { name } => {
            write!(formatter, "unknown ACME issuer {name:?}")
        }
        ConfigError::InvalidAcmeDirectoryUrl { issuer, url } => write!(
            formatter,
            "ACME issuer {issuer:?} must use an https directory URL, got {url:?}"
        ),
        ConfigError::InvalidAcmeTermsOfServiceAcceptance { issuer } => write!(
            formatter,
            "ACME issuer {issuer:?} terms_of_service_agreed requires an explicit valid HTTPS terms_of_service_url"
        ),
        ConfigError::InvalidAcmeEabSecretSource { issuer, field } => write!(
            formatter,
            "ACME issuer {issuer:?} EAB {field} must be read from an env var, file, or credential"
        ),
        ConfigError::InvalidAcmeEabCredentialName {
            issuer,
            field,
            credential,
        } => write!(
            formatter,
            "ACME issuer {issuer:?} EAB {field} credential name {credential:?} must be a safe credential name"
        ),
        ConfigError::ConflictingAcmeEabSecretSource { issuer, field } => write!(
            formatter,
            "ACME issuer {issuer:?} EAB {field} cannot use more than one secret source"
        ),
        ConfigError::VhostAcmeWithoutGlobalAcme { scope } => {
            write!(formatter, "{scope}.acme.enabled requires tls.acme.enabled")
        }
        ConfigError::EmptyVhostAcmeDomains { scope } => {
            write!(
                formatter,
                "{scope}.acme needs at least one non-wildcard domain"
            )
        }
        ConfigError::InvalidVhostAcmeDomain { scope, domain } => write!(
            formatter,
            "{scope}.acme.domains must contain concrete DNS names, got {domain:?}"
        ),
        ConfigError::DuplicateVhostAcmeDomain { scope, domain } => write!(
            formatter,
            "{scope}.acme.domains contains duplicate domain {domain:?}"
        ),
        ConfigError::MissingAcmeChallengeUpstream { vhost } => write!(
            formatter,
            "vhost {vhost:?} acme_challenge.enabled requires acme_challenge.upstream or acme_challenge.upstreams"
        ),
        ConfigError::ConflictingAcmeChallengeUpstreams { vhost } => write!(
            formatter,
            "vhost {vhost:?} acme_challenge.upstream and acme_challenge.upstreams cannot both be configured"
        ),
        ConfigError::TooManyAcmeChallengeUpstreams { vhost, max } => write!(
            formatter,
            "vhost {vhost:?} acme_challenge.upstreams must contain at most {max} entries"
        ),
        ConfigError::DuplicateAcmeChallengeUpstream { vhost, upstream } => write!(
            formatter,
            "vhost {vhost:?} acme_challenge.upstreams contains duplicate upstream {upstream:?}"
        ),
        _ => formatter.write_str("invalid TLS/ACME config error"),
    }
}
