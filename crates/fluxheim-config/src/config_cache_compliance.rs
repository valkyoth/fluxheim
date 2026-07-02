use crate::config::ConfigError;
use crate::config_cache::CacheConfig;
use crate::config_cache_encryption::{
    CacheDiskEncryptionProvider, fips_allowed_local_openbao_endpoint,
};

pub fn validate_cache_compliance_internal_crypto(
    cache: &CacheConfig,
    scope: &'static str,
    require_disk_cache_encryption: bool,
) -> Result<(), ConfigError> {
    if !cache.disk.enabled {
        return Ok(());
    }

    if !cache.disk.encryption.enabled {
        if require_disk_cache_encryption {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: scope,
                reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
            });
        }
        log::warn!(
            "{scope}.disk.enabled is true in FIPS/ISO-required mode without disk cache encryption; cached response bodies are written at rest without a Fluxheim-managed encryption boundary"
        );
        return Ok(());
    }

    match cache.disk.encryption.provider {
        CacheDiskEncryptionProvider::Local => Err(ConfigError::InvalidCompliancePolicy {
            field: scope,
            reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
        }),
        CacheDiskEncryptionProvider::OpenbaoTransit => {
            let address = cache
                .disk
                .encryption
                .openbao
                .address
                .as_deref()
                .unwrap_or_default();
            if !fips_allowed_local_openbao_endpoint(address) {
                return Err(ConfigError::InvalidCompliancePolicy {
                    field: scope,
                    reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
                });
            }
            Ok(())
        }
    }
}
