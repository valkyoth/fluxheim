use fluxheim_acme::alpn_control::{self, Broker};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use std::{collections::HashSet, io, sync::Arc, time::Instant};

pub(super) fn bind(
    config: &fluxheim_config::Config,
    resolver: Option<&super::DownstreamCertificateReloader>,
) -> io::Result<Option<Broker>> {
    if !config.tls.acme.enabled
        || config.tls.acme.challenge != fluxheim_config::AcmeChallenge::TlsAlpn01
    {
        return Ok(None);
    }
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let Some(super::DownstreamCertificateReloader::Rustls(resolver)) = resolver else {
        return Err(io::Error::other("no native challenge resolver"));
    };
    let store = resolver
        .challenge_store()
        .ok_or_else(|| io::Error::other("challenge store unavailable"))?;
    let mut names = HashSet::new();
    for target in fluxheim_acme::managed_acme_targets(config) {
        for name in target.domains {
            if !names.insert(name) {
                return Err(io::Error::other("ambiguous managed challenge domain"));
            }
        }
    }
    Broker::bind(
        storage,
        Arc::new(move |name, digest| {
            if !names.contains(name) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let (pem, secret) =
                alpn_control::tls_alpn_01_certificate(name, digest).map_err(io::Error::other)?;
            let cert = CertificateDer::from_pem_slice(&pem).map_err(io::Error::other)?;
            let key = secret
                .with_secret(PrivateKeyDer::from_pem_slice)
                .map_err(|_| io::Error::other("invalid generated challenge key"))?;
            // rcgen produced both halves from one fresh key. The ordinary webpki
            // end-entity parser rejects the mandatory critical ACME extension.
            let signing_key = fluxheim_tls::rustls_crypto_provider()
                .key_provider
                .load_private_key(key)
                .map_err(io::Error::other)?;
            let certified = rustls::sign::CertifiedKey::new(vec![cert], signing_key);
            let deadline = Instant::now()
                .checked_add(alpn_control::LIFETIME)
                .ok_or(io::ErrorKind::InvalidData)?;
            store.publish(name, Arc::new(certified), deadline)
        }),
    )
    .map(Some)
}
