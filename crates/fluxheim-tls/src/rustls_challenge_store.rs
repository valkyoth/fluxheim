use super::*;

struct PublicationGuard {
    store: Arc<RustlsTlsAlpnCertificateStore>,
    name: String,
    entry: Arc<ChallengeEntry>,
}
impl Drop for PublicationGuard {
    fn drop(&mut self) {
        let _guard = self.store.writers.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = (**self.store.certificates.load()).clone();
        if next
            .get(&self.name)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
        {
            next.remove(&self.name);
            self.store.certificates.store(Arc::new(next));
        }
    }
}

impl RustlsTlsAlpnCertificateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(
        self: &Arc<Self>,
        name: &str,
        key: Arc<CertifiedKey>,
        expires: std::time::Instant,
    ) -> io::Result<Box<dyn Send>> {
        let now = std::time::Instant::now();
        if name.len() > 253
            || normalize_host(name).as_deref() != Some(name)
            || expires <= now
            || expires.duration_since(now) > std::time::Duration::from_secs(180)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let _guard = self
            .writers
            .lock()
            .map_err(|_| io::Error::other("challenge store unavailable"))?;
        let mut next = (**self.certificates.load()).clone();
        next.retain(|_, entry| entry.expires > now);
        if next.contains_key(name) || next.len() >= MAX_TLS_ALPN_CHALLENGE_CERTIFICATES {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let entry = Arc::new(ChallengeEntry { key, expires });
        next.insert(name.into(), entry.clone());
        self.certificates.store(Arc::new(next));
        Ok(Box::new(PublicationGuard {
            store: self.clone(),
            name: name.into(),
            entry,
        }))
    }

    #[cfg(test)]
    pub(super) fn replace(
        &self,
        certificates: impl IntoIterator<Item = (String, Arc<CertifiedKey>)>,
    ) -> Result<(), RustlsDownstreamCertificateError> {
        let mut replacement = HashMap::new();
        for (index, (sni, certificate)) in certificates.into_iter().enumerate() {
            if index >= MAX_TLS_ALPN_CHALLENGE_CERTIFICATES {
                return Err(
                    RustlsDownstreamCertificateError::TooManyTlsAlpnCertificates {
                        maximum: MAX_TLS_ALPN_CHALLENGE_CERTIFICATES,
                    },
                );
            }
            let normalized = normalize_host(&sni)
                .ok_or(RustlsDownstreamCertificateError::InvalidTlsAlpnSni { sni })?;
            if replacement
                .insert(
                    normalized.clone(),
                    Arc::new(ChallengeEntry {
                        key: certificate,
                        expires: std::time::Instant::now() + std::time::Duration::from_secs(180),
                    }),
                )
                .is_some()
            {
                return Err(RustlsDownstreamCertificateError::DuplicateTlsAlpnSni {
                    sni: normalized,
                });
            }
        }
        self.certificates.store(Arc::new(replacement));
        Ok(())
    }

    pub(super) fn resolve(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let normalized = sni.and_then(normalize_host)?;
        self.certificates
            .load()
            .get(&normalized)
            .filter(|entry| entry.expires > std::time::Instant::now())
            .map(|entry| entry.key.clone())
    }
}
