use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sanitization::ct::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::RateLimitMode;
use crate::flux_error::{FluxError, FluxResult};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TrustedProxy {
    Exact(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

impl TrustedProxy {
    pub(crate) fn contains(self, address: IpAddr) -> bool {
        let address = normalize_ipv4_mapped_ip(address);
        match (self, address) {
            (Self::Exact(trusted), address) => normalize_ipv4_mapped_ip(trusted) == address,
            (
                Self::Cidr {
                    network: IpAddr::V4(network),
                    prefix,
                },
                IpAddr::V4(address),
            ) => ipv4_prefix_match(network, address, prefix),
            (
                Self::Cidr {
                    network: IpAddr::V6(network),
                    prefix,
                },
                IpAddr::V6(address),
            ) => ipv6_prefix_match(network, address, prefix),
            _ => false,
        }
    }
}

pub(crate) fn normalize_ipv4_mapped_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        IpAddr::V4(_) => address,
    }
}

#[derive(Debug)]
pub(crate) struct InFlightPermit {
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        let _ = self.permit.take();
    }
}

#[derive(Debug)]
struct QueuedConcurrencyWaiter {
    queued: Arc<AtomicUsize>,
}

impl Drop for QueuedConcurrencyWaiter {
    fn drop(&mut self) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeConcurrencyLimit {
    enabled: bool,
    max_queue: usize,
    status: u16,
    queue_timeout: Duration,
    semaphore: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
}

impl Default for RuntimeConcurrencyLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            max_queue: 0,
            status: 503,
            queue_timeout: Duration::ZERO,
            semaphore: Arc::new(Semaphore::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl RuntimeConcurrencyLimit {
    pub(crate) fn from_config(config: &crate::config::ConcurrencyLimitConfig) -> Self {
        let max_queue = if config.max_queue == 0 {
            config
                .max_in_flight
                .saturating_mul(4)
                .max(config.max_in_flight)
                .min(1_000_000)
        } else {
            config.max_queue
        };
        Self {
            enabled: config.enabled,
            max_queue,
            status: config.status,
            queue_timeout: Duration::from_millis(config.queue_timeout_ms),
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) async fn acquire(&self) -> std::result::Result<Option<InFlightPermit>, u16> {
        if !self.enabled {
            return Ok(None);
        }

        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => {
                return Ok(Some(InFlightPermit {
                    permit: Some(permit),
                }));
            }
            Err(_) if self.queue_timeout.is_zero() => return Err(self.status),
            Err(_) => {}
        }

        if !self.try_enter_queue() {
            return Err(self.status);
        }
        let queued = QueuedConcurrencyWaiter {
            queued: Arc::clone(&self.queued),
        };

        let result = tokio::time::timeout(
            self.queue_timeout,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await;
        drop(queued);

        match result {
            Ok(Ok(permit)) => Ok(Some(InFlightPermit {
                permit: Some(permit),
            })),
            Ok(Err(_)) | Err(_) => Err(self.status),
        }
    }

    fn try_enter_queue(&self) -> bool {
        let mut current = self.queued.load(Ordering::Acquire);
        loop {
            if current >= self.max_queue {
                return false;
            }
            let Some(next) = current.checked_add(1) else {
                return false;
            };
            match self.queued.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RateLimitKey {
    Ip(IpAddr),
    Indeterminate,
}

impl From<Option<IpAddr>> for RateLimitKey {
    fn from(value: Option<IpAddr>) -> Self {
        value.map(Self::Ip).unwrap_or(Self::Indeterminate)
    }
}

#[derive(Clone, Copy, Debug)]
struct RateLimitBucket {
    tokens: f64,
    updated_at: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
struct RuntimeRateLimitState {
    buckets: Mutex<HashMap<RateLimitKey, RateLimitBucket>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RateLimitDecision {
    Allow,
    Delay(Duration),
    Reject(u16),
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeRateLimit {
    enabled: bool,
    requests_per_second: f64,
    burst: f64,
    status: u16,
    table_max_entries: usize,
    entry_ttl: Duration,
    mode: RateLimitMode,
    max_delay: Duration,
    reject_indeterminate: bool,
    state: Arc<RuntimeRateLimitState>,
}

impl Default for RuntimeRateLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 0.0,
            burst: 0.0,
            status: 429,
            table_max_entries: 0,
            entry_ttl: Duration::from_secs(300),
            mode: RateLimitMode::Nodelay,
            max_delay: Duration::from_millis(1000),
            reject_indeterminate: false,
            state: Arc::new(RuntimeRateLimitState {
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl RuntimeRateLimit {
    pub(crate) fn from_config(config: &crate::config::RateLimitConfig) -> Self {
        let burst = if config.burst == 0 {
            config.requests_per_second.max(1)
        } else {
            config.burst
        };
        Self {
            enabled: config.enabled,
            requests_per_second: f64::from(config.requests_per_second),
            burst: f64::from(burst),
            status: config.status,
            table_max_entries: config.table_max_entries,
            entry_ttl: Duration::from_secs(config.entry_ttl_secs),
            mode: config.mode,
            max_delay: Duration::from_millis(config.max_delay_ms),
            reject_indeterminate: config.reject_indeterminate,
            state: Arc::new(RuntimeRateLimitState {
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn check(&self, client_ip: Option<IpAddr>) -> RateLimitDecision {
        if !self.enabled {
            return RateLimitDecision::Allow;
        }

        let now = Instant::now();
        let key = RateLimitKey::from(client_ip);
        if matches!(key, RateLimitKey::Indeterminate) && self.reject_indeterminate {
            return RateLimitDecision::Reject(self.status);
        }
        let mut buckets = match self.state.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "rate-limit bucket lock poisoned; aborting to avoid inconsistent edge limits"
                );
                std::process::abort();
            }
        };
        if !buckets.contains_key(&key) && buckets.len() >= self.table_max_entries {
            buckets.retain(|_, bucket| now.duration_since(bucket.last_seen) <= self.entry_ttl);
            if buckets.len() >= self.table_max_entries {
                return RateLimitDecision::Reject(self.status);
            }
        }

        let bucket = buckets.entry(key).or_insert(RateLimitBucket {
            tokens: self.burst,
            updated_at: now,
            last_seen: now,
        });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = self
            .burst
            .min(bucket.tokens + elapsed * self.requests_per_second);
        bucket.updated_at = now;
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateLimitDecision::Allow;
        }

        if !matches!(self.mode, RateLimitMode::Delay) || bucket.tokens <= -self.burst {
            return RateLimitDecision::Reject(self.status);
        }

        if !self.requests_per_second.is_finite() || self.requests_per_second <= 0.0 {
            return RateLimitDecision::Reject(self.status);
        }
        let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / self.requests_per_second);
        if wait > self.max_delay {
            return RateLimitDecision::Reject(self.status);
        }

        bucket.tokens -= 1.0;
        RateLimitDecision::Delay(wait)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeAccessPolicy {
    enabled: bool,
    allow: Vec<TrustedProxy>,
    deny: Vec<TrustedProxy>,
    require_client_cert: bool,
    allow_client_cert_sha256: Vec<String>,
    deny_client_cert_sha256: Vec<String>,
    allow_countries: Vec<String>,
    deny_countries: Vec<String>,
    allow_asns: Vec<u32>,
    deny_asns: Vec<u32>,
}

impl RuntimeAccessPolicy {
    pub(crate) fn from_config(config: &crate::config::AccessPolicyConfig) -> FluxResult<Self> {
        Ok(Self {
            enabled: config.enabled,
            allow: parse_trusted_proxies(&config.allow)?,
            deny: parse_trusted_proxies(&config.deny)?,
            require_client_cert: config.require_client_cert,
            allow_client_cert_sha256: normalized_cert_fingerprints(
                &config.allow_client_cert_sha256,
            ),
            deny_client_cert_sha256: normalized_cert_fingerprints(&config.deny_client_cert_sha256),
            allow_countries: normalized_countries(&config.allow_countries),
            deny_countries: normalized_countries(&config.deny_countries),
            allow_asns: config.allow_asns.clone(),
            deny_asns: config.deny_asns.clone(),
        })
    }

    pub(crate) fn allows(
        &self,
        client_ip: Option<IpAddr>,
        tls_identity: Option<&crate::headers::RequestTlsClientIdentity>,
        geo_context: Option<&crate::geo_context::GeoContext>,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        let ip_restrictive = !self.allow.is_empty() || !self.deny.is_empty();
        if let Some(client_ip) = client_ip {
            if self.deny.iter().any(|rule| rule.contains(client_ip)) {
                return false;
            }
            if !self.allow.is_empty() && !self.allow.iter().any(|rule| rule.contains(client_ip)) {
                return false;
            }
        } else if ip_restrictive {
            return false;
        }

        let cert_sha256 = tls_identity
            .and_then(|identity| identity.cert_sha256.as_deref())
            .map(str::to_ascii_lowercase);
        if self.require_client_cert && cert_sha256.is_none() {
            return false;
        }
        if let Some(cert_sha256) = cert_sha256.as_deref() {
            if cert_fingerprint_list_contains(&self.deny_client_cert_sha256, cert_sha256) {
                return false;
            }
            if !self.allow_client_cert_sha256.is_empty()
                && !cert_fingerprint_list_contains(&self.allow_client_cert_sha256, cert_sha256)
            {
                return false;
            }
        } else {
            if !self.allow_client_cert_sha256.is_empty() {
                return false;
            }
        }
        self.allows_geo(geo_context)
    }

    fn allows_geo(&self, geo_context: Option<&crate::geo_context::GeoContext>) -> bool {
        let has_allow = !self.allow_countries.is_empty() || !self.allow_asns.is_empty();
        let has_deny = !self.deny_countries.is_empty() || !self.deny_asns.is_empty();
        if !has_allow && !has_deny {
            return true;
        }
        let Some(geo_context) = geo_context else {
            return !has_allow;
        };

        let country = geo_context.country_iso();
        if let Some(country) = country
            && self
                .deny_countries
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(country))
        {
            return false;
        }
        if !self.allow_countries.is_empty()
            && !country
                .map(|country| {
                    self.allow_countries
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(country))
                })
                .unwrap_or(false)
        {
            return false;
        }

        let asn = geo_context.asn();
        if asn
            .map(|asn| self.deny_asns.contains(&asn))
            .unwrap_or(false)
        {
            return false;
        }
        if !self.allow_asns.is_empty()
            && !asn
                .map(|asn| self.allow_asns.contains(&asn))
                .unwrap_or(false)
        {
            return false;
        }
        true
    }
}

fn normalized_countries(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

pub(crate) fn parse_trusted_proxies(values: &[String]) -> FluxResult<Vec<TrustedProxy>> {
    values
        .iter()
        .map(|value| parse_trusted_proxy(value))
        .collect()
}

fn parse_trusted_proxy(value: &str) -> FluxResult<TrustedProxy> {
    let value = value.trim();
    if let Some((address, prefix)) = value.split_once('/') {
        let network =
            normalize_ipv4_mapped_ip(address.parse::<IpAddr>().map_err(invalid_trusted_proxy)?);
        let prefix = prefix.parse::<u8>().map_err(invalid_trusted_proxy)?;
        let valid_prefix = match network {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        };
        if !valid_prefix {
            return Err(invalid_trusted_proxy("invalid prefix length"));
        }
        return Ok(TrustedProxy::Cidr { network, prefix });
    }

    value
        .parse::<IpAddr>()
        .map(normalize_ipv4_mapped_ip)
        .map(TrustedProxy::Exact)
        .map_err(invalid_trusted_proxy)
}

fn invalid_trusted_proxy(error: impl std::fmt::Display) -> FluxError {
    FluxError::invalid_input(format!("invalid trusted proxy: {error}"))
}

fn ipv4_prefix_match(network: Ipv4Addr, address: Ipv4Addr, prefix: u8) -> bool {
    let mask = prefix_mask_u32(prefix);
    u32::from(network) & mask == u32::from(address) & mask
}

fn ipv6_prefix_match(network: Ipv6Addr, address: Ipv6Addr, prefix: u8) -> bool {
    let mask = prefix_mask_u128(prefix);
    u128::from(network) & mask == u128::from(address) & mask
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn normalized_cert_fingerprints(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn cert_fingerprint_list_contains(values: &[String], fingerprint: &str) -> bool {
    let fingerprint = fingerprint.as_bytes();
    let mut matched = 0u8;
    for value in values {
        matched |= value.as_bytes().ct_eq(fingerprint).unwrap_u8();
    }
    matched == 1
}
