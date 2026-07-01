use std::net::IpAddr;

use fluxheim_config::{LoadBalanceSelection, ProxyConfig};

use super::persistence::LoadBalancerRequestView;

pub(super) const MAX_PERSISTENCE_KEY_BYTES: usize = 512;

#[derive(Clone, Debug)]
pub(super) enum LoadBalanceKeySource {
    None,
    SourceIp,
    Uri,
    Header(String),
    Cookie(String),
}

impl LoadBalanceKeySource {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => Self::None,
            LoadBalanceSelection::LeastConnections => Self::None,
            LoadBalanceSelection::LeastSessions => Self::None,
            LoadBalanceSelection::LeastTime => Self::None,
            LoadBalanceSelection::PowerOfTwo => Self::None,
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::NginxConsistentSourceHash
            | LoadBalanceSelection::MaglevSourceHash => Self::SourceIp,
            LoadBalanceSelection::UriHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::NginxConsistentUriHash
            | LoadBalanceSelection::MaglevUriHash => Self::Uri,
            LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::NginxConsistentHeaderHash
            | LoadBalanceSelection::MaglevHeaderHash => config
                .load_balance
                .hash_header
                .clone()
                .map(Self::Header)
                .unwrap_or(Self::None),
            LoadBalanceSelection::CookieHash
            | LoadBalanceSelection::ConsistentCookieHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash
            | LoadBalanceSelection::NginxConsistentCookieHash
            | LoadBalanceSelection::MaglevCookieHash => config
                .load_balance
                .hash_cookie
                .clone()
                .map(Self::Cookie)
                .unwrap_or(Self::None),
        }
    }

    pub(super) fn request_key(
        &self,
        request: &impl LoadBalancerRequestView,
        client_ip: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        match self {
            Self::None => None,
            Self::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            Self::Uri => Some(request.uri_key()),
            Self::Header(name) => request_header_key(request, name),
            Self::Cookie(name) => cookie_key(request, name),
        }
    }
}

pub(super) fn request_header_key(
    request: &impl LoadBalancerRequestView,
    name: &str,
) -> Option<Vec<u8>> {
    let mut key = Vec::new();
    for bytes in request.header_values(name) {
        key.extend_from_slice(&bytes.len().to_le_bytes());
        key.extend_from_slice(bytes);
        if key.len() > MAX_PERSISTENCE_KEY_BYTES {
            return None;
        }
    }
    (!key.is_empty()).then_some(key)
}

pub(super) fn cookie_key(request: &impl LoadBalancerRequestView, name: &str) -> Option<Vec<u8>> {
    for header in request.cookie_headers() {
        for part in header.split(';') {
            let Some((candidate, value)) = part.trim().split_once('=') else {
                continue;
            };
            if candidate.trim() == name {
                let bytes = value.trim().as_bytes();
                if bytes.len() > MAX_PERSISTENCE_KEY_BYTES {
                    return None;
                }
                return Some(bytes.to_vec());
            }
        }
    }
    None
}
