use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use sanitization::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use fluxheim_common::{FluxError, FluxResult};

const MAX_HTTP_DISCOVERY_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES: u64 = 4096;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe load-balancer discovery token loading before building Fluxheim"
);

pub(super) async fn fetch_proxy_upstreams_http_for_discovery(
    url: String,
    bearer_token_file: Option<PathBuf>,
    allow_private_backends: bool,
) -> FluxResult<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || {
            fetch_proxy_upstreams_http(&url, bearer_token_file, allow_private_backends)
        })
        .await
        .map_err(|error| {
            FluxError::io(
                "proxy upstreams HTTP discovery task failed",
                io::Error::other(error.to_string()),
            )
        })?
    } else {
        // The construction-time update is synchronously polled before a Tokio
        // reactor exists. Keep the bootstrap fetch immediately ready; later
        // refreshes run through spawn_blocking().
        fetch_proxy_upstreams_http(&url, bearer_token_file, allow_private_backends)
    };

    result.map_err(|error| FluxError::io("failed to fetch proxy upstreams HTTP discovery", error))
}

pub(super) fn fetch_proxy_upstreams_http(
    url: &str,
    bearer_token_file: Option<PathBuf>,
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
    let timeout = Duration::from_secs(5);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent
        .get(url)
        .header("accept", "application/json")
        .header("cache-control", "no-store");
    let bearer_token = if let Some(path) = bearer_token_file {
        Some(read_http_discovery_bearer_token(&path)?)
    } else {
        None
    };
    if let Some(token) = bearer_token.as_ref() {
        let header_value = http_discovery_bearer_authorization_value(token)?;
        request = header_value
            .try_with_secret(|value| request.header("authorization", value))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    let mut response = request
        .call()
        .map_err(|error| io::Error::other(error.to_string()))?;
    if response.status().as_u16() != 200 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "HTTP discovery endpoint returned status {}",
                response.status().as_u16()
            ),
        ));
    }
    validate_http_discovery_content_type(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
    )?;
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_HTTP_DISCOVERY_RESPONSE_BYTES.saturating_add(1))
        .read_to_vec()
        .map_err(|error| io::Error::other(error.to_string()))?;
    if body.len() as u64 > MAX_HTTP_DISCOVERY_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery response is too large",
        ));
    }
    parse_proxy_upstreams_http_body(&body, allow_private_backends)
}

fn read_http_discovery_bearer_token(path: &Path) -> io::Result<SecretString> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP discovery bearer token file must be a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP discovery bearer token file must be a regular file",
        ));
    }
    if metadata.len() > MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file is too large",
        ));
    }

    let mut token = Zeroizing::new(String::new());
    let mut limited = file.take(MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES.saturating_add(1));
    limited.read_to_string(&mut token)?;
    if token.len() as u64 > MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file changed while reading and became too large",
        ));
    }
    validate_http_discovery_bearer_token(&token)?;
    Ok(SecretString::from_secret_str(token.trim()))
}

fn http_discovery_bearer_authorization_value(token: &SecretString) -> io::Result<SecretString> {
    token
        .try_with_secret(|token| {
            let token = token.trim();
            let mut header_value = SecretString::with_capacity("Bearer ".len() + token.len());
            header_value.push_str("Bearer ");
            header_value.push_str(token);
            header_value
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(super) fn validate_http_discovery_bearer_token(token: &str) -> io::Result<()> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file is empty",
        ));
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token contains whitespace",
        ));
    }
    Ok(())
}

pub(super) fn validate_http_discovery_content_type(content_type: Option<&str>) -> io::Result<()> {
    let Some(content_type) = content_type else {
        return Ok(());
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP discovery response content-type is not JSON",
    ))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HttpDiscoveryPayload {
    List(Vec<String>),
    Object { upstreams: Vec<String> },
}

pub(super) fn parse_proxy_upstreams_http_body(
    body: &[u8],
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
    let payload: HttpDiscoveryPayload = serde_json::from_slice(body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP discovery response is not a valid upstream JSON payload: {error}"),
        )
    })?;
    let upstreams = match payload {
        HttpDiscoveryPayload::List(upstreams) | HttpDiscoveryPayload::Object { upstreams } => {
            upstreams
        }
    };
    validate_http_discovery_upstreams(upstreams, allow_private_backends)
}

fn validate_http_discovery_upstreams(
    upstreams: Vec<String>,
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
    let mut validated = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for upstream in upstreams {
        let value = upstream.trim();
        if !fluxheim_config::config_net::valid_authority(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery upstream is not a host:port or ip:port authority",
            ));
        }
        if !allow_private_backends && http_discovery_upstream_uses_restricted_ip_literal(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery upstream uses a private, loopback, link-local, multicast, reserved, or documentation IP address without proxy.upstreams_http_allow_private_backends",
            ));
        }
        if !seen.insert(value.to_ascii_lowercase()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response repeats an upstream",
            ));
        }
        if validated.len() >= fluxheim_config::config_proxy::MAX_PROXY_UPSTREAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response contains too many upstreams",
            ));
        }
        validated.push(value.to_owned());
    }
    if validated.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery response must contain at least two upstreams",
        ));
    }
    Ok(validated)
}

fn http_discovery_upstream_uses_restricted_ip_literal(upstream: &str) -> bool {
    upstream
        .parse::<SocketAddr>()
        .is_ok_and(|socket| restricted_discovery_ip(socket.ip()))
}

pub(super) fn restricted_discovery_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => restricted_discovery_ipv4(ip),
        IpAddr::V6(ip) => restricted_discovery_ipv6(ip),
    }
}

fn restricted_discovery_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 198 && matches!(second, 18 | 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
}

fn restricted_discovery_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return restricted_discovery_ipv4(mapped);
    }
    if let Some(compatible) = ip.to_ipv4()
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        return restricted_discovery_ipv4(compatible);
    }
    let segments = ip.segments();
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        if restricted_discovery_ipv4(embedded) {
            return true;
        }
    }
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        let raw = ((segments[6] as u32) << 16) | u32::from(segments[7]);
        let embedded = Ipv4Addr::from(!raw);
        if restricted_discovery_ipv4(embedded) {
            return true;
        }
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
}
