use std::net::IpAddr;

pub fn effective_client_ip(
    direct_ip: IpAddr,
    trusted_direct_peer: bool,
    original_x_forwarded_for: Option<&str>,
    trusted_proxy_matcher: Option<&dyn Fn(IpAddr) -> bool>,
) -> IpAddr {
    if !trusted_direct_peer {
        return direct_ip;
    }

    let Some(original_x_forwarded_for) = original_x_forwarded_for else {
        return direct_ip;
    };
    let Some(trusted_proxy_matcher) = trusted_proxy_matcher else {
        return direct_ip;
    };

    let mut last_valid_hop = None;
    for raw_hop in original_x_forwarded_for.split(',').rev() {
        let Some(hop) = parse_x_forwarded_for_ip(raw_hop) else {
            return direct_ip;
        };
        last_valid_hop.get_or_insert(hop);
        if !trusted_proxy_matcher(hop) {
            return hop;
        }
    }

    last_valid_hop.unwrap_or(direct_ip)
}

pub fn parse_x_forwarded_for_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let value = match (value.starts_with('"'), value.ends_with('"')) {
        (true, true) => {
            let inner = value.strip_prefix('"')?.strip_suffix('"')?;
            if inner.is_empty() || inner.contains('"') {
                return None;
            }
            inner
        }
        (false, false) => value,
        (true, false) | (false, true) => return None,
    };

    if let Some(value) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let address = value.parse().ok()?;
        return matches!(address, IpAddr::V6(_)).then_some(address);
    }
    value.parse().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedProto {
    Http,
    Https,
}

impl ForwardedProto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

pub fn build_forwarded_header(
    client_ip: IpAddr,
    host: Option<&str>,
    proto: ForwardedProto,
) -> Option<String> {
    if host.is_some_and(|host| !valid_forwarded_host(host)) {
        return None;
    }

    let mut value = format!("for={}", forwarded_ip(client_ip));
    if let Some(host) = host {
        value.push_str(";host=");
        value.push_str(&quote_forwarded_value(host));
    }
    value.push_str(";proto=");
    value.push_str(proto.as_str());
    Some(value)
}

fn valid_forwarded_host(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && host.trim() == host
        && !host.bytes().any(|byte| {
            byte.is_ascii_control() || byte == b' ' || matches!(byte, b'"' | b'\\' | b';' | b',')
        })
        && fluxheim_config::normalize_host(host).is_some()
        && (host.starts_with('[') || host.bytes().filter(|byte| *byte == b':').count() <= 1)
}

fn forwarded_ip(client_ip: IpAddr) -> String {
    match client_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    }
}

fn quote_forwarded_value(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        ForwardedProto, build_forwarded_header, effective_client_ip, parse_x_forwarded_for_ip,
    };

    #[test]
    fn parses_forwarded_for_ip_shapes() {
        assert_eq!(
            parse_x_forwarded_for_ip(" 198.51.100.10 "),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
        );
        assert_eq!(
            parse_x_forwarded_for_ip("\"[2001:db8::1]\""),
            Some(IpAddr::V6("2001:db8::1".parse().expect("valid IPv6")))
        );
        assert_eq!(parse_x_forwarded_for_ip("not-an-ip"), None);
        assert_eq!(parse_x_forwarded_for_ip("\"\"198.51.100.7\"\""), None);
        assert_eq!(parse_x_forwarded_for_ip("\"198.51.100.7"), None);
        assert_eq!(parse_x_forwarded_for_ip("198.51.100.7\""), None);
        assert_eq!(parse_x_forwarded_for_ip("\"198.51.\"100.7\""), None);
        assert_eq!(parse_x_forwarded_for_ip("\"\""), None);
        assert_eq!(parse_x_forwarded_for_ip("[198.51.100.7]"), None);
        assert_eq!(
            parse_x_forwarded_for_ip("[::ffff:198.51.100.7]"),
            Some(IpAddr::V6(
                "::ffff:198.51.100.7".parse().expect("valid mapped IPv6")
            ))
        );
    }

    #[test]
    fn restores_client_ip_from_trusted_forwarded_chain() {
        let direct = IpAddr::V4(Ipv4Addr::new(10, 89, 0, 254));
        let matcher = |address: IpAddr| match address {
            IpAddr::V4(address) => {
                address == Ipv4Addr::new(10, 89, 0, 254)
                    || address == Ipv4Addr::new(203, 0, 113, 10)
            }
            IpAddr::V6(_) => false,
        };

        assert_eq!(
            effective_client_ip(
                direct,
                true,
                Some("198.51.100.9, 203.0.113.10"),
                Some(&matcher),
            ),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
        );
        assert_eq!(
            effective_client_ip(direct, false, Some("198.51.100.9"), Some(&matcher)),
            direct
        );
    }

    #[test]
    fn rejects_malformed_trusted_forwarded_chain() {
        let direct = IpAddr::V4(Ipv4Addr::new(10, 89, 0, 254));
        let matcher = |address: IpAddr| match address {
            IpAddr::V4(address) => {
                address == Ipv4Addr::new(10, 89, 0, 254)
                    || address == Ipv4Addr::new(203, 0, 113, 10)
            }
            IpAddr::V6(_) => false,
        };

        assert_eq!(
            effective_client_ip(
                direct,
                true,
                Some("198.51.100.9, not-an-ip, 203.0.113.10"),
                Some(&matcher),
            ),
            direct
        );
        assert_eq!(
            effective_client_ip(
                direct,
                true,
                Some("198.51.100.9, \"\"203.0.113.10\"\""),
                Some(&matcher),
            ),
            direct
        );
    }

    #[test]
    fn builds_forwarded_header_values() {
        assert_eq!(
            build_forwarded_header(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                Some("example.test"),
                ForwardedProto::Https,
            ),
            Some("for=198.51.100.9;host=\"example.test\";proto=https".to_owned())
        );
        assert_eq!(
            build_forwarded_header(IpAddr::V6(Ipv6Addr::LOCALHOST), None, ForwardedProto::Http,),
            Some("for=\"[::1]\";proto=http".to_owned())
        );
        assert_eq!(
            build_forwarded_header(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some("[2001:db8::1]:8443"),
                ForwardedProto::Https,
            ),
            Some("for=127.0.0.1;host=\"[2001:db8::1]:8443\";proto=https".to_owned())
        );
    }

    #[test]
    fn rejects_unsafe_forwarded_host_values() {
        for host in [
            "",
            " example.test",
            "example.test ",
            "example.test\\evil",
            "example.test;proto=http",
            "example.test,for=192.0.2.1",
            "example.test\r\nfor=192.0.2.1",
            "2001:db8::1",
        ] {
            assert_eq!(
                build_forwarded_header(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(host),
                    ForwardedProto::Https,
                ),
                None,
                "unsafe forwarded host was accepted: {host:?}"
            );
        }
    }
}
