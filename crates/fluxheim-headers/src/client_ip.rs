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
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Some(value) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return value.parse().ok();
    }
    value.parse().ok()
}

pub fn build_forwarded_header(client_ip: IpAddr, host: Option<&str>, proto: &str) -> String {
    let mut value = format!("for={}", forwarded_ip(client_ip));
    if let Some(host) = host {
        value.push_str(";host=");
        value.push_str(&quote_forwarded_value(host));
    }
    value.push_str(";proto=");
    value.push_str(proto);
    value
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

    use super::{build_forwarded_header, effective_client_ip, parse_x_forwarded_for_ip};

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
    }

    #[test]
    fn builds_forwarded_header_values() {
        assert_eq!(
            build_forwarded_header(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                Some("example.test"),
                "https"
            ),
            "for=198.51.100.9;host=\"example.test\";proto=https"
        );
        assert_eq!(
            build_forwarded_header(IpAddr::V6(Ipv6Addr::LOCALHOST), None, "https"),
            "for=\"[::1]\";proto=https"
        );
    }
}
