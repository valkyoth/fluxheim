#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::{IpAddr, SocketAddr};

pub fn proxy_protocol_v1_header(
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> Vec<u8> {
    let Some(source) = source else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };
    let Some(destination) = destination else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => format!(
            "PROXY TCP4 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => format!(
            "PROXY TCP6 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

pub fn proxy_protocol_v2_header(
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> Vec<u8> {
    let mut header = Vec::from(&PROXY_PROTOCOL_V2_SIGNATURE[..]);
    let Some(source) = source else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };
    let Some(destination) = destination else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        _ => header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]),
    }
    header
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{proxy_protocol_v1_header, proxy_protocol_v2_header};

    #[test]
    fn proxy_protocol_v1_header_encodes_matching_ip_families() {
        let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
        let destination: SocketAddr = "198.51.100.20:443".parse().expect("valid destination");
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n"
        );

        let source: SocketAddr = "[2001:db8::1]:12345".parse().expect("valid source");
        let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n"
        );
    }

    #[test]
    fn proxy_protocol_v1_header_falls_back_to_unknown_for_ambiguous_inputs() {
        let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
        let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY UNKNOWN\r\n"
        );
        assert_eq!(
            proxy_protocol_v1_header(None, Some(destination)),
            b"PROXY UNKNOWN\r\n"
        );
    }

    #[test]
    fn proxy_protocol_v2_header_encodes_matching_ip_families() {
        let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
        let destination: SocketAddr = "198.51.100.20:443".parse().expect("valid destination");
        let header = proxy_protocol_v2_header(Some(source), Some(destination));
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
        assert_eq!(&header[16..20], &[192, 0, 2, 10]);
        assert_eq!(&header[20..24], &[198, 51, 100, 20]);
        assert_eq!(&header[24..26], &12345u16.to_be_bytes());
        assert_eq!(&header[26..28], &443u16.to_be_bytes());

        let source: SocketAddr = "[2001:db8::1]:12345".parse().expect("valid source");
        let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
        let header = proxy_protocol_v2_header(Some(source), Some(destination));
        assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(&header[48..50], &12345u16.to_be_bytes());
        assert_eq!(&header[50..52], &443u16.to_be_bytes());
    }

    #[test]
    fn proxy_protocol_v2_header_falls_back_to_unspec_for_ambiguous_inputs() {
        let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
        let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
        assert_eq!(
            &proxy_protocol_v2_header(Some(source), Some(destination))[12..16],
            &[0x21, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &proxy_protocol_v2_header(None, Some(destination))[12..16],
            &[0x21, 0x00, 0x00, 0x00]
        );
    }
}
