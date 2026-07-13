#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use fluxheim_config::{ResponseHeaderRewriteConfig, ResponseHeaderRewriteRuleConfig};
use fluxheim_headers::{
    ForwardedProto, build_forwarded_header, hop_by_hop_request_header_policy,
    parse_x_forwarded_for_ip, rewrite_refresh_url, rewrite_set_cookie_value,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let first = String::from_utf8_lossy(&data[..split]);
    let second = String::from_utf8_lossy(&data[split..]);

    let _ = parse_x_forwarded_for_ip(&first);
    let _ = build_forwarded_header(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(&first),
        ForwardedProto::Https,
    );
    let _ = hop_by_hop_request_header_policy([first.as_ref()], [second.as_ref()]);

    let rules = [ResponseHeaderRewriteRuleConfig {
        from: "http://backend.internal".to_owned(),
        to: "https://public.example".to_owned(),
    }];
    let _ = rewrite_refresh_url(&first, &rules);

    let rewrite = ResponseHeaderRewriteConfig {
        cookie_domain: rules.to_vec(),
        cookie_path: vec![ResponseHeaderRewriteRuleConfig {
            from: "/internal".to_owned(),
            to: "/".to_owned(),
        }],
        ..ResponseHeaderRewriteConfig::default()
    };
    let _ = rewrite_set_cookie_value(&second, &rewrite);
});
