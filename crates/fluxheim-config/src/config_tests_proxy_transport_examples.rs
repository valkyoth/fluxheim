use crate::Config;

#[test]
fn proxy_transport_recipe_and_socket_limits_validate() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/proxy/transport.toml")).unwrap();
    let root = super::super::secure_test_dir("proxy-transport-guide");
    for page in &mut config.vhosts[0].proxy.error_pages {
        page.web.root = Some(root.clone());
    }
    config.validate().unwrap();
    let proxy = &mut config.vhosts[0].proxy;
    proxy.upstream_tcp_keepalive_idle_secs = Some(60);
    proxy.upstream_tcp_keepalive_interval_secs = Some(10);
    proxy.upstream_tcp_keepalive_count = Some(3);
    proxy.upstream_tcp_recv_buffer_bytes = Some(crate::ByteSize::from_bytes(256 * 1024));
    proxy.upstream_dscp = Some(0);
    config.validate().unwrap();
    for case in 0..8 {
        let mut invalid = config.clone();
        let proxy = &mut invalid.vhosts[0].proxy;
        match case {
            0 => proxy.read_timeout_secs = Some(0),
            1 => proxy.upstream_total_connection_timeout_secs = Some(86401),
            2 => proxy.upstream_tcp_keepalive_count = None,
            3 => proxy.upstream_tcp_recv_buffer_bytes = Some(crate::ByteSize::from_bytes(0)),
            4 => proxy.upstream_dscp = Some(64),
            5 => proxy.error_pages[0].status = 200,
            6 => proxy.error_pages[0].path = "../outside.html".into(),
            _ => proxy.error_pages[1].status = proxy.error_pages[0].status,
        }
        assert!(invalid.validate().is_err(), "case {case}");
    }
    std::fs::remove_dir_all(root).unwrap();
}
