pub const fn admin_mac_is_compliance_capable() -> bool {
    cfg!(any(
        feature = "tls-openssl-fips",
        feature = "tls-rustls-fips"
    ))
}
