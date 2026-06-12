#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdminMacProvider {
    Ring,
    OpenSslFips,
    AwsLcFips,
}

impl AdminMacProvider {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ring => "ring-hmac-sha256",
            Self::OpenSslFips => "openssl-fips-hmac-sha256",
            Self::AwsLcFips => "aws-lc-fips-hmac-sha256",
        }
    }

    pub const fn compliance_capable(self) -> bool {
        !matches!(self, Self::Ring)
    }
}

pub const fn admin_mac_provider() -> AdminMacProvider {
    #[cfg(feature = "tls-openssl-fips")]
    {
        AdminMacProvider::OpenSslFips
    }
    #[cfg(all(not(feature = "tls-openssl-fips"), feature = "tls-rustls-fips"))]
    {
        AdminMacProvider::AwsLcFips
    }
    #[cfg(not(any(feature = "tls-openssl-fips", feature = "tls-rustls-fips")))]
    {
        AdminMacProvider::Ring
    }
}

pub const fn admin_mac_provider_for_compliance_required(required: bool) -> AdminMacProvider {
    if required {
        admin_mac_provider()
    } else {
        AdminMacProvider::Ring
    }
}

pub const fn admin_mac_provider_label() -> &'static str {
    admin_mac_provider().label()
}

pub const fn admin_mac_is_compliance_capable() -> bool {
    admin_mac_provider().compliance_capable()
}
