#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GeoContext {
    country_iso: Option<String>,
    asn: Option<u32>,
}

impl GeoContext {
    #[cfg(feature = "geoip")]
    pub(crate) fn new(country_iso: Option<String>, asn: Option<u32>) -> Self {
        Self { country_iso, asn }
    }

    pub(crate) fn country_iso(&self) -> Option<&str> {
        self.country_iso.as_deref()
    }

    pub(crate) fn asn(&self) -> Option<u32> {
        self.asn
    }

    #[cfg(feature = "geoip")]
    pub(crate) fn is_empty(&self) -> bool {
        self.country_iso.is_none() && self.asn.is_none()
    }
}
