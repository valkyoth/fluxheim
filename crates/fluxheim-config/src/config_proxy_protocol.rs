use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamHttpVersion {
    #[default]
    Http1,
    Http2,
    Http1AndHttp2,
}
