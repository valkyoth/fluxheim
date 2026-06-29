#[allow(unused_imports)]
pub(crate) use fluxheim_common::{FluxError, FluxResult};

#[cfg(all(feature = "ingress", feature = "pingora-compat"))]
pub(crate) trait FluxErrorPingoraExt {
    fn into_pingora(self, kind: pingora::ErrorType) -> Box<pingora::Error>;
}

#[cfg(all(feature = "ingress", feature = "pingora-compat"))]
impl FluxErrorPingoraExt for FluxError {
    fn into_pingora(self, kind: pingora::ErrorType) -> Box<pingora::Error> {
        let description = self.to_string();
        pingora::Error::because(kind, description, self)
    }
}
