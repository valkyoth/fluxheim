pub(crate) use fluxheim_common::{FluxError, FluxResult};

#[cfg(feature = "ingress")]
pub(crate) trait FluxErrorPingoraExt {
    fn into_pingora(self, kind: pingora::ErrorType) -> Box<pingora::Error>;
}

#[cfg(feature = "ingress")]
impl FluxErrorPingoraExt for FluxError {
    fn into_pingora(self, kind: pingora::ErrorType) -> Box<pingora::Error> {
        let description = self.to_string();
        pingora::Error::because(kind, description, self)
    }
}
