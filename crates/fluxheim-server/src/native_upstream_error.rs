use std::io;

use crate::NativeHttp1Error;

#[cfg(test)]
#[path = "native_upstream_error_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamPhase {
    Connect,
    Tls,
    Write,
    Read,
}

#[derive(Debug)]
struct PhasedIoError {
    phase: UpstreamPhase,
    classification: io::ErrorKind,
    source: io::Error,
}

impl std::fmt::Display for PhasedIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream {:?} failure", self.phase)
    }
}

impl std::error::Error for PhasedIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl NativeHttp1Error {
    // Preserve ErrorKind for transport retry decisions; phase never comes from text.
    pub(crate) fn with_upstream_phase(self, phase: UpstreamPhase) -> Self {
        let classification = match &self {
            Self::Io(error) => error.kind(),
            Self::Parse(_) => return self,
        };
        self.with_upstream_failure(phase, classification)
    }

    pub(crate) fn with_upstream_failure(
        self,
        phase: UpstreamPhase,
        classification: io::ErrorKind,
    ) -> Self {
        match self {
            Self::Io(error) if upstream_phase(&error).is_none() => Self::Io(io::Error::new(
                error.kind(),
                PhasedIoError {
                    phase,
                    classification,
                    source: error,
                },
            )),
            error => error,
        }
    }
}

pub(crate) fn upstream_error_kind(error: &io::Error) -> io::ErrorKind {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PhasedIoError>())
        .map_or(error.kind(), |source| source.classification)
}

pub(crate) fn upstream_phase(error: &io::Error) -> Option<UpstreamPhase> {
    error
        .get_ref()?
        .downcast_ref::<PhasedIoError>()
        .map(|error| error.phase)
}
