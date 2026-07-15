use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenSslDownstreamAcceptorError {
    #[error("failed to build OpenSSL downstream TLS acceptor: {0}")]
    BuildAcceptor(#[source] openssl::error::ErrorStack),
    #[error("failed to read TLS certificate chain {path}: {source}")]
    ReadCertificate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS certificate chain {path}: {source}")]
    ParseCertificate {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("TLS certificate chain {path} does not contain any certificates")]
    EmptyCertificate { path: PathBuf },
    #[error("TLS certificate chain {path} contains {count} certificates; maximum is {maximum}")]
    TooManyCertificates {
        path: PathBuf,
        count: usize,
        maximum: usize,
    },
    #[error("failed to read TLS private key {path}: {source}")]
    ReadPrivateKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS private key {path}: {source}")]
    ParsePrivateKey {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("failed to apply TLS certificate to OpenSSL acceptor: {0}")]
    ApplyCertificate(#[source] openssl::error::ErrorStack),
    #[error("failed to apply TLS private key to OpenSSL acceptor: {0}")]
    ApplyPrivateKey(#[source] openssl::error::ErrorStack),
    #[error("failed to inspect TLS certificate public key: {0}")]
    InspectCertificatePublicKey(#[source] openssl::error::ErrorStack),
    #[error("TLS certificate and private key do not match; cert={cert_path} key={key_path}")]
    CertificateKeyMismatch {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    #[error("failed to apply complete OpenSSL SNI certificate context: {0}")]
    ApplyCertificateContext(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS curve policy: {0}")]
    ApplyCurves(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS 1.2 cipher policy: {0}")]
    ApplyTls12Ciphers(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS 1.3 cipher policy: {0}")]
    ApplyTls13Ciphers(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS protocol policy: {0}")]
    ApplyProtocol(#[source] openssl::error::ErrorStack),
    #[error("tls.client_auth.ca_path is required when client auth is enabled")]
    MissingClientAuthCa,
    #[error("failed to read TLS client-auth CA bundle {path}: {source}")]
    ReadClientAuthCa {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS client-auth CA bundle {path}: {source}")]
    ParseClientAuthCa {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("TLS client-auth CA bundle {path} contains no certificates")]
    EmptyClientAuthCa { path: PathBuf },
    #[error("TLS client-auth CA bundle {path} contains {count} certificates; maximum is {maximum}")]
    TooManyClientAuthCa {
        path: PathBuf,
        count: usize,
        maximum: usize,
    },
    #[error("OpenSSL rejected TLS client-auth CA bundle {path}: {source}")]
    ApplyClientAuthCa {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("OpenSSL rejected TLS client-auth CA list {path}: {source}")]
    ApplyClientAuthCaList {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("failed to read TLS client-auth CRL {path}: {source}")]
    ReadClientAuthCrl {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS client-auth CRL {path}: {source}")]
    ParseClientAuthCrl {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("failed to stage bounded TLS client-auth CRL {path}: {source}")]
    StageClientAuthCrl {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS client-auth CRL path cannot be passed safely to OpenSSL: {path}")]
    UnsupportedClientAuthCrlPath { path: PathBuf },
    #[error(
        "TLS client-auth CRL bundle {path} contains {count} revocation lists; expected 1..={maximum}"
    )]
    InvalidClientAuthCrlCount {
        path: PathBuf,
        count: usize,
        maximum: usize,
    },
    #[error("OpenSSL rejected TLS client-auth CRL {path}: {source}")]
    ApplyClientAuthCrl {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("TLS client-auth policy input size overflowed its resource budget")]
    ClientAuthPolicySizeOverflow,
}

#[derive(Debug, Error)]
pub enum OpenSslDownstreamCertificateStoreError {
    #[error(transparent)]
    Certificate(#[from] OpenSslDownstreamAcceptorError),
    #[error(
        "failed to inspect managed certificate paths; cert={cert_path} key={key_path}: {source}"
    )]
    InspectManagedCertificate {
        cert_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("downstream SNI certificate index {index} was not loaded")]
    MissingLoadedCertificate { index: usize },
    #[error(
        "projected OpenSSL SNI client-auth policy storage is {projected_bytes} bytes across {context_count} contexts; maximum is {maximum_bytes} bytes"
    )]
    ClientAuthPolicyBudgetExceeded {
        context_count: usize,
        projected_bytes: usize,
        maximum_bytes: usize,
    },
    #[error("OpenSSL SNI context count overflowed its resource budget")]
    ContextBudgetOverflow,
    #[error("failed to allocate OpenSSL SSL generation-lease storage: {0}")]
    CreateGenerationLeaseIndex(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL SNI reload generation state lock was poisoned")]
    ReloadGenerationStatePoisoned,
    #[error(
        "OpenSSL SNI reload would exceed {maximum} live certificate generations; currently live: {count}"
    )]
    TooManyLiveGenerations { count: usize, maximum: usize },
}
