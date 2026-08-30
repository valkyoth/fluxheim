use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::io::{BufReader, Read as _};
use std::pin::Pin;
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};
use http_body_util::BodyExt as _;
use hyper::body::Body as _;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};

use crate::AcmeInstantClientError;

pub(crate) const MAX_ACME_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const ACME_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const ACME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ACME_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_ACME_CA_CERTIFICATES: usize = 128;

type InnerClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>;

#[derive(Clone)]
struct BoundedAcmeHttpClient {
    inner: InnerClient,
}

impl BoundedAcmeHttpClient {
    fn try_new(issuer: &fluxheim_config::AcmeIssuerConfig) -> Result<Self, BoundedAcmeHttpError> {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(ACME_CONNECT_TIMEOUT));
        let https = if let Some(path) = issuer.ca_bundle_file.as_deref() {
            let roots = load_ca_bundle(path)?;
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_only()
                .enable_http1()
                .enable_http2()
                .build()
        } else {
            HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(BoundedAcmeHttpError::TrustStore)?
                .https_only()
                .enable_http1()
                .enable_http2()
                .build()
        };
        Ok(Self {
            inner: Client::builder(TokioExecutor::new()).build(https),
        })
    }

    async fn request_bounded(
        inner: InnerClient,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Result<BytesResponse, instant_acme::Error> {
        let response = inner
            .request(request)
            .await
            .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
        let (parts, mut body) = response.into_parts();
        let output = collect_capped_body(&mut body, MAX_ACME_RESPONSE_BYTES)
            .await
            .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;

        Ok(BytesResponse {
            parts,
            body: Box::new(output),
        })
    }
}

impl HttpClient for BoundedAcmeHttpClient {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            tokio::time::timeout(ACME_REQUEST_TIMEOUT, Self::request_bounded(inner, request))
                .await
                .map_err(|_| {
                    instant_acme::Error::Other(Box::new(BoundedAcmeHttpError::RequestTimeout))
                })?
        })
    }
}

#[derive(Debug)]
enum BoundedAcmeHttpError {
    Body(String),
    InvalidTrustBundle,
    RequestTimeout,
    ResponseTooLarge,
    TrustStore(std::io::Error),
}

impl fmt::Display for BoundedAcmeHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(message) => write!(formatter, "ACME HTTP response body failed: {message}"),
            Self::InvalidTrustBundle => write!(
                formatter,
                "ACME issuer CA bundle is empty, oversized, symlinked, or invalid"
            ),
            Self::RequestTimeout => write!(formatter, "ACME HTTP request exceeded its deadline"),
            Self::ResponseTooLarge => write!(
                formatter,
                "ACME HTTP response exceeds {MAX_ACME_RESPONSE_BYTES} bytes"
            ),
            Self::TrustStore(error) => {
                write!(
                    formatter,
                    "failed to load ACME platform trust store: {error}"
                )
            }
        }
    }
}

impl StdError for BoundedAcmeHttpError {}

async fn collect_capped_body<B>(
    body: &mut B,
    max_bytes: usize,
) -> Result<Bytes, BoundedAcmeHttpError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: fmt::Display,
{
    if body
        .size_hint()
        .upper()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BoundedAcmeHttpError::ResponseTooLarge);
    }

    let initial = usize::try_from(body.size_hint().lower())
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut output = BytesMut::with_capacity(initial);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| BoundedAcmeHttpError::Body(error.to_string()))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let new_len = output
            .len()
            .checked_add(data.remaining())
            .filter(|length| *length <= max_bytes)
            .ok_or(BoundedAcmeHttpError::ResponseTooLarge)?;
        output.reserve(new_len - output.len());
        output.extend_from_slice(&data);
    }
    Ok(output.freeze())
}

pub(crate) fn bounded_acme_account_builder(
    issuer: &fluxheim_config::AcmeIssuerConfig,
) -> Result<instant_acme::AccountBuilder, AcmeInstantClientError> {
    let client = BoundedAcmeHttpClient::try_new(issuer).map_err(|error| {
        AcmeInstantClientError::Account {
            issuer: issuer.name.clone(),
            message: error.to_string(),
        }
    })?;
    Ok(instant_acme::Account::builder_with_http(Box::new(client)))
}

pub(crate) async fn probe_acme_directory(
    issuer: &fluxheim_config::AcmeIssuerConfig,
) -> Result<(), AcmeInstantClientError> {
    let client = BoundedAcmeHttpClient::try_new(issuer).map_err(|error| {
        AcmeInstantClientError::Account {
            issuer: issuer.name.clone(),
            message: error.to_string(),
        }
    })?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(&issuer.directory_url)
        .body(BodyWrapper::default())
        .map_err(|error| AcmeInstantClientError::Account {
            issuer: issuer.name.clone(),
            message: error.to_string(),
        })?;
    let response =
        client
            .request(request)
            .await
            .map_err(|error| AcmeInstantClientError::Account {
                issuer: issuer.name.clone(),
                message: error.to_string(),
            })?;
    let status = response.parts.status;
    let mut body = response.body;
    let bytes = body
        .into_bytes()
        .await
        .map_err(|error| issuer_probe_error(issuer, error.to_string()))?;
    validate_acme_directory_response(issuer, status, &bytes)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryProbe {
    new_nonce: String,
    new_account: String,
    new_order: String,
    #[serde(default)]
    meta: DirectoryProbeMeta,
}

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryProbeMeta {
    terms_of_service: Option<String>,
}

fn validate_acme_directory_response(
    issuer: &fluxheim_config::AcmeIssuerConfig,
    status: http::StatusCode,
    bytes: &[u8],
) -> Result<(), AcmeInstantClientError> {
    if !status.is_success() {
        return Err(issuer_probe_error(
            issuer,
            format!("ACME directory returned HTTP status {status}"),
        ));
    }
    let directory: DirectoryProbe = serde_json::from_slice(bytes)
        .map_err(|_| issuer_probe_error(issuer, "response is not a valid ACME directory"))?;
    for (name, endpoint) in [
        ("newNonce", directory.new_nonce.as_str()),
        ("newAccount", directory.new_account.as_str()),
        ("newOrder", directory.new_order.as_str()),
    ] {
        if !valid_acme_endpoint(endpoint) {
            return Err(issuer_probe_error(
                issuer,
                format!("ACME directory {name} endpoint is not a valid HTTPS URL"),
            ));
        }
    }
    match (
        directory.meta.terms_of_service.as_deref(),
        issuer.terms_of_service_url.as_deref(),
    ) {
        (Some(advertised), Some(accepted)) if advertised == accepted => Ok(()),
        (None, Some(_)) if issuer.allow_unadvertised_terms_of_service => Ok(()),
        _ => Err(AcmeInstantClientError::TermsOfServiceNotAccepted {
            issuer: issuer.name.clone(),
        }),
    }
}

fn valid_acme_endpoint(endpoint: &str) -> bool {
    let Ok(uri) = endpoint.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty()
                && authority.as_str().len() <= 255
                && !authority.as_str().contains('@')
        })
        && uri.path().starts_with('/')
}

fn issuer_probe_error(
    issuer: &fluxheim_config::AcmeIssuerConfig,
    message: impl Into<String>,
) -> AcmeInstantClientError {
    AcmeInstantClientError::Account {
        issuer: issuer.name.clone(),
        message: message.into(),
    }
}

fn load_ca_bundle(path: &std::path::Path) -> Result<rustls::RootCertStore, BoundedAcmeHttpError> {
    let file = open_ca_bundle_no_follow(path).map_err(BoundedAcmeHttpError::TrustStore)?;
    let metadata = file.metadata().map_err(BoundedAcmeHttpError::TrustStore)?;
    if !metadata.is_file() || metadata.len() > MAX_ACME_CA_BUNDLE_BYTES {
        return Err(BoundedAcmeHttpError::InvalidTrustBundle);
    }
    let mut limited = BufReader::new(file.take(MAX_ACME_CA_BUNDLE_BYTES.saturating_add(1)));
    let mut roots = rustls::RootCertStore::empty();
    let mut count = 0_usize;
    use rustls::pki_types::pem::PemObject as _;
    for certificate in rustls::pki_types::CertificateDer::pem_reader_iter(&mut limited) {
        let certificate = certificate.map_err(|_| BoundedAcmeHttpError::InvalidTrustBundle)?;
        count = count.saturating_add(1);
        if count > MAX_ACME_CA_CERTIFICATES || roots.add(certificate).is_err() {
            return Err(BoundedAcmeHttpError::InvalidTrustBundle);
        }
    }
    if count == 0 {
        return Err(BoundedAcmeHttpError::InvalidTrustBundle);
    }
    Ok(roots)
}

fn open_ca_bundle_no_follow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(super::UNIX_O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::BoundedAcmeHttpClient;
    use super::{
        MAX_ACME_RESPONSE_BYTES, collect_capped_body, valid_acme_endpoint,
        validate_acme_directory_response,
    };
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn capped_collector_accepts_bounded_body_and_rejects_oversized_hint() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bounded = runtime
            .block_on(collect_capped_body(
                &mut Full::new(Bytes::from_static(b"bounded")),
                MAX_ACME_RESPONSE_BYTES,
            ))
            .unwrap();
        assert_eq!(bounded, Bytes::from_static(b"bounded"));

        let error = runtime
            .block_on(collect_capped_body(
                &mut Full::new(Bytes::from(vec![0_u8; MAX_ACME_RESPONSE_BYTES + 1])),
                MAX_ACME_RESPONSE_BYTES,
            ))
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn dedicated_ca_bundle_rejects_a_symlink() {
        let root = fluxheim_common::test_support::unique_temp_path("acme-ca-bundle-symlink");
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real.pem");
        let link = root.join("bundle.pem");
        std::fs::write(
            &real,
            include_bytes!("../../../tests/fixtures/tls/localhost-cert.pem"),
        )
        .unwrap();
        std::os::unix::fs::symlink(real, &link).unwrap();
        let issuer = fluxheim_config::AcmeIssuerConfig {
            name: "test".to_owned(),
            directory_url: "https://acme.example.test/directory".to_owned(),
            terms_of_service_agreed: true,
            terms_of_service_url: Some("https://acme.example.test/terms/v1".to_owned()),
            allow_unadvertised_terms_of_service: false,
            ca_bundle_file: Some(link),
            eab: None,
        };

        assert!(BoundedAcmeHttpClient::try_new(&issuer).is_err());
    }

    #[test]
    fn directory_probe_requires_acme_endpoints_and_exact_terms() {
        let issuer = fluxheim_config::AcmeIssuerConfig {
            name: "test".to_owned(),
            directory_url: "https://acme.example.test/directory".to_owned(),
            terms_of_service_agreed: true,
            terms_of_service_url: Some("https://acme.example.test/terms/v2".to_owned()),
            allow_unadvertised_terms_of_service: false,
            ca_bundle_file: None,
            eab: None,
        };
        let valid = br#"{
            "newNonce":"https://acme.example.test/new-nonce",
            "newAccount":"https://acme.example.test/new-account",
            "newOrder":"https://acme.example.test/new-order",
            "meta":{"termsOfService":"https://acme.example.test/terms/v2"}
        }"#;
        validate_acme_directory_response(&issuer, http::StatusCode::OK, valid).unwrap();

        let non_acme = br#"{"status":"ok"}"#;
        assert!(validate_acme_directory_response(&issuer, http::StatusCode::OK, non_acme).is_err());
        let wrong_terms = valid
            .windows("terms/v2".len())
            .position(|window| window == b"terms/v2")
            .map(|position| {
                let mut changed = valid.to_vec();
                changed[position + "terms/".len()] = b'3';
                changed
            })
            .unwrap();
        assert!(
            validate_acme_directory_response(&issuer, http::StatusCode::OK, &wrong_terms).is_err()
        );

        let missing_terms = br#"{
            "newNonce":"https://acme.example.test/new-nonce",
            "newAccount":"https://acme.example.test/new-account",
            "newOrder":"https://acme.example.test/new-order"
        }"#;
        assert!(
            validate_acme_directory_response(&issuer, http::StatusCode::OK, missing_terms).is_err()
        );
        let mut private_issuer = issuer;
        private_issuer.allow_unadvertised_terms_of_service = true;
        validate_acme_directory_response(&private_issuer, http::StatusCode::OK, missing_terms)
            .unwrap();
        assert!(
            validate_acme_directory_response(&private_issuer, http::StatusCode::OK, &wrong_terms,)
                .is_err()
        );
    }

    #[test]
    fn acme_endpoint_requires_parsed_https_authority() {
        assert!(valid_acme_endpoint("https://acme.example.test/new-order"));
        assert!(valid_acme_endpoint("https://[::1]:8443/new-order"));
        for invalid in [
            "http://acme.example.test/new-order",
            "https://?query",
            "https://#fragment",
            "https:///missing-authority",
            "https://user@acme.example.test/new-order",
            "not-a-uri",
        ] {
            assert!(!valid_acme_endpoint(invalid), "accepted {invalid:?}");
        }
    }
}
