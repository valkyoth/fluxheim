use std::io::Write as _;

use fluxheim_config::{TlsClientAuthMode, TlsConfig};
use openssl::ssl::{SslAcceptorBuilder, SslFiletype, SslVerifyMode};
use openssl::stack::Stack;
use openssl::x509::store::{X509Lookup, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509Crl, X509Name};

use super::OpenSslDownstreamAcceptorError;
use crate::tls_input::{
    MAX_CA_BUNDLE_BYTES, MAX_CA_CERTIFICATES, MAX_CRL_BYTES, read_bounded_file,
};

pub(super) fn apply_client_auth(
    builder: &mut SslAcceptorBuilder,
    tls: &TlsConfig,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    if tls.client_auth.mode == TlsClientAuthMode::Off {
        return Ok(());
    }
    let ca_path = tls
        .client_auth
        .ca_path
        .as_deref()
        .ok_or(OpenSslDownstreamAcceptorError::MissingClientAuthCa)?;
    let verify = match tls.client_auth.mode {
        TlsClientAuthMode::Off => SslVerifyMode::NONE,
        TlsClientAuthMode::Optional => SslVerifyMode::PEER,
        TlsClientAuthMode::Required => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    };
    builder.set_verify(verify);
    let bytes = read_bounded_file(ca_path, MAX_CA_BUNDLE_BYTES).map_err(|source| {
        OpenSslDownstreamAcceptorError::ReadClientAuthCa {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    let certificates = X509::stack_from_pem(&bytes).map_err(|source| {
        OpenSslDownstreamAcceptorError::ParseClientAuthCa {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    if certificates.is_empty() {
        return Err(OpenSslDownstreamAcceptorError::EmptyClientAuthCa {
            path: ca_path.to_path_buf(),
        });
    }
    if certificates.len() > MAX_CA_CERTIFICATES {
        return Err(OpenSslDownstreamAcceptorError::TooManyClientAuthCa {
            path: ca_path.to_path_buf(),
            count: certificates.len(),
            maximum: MAX_CA_CERTIFICATES,
        });
    }
    let mut store = X509StoreBuilder::new().map_err(|source| {
        OpenSslDownstreamAcceptorError::ApplyClientAuthCa {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    let mut names = Stack::<X509Name>::new().map_err(|source| {
        OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    for certificate in certificates {
        names
            .push(certificate.subject_name().to_owned().map_err(|source| {
                OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                    path: ca_path.to_path_buf(),
                    source,
                }
            })?)
            .map_err(
                |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                    path: ca_path.to_path_buf(),
                    source,
                },
            )?;
        store.add_cert(certificate).map_err(|source| {
            OpenSslDownstreamAcceptorError::ApplyClientAuthCa {
                path: ca_path.to_path_buf(),
                source,
            }
        })?;
    }
    if let Some(crl_path) = tls.client_auth.crl_path.as_deref() {
        let crl_bytes = read_bounded_file(crl_path, MAX_CRL_BYTES).map_err(|source| {
            OpenSslDownstreamAcceptorError::ReadClientAuthCrl {
                path: crl_path.to_path_buf(),
                source,
            }
        })?;
        X509Crl::from_pem(&crl_bytes).map_err(|source| {
            OpenSslDownstreamAcceptorError::ParseClientAuthCrl {
                path: crl_path.to_path_buf(),
                source,
            }
        })?;
        let mut staged_crl = tempfile::Builder::new()
            .prefix("fluxheim-client-crl-")
            .tempfile()
            .map_err(
                |source| OpenSslDownstreamAcceptorError::StageClientAuthCrl {
                    path: crl_path.to_path_buf(),
                    source,
                },
            )?;
        staged_crl.write_all(&crl_bytes).map_err(|source| {
            OpenSslDownstreamAcceptorError::StageClientAuthCrl {
                path: crl_path.to_path_buf(),
                source,
            }
        })?;
        staged_crl.flush().map_err(|source| {
            OpenSslDownstreamAcceptorError::StageClientAuthCrl {
                path: crl_path.to_path_buf(),
                source,
            }
        })?;
        let path = staged_crl
            .path()
            .to_str()
            .filter(|path| !path.contains('\0'))
            .ok_or_else(
                || OpenSslDownstreamAcceptorError::UnsupportedClientAuthCrlPath {
                    path: crl_path.to_path_buf(),
                },
            )?;
        let lookup = store.add_lookup(X509Lookup::file()).map_err(|source| {
            OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
                path: crl_path.to_path_buf(),
                source,
            }
        })?;
        let loaded = lookup
            .load_crl_file(path, SslFiletype::PEM)
            .map_err(
                |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
                    path: crl_path.to_path_buf(),
                    source,
                },
            )?;
        if loaded != 1 {
            return Err(OpenSslDownstreamAcceptorError::InvalidClientAuthCrlCount {
                path: crl_path.to_path_buf(),
            });
        }
        store
            .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)
            .map_err(
                |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
                    path: crl_path.to_path_buf(),
                    source,
                },
            )?;
    }
    builder.set_cert_store(store.build());
    builder.set_client_ca_list(names);
    Ok(())
}
