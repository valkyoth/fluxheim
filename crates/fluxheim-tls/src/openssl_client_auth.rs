use std::io::Write as _;
use std::path::PathBuf;

use fluxheim_config::{TlsClientAuthMode, TlsConfig};
use openssl::ssl::{SslAcceptorBuilder, SslFiletype, SslVerifyMode};
use openssl::stack::Stack;
use openssl::x509::store::{X509Lookup, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509Crl, X509Name};

use super::OpenSslDownstreamAcceptorError;
use crate::tls_input::{
    MAX_CA_BUNDLE_BYTES, MAX_CA_CERTIFICATES, MAX_CRL_BYTES, MAX_CRL_COUNT, read_bounded_file,
};

pub(super) struct OpenSslClientAuthPolicy {
    verify: Option<SslVerifyMode>,
    ca_path: Option<PathBuf>,
    certificates: Vec<X509>,
    crl: Option<OpenSslClientAuthCrl>,
    input_bytes: usize,
}

struct OpenSslClientAuthCrl {
    source_path: PathBuf,
    staged: tempfile::NamedTempFile,
    input_bytes: usize,
}

impl OpenSslClientAuthPolicy {
    pub(super) fn load(tls: &TlsConfig) -> Result<Self, OpenSslDownstreamAcceptorError> {
        if tls.client_auth.mode == TlsClientAuthMode::Off {
            return Ok(Self {
                verify: None,
                ca_path: None,
                certificates: Vec::new(),
                crl: None,
                input_bytes: 0,
            });
        }

        let ca_path = tls
            .client_auth
            .ca_path
            .as_deref()
            .ok_or(OpenSslDownstreamAcceptorError::MissingClientAuthCa)?;
        let ca_bytes = read_bounded_file(ca_path, MAX_CA_BUNDLE_BYTES).map_err(|source| {
            OpenSslDownstreamAcceptorError::ReadClientAuthCa {
                path: ca_path.to_path_buf(),
                source,
            }
        })?;
        let certificates = X509::stack_from_pem(&ca_bytes).map_err(|source| {
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

        let crl = tls
            .client_auth
            .crl_path
            .as_deref()
            .map(stage_crl_bundle)
            .transpose()?;
        let input_bytes = ca_bytes
            .len()
            .checked_add(crl.as_ref().map_or(0, |crl| crl.input_bytes))
            .ok_or(OpenSslDownstreamAcceptorError::ClientAuthPolicySizeOverflow)?;
        let verify = match tls.client_auth.mode {
            TlsClientAuthMode::Off => None,
            TlsClientAuthMode::Optional => Some(SslVerifyMode::PEER),
            TlsClientAuthMode::Required => {
                Some(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT)
            }
        };

        Ok(Self {
            verify,
            ca_path: Some(ca_path.to_path_buf()),
            certificates,
            crl,
            input_bytes,
        })
    }

    pub(super) fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub(super) fn apply(
        &self,
        builder: &mut SslAcceptorBuilder,
    ) -> Result<(), OpenSslDownstreamAcceptorError> {
        let Some(verify) = self.verify else {
            return Ok(());
        };
        let ca_path = self
            .ca_path
            .as_ref()
            .ok_or(OpenSslDownstreamAcceptorError::MissingClientAuthCa)?;
        builder.set_verify(verify);
        let mut store = X509StoreBuilder::new().map_err(|source| {
            OpenSslDownstreamAcceptorError::ApplyClientAuthCa {
                path: ca_path.clone(),
                source,
            }
        })?;
        let mut names = Stack::<X509Name>::new().map_err(|source| {
            OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                path: ca_path.clone(),
                source,
            }
        })?;
        for certificate in &self.certificates {
            names
                .push(certificate.subject_name().to_owned().map_err(|source| {
                    OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                        path: ca_path.clone(),
                        source,
                    }
                })?)
                .map_err(
                    |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                        path: ca_path.clone(),
                        source,
                    },
                )?;
            store.add_cert(certificate.clone()).map_err(|source| {
                OpenSslDownstreamAcceptorError::ApplyClientAuthCa {
                    path: ca_path.clone(),
                    source,
                }
            })?;
        }
        if let Some(crl) = &self.crl {
            apply_crl_bundle(&mut store, crl)?;
        }
        builder.set_cert_store(store.build());
        builder.set_client_ca_list(names);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn apply_client_auth(
    builder: &mut SslAcceptorBuilder,
    tls: &TlsConfig,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    OpenSslClientAuthPolicy::load(tls)?.apply(builder)
}

fn stage_crl_bundle(
    path: &std::path::Path,
) -> Result<OpenSslClientAuthCrl, OpenSslDownstreamAcceptorError> {
    let crl_bytes = read_bounded_file(path, MAX_CRL_BYTES).map_err(|source| {
        OpenSslDownstreamAcceptorError::ReadClientAuthCrl {
            path: path.to_path_buf(),
            source,
        }
    })?;
    X509Crl::from_pem(&crl_bytes).map_err(|source| {
        OpenSslDownstreamAcceptorError::ParseClientAuthCrl {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let mut staged = tempfile::Builder::new()
        .prefix("fluxheim-client-crl-")
        .tempfile()
        .map_err(
            |source| OpenSslDownstreamAcceptorError::StageClientAuthCrl {
                path: path.to_path_buf(),
                source,
            },
        )?;
    staged.write_all(&crl_bytes).map_err(|source| {
        OpenSslDownstreamAcceptorError::StageClientAuthCrl {
            path: path.to_path_buf(),
            source,
        }
    })?;
    staged.flush().map_err(
        |source| OpenSslDownstreamAcceptorError::StageClientAuthCrl {
            path: path.to_path_buf(),
            source,
        },
    )?;
    Ok(OpenSslClientAuthCrl {
        source_path: path.to_path_buf(),
        staged,
        input_bytes: crl_bytes.len(),
    })
}

fn apply_crl_bundle(
    store: &mut X509StoreBuilder,
    crl: &OpenSslClientAuthCrl,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    let path = crl
        .staged
        .path()
        .to_str()
        .filter(|path| !path.contains('\0'))
        .ok_or_else(
            || OpenSslDownstreamAcceptorError::UnsupportedClientAuthCrlPath {
                path: crl.source_path.clone(),
            },
        )?;
    let lookup = store.add_lookup(X509Lookup::file()).map_err(|source| {
        OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
            path: crl.source_path.clone(),
            source,
        }
    })?;
    let loaded = lookup
        .load_crl_file(path, SslFiletype::PEM)
        .map_err(
            |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
                path: crl.source_path.clone(),
                source,
            },
        )?;
    let loaded = usize::try_from(loaded).unwrap_or(usize::MAX);
    if loaded == 0 || loaded > MAX_CRL_COUNT {
        return Err(OpenSslDownstreamAcceptorError::InvalidClientAuthCrlCount {
            path: crl.source_path.clone(),
            count: loaded,
            maximum: MAX_CRL_COUNT,
        });
    }
    store
        .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)
        .map_err(
            |source| OpenSslDownstreamAcceptorError::ApplyClientAuthCrl {
                path: crl.source_path.clone(),
                source,
            },
        )?;
    Ok(())
}
