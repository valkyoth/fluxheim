use std::error::Error;

#[cfg(all(test, feature = "acme-client", unix))]
#[path = "acme_companion_reload_contract_tests.rs"]
mod contract_tests;

#[cfg(all(feature = "acme-client", unix))]
use super::config_loader::load_validated_config;
#[cfg(feature = "acme-client")]
use crate::config::Config;

#[cfg(all(feature = "acme-client", unix))]
pub(super) const MAX_CERTIFICATE_RELOAD_RESPONSE_BYTES: u64 = 4096;

#[cfg(all(feature = "acme-client", unix))]
pub(super) fn request_certificate_reload(
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate_certificate_reload_path()?;
    let path = &config.server.process.certificate_reload_sock;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Allow the server's OpenSSL generation drain (10 s) within the exchange.
    runtime
        .block_on(reload_exchange(path, std::time::Duration::from_secs(15)))
        .map_err(|error| {
            format!(
                "certificate reload request through {} failed: {error}; activation not confirmed",
                path.display()
            )
        })?;
    println!("certificate reload: ok");
    Ok(())
}

#[cfg(all(feature = "acme-client", unix))]
async fn reload_exchange(
    path: &std::path::Path,
    limit: std::time::Duration,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

    tokio::time::timeout(limit, async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        stream.write_all(b"reload-certificates\n").await?;
        let mut reply = Vec::new();
        BufReader::new(stream.take(MAX_CERTIFICATE_RELOAD_RESPONSE_BYTES))
            .read_until(b'\n', &mut reply)
            .await?;
        match reply.as_slice() {
            b"ok\n" => Ok(()),
            line if line.starts_with(b"error: ") && line.ends_with(b"\n") => {
                Err(Error::other("server rejected certificate reload"))
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "invalid or incomplete reload reply",
            )),
        }
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "reload exchange timed out"))?
}

#[cfg(all(feature = "acme-client", unix))]
pub(super) fn request_certificate_reload_for_config(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
    request_certificate_reload(&config)
}

#[cfg(all(feature = "acme-client", not(unix)))]
pub(super) fn request_certificate_reload(
    _config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("certificate reload control socket requires Unix domain sockets; use renew --no-reload and activate installed certificates by restarting the Windows service".into())
}

#[cfg(all(test, feature = "acme-client", windows))]
#[test]
fn windows_external_reload_cannot_acknowledge_activation() {
    assert!(
        request_certificate_reload(&Config::default())
            .unwrap_err()
            .to_string()
            .contains("renew --no-reload")
    );
    assert!(request_certificate_reload_for_config(None).is_err());
}

#[cfg(any(not(feature = "acme-client"), all(feature = "acme-client", not(unix))))]
pub(super) fn request_certificate_reload_for_config(
    _config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err(
        "certificate reload control socket requires Unix domain sockets and the `acme-client` feature"
            .into(),
    )
}
