use std::error::Error;

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
    use std::io::{Read, Write};

    let path = &config.server.process.certificate_reload_sock;
    let mut stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.write_all(b"reload-certificates\n")?;
    let mut response = String::new();
    let mut limited = (&mut stream).take(MAX_CERTIFICATE_RELOAD_RESPONSE_BYTES);
    limited.read_to_string(&mut response)?;
    let response = response.trim();
    if response == "ok" {
        println!("certificate reload: ok");
        return Ok(());
    }
    Err(format!(
        "certificate reload request through {} failed: {response}",
        path.display()
    )
    .into())
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
    Err("certificate reload control socket requires Unix domain sockets".into())
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
