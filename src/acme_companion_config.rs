#[cfg(feature = "acme")]
use std::error::Error;

#[cfg(feature = "acme")]
use crate::config::{Config, ValidationScope};

#[cfg(feature = "acme")]
pub(super) fn load_validated_config(
    config_path: Option<&std::path::Path>,
) -> Result<Config, Box<dyn Error + Send + Sync>> {
    let config = Config::load_for_scope(config_path, ValidationScope::Acme)?;
    Ok(config)
}
