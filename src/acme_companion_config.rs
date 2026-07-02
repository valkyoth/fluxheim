#[cfg(feature = "acme")]
use std::error::Error;

#[cfg(feature = "acme")]
use crate::config::Config;

#[cfg(feature = "acme")]
pub(super) fn load_validated_config(
    config_path: Option<&std::path::Path>,
) -> Result<Config, Box<dyn Error + Send + Sync>> {
    let config = Config::load(config_path)?;
    config.validate()?;
    crate::cli::validate_compiled_module_config(&config)?;
    Ok(config)
}
