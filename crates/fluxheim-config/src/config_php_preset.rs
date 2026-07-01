use crate::config::extend_unique;
use crate::config_php::{PhpConfig, PhpPreset, PhpTryFilesMode};

pub(crate) fn apply_php_preset_defaults(config: &mut PhpConfig) {
    match config.preset {
        PhpPreset::None => {}
        PhpPreset::WordPress => apply_wordpress_preset_defaults(config),
    }
}

fn apply_wordpress_preset_defaults(config: &mut PhpConfig) {
    if config.try_files == PhpTryFilesMode::FrontController {
        config.try_files = PhpTryFilesMode::WordPress;
    }
    extend_unique(
        &mut config.deny_path_prefixes,
        [
            "/wp-content/uploads/",
            "/wp-content/blogs.dir/",
            "/blogs.dir/",
            "/uploads/",
            "/files/",
        ]
        .map(str::to_owned),
    );
}
