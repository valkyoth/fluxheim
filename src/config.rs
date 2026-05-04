#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub app_name: &'static str,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_name: "fluxheim",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn default_config_names_fluxheim() {
        assert_eq!(Config::default().app_name, "fluxheim");
    }
}
