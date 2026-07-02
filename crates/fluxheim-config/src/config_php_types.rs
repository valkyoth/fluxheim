use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PhpPreset {
    #[default]
    None,
    #[serde(rename = "wordpress")]
    WordPress,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpRuntime {
    #[default]
    #[serde(rename = "php-fpm")]
    PhpFpm,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpPathInfoMode {
    #[default]
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "split", alias = "strict")]
    Split,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpTryFilesMode {
    #[default]
    #[serde(rename = "front-controller")]
    FrontController,
    #[serde(rename = "wordpress")]
    WordPress,
    #[serde(rename = "strict")]
    Strict,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpStderrLogLevel {
    #[serde(rename = "error")]
    Error,
    #[default]
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "debug")]
    Debug,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpFpmMode {
    #[default]
    #[serde(rename = "external")]
    External,
    #[serde(rename = "managed")]
    Managed,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpFpmProcessManager {
    #[default]
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "dynamic")]
    Dynamic,
    #[serde(rename = "ondemand")]
    Ondemand,
}
