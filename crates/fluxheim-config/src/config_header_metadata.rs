use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

const MAX_RESPONSE_METADATA_IDENTIFIER_BYTES: usize = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMetadataConfig {
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub cache_status: bool,
    #[serde(default)]
    pub proxy_status: bool,
    #[serde(default)]
    pub content_digest: bool,
    #[serde(default)]
    pub repr_digest: bool,
}

impl ResponseMetadataConfig {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if (self.cache_status || self.proxy_status)
            && self
                .identifier
                .as_deref()
                .is_none_or(|identifier| !structured_field_token(identifier))
        {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        Ok(())
    }

    pub fn apply_overlay(&mut self, overlay: &ResponseMetadataOverlayConfig) {
        if let Some(identifier) = &overlay.identifier {
            self.identifier = identifier.clone();
        }
        if let Some(cache_status) = overlay.cache_status {
            self.cache_status = cache_status;
        }
        if let Some(proxy_status) = overlay.proxy_status {
            self.proxy_status = proxy_status;
        }
        if let Some(content_digest) = overlay.content_digest {
            self.content_digest = content_digest;
        }
        if let Some(repr_digest) = overlay.repr_digest {
            self.repr_digest = repr_digest;
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMetadataOverlayConfig {
    #[serde(default)]
    pub identifier: Option<Option<String>>,
    #[serde(default)]
    pub cache_status: Option<bool>,
    #[serde(default)]
    pub proxy_status: Option<bool>,
    #[serde(default)]
    pub content_digest: Option<bool>,
    #[serde(default)]
    pub repr_digest: Option<bool>,
}

impl ResponseMetadataOverlayConfig {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self
            .identifier
            .as_ref()
            .and_then(Option::as_deref)
            .is_some_and(|identifier| !structured_field_token(identifier))
        {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        Ok(())
    }
}

fn structured_field_token(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RESPONSE_METADATA_IDENTIFIER_BYTES {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_alphabetic() || byte == b'*'
        } else {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                        | b':'
                        | b'/'
                )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::structured_field_token;

    #[test]
    fn metadata_identifier_uses_structured_field_token_grammar() {
        assert!(structured_field_token("edge-gateway"));
        assert!(structured_field_token("edge.example:8443"));
        assert!(!structured_field_token(""));
        assert!(!structured_field_token("9edge"));
        assert!(!structured_field_token("edge gateway"));
        assert!(!structured_field_token("edge,other"));
    }
}
