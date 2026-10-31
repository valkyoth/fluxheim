use super::{ConfigError, WasmAttachmentConfig, WasmPluginConfig, WasmPluginPhase};
use crate::{ProxyConfig, VhostConfig};

impl WasmAttachmentConfig {
    pub(crate) fn validate_upgrade_policy(
        &self,
        vhost: &VhostConfig,
        plugin: &WasmPluginConfig,
    ) -> Result<(), ConfigError> {
        let websocket = |proxy: &ProxyConfig| proxy.websocket;
        let affected = match &self.route {
            Some(name) => vhost
                .routes
                .iter()
                .any(|route| &route.name == name && route.proxy.as_ref().is_some_and(websocket)),
            None => {
                websocket(&vhost.proxy)
                    || vhost
                        .routes
                        .iter()
                        .any(|route| route.proxy.as_ref().is_some_and(websocket))
            }
        };
        let phases = if self.phases.is_empty() {
            &plugin.phases
        } else {
            &self.phases
        };
        if affected
            && phases.iter().any(|phase| {
                matches!(
                    phase,
                    WasmPluginPhase::RouteDecision
                        | WasmPluginPhase::RequestHeaders
                        | WasmPluginPhase::ResponseHeaders
                )
            })
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm attachment for vhost {:?}", self.vhost),
                field: "phases",
                reason: "WebSocket-enabled proxy scopes do not support Wasm route-decision or request/response-header hooks; disable WebSocket or move those hooks to an HTTP-only scope",
            });
        }
        Ok(())
    }
}
