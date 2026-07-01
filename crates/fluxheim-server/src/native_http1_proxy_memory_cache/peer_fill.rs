use crate::NativeHttp1Request;
use crate::native_http1_proxy_cache_fill::{NativePeerFillPermit, acquire_native_peer_fill_permit};
use crate::native_http1_proxy_cache_headers::native_request_cache_only_if_cached;
use crate::native_http1_proxy_peer_fill::{native_peer_fill_fetch, native_request_is_peer_fill};

use super::{NativePeerFillDecision, NativeProxyMemoryCache};

impl NativeProxyMemoryCache {
    fn acquire_peer_fill_permit(&self) -> Option<NativePeerFillPermit> {
        acquire_native_peer_fill_permit(
            self.peer_fill_key.as_ref().to_owned(),
            self.config.peer_fill.max_concurrent_requests,
        )
    }

    pub(crate) async fn peer_fill(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> NativePeerFillDecision {
        if !self.config.peer_fill.enabled
            || request.method != "GET"
            || (native_request_is_peer_fill(request)
                && native_request_cache_only_if_cached(request))
        {
            return NativePeerFillDecision::Skip;
        }
        let Some(_permit) = self.acquire_peer_fill_permit() else {
            return if self.config.peer_fill.fail_open {
                self.record_policy_activity("peer_fill_fallback");
                NativePeerFillDecision::Skip
            } else {
                self.record_policy_activity("peer_fill_fail_closed");
                NativePeerFillDecision::FailClosed("peer-fill-concurrency-limit")
            };
        };
        let max_body_bytes = self
            .config
            .peer_fill
            .max_object_bytes
            .unwrap_or(self.config.max_object_bytes)
            .as_u64()
            .min(self.config.max_object_bytes.as_u64());

        for peer in &self.peer_fill_peers {
            match native_peer_fill_fetch(
                peer,
                &self.config,
                self.peer_fill_auth.as_deref(),
                request,
                max_body_bytes,
            )
            .await
            {
                Ok(Some(response)) => {
                    if response.status() != 200 {
                        continue;
                    }
                    if self.store_peer_fill(key, request, &response).await.is_err() {
                        self.record_policy_activity("peer_fill_error");
                        continue;
                    }
                    self.record_policy_activity("peer_fill_hit");
                    return NativePeerFillDecision::Hit(response);
                }
                Ok(None) => {}
                Err(error) => {
                    self.record_policy_activity("peer_fill_error");
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "native peer fill from {} failed: {error:?}",
                        peer.name
                    );
                }
            }
        }

        if self.config.peer_fill.fail_open {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fallback");
            NativePeerFillDecision::Skip
        } else {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fail_closed");
            NativePeerFillDecision::FailClosed("peer-fill-miss")
        }
    }
}
