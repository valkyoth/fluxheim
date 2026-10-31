use std::time::Duration;

use super::NativeHttp1Upstream;
use crate::DownstreamHttp2Policy;

#[test]
fn setup_timeout_also_shortens_only_the_fresh_h2_response_wait() {
    // documented contract: setup and response phases currently have inconsistent budgets.
    let upstream = NativeHttp1Upstream::new("127.0.0.1:9001")
        .with_http2_policy(
            DownstreamHttp2Policy::default().with_handler_timeout(Duration::from_secs(30)),
        )
        .with_total_connection_timeout(Some(Duration::from_secs(1)));
    assert_eq!(
        upstream.http2_request_policy(true).handler_timeout(),
        Duration::from_secs(1)
    );
    assert_eq!(
        upstream.http2_request_policy(false).handler_timeout(),
        Duration::from_secs(30)
    );
}
