use super::upgrade::{
    validate_websocket_upgrade_response, websocket_downstream_upgrade_response_head,
};
use crate::native_http1_upstream_response::parsed_upstream_response_head;

#[test]
fn websocket_negotiation_accepts_unbound_accept_and_discards_cookie() {
    let head = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: not-a-valid-accept\r\nSec-WebSocket-Protocol: unoffered\r\nSet-Cookie: session=fixture\r\n\r\n";
    let limits = fluxheim_protocol::Http1HeadLimits::default();
    validate_websocket_upgrade_response(head, limits).unwrap();
    let parsed = parsed_upstream_response_head(head, limits).unwrap();
    let output =
        String::from_utf8(websocket_downstream_upgrade_response_head(&parsed).unwrap()).unwrap();
    assert!(output.contains("sec-websocket-accept: not-a-valid-accept\r\n"));
    assert!(output.contains("sec-websocket-protocol: unoffered\r\n"));
    assert!(!output.contains("session=fixture"));
}
