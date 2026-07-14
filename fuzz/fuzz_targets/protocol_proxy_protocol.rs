#![no_main]

use fluxheim_protocol::{
    PROXY_PROTOCOL_V2_HEADER_LEN, parse_downstream_proxy_protocol_v1,
    parse_downstream_proxy_protocol_v2,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_downstream_proxy_protocol_v1(data);
    if data.len() < PROXY_PROTOCOL_V2_HEADER_LEN {
        return;
    }
    let mut header = [0; PROXY_PROTOCOL_V2_HEADER_LEN];
    header.copy_from_slice(&data[..PROXY_PROTOCOL_V2_HEADER_LEN]);
    let _ = parse_downstream_proxy_protocol_v2(&header, &data[PROXY_PROTOCOL_V2_HEADER_LEN..]);
});
