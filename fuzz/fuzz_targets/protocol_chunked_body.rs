#![no_main]

use fluxheim_protocol::{Http1ChunkLimits, Http1ChunkedDecoder, decode_http1_chunked_body};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Http1ChunkLimits {
        max_chunk_size: 64 * 1024,
        max_body_bytes: 64 * 1024,
        max_encoded_bytes: 96 * 1024,
        max_chunk_line_bytes: 1024,
        max_chunk_count: 4096,
        max_chunk_extension_bytes: 4096,
    };
    let mut output = vec![0; limits.max_body_bytes];
    let _ = decode_http1_chunked_body(data, &mut output, limits);

    let mut decoder = Http1ChunkedDecoder::new(limits);
    for fragment in data.chunks(7) {
        if decoder.push(fragment).is_err() {
            break;
        }
    }
});
