use crate::native_http1_client_tests::request;
use crate::native_http1_static_web::{NativeHttp1StaticWeb, NativeStaticResolve};

// documented contract: characterization, not a desired publication contract.
#[test]
fn replacement_after_resolution_uses_old_validator_with_new_body() {
    use std::os::unix::fs::MetadataExt;
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let asset = root_path.join("asset.txt");
    std::fs::write(&asset, b"old!").unwrap();
    let web = NativeHttp1StaticWeb::from_config(&fluxheim_config::WebConfig {
        root: Some(root_path.clone()),
        ..Default::default()
    })
    .unwrap()
    .unwrap();
    let NativeStaticResolve::Found(file) = web.resolve("/asset.txt").unwrap() else {
        panic!("missing fixture");
    };
    let original = web.file_response(&request(), &file);
    let replacement = root_path.join("replacement.txt");
    std::fs::write(&replacement, b"new!").unwrap();
    assert_ne!(file.inode, std::fs::metadata(&replacement).unwrap().ino());
    std::fs::rename(replacement, &asset).unwrap();
    let response = web.file_response(&request(), &file);
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"new!");
    let etag = |response: &crate::NativeHttp1Response| {
        response
            .headers()
            .iter()
            .find(|(name, _)| name == "etag")
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(etag(&response), etag(&original));
}
