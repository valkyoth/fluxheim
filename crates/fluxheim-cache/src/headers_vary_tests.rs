#[test]
fn vary_cache_policy_rejects_unsafe_vary_headers() {
    let response = http::Response::builder().body(()).unwrap();
    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::None
    );

    let response = http::Response::builder()
        .header("vary", "*")
        .body(())
        .unwrap();
    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::Uncacheable("vary-star")
    );

    let response = http::Response::builder()
        .header("vary", "accept-encoding,,user-agent")
        .body(())
        .unwrap();
    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::Uncacheable("vary-invalid")
    );

    let mut vary = String::new();
    for index in 0..super::MAX_VARY_FIELDS {
        vary.push_str(&format!("x-test-{index},"));
    }
    vary.push_str("x-overflow");
    let response = http::Response::builder()
        .header("vary", vary)
        .body(())
        .unwrap();
    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
    );

    let response = http::Response::builder()
        .header("vary", "authorization")
        .body(())
        .unwrap();
    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::Uncacheable("vary-sensitive-field")
    );
}

#[test]
fn vary_cache_policy_normalizes_repeated_vary_fields() {
    let response = http::Response::builder()
        .header("vary", "Accept-Encoding, User-Agent")
        .header("vary", "accept-encoding")
        .body(())
        .unwrap();

    assert_eq!(
        super::vary_cache_policy(response.headers()),
        super::VaryCachePolicy::Fields(
            vec!["accept-encoding".to_owned(), "user-agent".to_owned(),]
        )
    );
}

#[test]
fn vary_hash_material_tracks_repeated_values() {
    let single = super::vary_request_hash_material([super::VaryRequestHashField {
        name: "accept-encoding",
        values: vec![b"br".as_slice()],
    }]);
    let repeated = super::vary_request_hash_material([super::VaryRequestHashField {
        name: "accept-encoding",
        values: vec![b"br".as_slice(), b"gzip".as_slice()],
    }]);
    let different_field = super::vary_request_hash_material([super::VaryRequestHashField {
        name: "x-mode",
        values: vec![b"br".as_slice()],
    }]);

    assert_ne!(single, repeated);
    assert_ne!(single, different_field);
    assert!(single.starts_with(b"fluxheim-vary-v2"));
}

#[test]
fn cache_vary_policy_merges_configured_request_headers() {
    let mut cache = fluxheim_config::CacheConfig {
        vary_request_headers: vec!["Accept-Encoding".to_owned(), "X-Device".to_owned()],
        ..fluxheim_config::CacheConfig::default()
    };
    let response = http::Response::builder()
        .header("vary", "User-Agent")
        .body(())
        .unwrap();

    assert_eq!(
        super::cache_vary_policy(response.headers(), &cache),
        super::VaryCachePolicy::Fields(vec![
            "accept-encoding".to_owned(),
            "user-agent".to_owned(),
            "x-device".to_owned(),
        ])
    );

    cache.vary_request_headers = (0..super::MAX_VARY_FIELDS)
        .map(|index| format!("x-config-{index}"))
        .collect();
    assert_eq!(
        super::cache_vary_policy(response.headers(), &cache),
        super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
    );
}
