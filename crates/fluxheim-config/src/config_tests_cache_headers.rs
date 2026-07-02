use super::super::*;

#[test]
fn rejects_invalid_cache_status_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_status_reason_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_reason_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_hidden_response_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            hide_response_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_bypass_request_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            bypass_request_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_bypass_request_header_value() {
    for value in ["", " ", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_request_header_values = {{ x-preview-mode = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
                scope: "cache",
                header: "x-preview-mode".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_no_store_response_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            no_store_response_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_no_store_response_header_value() {
    for value in ["", " ", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                no_store_response_header_values = {{ x-app-cache = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
                scope: "cache",
                header: "x-app-cache".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_query_param() {
    for param in ["", "bad param", "token=value", "a&b", "a?b"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_query_params = [{param:?}]
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassQueryParam {
                scope: "cache",
                param: param.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_query_value() {
    for value in ["", " ", "bad value", "bad&value", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_query_values = {{ mode = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassQueryValue {
                scope: "cache",
                param: "mode".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_cookie_name() {
    for name in ["", "bad name", "session=value", "a;b", "a,b"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_cookie_names = [{name:?}]
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassCookieName {
                scope: "cache",
                name: name.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_cookie_value() {
    for value in ["bad;value", "bad,value", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_cookie_values = {{ preview = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassCookieValue {
                scope: "cache",
                name: "preview".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_vary_request_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            vary_request_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_sensitive_cache_vary_request_header() {
    for header in ["cookie", "authorization", "proxy-authorization"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                vary_request_headers = [{header:?}]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheVaryRequestHeader {
                scope: "cache",
                header: header.to_owned(),
            }),
            "{header}"
        );
    }
}

#[test]
fn rejects_too_many_cache_bypass_paths() {
    let prefixes = (0..=crate::MAX_CACHE_BYPASS_PATHS)
        .map(|index| format!("\"/private-{index}/\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            bypass_path_prefixes = [{prefixes}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.bypass_path_prefixes"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_bypass_cookies() {
    let cookies = (0..=crate::MAX_CACHE_BYPASS_COOKIES)
        .map(|index| format!("\"cookie_{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            bypass_cookie_name_prefixes = [{cookies}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("cache.bypass_cookie_name_prefixes"),
        "{error}"
    );
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_vary_headers() {
    let headers = (0..=crate::MAX_CACHE_VARY_REQUEST_HEADERS)
        .map(|index| format!("\"x-vary-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            vary_request_headers = [{headers}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.vary_request_headers"), "{error}");
    assert!(error.contains("at most 16 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_status_ttls() {
    let status_ttls = (0..=crate::MAX_CACHE_STATUS_TTLS)
        .map(|index| format!("\"{}\" = 60", 100 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            status_ttls = {{ {status_ttls} }}
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.status_ttls"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_content_types_extensions_and_methods() {
    let content_types = (0..=crate::MAX_CACHE_CONTENT_TYPES)
        .map(|index| format!("\"application/x-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            content_types = [{content_types}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.content_types"), "{error}");
    assert!(error.contains("at most 64 entries"), "{error}");

    let extensions = (0..=crate::MAX_CACHE_IMAGE_EXTENSIONS)
        .map(|index| format!("\"ext{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            image_extensions = [{extensions}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.image_extensions"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");

    let methods = (0..=crate::MAX_CACHE_METHODS)
        .map(|index| format!("\"M{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            methods = [{methods}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.methods"), "{error}");
    assert!(error.contains("at most 16 entries"), "{error}");
}
