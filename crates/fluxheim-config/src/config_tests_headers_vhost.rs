use super::super::*;
use crate::ForwardedClientIpHeaderMode;

#[test]
fn parses_vhost_header_policy_overlay() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request]
            x_forwarded_for = "off"
            unset = ["x-powered-by"]
            remove = ["x-legacy-route"]

            [vhosts.headers.request.set]
            host = "api.internal"

            [vhosts.headers.request.operations]
            remove = ["x-old-api"]
            add = { x-api-route = "true" }

            [vhosts.headers.response]
            x_frame_options = "SAMEORIGIN"
            unset = ["server"]
            remove = ["x-origin-banner"]

            [vhosts.headers.response.set]
            access-control-allow-origin = "https://app.example.test"

            [vhosts.headers.response.append]
            vary = "Origin"

            [vhosts.headers.response.operations]
            remove = ["x-debug"]
            add = { x-response-route = "api" }
            "#,
    )
    .unwrap();

    let headers = &config.vhosts[0].headers;
    assert_eq!(
        headers.request.x_forwarded_for,
        Some(ForwardedClientIpHeaderMode::Off)
    );
    assert_eq!(headers.request.unset, ["x-powered-by"]);
    assert_eq!(
        headers.request.effective_unset(),
        ["x-powered-by", "x-legacy-route", "x-old-api"]
    );
    assert_eq!(
        headers.request.set.get("host").map(String::as_str),
        Some("api.internal")
    );
    assert_eq!(
        headers
            .request
            .effective_set()
            .get("x-api-route")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        headers
            .response
            .x_frame_options
            .as_ref()
            .and_then(Option::as_deref),
        Some("SAMEORIGIN")
    );
    assert_eq!(headers.response.unset, ["server"]);
    assert_eq!(
        headers.response.effective_unset(),
        ["server", "x-origin-banner", "x-debug"]
    );
    assert_eq!(
        headers
            .response
            .set
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://app.example.test")
    );
    assert_eq!(
        headers
            .response
            .append
            .get("vary")
            .and_then(|values| values.iter().next()),
        Some("Origin")
    );
    assert_eq!(
        headers
            .response
            .effective_set()
            .get("x-response-route")
            .map(String::as_str),
        Some("api")
    );
    config.validate().unwrap();
}
