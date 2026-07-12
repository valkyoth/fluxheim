use bytes::Bytes;
use http_body_util::BodyExt as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct AccountCreationHttp {
    request_body: Arc<Mutex<Option<Bytes>>>,
}

impl instant_acme::HttpClient for AccountCreationHttp {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let captured = self.request_body.clone();
        Box::pin(async move {
            let uri = request.uri().path().to_owned();
            let method = request.method().clone();
            let body = match request.into_body().collect().await {
                Ok(body) => body.to_bytes(),
                Err(never) => match never {},
            };
            let response = match (method, uri.as_str()) {
                (http::Method::GET, "/directory") => http::Response::builder()
                    .status(200)
                    .body(instant_acme::BodyWrapper::from(
                        br#"{"newNonce":"https://acme.example/new-nonce","newAccount":"https://acme.example/new-account","newOrder":"https://acme.example/new-order"}"#.to_vec(),
                    )),
                (http::Method::HEAD, "/new-nonce") => http::Response::builder()
                    .status(200)
                    .header("replay-nonce", "test-nonce")
                    .body(instant_acme::BodyWrapper::from(Vec::new())),
                (http::Method::POST, "/new-account") => {
                    *captured.lock().unwrap() = Some(body);
                    http::Response::builder()
                        .status(201)
                        .header("location", "https://acme.example/account/1")
                        .body(instant_acme::BodyWrapper::from(Vec::new()))
                }
                _ => http::Response::builder()
                    .status(404)
                    .body(instant_acme::BodyWrapper::from(Vec::new())),
            }
            .map_err(instant_acme::Error::Http)?;
            Ok(response.into())
        })
    }
}

#[test]
fn patched_account_creation_preserves_key_contacts_and_eab() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = AccountCreationHttp::default();
        let captured = client.request_body.clone();
        let (key, key_der) = instant_acme::Key::generate_pkcs8().unwrap();
        let expected_key = key_der.secret_pkcs8_der().to_vec();
        let contacts = ["mailto:security@example.test"];
        let request = instant_acme::NewAccount {
            contact: &contacts,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let eab = instant_acme::ExternalAccountKey::new("eab-key-id".to_owned(), b"secret");
        let (_, credentials) = instant_acme::Account::builder_with_http(Box::new(client))
            .create_with_key(
                &request,
                (key, key_der),
                "https://acme.example/directory".to_owned(),
                Some(&eab),
            )
            .await
            .unwrap();

        assert_eq!(credentials.private_key().secret_pkcs8_der(), expected_key);
        let request = captured.lock().unwrap().take().unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&request).unwrap();
        let payload = base64_ng::URL_SAFE_NO_PAD
            .decode_vec(envelope["payload"].as_str().unwrap().as_bytes())
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["contact"][0], "mailto:security@example.test");
        assert_eq!(payload["termsOfServiceAgreed"], true);
        assert!(payload["externalAccountBinding"].is_object());
    });
}
