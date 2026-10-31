use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1Proxy, NativeHttp1RequestContext,
    NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute, NativeHttp2RouteAdapter,
    serve_native_http2_connection,
};

#[tokio::test]
async fn routed_h2_grpc_response_loses_origin_status_trailers() {
    timeout(Duration::from_secs(10), async {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = fluxheim_config::Config::load_snapshot_bytes(include_bytes!(
            "../../../examples/proxy/grpc.toml"
        ))
        .unwrap();
        let route = &mut config.vhosts[0].routes[0];
        route.proxy.as_mut().unwrap().upstreams = vec![origin.local_addr().unwrap().to_string()];
        config.validate().unwrap();
        let route = &config.vhosts[0].routes[0];
        let proxy = NativeHttp1Proxy::from_proxy_config(
            route.proxy.as_ref().unwrap(),
            DownstreamHttp1Policy::default(),
        )
        .unwrap()
        .unwrap();
        let router = NativeHttp1RouteProxy::new(
            vec![
                NativeHttp1RouteProxyRoute::prefix("/example.Greeter/", Vec::new(), proxy)
                    .with_grpc_policy(route.grpc),
            ],
            None,
        );
        let adapter = NativeHttp2RouteAdapter::new(
            Arc::new(router),
            None,
            NativeHttp1RequestContext::default(),
        );
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = gateway.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/example.Greeter/Hello");
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), false)
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "7".parse().unwrap());
            trailers.insert("grpc-message", "permission denied".parse().unwrap());
            body.send_trailers(trailers).unwrap();
            connection.graceful_shutdown();
            let _ = timeout(
                Duration::from_secs(2),
                std::future::poll_fn(|cx| connection.poll_closed(cx)),
            )
            .await;
        });
        tasks.spawn(async move {
            let (stream, _) = gateway.accept().await.unwrap();
            let _ = serve_native_http2_connection(
                stream,
                DownstreamHttp2Policy::default(),
                Arc::new(adapter),
            )
            .await;
        });
        let (client, driver) = h2::client::handshake(TcpStream::connect(address).await.unwrap())
            .await
            .unwrap();
        tasks.spawn(async move {
            let _ = driver.await;
        });
        let mut client = client.ready().await.unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri("http://app.example.test/example.Greeter/Hello")
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("grpc-status"));
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(data) = body.data().await {
            let data = data.unwrap();
            assert!(bytes.len() + data.len() <= 5);
            body.flow_control().release_capacity(data.len()).unwrap();
            bytes.extend_from_slice(&data);
        }
        assert_eq!(bytes, [0, 0, 0, 0, 0]);
        // documented contract: HTTP 200/body survived, but the RPC failure disappeared.
        assert!(body.trailers().await.unwrap().is_none());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    })
    .await
    .expect("bounded routed gRPC characterization");
}
