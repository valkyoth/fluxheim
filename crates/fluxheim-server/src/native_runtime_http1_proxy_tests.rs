use fluxheim_runtime::NativeBackgroundSupervisor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{NativeHttp1ProxyRuntime, ServerPlan};

async fn upstream_response(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    addr
}

async fn downstream_get(proxy: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn native_http1_proxy_runtime_binds_launch_plan_and_serves_proxy_listener() {
    let upstream = upstream_response("runtime-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    assert_eq!(
        runtime.planned_addrs(),
        [std::net::SocketAddr::from(([127, 0, 0, 1], 0))]
    );
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);
    assert_eq!(handle.local_addrs(), [local_addr]);

    let response = downstream_get(local_addr).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native listener stopped cleanly");
    }
}
