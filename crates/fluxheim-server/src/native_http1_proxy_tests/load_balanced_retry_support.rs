use super::*;

pub(super) struct Origin {
    pub(super) address: std::net::SocketAddr,
    pub(super) count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) async fn origins(replies: &[String]) -> Vec<Origin> {
    let mut listeners = Vec::new();
    for _ in replies {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    listeners.sort_by_key(|listener| listener.local_addr().unwrap());
    listeners
        .into_iter()
        .zip(replies)
        .map(|(listener, reply)| {
            let address = listener.local_addr().unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let seen = count.clone();
            let reply = reply.clone();
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while head.len() < 16384 && !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            break;
                        }
                        head.push(byte[0]);
                    }
                    if head.ends_with(b"\r\n\r\n") {
                        seen.fetch_add(1, Ordering::SeqCst);
                        let length = String::from_utf8_lossy(&head)
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        assert!(length <= 16384);
                        let mut body = vec![0; length];
                        if stream.read_exact(&mut body).await.is_err() {
                            continue;
                        }
                        let _ = stream.write_all(reply.as_bytes()).await;
                    }
                }
            });
            Origin {
                address,
                count,
                task,
            }
        })
        .collect()
}

pub(super) async fn h2_origins(statuses: &[u16]) -> Vec<Origin> {
    let mut listeners = Vec::new();
    for _ in statuses {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    listeners.sort_by_key(|listener| listener.local_addr().unwrap());
    listeners
        .into_iter()
        .zip(statuses)
        .map(|(listener, &status)| {
            let address = listener.local_addr().unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let seen = count.clone();
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            let seen = seen.clone();
                            connections.spawn(async move {
                                let mut connection = h2::server::handshake(stream).await.unwrap();
                                let mut responses = tokio::task::JoinSet::new();
                                loop {
                                    tokio::select! {
                                        request = connection.accept() => {
                                            let Some(Ok((request, mut respond))) = request else { break };
                                            seen.fetch_add(1, Ordering::SeqCst);
                                            responses.spawn(async move {
                                                let mut body = request.into_body();
                                                while let Some(chunk) = body.data().await {
                                                    let chunk = chunk.unwrap();
                                                    body.flow_control().release_capacity(chunk.len()).unwrap();
                                                }
                                                if status == 0 {
                                                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                                                } else {
                                                    let response = http::Response::builder().status(status).body(()).unwrap();
                                                    let mut send = respond.send_response(response, false).unwrap();
                                                    send.send_data(bytes::Bytes::from_static(b"ok"), true).unwrap();
                                                }
                                            });
                                        }
                                        Some(result) = responses.join_next() => { result.unwrap(); }
                                    }
                                }
                            });
                        }
                        Some(result) = connections.join_next() => { result.unwrap(); }
                    }
                }
            });
            Origin {
                address,
                count,
                task,
            }
        })
        .collect()
}

pub(super) fn reply(status: u16, extra: &str) -> String {
    format!("HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n{extra}\r\nok")
}

pub(super) fn config(origins: &[Origin]) -> fluxheim_config::ProxyConfig {
    let mut config = fluxheim_config::ProxyConfig {
        upstreams: origins
            .iter()
            .map(|origin| origin.address.to_string())
            .collect(),
        ..Default::default()
    };
    config.load_balance.health_check.enabled = false;
    config.load_balance.retry.enabled = true;
    config.load_balance.retry.budget_per_window = 100;
    config.load_balance.retry.budget_window_secs = 3600;
    config.load_balance.retry.max_retries = 2;
    config.load_balance.retry.statuses = vec![503];
    config
}

pub(super) fn proxy(config: &fluxheim_config::ProxyConfig) -> NativeHttp1Proxy {
    NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "retry-test",
        "proxy.test",
        None,
        config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .unwrap()
    .0
}

pub(super) fn calls(origins: &[Origin]) -> usize {
    origins
        .iter()
        .map(|origin| origin.count.load(Ordering::SeqCst))
        .sum()
}

pub(super) async fn dispatch(
    proxy: &NativeHttp1Proxy,
    request: NativeHttp1Request,
) -> crate::NativeHttp1Response {
    use crate::NativeHttp1Handler;
    tokio::time::timeout(Duration::from_secs(3), proxy.handle(request))
        .await
        .unwrap()
}
