use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

fn collector(replies: Vec<String>) -> (String, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/traces", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(8);
        let mut received = Vec::new();
        for reply in replies {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut byte = [0];
            while !bytes.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                assert!(bytes.len() < 8192);
            }
            let headers = String::from_utf8(bytes).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            assert!(length <= MAX_EXPORT_BYTES);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            received.push(body);
            let _ = stream.write_all(reply.as_bytes());
        }
        received
    });
    (endpoint, handle)
}

fn response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}
fn worker(endpoint: &str) -> ExportWorker {
    ExportWorker::new(ExportOptions {
        endpoint,
        ca: None,
        token: None,
        signal: ExportSignal::Traces,
        queue_size: 8,
        timeout: Duration::from_secs(4),
        on_complete: None,
    })
    .unwrap()
}
fn wait_finished(state: &State) {
    let end = Instant::now() + Duration::from_secs(3);
    let mut queue = state.queue.lock().unwrap();
    while !queue.finished {
        let wait = end.saturating_duration_since(Instant::now());
        assert!(
            !wait.is_zero(),
            "worker must terminate within bounded drain"
        );
        queue = state.wake.wait_timeout(queue, wait).unwrap().0;
    }
}
fn enqueue(worker: &ExportWorker, payload: &str) {
    let end = Instant::now() + Duration::from_secs(1);
    while !worker.try_export(payload.to_owned()) {
        assert!(Instant::now() < end);
        std::thread::yield_now();
    }
}

#[test]
fn retryable_replies_recover_with_identical_payload() {
    let (endpoint, fixture) = collector(vec![
        response(429, "secret-canary"),
        response(503, "secret-canary"),
        response(200, "{}"),
    ]);
    let worker = worker(&endpoint);
    enqueue(&worker, "{\"resourceSpans\":[]}");
    let received = fixture.join().unwrap();
    assert_eq!(received.len(), 3);
    assert!(received.iter().all(|body| body == &received[0]));
    worker.shutdown();
    wait_finished(&worker.0.0);
    assert!(!export_health_text().contains("secret-canary"));
}

#[test]
fn terminal_replies_are_never_retried_and_next_data_recovers() {
    let cases = [
        (401, "secret-canary"),
        (403, "secret-canary"),
        (400, "secret-canary"),
        (200, "not-json"),
        (
            200,
            "{\"partialSuccess\":{\"rejectedSpans\":\"1\",\"errorMessage\":\"secret-canary\"}}",
        ),
    ];
    for (status, body) in cases {
        let (endpoint, fixture) = collector(vec![response(status, body), response(200, "{}")]);
        let worker = worker(&endpoint);
        enqueue(&worker, "first");
        enqueue(&worker, "second");
        assert_eq!(
            fixture.join().unwrap(),
            [b"first".to_vec(), b"second".to_vec()]
        );
        worker.shutdown();
        wait_finished(&worker.0.0);
    }
}

#[test]
fn shutdown_and_last_owner_drop_stop_idle_workers() {
    let worker = worker("http://127.0.0.1:1/v1/traces");
    let state = worker.0.0.clone();
    let clone = worker.clone();
    drop(worker);
    assert!(!state.queue.lock().unwrap().finished);
    drop(clone);
    wait_finished(&state);
}

#[test]
fn queue_byte_count_limits_are_enforced_before_admission() {
    let worker = worker("http://127.0.0.1:1/v1/traces");
    assert!(!worker.try_export("a".repeat(MAX_EXPORT_BYTES + 1)));
    let mut queue = worker.0.0.queue.lock().unwrap();
    // Hold a full queue behind its lock so the worker cannot race the assertions.
    queue.bytes = MAX_QUEUE_BYTES;
    add(&worker.0.0.health.queued_bytes, MAX_QUEUE_BYTES as u64);
    drop(queue);
    assert!(!worker.try_export("over-budget".into()));
    worker.shutdown();
    wait_finished(&worker.0.0);
    assert!(!worker.try_export("after-stop".into()));
}

#[test]
fn queue_bookkeeping_contention_does_not_drop_an_admissible_export() {
    let (endpoint, fixture) = collector(vec![response(200, "{}")]);
    let worker = worker(&endpoint);
    let queue = worker.0.0.queue.lock().unwrap();
    let producer = worker.clone();
    let (started, start) = mpsc::sync_channel(1);
    let (sent, result) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        started.send(()).unwrap();
        sent.send(producer.try_export("normal-load".into()))
            .unwrap();
    });
    start.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        result.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    drop(queue);
    assert!(result.recv_timeout(Duration::from_secs(2)).unwrap());
    thread.join().unwrap();
    assert_eq!(fixture.join().unwrap(), [b"normal-load".to_vec()]);
    worker.shutdown();
    wait_finished(&worker.0.0);
}

#[test]
fn blocked_collector_cannot_hold_shutdown_or_start_a_retry_storm() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let worker = worker(&format!(
        "http://{}/v1/traces",
        listener.local_addr().unwrap()
    ));
    let (accepted, receiver) = mpsc::sync_channel(1);
    let fixture = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let mut connections = Vec::new();
        let mut times = Vec::new();
        while Instant::now() < end {
            if let Ok((stream, _)) = listener.accept() {
                connections.push(stream);
                times.push(Instant::now());
                let _ = accepted.try_send(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        times
    });
    enqueue(&worker, "first");
    receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    for _ in 0..100 {
        worker.try_export("queued".into());
    }
    let start = Instant::now();
    worker.shutdown();
    wait_finished(&worker.0.0);
    assert!(start.elapsed() < Duration::from_secs(3));
    let times = fixture.join().unwrap();
    assert!((1..=9).contains(&times.len()));
    // A queued item may start in the few milliseconds between the first
    // request's deadline and the shutdown deadline, but not alongside it.
    assert!(
        times
            .iter()
            .skip(1)
            .all(|time| time.duration_since(times[0]) >= Duration::from_millis(1700))
    );
    assert_eq!(worker.0.0.queue.lock().unwrap().bytes, 0);
}

#[test]
fn retries_are_bounded_even_when_every_reply_is_unavailable() {
    let (endpoint, fixture) = collector(vec![response(503, ""); 3]);
    let worker = worker(&endpoint);
    enqueue(&worker, "first");
    assert_eq!(fixture.join().unwrap().len(), 3);
    worker.shutdown();
    wait_finished(&worker.0.0);
}

#[test]
fn expired_jobs_never_contact_collector() {
    let delivery = Delivery::new(
        "http://127.0.0.1:1/v1/traces",
        None,
        None,
        ExportSignal::Traces,
    )
    .unwrap();
    let worker = worker("http://127.0.0.1:1/v1/traces");
    assert_eq!(
        deliver(&worker.0.0, &delivery, "{}", Instant::now()),
        ExportOutcome::Transport
    );
    worker.shutdown();
    wait_finished(&worker.0.0);
}

#[test]
fn oversized_response_bodies_are_bounded() {
    let (endpoint, fixture) = collector(vec![response(200, &"x".repeat(20 * 1024))]);
    let delivery = Delivery::new(&endpoint, None, None, ExportSignal::Metrics).unwrap();
    assert_eq!(
        delivery.post("{}", Duration::from_secs(1)),
        ExportOutcome::Malformed
    );
    fixture.join().unwrap();
}

#[test]
fn retry_after_longer_than_remaining_budget_drops_without_sleeping() {
    let (endpoint, fixture) = collector(vec![
        "HTTP/1.1 429 Busy\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .into(),
    ]);
    let delivery = Delivery::new(&endpoint, None, None, ExportSignal::Traces).unwrap();
    let worker = worker("http://127.0.0.1:1/v1/traces");
    let start = Instant::now();
    assert_eq!(
        deliver(&worker.0.0, &delivery, "{}", start + Duration::from_secs(1)),
        ExportOutcome::Retry(Duration::from_secs(60))
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(fixture.join().unwrap().len(), 1);
    worker.shutdown();
    wait_finished(&worker.0.0);
}

#[test]
fn stalled_response_after_headers_obeys_the_request_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/traces", listener.local_addr().unwrap());
    let fixture = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
    });
    let delivery = Delivery::new(&endpoint, None, None, ExportSignal::Traces).unwrap();
    let start = Instant::now();
    assert_eq!(
        delivery.post("{}", Duration::from_millis(100)),
        ExportOutcome::Malformed
    );
    assert!(start.elapsed() < Duration::from_millis(450));
    fixture.join().unwrap();
}
