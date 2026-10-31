use std::io::{Read as _, Write as _};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn reload_client_currently_waits_for_peer_close_even_after_ok_line() {
    for reply in [b"".as_slice(), b"ok\n".as_slice()] {
        let root = tempfile::Builder::new()
            .prefix("arc-")
            .tempdir_in(std::fs::canonicalize("target").unwrap())
            .unwrap();
        let socket = root.path().join("reload.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "reload fixture accept timed out");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("reload fixture accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut command = [0; b"reload-certificates\n".len()];
            stream.read_exact(&mut command).unwrap();
            assert_eq!(&command, b"reload-certificates\n");
            stream.write_all(reply).unwrap();
            ready_tx.send(()).unwrap();
            // Always close the peer within a finite time, even if the test
            // controller fails, so the production blocking read is released.
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
        });
        let mut config = crate::config::Config::default();
        config.server.process.certificate_reload_sock = socket;
        let (done_tx, done_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            let result =
                super::request_certificate_reload(&config).map_err(|error| error.to_string());
            let _ = done_tx.send(result);
        });

        let ready = ready_rx.recv_timeout(Duration::from_secs(6));
        let while_open = done_rx.recv_timeout(Duration::from_millis(200));
        let _ = release_tx.send(());
        peer.join().unwrap();
        client.join().unwrap();
        ready.unwrap();
        assert!(matches!(while_open, Err(mpsc::RecvTimeoutError::Timeout)));
        let after_close = done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(after_close.is_ok(), !reply.is_empty(), "{after_close:?}");
    }
}
