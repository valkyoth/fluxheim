//! One process-wide blocking DNS worker, with a bounded mailbox and caller timeout.
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

type Reply = mpsc::SyncSender<std::io::Result<Vec<SocketAddr>>>;
struct Lookup {
    host: String,
    port: u16,
    deadline: Instant,
    reply: Reply,
}

#[derive(Debug)]
pub(super) struct BoundedResolver;

impl Resolver for BoundedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.len() > 255 {
            return Err(ureq::Error::HostNotFound);
        }
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let mut result = self.empty();
        if let Ok(ip) = host.parse::<IpAddr>() {
            result.push(SocketAddr::new(ip, port));
            return Ok(result);
        }
        static WORKER: OnceLock<Option<mpsc::SyncSender<Lookup>>> = OnceLock::new();
        let sender = WORKER
            .get_or_init(|| {
                let (sender, receiver) = mpsc::sync_channel::<Lookup>(1);
                std::thread::Builder::new()
                    .name("Fluxheim OTLP DNS".into())
                    .spawn(move || {
                        while let Ok(job) = receiver.recv() {
                            if Instant::now() >= job.deadline {
                                continue;
                            }
                            let addresses = (job.host.as_str(), job.port)
                                .to_socket_addrs()
                                .map(|addresses| addresses.take(16).collect());
                            let _ = job.reply.try_send(addresses);
                        }
                    })
                    .ok()
                    .map(|_| sender)
            })
            .as_ref()
            .ok_or(ureq::Error::HostNotFound)?;
        let budget = if timeout.after.is_not_happening() {
            Duration::from_secs(2)
        } else {
            (*timeout.after).min(Duration::from_secs(2))
        };
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(Lookup {
                host: host.to_owned(),
                port,
                deadline: Instant::now() + budget,
                reply,
            })
            .map_err(|_| ureq::Error::HostNotFound)?;
        let addresses = receiver
            .recv_timeout(budget)
            .map_err(|_| ureq::Error::Timeout(timeout.reason))?
            .map_err(|_| ureq::Error::HostNotFound)?;
        for address in addresses {
            result.push(address);
        }
        if result.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(result)
        }
    }
}
