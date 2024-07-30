use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher;
use rustls::pki_types::ServerName;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use tls_helpers::{tls_acceptor_from_base64, tls_connector_from_base64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::Duration;
use tokio_rustls::server;
use tracing::{debug, error, info, warn};

pub struct Payload {
    tag: String,
    val: Bytes,
}

pub struct Client {
    dns_name: String,
    addr: SocketAddr,
    ca_cert_pem: String,
}

impl Client {
    pub fn new(dns_name: String, addr: SocketAddr, ca_cert_pem: String) -> Self {
        Self {
            dns_name,
            addr,
            ca_cert_pem,
        }
    }

    pub async fn start(
        &self,
        id: u64,
    ) -> Result<
        (
            oneshot::Receiver<()>,
            oneshot::Receiver<()>,
            broadcast::Sender<()>,
            mpsc::Receiver<Payload>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(16);
        let (up_tx, up_rx) = oneshot::channel();
        let (fin_tx, fin_rx) = oneshot::channel();
        let (tx, mut rx) = mpsc::channel::<Payload>(64);

        let connector = tls_connector_from_base64(&self.ca_cert_pem).unwrap();
        let stream = TcpStream::connect(self.addr).await?;
        let dns = self.dns_name.clone();
        let domain = ServerName::try_from(dns).map_err(|_| "Invalid DNS name")?;
        let mut stream = connector.connect(domain, stream).await?;

        stream.write_all(&id.to_be_bytes()).await?;

        let srv = async move {
            up_tx.send(()).unwrap();

            let mut buffer = BytesMut::with_capacity(1024);
            let mut current_frame_length: Option<usize> = None;

            'outer: loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    },
                    read_result = stream.read_buf(&mut buffer) => {
                        match read_result {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                debug!("Read {} bytes", n); // Debug information for the number of bytes read

                                while buffer.len() > 0 {
                                    if current_frame_length.is_none() {
                                        if buffer.len() < 4 {
                                            break; // Need more data for length
                                        }
                                        current_frame_length = Some(u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize);
                                        buffer.advance(4); // Remove length bytes from buffer
                                    }

                                    if let Some(len) = current_frame_length {
                                        if buffer.len() >= len {
                                            let tag = buffer.split_to(4);
                                            let val = buffer.split_to(len - 4);
                                            let pkt = Payload {
                                                tag: std::str::from_utf8(&tag).unwrap_or("invalid").to_string(),
                                                val: val.freeze(),
                                            };

                                            match tx.send(pkt).await {
                                                Ok(_) => {},
                                                Err(e) => {
                                                    error!("Error sending frame to channel: {:?}", e);
                                                }
                                            }

                                            current_frame_length = None;
                                        } else {
                                            break; // Need more data for current frame
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Read error: {:?}", e);
                                break;
                            },
                        }
                    }
                }
            }

            fin_tx.send(()).unwrap();
        };

        tokio::spawn(srv);

        Ok((up_rx, fin_rx, shutdown_tx, rx))
    }
}

pub struct Server {
    streams: Arc<RwLock<BTreeMap<u64, broadcast::Sender<Bytes>>>>,
    changes: Arc<broadcast::Sender<Bytes>>,
    cert_pem: String,
    privkey_pem: String,
}

impl Server {
    pub fn new(cert_pem: String, privkey_pem: String) -> Self {
        let (tx, _) = broadcast::channel(16);

        Self {
            streams: Arc::new(RwLock::new(BTreeMap::new())),
            changes: Arc::new(tx),
            cert_pem,
            privkey_pem,
        }
    }

    fn send(&self, id: u64, packet: Bytes) {
        let mut inserted = false;
        {
            let mut lock = self.streams.write().unwrap();
            let tx = lock.entry(id).or_insert_with(|| {
                let (tx, _) = broadcast::channel(16);
                inserted = true;
                tx
            });

            match tx.send(packet) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error broadcasting: {}", e);
                }
            }
        }

        if inserted {
            let keys: Vec<u64> = {
                let lock = self.streams.read().unwrap();
                lock.keys().cloned().collect()
            };

            let mut data = BytesMut::new();
            data.put_u32((keys.len() * 8) as u32);
            for key in keys {
                data.put_u64(key);
            }

            match self.changes.send(data.freeze()) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error broadcasting: {}", e);
                }
            }
        }
    }

    pub fn fin(&self, id: u64) {
        let packet_size = 4 as u32;
        let mut packet = BytesMut::with_capacity(4 + packet_size as usize);
        packet.put_u32(packet_size);
        packet.put_slice(b"fini");
        self.send(id, packet.freeze());
        self.streams.write().unwrap().remove(&id);
    }

    pub fn add(&self, id: u64, tag: &[u8], data: Vec<Bytes>) {
        let mut packet_size = 4;
        for d in &data {
            packet_size += d.len();
        }

        {
            let mut packet = BytesMut::with_capacity(4);
            packet.put_u32(packet_size as u32);
            self.send(id, packet.freeze())
        }
        {
            let mut packet = BytesMut::with_capacity(4);
            packet.put_slice(tag);
            self.send(id, packet.freeze())
        }

        for d in data {
            self.send(id, d);
        }
    }

    pub async fn start(
        &self,
        addr: SocketAddr,
    ) -> Result<
        (
            oneshot::Receiver<()>,
            oneshot::Receiver<()>,
            watch::Sender<()>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (up_tx, up_rx) = oneshot::channel();
        let (fin_tx, fin_rx) = oneshot::channel();

        let tls_acceptor = tls_acceptor_from_base64(&self.cert_pem, &self.privkey_pem).unwrap();
        let incoming = TcpListener::bind(addr).await.unwrap();
        up_tx.send(()).unwrap();

        let streams_clone = Arc::clone(&self.streams);
        let changes_clone = Arc::clone(&self.changes);

        let srv = async move {
            loop {
                tokio::select! {
                    result = incoming.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let tls_acceptor = tls_acceptor.clone();
                                let streams_clone = Arc::clone(&streams_clone);
                                let changes_clone = Arc::clone(&changes_clone);
                                tokio::task::spawn(async move {
                                    let stream = tls_acceptor.accept(stream).await.unwrap();
                                    stream_handler(stream, streams_clone, changes_clone).await;
                                });
                            }
                            Err(err) => {
                                eprintln!("Error accepting connection: {:?}", err);
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("Received shutdown signal, exiting...");
                        break;
                    }
                }
            }

            fin_tx.send(()).unwrap();
        };

        info!("tcp-changes server listening on {:?}", addr);

        tokio::spawn(srv);

        Ok((up_rx, fin_rx, shutdown_tx))
    }
}

async fn stream_handler(
    mut stream: server::TlsStream<TcpStream>,
    streams: Arc<RwLock<BTreeMap<u64, broadcast::Sender<Bytes>>>>,
    changes: Arc<broadcast::Sender<Bytes>>,
) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer).await {
        Ok(n) => {
            if let Ok(command) = String::from_utf8(buffer[..n].to_vec()) {
                let command = command.trim().to_string();
                if command == "LIST" {
                    handle_list_command(&mut stream, &streams, changes).await;
                } else {
                    let id = u64::from_be_bytes(buffer[..8].try_into().unwrap());
                    handle_stream_command(&mut stream, &streams, id).await;
                }
            }
        }
        Err(e) => {
            error!("Error reading from stream: {:?}", e);
        }
    }
}

async fn handle_list_command(
    stream: &mut server::TlsStream<TcpStream>,
    streams: &Arc<RwLock<BTreeMap<u64, broadcast::Sender<Bytes>>>>,
    changes: Arc<broadcast::Sender<Bytes>>,
) {
    let ids = {
        let lock = streams.read().unwrap();
        lock.keys().cloned().collect::<Vec<_>>()
    };
    let mut data = BytesMut::new();
    data.put_u32((ids.len() * 8) as u32);
    for id in &ids {
        data.put_u64(*id);
    }
    info!("Sending initial changes {:?}", ids);
    if let Err(e) = stream.write_all(&data).await {
        error!("Error sending initial changes: {:?}", e);
        return;
    }

    let mut rx = changes.subscribe();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
            Ok(result) => match result {
                Ok(data) => {
                    info!("Sending change {:?}", data);
                    if let Err(e) = stream.write_all(&data).await {
                        error!("Error sending change: {:?}", e);
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(e) => {
                    error!("Error receiving data from broadcast channel: {:?}", e);
                    break;
                }
            },
            Err(_) => {
                debug!("Timeout waiting for changes, continuing...");
                // Instead of breaking, we continue to wait for more changes
            }
        }
    }
}

async fn handle_stream_command(
    stream: &mut server::TlsStream<TcpStream>,
    streams: &Arc<RwLock<BTreeMap<u64, broadcast::Sender<Bytes>>>>,
    id: u64,
) {
    let tx = {
        let lock = streams.read().unwrap();
        lock.get(&id).cloned()
    };

    if let Some(tx) = tx {
        let mut rx = tx.subscribe();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(result) => match result {
                    Ok(data) => {
                        debug!("Writing data for stream {}: {:?}", id, data);
                        if let Err(e) = stream.write_all(&data).await {
                            error!("Error writing to stream {}: {:?}", id, e);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            "Broadcast channel lagged for stream {}, skipped {} messages",
                            id, skipped
                        );
                        // Continue listening instead of breaking
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Broadcast channel closed for stream {}", id);
                        break;
                    }
                },
                Err(_) => {
                    debug!("Timeout waiting for data on stream {}, continuing...", id);
                    // Instead of breaking, we continue to wait for more data
                }
            }
        }
    } else {
        error!("No broadcast sender found for stream {}", id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_server() {
        let cert = env::var("CERT_PEM").unwrap();
        let privkey = env::var("PRIVKEY_PEM").unwrap();
        let ca_cert = env::var("FULLCHAIN_PEM").unwrap();

        let mq = Server::new(cert, privkey);
        let addr: SocketAddr = ([0, 0, 0, 0], 4243).into();
        let (up, fin, shutdown) = mq.start(addr).await.unwrap();
        up.await.unwrap();
        mq.add(1, b"abcd", vec![Bytes::from("foo")]);

        let mb = Client::new("local.wavey.io".to_string(), addr, ca_cert);
        let (mb_up, mb_fin, mb_shutdown, mut rx) = mb.start(1).await.unwrap();
        mb_up.await.unwrap();
        sleep(Duration::from_millis(100)).await;

        // Test different packets with assertions for both tag and value
        let test_cases = vec![(b"abcd", "foo"), (b"efgh", "bar"), (b"abcd", "baz")];

        for (tag, val) in test_cases.into_iter() {
            mq.add(1, tag, vec![Bytes::from(val)]);
            sleep(Duration::from_millis(10)).await;

            let payload = rx.try_recv().expect("expected data on channel");

            assert_eq!(payload.tag, String::from_utf8_lossy(tag), "Tag mismatch");
            assert_eq!(payload.val, Bytes::from(val), "Value mismatch");
        }

        mb_shutdown.send(()).unwrap();
        mb_fin.await.unwrap();

        shutdown.send(()).unwrap();
        fin.await.unwrap();
    }
}
