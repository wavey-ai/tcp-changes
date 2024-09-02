mod log;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rustls::pki_types::ServerName;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_helpers::{tls_acceptor_from_base64, tls_connector_from_base64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_rustls::server;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct Message {
    tag: [u8; 4],
    data: Vec<Bytes>,
    timestamp: u64,
}

impl Message {
    pub fn new(tag: [u8; 4], data: Vec<Bytes>) -> Self {
        Message {
            tag,
            data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        }
    }

    pub async fn send(&self, chan: mpsc::Sender<Message>) {
        chan.send(self.clone()).await.unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub tag: [u8; 4],
    pub val: Bytes,
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert tag to a readable ASCII string, safely handling non-ASCII bytes
        let tag_string = self
            .tag
            .iter()
            .map(|&c| if c.is_ascii() { c as char } else { '.' })
            .collect::<String>();

        // Attempt to convert `val` to a UTF-8 string, if possible
        let val_string = match str::from_utf8(&self.val) {
            Ok(v) => v.to_string(),              // Convert to string if it's valid UTF-8
            Err(_) => format!("{:?}", self.val), // Use debug print if not valid UTF-8
        };

        write!(f, "Tag: {}, Value: {}", tag_string, val_string)
    }
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
        cmd: &str,
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
        let (tx, rx) = mpsc::channel::<Payload>(16);

        let tx_clone = tx.clone();

        let connector = tls_connector_from_base64(&self.ca_cert_pem).unwrap();
        let stream = TcpStream::connect(self.addr).await?;
        let dns = self.dns_name.clone();
        let domain = ServerName::try_from(dns).map_err(|_| "Invalid DNS name")?;
        let mut stream = connector.connect(domain, stream).await?;

        stream.write_all(&cmd.as_bytes()).await?;

        let srv = async move {
            up_tx.send(());

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
                                            let tag_bytes = buffer.split_to(4);
                                            let mut tag = [0u8; 4];
                                            tag.copy_from_slice(&tag_bytes);

                                            let val = buffer.split_to(len - 4);
                                            let pkt = Payload {
                                                tag,
                                                val: val.freeze(),
                                            };

                                            if let Err(e) = tx_clone.send(pkt).await {
                                                // this will error if there are no subscribers;
                                                // error!("Broadcast error: {:?}", e);
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
    cert_pem: String,
    privkey_pem: String,
    priv_ipv4: Ipv4Addr,
}

impl Server {
    pub fn new(cert_pem: String, privkey_pem: String, priv_ipv4: Ipv4Addr) -> Self {
        Self {
            cert_pem,
            privkey_pem,
            priv_ipv4,
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
            mpsc::Sender<Message>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (up_tx, up_rx) = oneshot::channel();
        let (fin_tx, fin_rx) = oneshot::channel();
        let (tx, mut rx) = mpsc::channel::<Message>(16);
        let (btx, _) = broadcast::channel(16);

        let tls_acceptor =
            tls_acceptor_from_base64(&self.cert_pem, &self.privkey_pem, false, false).unwrap();
        let incoming = TcpListener::bind(addr).await.unwrap();
        up_tx.send(()).unwrap();

        let priv_ip = self.priv_ipv4.clone();
        let srv = async move {
            loop {
                tokio::select! {
                    result = incoming.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let tls_acceptor = tls_acceptor.clone();
                                let rx = btx.subscribe();
                                let priv_ip = priv_ip.clone();
                                tokio::task::spawn(async move {
                                    match tls_acceptor.accept(stream).await {
                                        Ok(stream) => {
                                            stream_handler(stream, rx, priv_ip.clone()).await;
                                        }
                                        Err(err) => {
                                           error!("tcp stream error: {:?}", err);
                                        }
                                    }
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
                    Some(message) = rx.recv() => {
                        btx.send(message);
                    }
                }
            }

            fin_tx.send(()).unwrap();
        };

        tokio::spawn(srv);

        Ok((up_rx, fin_rx, shutdown_tx, tx))
    }
}

async fn stream_handler(
    mut stream: server::TlsStream<TcpStream>,
    mut rx: broadcast::Receiver<Message>,
    priv_ipv4: Ipv4Addr,
) {
    let mut buffer: [u8; 1024] = [0; 1024];
    match stream.read(&mut buffer).await {
        Ok(n) => {
            if let Ok(command) = String::from_utf8(buffer[..n].to_vec()) {
                let command = command.trim().to_string();
                if command == "HELLO" {
                    let mut buf = BytesMut::with_capacity(4);
                    buf.extend_from_slice(&priv_ipv4.octets());
                    let data = buf.freeze();
                    let tag = *b"myip";
                    let message = Message::new(tag, vec![data]);

                    if let Err(e) = send_message(&mut stream, message).await {
                        error!("Failed to send message: {:?}", e);
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            info!("Broken pipe detected, closing stream handler.");
                            return; // Exit the function to stop the loop
                        }
                    }

                    loop {
                        match rx.recv().await {
                            Ok(message) => {
                                if let Err(e) = send_message(&mut stream, message).await {
                                    error!("Failed to send message: {:?}", e);
                                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                                        info!("Broken pipe detected, closing stream handler.");
                                        break; // Break the loop on broken pipe error
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("Broadcast channel lagged, skipped {} messages", skipped);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!("Broadcast channel closed");
                                break;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("Error reading from stream: {:?}", e);
        }
    }
}

async fn send_message(
    stream: &mut server::TlsStream<TcpStream>,
    message: Message,
) -> Result<(), std::io::Error> {
    let tag = message.tag;
    let data = message.data;

    let mut packet_size = 4;
    for d in &data {
        packet_size += d.len();
    }

    {
        let mut packet = BytesMut::with_capacity(4);
        packet.put_u32(packet_size as u32);
        if let Err(e) = stream.write_all(&packet.freeze()).await {
            error!("Error sending packet size: {:?}", e);
            return Err(e); // Propagate the error
        }
    }

    {
        let mut packet = BytesMut::with_capacity(4);
        packet.put_slice(&tag);
        if let Err(e) = stream.write_all(&packet.freeze()).await {
            error!("Error sending tag: {:?}", e);
            return Err(e); // Propagate the error
        }
    }

    for d in data {
        if let Err(e) = stream.write_all(&d).await {
            error!("Error sending data: {:?}", e);
            return Err(e); // Propagate the error
        }
    }

    Ok(())
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

        let mq = Server::new(cert, privkey, Ipv4Addr::new(192, 168, 0, 1));
        let addr: SocketAddr = ([0, 0, 0, 0], 4243).into();
        let (up, fin, shutdown, tx) = mq.start(addr).await.unwrap();
        up.await.unwrap();
        let mb = Client::new("local.wavey.io".to_string(), addr, ca_cert);
        let (mb_up, mb_fin, mb_shutdown, mut rx) = mb.start("HELLO").await.unwrap();
        mb_up.await.unwrap();
        sleep(Duration::from_millis(100)).await;

        let test_cases = vec![(b"abcd", b"foo"), (b"efgh", b"bar"), (b"abcd", b"baz")];
        let payload = rx.try_recv().expect("expected data on channel");

        let tag: [u8; 4] = *b"myip";
        assert_eq!(payload.tag, tag, "Tag mismatch");

        for (tag, val) in test_cases.into_iter() {
            let msg = Message::new(*tag, vec![Bytes::copy_from_slice(val)]);
            tx.send(msg).await;
            sleep(Duration::from_millis(100)).await;
            let payload = rx.try_recv().expect("expected data on channel");

            assert_eq!(payload.tag, *tag, "Tag mismatch");
            assert_eq!(payload.val, Bytes::copy_from_slice(val), "Value mismatch");
        }
        mb_shutdown.send(()).unwrap();
        mb_fin.await.unwrap();

        shutdown.send(()).unwrap();
        fin.await.unwrap();
    }
}
