use std::env;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tcp_changes::{Client, Payload};
use tokio::sync::mpsc::{Receiver, Sender};

#[tokio::main]
async fn main() {
    const ENV_FILE: &str = include_str!("../../io/.env");

    for line in ENV_FILE.lines() {
        if let Some((key, value)) = line.split_once('=') {
            env::set_var(key.trim(), value.trim());
        }
    }

    let cert: String = env::var("CERT_PEM").unwrap();
    let privkey: String = env::var("PRIVKEY_PEM").unwrap();
    let ca_cert: String = env::var("FULLCHAIN_PEM").unwrap();

    let addr: SocketAddr = ([0, 0, 0, 0], 4243).into();
    let mb: Client = Client::new("local.wavey.io".to_string(), addr, ca_cert);

    let (up, fin, shutdown, mut rx) = mb.start("HELLO").await.unwrap();

    up.await.unwrap();

    let myip: [u8; 4] = *b"myip";
    while let Some(msg) = rx.recv().await {
        if msg.tag == myip {
            let ip_bytes: [u8; 4] = msg
                .val
                .as_ref()
                .try_into()
                .expect("slice with incorrect length");
            let ip_addr = Ipv4Addr::from(ip_bytes);
            println!("myip - {}", ip_addr);
        } else {
            println!("{}", msg);
        }
    }
}
