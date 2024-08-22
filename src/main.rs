use std::env;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tcp_changes::{Client, Payload};
use tokio::sync::mpsc::{Receiver, Sender};

async fn run() {
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

// Since the main function cannot be async directly, use tokio or async-std runtime to start it
#[tokio::main]
async fn main() {
    run().await;
}
