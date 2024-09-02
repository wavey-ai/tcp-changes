## tcp-changes

Provides a server and client for sending and reading log messages as a tcp stream.

With the use of `tcp_changes::log::ChannelLayer` any events logged with `tracing::*` level macros will also be captured and sent to the tcp stream, like a log sink.

```rust
    use tcp_changes::log::ChannelLayer;
    use tcp_changes::Server;
    use tracing::info;
    use tracing_subscriber::{fmt, prelude::*, registry::Registry, EnvFilter};

    let socket_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4243);
    let changes = Server::new(cert_pem.clone(), privkey_pem.clone());

    let (changes_up, changes_fin, changes_shutdown, changes_tx) =
        changes.start(socket_v4).await.unwrap();

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::Layer::default())
        .with(ChannelLayer::new(changes_tx));

    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global default subscriber");

    info!("this will also log to the tcp feed")
```
