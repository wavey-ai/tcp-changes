use crate::Message;
use bytes::Bytes;
use std::fmt::Write;
use tokio::sync::mpsc::Sender;
use tracing::{
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::layer::{Context, Layer};

pub struct ChannelLayer {
    sender: Sender<Message>,
}

impl ChannelLayer {
    pub fn new(sender: Sender<Message>) -> Self {
        ChannelLayer { sender }
    }
}

struct EventVisitor {
    message: String,
}

impl EventVisitor {
    fn new() -> Self {
        EventVisitor {
            message: String::new(),
        }
    }
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        write!(&mut self.message, "{}={:?} ", field.name(), value).unwrap();
    }
}

impl<S: Subscriber> Layer<S> for ChannelLayer {
    fn on_event(&self, event: &Event, _ctx: Context<S>) {
        let mut visitor = EventVisitor::new();
        event.record(&mut visitor);

        let log_msg = format!("{} - {}", event.metadata().target(), visitor.message);
        let level_str = event.metadata().level().to_string();
        let tag: [u8; 4] = {
            let mut tag = [0; 4];
            let level_bytes = level_str.as_bytes();
            for (i, &b) in level_bytes.iter().take(4).enumerate() {
                tag[i] = b;
            }
            tag
        };
        let msg = Message::new(tag, vec![Bytes::from(log_msg)]);
        let _ = self.sender.try_send(msg);
    }
}
