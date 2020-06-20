use std::net::SocketAddr;

use crate::comm::{CommandReceiver, EventSender};

/// Launches the blockchain state machine with p2p interface listening on the provided address and port.
pub async fn launch(
    addr: impl Into<SocketAddr> + 'static,
    cmd_receiver: CommandReceiver,
    event_sender: EventSender,
) {
}
