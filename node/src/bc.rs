use crate::comm::{CommandReceiver, EventSender};
use crate::config;

/// Launches the blockchain state machine with p2p interface listening on the provided address and port.
pub async fn launch(
    p2p_config: config::P2P,
    mempool_config: config::Mempool,
    cmd_receiver: CommandReceiver,
    event_sender: EventSender,
) {
}
