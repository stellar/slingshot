use std::path::Path;
use crate::comm::{CommandReceiver, EventSender};
use crate::config;

const BC_STATE_FILENAME: &'static str = "state.bin";

/// Launches the blockchain state machine with p2p interface listening on the provided address and port.
pub async fn launch(
    storage_path: &Path,
    p2p_config: config::P2P,
    blockchain_config: config::Blockchain,
    cmd_receiver: CommandReceiver,
    event_sender: EventSender,
) {
    
}


/// Checks if the storage is initialized
pub fn blockchain_exists(path: &Path) -> bool {
    let mut path = path.to_path_buf();
    path.push(BC_STATE_FILENAME);
    path.exists()
}
