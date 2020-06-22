use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::config;

const BC_STATE_FILENAME: &'static str = "state.bin";

pub struct Blockchain {
    /// Directory where all blockchain state and archive data is stored.
    storage_path: PathBuf,

    /// Sender end of the notification channel
    notifications_sender: broadcast::Sender<BlockchainEvent>,

    /// P2P networking options
    p2p_config: config::P2P,

    /// Blockchain configuration options
    blockchain_config: config::Blockchain,
}

/// Reference to the Blockchain instance
pub type BlockchainRef = Arc<RwLock<Blockchain>>;

/// Receiver of the blockchain events.
pub type BlockchainEventReceiver = broadcast::Receiver<BlockchainEvent>;

/// Type for all events about the BC state into the UI.
#[derive(Clone, Debug)]
pub enum BlockchainEvent {}

impl Blockchain {
    /// Launches the blockchain instance with the given configuration.
    /// If the blockchain is not initialized yet, this instance provides ways to initialize it.
    pub async fn launch(
        storage_path: PathBuf,
        p2p_config: config::P2P,
        blockchain_config: config::Blockchain,
    ) -> BlockchainRef {
        // TODO: make this channel capacity a config option
        let (notifications_sender, _recv) = broadcast::channel(1000);

        let bc = Arc::new(RwLock::new(Self {
            storage_path,
            notifications_sender,
            p2p_config,
            blockchain_config,
        }));

        // TODO: Launch p2p stack.

        bc
    }

    /// Creates a subscription for notifications and returns a receiving end of a broadcast channel.
    pub async fn subscribe(&self) -> BlockchainEventReceiver {
        self.notifications_sender.subscribe()
    }

    /// Returns true if blockchain is initialized
    pub fn initialized(&self) -> bool {
        let mut path = self.storage_path.clone();
        path.push(BC_STATE_FILENAME);
        path.exists()
    }
}
