use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use blockchain::BlockchainState;

use crate::config::Config;
use crate::errors::Error;

const BC_STATE_FILENAME: &'static str = "blockchain_state";

/// Interface for initializing and launching blockchain state machine.
pub struct Blockchain;

/// Idle state of the blockchain
pub struct BlockchainIdle {
    config: Config,
    state: Option<BlockchainState>,
}

#[derive(Debug)]
pub struct BlockchainRunning {
    /// Configuration
    config: Config,

    /// Sender end of the notification channel
    notifications_sender: broadcast::Sender<BlockchainEvent>,
}

/// Reference to the Blockchain instance
pub type BlockchainRef = Arc<RwLock<BlockchainRunning>>;

/// Receiver of the blockchain events.
pub type BlockchainEventReceiver = broadcast::Receiver<BlockchainEvent>;

/// Type for all events about the BC state into the UI.
#[derive(Clone, Debug)]
pub enum BlockchainEvent {}

impl Blockchain {
    /// Sets up a blockchain instance, initialized or not.
    pub fn new(config: Config) -> Result<BlockchainIdle, Error> {
        let path = config.blockchain_state_filepath();
        let maybe_state = if path.exists() {
            Some(bincode::deserialize_from(File::open(&path)?)?)
        } else {
            None
        };
        Ok(BlockchainIdle {
            config,
            state: maybe_state,
        })
    }
}

impl BlockchainIdle {
    /// Returns true if blockchain is initialized
    pub fn is_initialized(&self) -> bool {
        self.state.is_some()
    }

    /// Initializes blockchain
    pub fn init(mut self, state: BlockchainState) -> Result<Self, Error> {
        if self.is_initialized() {
            return Err(Error::BlockchainAlreadyExists);
        }
        let path = self.config.blockchain_state_filepath();
        if let Some(folder) = path.parent() {
            fs::create_dir_all(folder)?;
        }
        bincode::serialize_into(File::create(path)?, &state)?;
        self.state = Some(state);
        Ok(self)
    }

    /// Launches the blockchain p2p stack and returns the communication reference to it.
    pub async fn launch(self) -> Result<BlockchainRef, Error> {
        // TODO: make this channel capacity a config option
        let (notifications_sender, _recv) = broadcast::channel(1000);

        let bc = Arc::new(RwLock::new(BlockchainRunning {
            config: self.config,
            notifications_sender,
        }));

        // TODO: launch p2p stack

        Ok(bc)
    }
}

impl BlockchainRunning {
    /// Creates a subscription for notifications and returns a receiving end of a broadcast channel.
    pub async fn subscribe(&self) -> BlockchainEventReceiver {
        self.notifications_sender.subscribe()
    }

    /// Stops the blockchain stack
    pub async fn stop(&self) {}
}
