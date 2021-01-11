use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io;
use tokio::prelude::*;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tokio::task;

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use blockchain::{self, BlockchainState};
use p2p::{cybershake, PeerID};

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

        // TODO: store the newly generated p2p privkey if it does not exist.

        self.state = Some(state);
        Ok(self)
    }

    /// Launches the blockchain p2p stack and returns the communication reference to it.
    pub async fn launch(self) -> Result<BlockchainRef, Error> {
        // TODO: make this channel capacity a config option
        let (notifications_sender, _recv) = broadcast::channel(1000);

        // Launch p2p stack

        // TBD: load the peer privkey from disk instead of picking a random one.
        let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

        let (node, mut p2p_channel) = p2p::Node::<blockchain::Message>::spawn(
            host_privkey,
            p2p::NodeConfig {
                listen_addr: self.config.data.p2p.listen_addr,
                inbound_limit: self.config.data.p2p.inbound_limit,
                outbound_limit: self.config.data.p2p.outbound_limit,
                heartbeat_interval_sec: self.config.data.p2p.heartbeat_interval_sec,
            },
        )
        .await?;

        println!(
            "Listening on {} with peer ID: {}",
            node.socket_address(),
            node.id()
        );

        // Handle to a shared blockchain state machine instance.
        let bc = Arc::new(RwLock::new(BlockchainRunning {
            config: self.config,
            notifications_sender,
        }));

        let notifications_loop = {
            task::spawn_local(async move {
                while let Some(notif) = p2p_channel.recv().await {
                    match notif {
                        p2p::NodeNotification::PeerAdded(pid) => {
                            println!("\n=>    Peer connected: {}", pid);
                        }
                        p2p::NodeNotification::PeerDisconnected(pid) => {
                            println!("\n=> Peer disconnected: {}", pid)
                        }
                        p2p::NodeNotification::MessageReceived(pid, msg) => {
                            println!("\n=> Received: `{:?}` from {}", &msg, pid)
                        }
                        p2p::NodeNotification::InboundConnectionFailure(err) => {
                            println!("\n=> Inbound connection failure: {:?}", err)
                        }
                        p2p::NodeNotification::OutboundConnectionFailure(err) => {
                            println!("\n=> Outbound connection failure: {:?}", err)
                        }
                        p2p::NodeNotification::Shutdown => {
                            println!("\n=> Node did shutdown.");
                            break;
                        }
                    }
                }
                Result::<(), Error>::Ok(())
            })
        };

        notifications_loop.await.expect("panic on JoinError")?;

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

/*
impl protocol::Delegate for BlockchainRunning {
    type PeerIdentifier = p2p::PeerID;

    /// ID of our node.
    fn self_id(&self) -> Self::PeerIdentifier;

    /// Send a message to a given peer.
    async fn send(&mut self, peer: Self::PeerIdentifier, message: Message);

    /// Returns current height of the chain.
    /// Default implementation calls `tip().0.height`.
    fn tip_height(&self) -> u64 {
        self.tip().0.height
    }

    /// Returns ID of the current tip.
    fn tip_id(&self) -> BlockID {
        self.tip().0.id()
    }

    /// Returns the signed tip of the blockchain
    fn tip(&self) -> (BlockHeader, Signature);

    /// Returns a block at a given height
    fn block_at_height(&self, height: u64) -> Option<Block>;

    /// Blockchain state
    fn blockchain_state(&self) -> &BlockchainState {

    }

    /// Stores a new block and an updated state.
    /// Guaranteed to be called monotonically for blocks with height=2, then 3, etc.
    fn store_block(&mut self, verified_block: VerifiedBlock, signature: Signature) {

    }
}
*/
