use super::config;
use super::errors::Error;
use super::wallet::Wallet;
use std::io;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reference to the Blockchain instance
pub type WalletRef = Arc<RwLock<WalletManager>>;

/// Interface for loading/saving/updating the wallet.
pub struct WalletManager {
    config: config::Wallet,
    wallet: Option<Wallet>,
}

impl WalletManager {
    /// Initializes the wallet
    pub fn new(config: config::Wallet) -> Result<WalletRef, Error> {
        let mut wm = WalletManager {
            config,
            wallet: None,
        };

        // Attempt to open the file if it exists.
        // If the file exists, but is broken, raise an error.
        //if wm.config.absolute_storage_path().exists() {
        // TBD.
        //}
        unimplemented!()
    }
}
