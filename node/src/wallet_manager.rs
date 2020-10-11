use super::config;
use super::errors::Error;
use super::wallet::Wallet;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reference to the Blockchain instance
pub type WalletRef = Arc<RwLock<WalletManager>>;

/// Interface for loading/saving/updating the wallet.
#[derive(Debug)]
pub struct WalletManager {
    config: config::Wallet,
    wallet_path: PathBuf,
    wallet: Option<Wallet>,
}

impl WalletManager {
    /// Initializes the wallet
    pub fn new(config: config::Wallet, config_path: &Path) -> Result<WalletRef, Error> {
        let wallet_path = config.absolute_storage_path(config_path);
        let mut wm = WalletManager {
            config,
            wallet_path,
            wallet: None,
        };

        // Attempt to open the file if it exists.
        // If the file exists, but is broken, raise an error.

        if wm.wallet_path.exists() {
            wm.wallet = Some(bincode::deserialize_from(File::open(&wm.wallet_path)?)?);
        }

        Ok(Arc::new(RwLock::new(wm)))
    }

    /// Returns true if the wallet is initialized
    pub fn wallet_exists(&self) -> bool {
        self.wallet.is_some()
    }

    /// Returns a read-only reference to the wallet
    pub fn wallet_ref(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    /// Returns a mutable reference to the wallet
    pub fn update_wallet<F, T>(&mut self, closure: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Wallet) -> Result<T, Error>,
    {
        let path = &self.wallet_path;
        self.wallet
            .as_mut()
            .map(|w| {
                let r = closure(w)?;

                // TODO: save the wallet at self.wallet_path
                File::create(path)?;

                Ok(r)
            })
            .unwrap_or(Err(Error::WalletNotInitialized))
    }
}
