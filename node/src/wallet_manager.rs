use super::config::Config;
use super::errors::Error;
use super::wallet::Wallet;
use keytree::Xprv;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reference to the Blockchain instance
pub type WalletRef = Arc<RwLock<WalletManager>>;

/// Interface for loading/saving/updating the wallet.
#[derive(Debug)]
pub struct WalletManager {
    config: Config,
    wallet: Option<Wallet>,
}

impl WalletManager {
    /// Initializes the wallet
    pub fn new(config: Config) -> Result<WalletRef, Error> {
        let mut wm = WalletManager {
            config,
            wallet: None,
        };

        // Attempt to open the wallet file if it exists.
        // If the file exists, but is broken, raise an error.
        let wpath = wm.wallet_filepath();
        if wpath.exists() {
            wm.wallet = Some(bincode::deserialize_from(File::open(&wpath)?)?);
        }

        Ok(Arc::new(RwLock::new(wm)))
    }

    /// Returns true if the wallet is initialized
    pub fn wallet_exists(&self) -> bool {
        self.wallet.is_some()
    }

    /// Path to the wallet file
    pub fn wallet_filepath(&self) -> PathBuf {
        let mut p = self.config.wallet_path();
        p.push("wallet.bincode");
        p
    }

    /// Path to the keyfile
    pub fn wallet_keypath(&self) -> PathBuf {
        let mut p = self.config.wallet_path();
        p.push("wallet.xprv");
        p
    }

    /// Returns a read-only reference to the wallet
    pub fn wallet_ref(&self) -> Result<&Wallet, Error> {
        self.wallet.as_ref().ok_or(Error::WalletNotInitialized)
    }

    /// Saves
    pub fn save_xprv(&self, xprv: Xprv) -> Result<(), Error> {
        let path = self.wallet_keypath();
        if let Some(folder) = path.parent() {
            fs::create_dir_all(folder)?;
        }

        let mut file = File::create(path)?;
        file.write_all(&xprv.to_bytes()[..])?;
        Ok(())
    }

    /// Reads
    pub fn read_xprv(&self) -> Result<Xprv, Error> {
        let path = self.wallet_keypath();

        let mut file = File::open(path)?;
        let mut out = String::with_capacity(64);
        file.read_to_string(&mut out)?;
        let xprv = Xprv::from_bytes(out.as_bytes())
            .expect("We previously write Xprv by self so we expect that it must be valid");
        Ok(xprv)
    }

    /// Removes the wallet
    pub fn clear_wallet(&mut self) -> Result<(), Error> {
        fs::remove_file(self.wallet_filepath())?;
        self.wallet = None;
        Ok(())
    }

    /// Sets the wallet
    pub fn initialize_wallet(&mut self, wallet: Wallet) -> Result<(), Error> {
        if self.wallet.is_some() {
            return Err(Error::WalletAlreadyExists);
        }
        let prev_wallet = self.wallet.replace(wallet);
        self.update_wallet(|_| Ok(prev_wallet));
        Ok(())
    }

    /// Returns a mutable reference to the wallet
    pub fn update_wallet<F, T>(&mut self, closure: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Wallet) -> Result<T, Error>,
    {
        let path = self.wallet_filepath();
        self.wallet
            .as_mut()
            .map(|w| {
                // run the closure
                let r = closure(w)?;
                // save the modified wallet
                if let Some(folder) = path.parent() {
                    fs::create_dir_all(folder)?;
                }
                bincode::serialize_into(File::create(path)?, w)?;
                Ok(r)
            })
            .unwrap_or(Err(Error::WalletNotInitialized))
    }
}
