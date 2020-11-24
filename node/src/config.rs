use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::errors::Error;

/// Default config location
pub const DEFAULT_CONFIG_LOCATION: &'static str = "~/.slingshot/config.toml";
const BC_STATE_FILENAME: &'static str = "blockchain_state";

#[derive(Clone, Debug)]
pub struct Config {
    /// Config data
    pub data: ConfigData,

    /// Config path
    pub path: PathBuf,
}
/// Configuration file for the node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigData {
    /// UI options
    #[serde(default)]
    pub ui: UI,

    /// API options
    #[serde(default)]
    pub api: API,

    /// Peer-to-peer networking options
    #[serde(default)]
    pub p2p: P2P,

    /// Blockchain storage and mempool options
    #[serde(default)]
    pub blockchain: Blockchain,

    /// Wallet storage location
    #[serde(default)]
    pub wallet: Wallet,
}

/// UI configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UI {
    /// Listening address for the UI webserver.
    #[serde(default = "UI::default_listen_addr")]
    pub listen: SocketAddr,

    /// Disable UI by setting ui.disabled=true. Default is false (enabled).
    #[serde(default)]
    pub disabled: bool,
}

/// API configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct API {
    /// Listening address for the API webserver.
    #[serde(default = "API::default_listen_addr")]
    pub listen: SocketAddr,

    /// Disable API by setting api.disabled=true. Default is false (enabled).
    #[serde(default)]
    pub disabled: bool,
}

/// P2P configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2P {
    /// Listening address for the P2P webserver.
    #[serde(default = "P2P::default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// List of initial peers
    #[serde(default)]
    pub peers: Vec<SocketAddr>,
}

/// P2P configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blockchain {
    /// Location of the blockchain data
    #[serde(default = "Blockchain::default_storage_path")]
    pub storage_path: PathBuf,

    /// Maximum size of the mempool in bytes.
    #[serde(default = "Blockchain::default_mempool_max_size")]
    pub mempool_max_size: usize,

    /// Minimum feerate in units/byte.
    #[serde(default)]
    pub mempool_min_feerate: f32,
}

/// P2P configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Listening address for the P2P webserver.
    #[serde(default = "Wallet::default_storage_path")]
    pub storage_path: PathBuf,
}

impl Config {
    /// Returns a documentation for the config file.
    pub fn description() -> &'static str {
        r##"
    [ui]
    listen = "127.0.0.1:3000"      # socket address for the webserver running the UI
    disabled = false               # whether the UI server should be disabled

    [api]
    listen = "127.0.0.1:3001"      # socket address for the webserver running the API
    disabled = false               # whether the API server should be disabled

    [p2p]
    listen = "0.0.0.0:0"           # socket address to listen in the peer-to-peer network
    peers = ["127.0.0.0:4000"]     # list of initial peers to connect to
    
    [blockchain]
    storage_path = "./storage"     # location of the stored data 
                                   # (if relative, resolved based on the config file location,
                                   #  which is ~/.slingshot/config.toml by default)
    mempool_max_size = 10_000_000  # maximum size in bytes for the mempool transactions
    mempool_min_feerate = 0        # minimum feerate for the transactions to be included in mempool

    [wallet]
    storage_path = "./wallet"      # location of the wallet keys and account data
                                   # (if relative, resolved based on the config file location,
                                   #  which is ~/.slingshot/wallet by default)
"##
    }

    /// Reads the config from the file
    pub fn load(path: Option<PathBuf>) -> Result<Config, Error> {
        let use_default = path.is_none();
        let path = path
            .map(|p| expand_path(p))
            .unwrap_or_else(|| expand_path(DEFAULT_CONFIG_LOCATION));

        if path.exists() {
            let string = fs::read_to_string(&path)?;
            let data = toml::from_str(&string).map_err(|e| Error::ConfigError(e))?;
            Ok(Config { data, path })
        } else if use_default {
            Ok(Config {
                data: ConfigData::default(),
                path,
            })
        } else {
            Err(Error::ConfigNotFound(path))
        }
    }

    /// Absolute wallet storage path
    pub fn wallet_path(&self) -> PathBuf {
        let mut path = self.path.clone();
        path.pop(); // remove the filename (config.toml)
                    // push the relative storage path (if absolute, it'll replace the whole path)
        path.push(&self.data.wallet.storage_path);
        path
    }

    /// Absolute blockchain storage path
    pub fn blockchain_path(&self) -> PathBuf {
        let mut path = self.path.clone();
        path.pop(); // remove the filename (config.toml)
        path.push(&self.data.blockchain.storage_path); // push the relative storage path (if absolute, it'll replace the whole path)
        path
    }

    /// Path to the blockchain state file
    pub fn blockchain_state_filepath(&self) -> PathBuf {
        let mut path = self.blockchain_path();
        path.push(BC_STATE_FILENAME);
        path
    }
}

impl UI {
    /// Default address for UI is only accessible from the localhost.
    pub fn default_listen_addr() -> SocketAddr {
        ([127, 0, 0, 1], 3000).into()
    }
}

impl Default for UI {
    fn default() -> Self {
        UI {
            listen: Self::default_listen_addr(),
            disabled: false,
        }
    }
}

impl API {
    /// Default address for API is accessible only from the localhost.
    pub fn default_listen_addr() -> SocketAddr {
        ([127, 0, 0, 1], 3001).into()
    }
}

impl Default for API {
    fn default() -> Self {
        API {
            listen: Self::default_listen_addr(),
            disabled: false,
        }
    }
}

impl P2P {
    /// Default address for P2P is accessible only from the localhost.
    pub fn default_listen_addr() -> SocketAddr {
        ([0, 0, 0, 0], 0).into()
    }
}

impl Default for P2P {
    fn default() -> Self {
        P2P {
            listen_addr: Self::default_listen_addr(),
            peers: Vec::new(),
        }
    }
}

impl Blockchain {
    /// Default storage path
    pub fn default_storage_path() -> PathBuf {
        PathBuf::from("./storage")
    }
    /// Default maximum size of the mempool (1M bytes).
    pub fn default_mempool_max_size() -> usize {
        1_000_000
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Blockchain {
            storage_path: Self::default_storage_path(),
            mempool_max_size: Self::default_mempool_max_size(),
            mempool_min_feerate: 0.0,
        }
    }
}

impl Wallet {
    /// Default storage path
    pub fn default_storage_path() -> PathBuf {
        PathBuf::from("./wallet")
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Wallet {
            storage_path: Self::default_storage_path(),
        }
    }
}

fn expand_path(path: impl Into<PathBuf>) -> PathBuf {
    let mut path = path.into();
    if let Ok(p) = path.strip_prefix("~/") {
        if let Some(mut home) = dirs::home_dir() {
            home.push(p);
            path = home;
        }
    }
    path
}
