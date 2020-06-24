use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Configuration file for the node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
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
    pub listen_addr: SocketAddr,

    /// Disable UI by setting ui.disabled=true. Default is false (enabled).
    #[serde(default)]
    pub disabled: bool,
}

/// API configuration options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct API {
    /// Listening address for the API webserver.
    #[serde(default = "API::default_listen_addr")]
    pub listen_addr: SocketAddr,

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
            listen_addr: Self::default_listen_addr(),
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
            listen_addr: Self::default_listen_addr(),
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
        }
    }
}

impl Blockchain {
    /// Computes the absolute storage path based on the config file location
    pub fn absolute_storage_path(&self, config_path: &Path) -> PathBuf {
        let mut path = config_path.to_path_buf();
        path.pop(); // remove the filename (config.toml)
        path.push(&self.storage_path); // push the relative storage path (if absolute, it'll replace the whole path)
        path
    }

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
    /// Computes the absolute storage path based on the config file location
    pub fn absolute_storage_path(&self, config_path: &Path) -> PathBuf {
        let mut path = config_path.to_path_buf();
        path.pop(); // remove the filename (config.toml)
        path.push(&self.storage_path); // push the relative storage path (if absolute, it'll replace the whole path)
        path
    }

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
