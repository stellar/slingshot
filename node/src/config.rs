use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/*
Example config file:

[ui]
listen = "127.0.0.1:3000"

[api]
listen = "127.0.0.1:3001"

[p2p]
listen = "0.0.0.0:0" # port 0 means it is system-assigned.
priority_peers = ["..."]
blocked_peers = ["..."]

[mempool]
max_size = 1_000_000
min_feerate = 1_000  # units/byte

*/

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

    /// Peer-to-peer networking options
    #[serde(default)]
    pub mempool: Mempool,
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
pub struct Mempool {
    /// Maximum size of the mempool in bytes.
    #[serde(default = "Mempool::default_max_size")]
    pub max_size: usize,

    /// Minimum feerate in units/byte.
    #[serde(default)]
    pub min_feerate: f32,
}

impl Config {
    /// Returns a documentation for the config file.
    pub fn documentation() -> &'static str {
        r##"
    [ui]
    listen = "127.0.0.1:3000"    # socket address for the webserver running the UI
    disabled = false             # whether the UI server should be disabled

    [api]
    listen = "127.0.0.1:3001"    # socket address for the webserver running the API
    disabled = false             # whether the API server should be disabled

    [p2p]
    listen = "0.0.0.0:0"         # socket address to listen in the peer-to-peer network
    
    [mempool]
    max_size = 10_000_000        # maximum size in bytes for the mempool transactions
    min_feerate = 0              # minimum feerate for the transactions to be included in mempool
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

impl Mempool {
    /// Default maximum size of the mempool (1M bytes).
    pub fn default_max_size() -> usize {
        1_000_000
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Mempool {
            max_size: Self::default_max_size(),
            min_feerate: 0.0,
        }
    }
}
