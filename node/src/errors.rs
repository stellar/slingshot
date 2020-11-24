use std;
use std::path::PathBuf;
use thiserror::Error as ThisError;

/// All error types in the node implementation
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    IoError(std::io::Error),

    #[error("Decoding error: {0}")]
    BincodeError(bincode::Error),

    #[error("Wallet is not initialized")]
    WalletNotInitialized,

    #[error("Wallet is already initialized")]
    WalletAlreadyExists,

    #[error("Blockchain is already initialized")]
    BlockchainAlreadyExists,

    #[error("Configuration file does not exist")]
    ConfigNotFound(PathBuf),

    #[error("Configuration error: {0}")]
    ConfigError(toml::de::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::BincodeError(err)
    }
}
