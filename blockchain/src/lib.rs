//! Implementation of the blockchain state machine.

#[macro_use]
extern crate failure;
extern crate serde;

#[macro_use]
extern crate zkvm;

extern crate starsig;

mod block;
mod errors;
mod mempool;
mod protocol;
mod shortid;
mod state;
pub mod utreexo;

#[cfg(test)]
mod tests;

pub use self::block::*;
pub use self::errors::*;
pub use self::mempool::*;
pub use self::protocol::*;
pub use self::state::*;
