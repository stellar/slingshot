extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;

#[macro_use]
extern crate failure;

mod error;
mod gadgets;
mod spacesuit;
mod value;

pub use error::SpacesuitError;
pub use spacesuit::*;
pub use value::*;
