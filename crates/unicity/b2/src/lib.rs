//! Inactive, pure B2 kernel reserved at 0x0104. No provider or node factory
//! installs it. Results export inclusion obligations; they prove neither backing,
//! aggregator admission nor inclusion. Candidate gas is not an activation price.
mod cfg;
mod encode;
mod error;
mod history;
mod limits;
pub mod provider;
mod scan;
mod unlock;
mod wire;

pub use error::{BridgeError, Family};
use sha2::{Digest, Sha256};
pub use wire::{address, run, Error, Output};

fn h(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests;
