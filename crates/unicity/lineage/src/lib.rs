//! Inactive Q3 lineage and activation-proof verifier (Q3 #50, slice C2a).
//!
//! The crate authenticates the V3 trust-base lineage of a Unicity chain from a locally pinned root
//! genesis: every link's body, its activation record and A*, derived from the previous committee's
//! commit proof, never from a supplied body id, projection, capability or token. See `README.md`.

mod cbor;
mod proof;
mod sig;
mod trustbase;

pub mod body;
pub mod config;
pub mod envelope;
pub mod error;
pub mod history;
pub mod receipt;
pub mod votesig;

pub use body::{BodyV3, Member, Prior};
pub use config::ProtocolConfig;
pub use envelope::{Claim, Envelope, Evidence, Link};
pub use error::{Error, Kind, Result};
pub use history::{Entry, History};
pub use receipt::{verify_receipts, Receipt, ReceiptContext};
