//! Durable, block-hash-keyed storage for `SealCompanion` values.
//!
//! This crate is the persistence half of Unicity companion retention. It is a library only: it has
//! no node wiring, no RPC, no reth component, no provider and no notion of canonicality. A caller
//! tells it what to store with [`CompanionStore::put`] and what to drop with
//! [`CompanionStore::remove`] and [`CompanionStore::prune_below`].
//!
//! The store owns a separate MDBX environment under the directory it is given. It never registers
//! a table in reth's own environment and never touches reth's databases.
//!
//! # The three outcomes, and the `Unavailable`/`Unknown` boundary
//!
//! [`Lookup`] has three variants, not two, and collapsing the last two would lose information:
//!
//! - [`Lookup::Found`] carries the companion, decoded from exactly the bytes that were stored;
//! - [`Lookup::Unavailable`] says this node cannot produce the companion and has published a
//!   retention horizon, which accompanies the answer. The horizon is the node's retention boundary,
//!   not a claim about the block's number: the variant covers both a pruned block and a hash the
//!   node never recorded, so a caller cannot infer that the block is below the horizon;
//! - [`Lookup::Unknown`] says this node has no record of the hash at all.
//!
//! A pruned entry no longer exists, and the store keeps **no tombstones**, because a tombstone for
//! every pruned hash would retain exactly the unbounded set that pruning exists to drop. The
//! consequence is unavoidable and is accepted deliberately: once a horizon is published, an absent
//! hash cannot be distinguished from a pruned one, so it answers [`Lookup::Unavailable`] and
//! [`Lookup::Unknown`] becomes reachable only on a node that has never pruned. This is a real loss
//! of precision, not an oversight: with no horizon a node answers `Unknown`, and the moment it
//! advertises that it drops history it answers `Unavailable` for anything it cannot produce. Both
//! are statements about what this node can serve, never about the block: per D2, a missing
//! companion does not un-certify a block.
//!
//! # Durability and framing
//!
//! Every mutating call commits its own transaction and forces an environment sync before it
//! returns, so a reopen in a fresh process observes the write. Durability is the store's, not the
//! caller's.
//!
//! Values are stored with a versioned, length-prefixed record encoding defined in this crate, so a
//! stored companion decodes back to exactly the bytes that were written, with no dependence on a
//! serde or JSON round trip.

mod accounting;
mod encoding;
mod error;
mod store;

pub use accounting::{StoredAccounting, RULE_VERSION};
pub use error::StoreError;
pub use store::{open, CompanionStore, Lookup};
