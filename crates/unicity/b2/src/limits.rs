//! DEV-DEFAULT safety ceilings and fixed protocol bytes of the profile.

pub(crate) const MAX_TRANSFERS: usize = 64;
pub(crate) const MAX_SEMANTIC_BYTES: usize = 64 << 10;
pub(crate) const MAX_CBOR_ITEMS: usize = 32768;
pub(crate) const MAX_AMOUNT_BYTES: usize = 32;

pub(crate) const TAG_PREDICATE: u64 = 39032;
pub(crate) const TAG_MINT: u64 = 39041;
pub(crate) const TAG_TRANSFER: u64 = 39045;
pub(crate) const TAG_CERTIFICATION: u64 = 39031;
pub(crate) const TAG_MINT_LOCK: u64 = 39049;
pub(crate) const TAG_RETURN_REASON: u64 = 39048;

pub(crate) const PRED_SIGNATURE: u8 = 1;
pub(crate) const PRED_BURN: u8 = 2;
