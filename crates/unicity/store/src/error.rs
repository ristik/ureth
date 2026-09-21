//! Error type for the companion store.

/// Everything that can go wrong while opening, encoding, reading or pruning the store.
///
/// The variants are part of the crate's API on purpose: a caller distinguishes a horizon that
/// would move backwards from a record it cannot decode, and both are different from the backing
/// environment failing. Matching a generic error string is never required.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The backing MDBX environment reported an error.
    #[error("mdbx error: {0}")]
    Mdbx(#[from] reth_libmdbx::Error),
    /// The store directory could not be created or inspected.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A record's leading version byte is not one this crate can decode.
    ///
    /// The byte is carried so a caller can tell a newer writer from a corrupted value. This crate
    /// never skips an unknown version: an unrecognised version is a refusal, never a best guess.
    #[error("unknown record version {0}")]
    UnknownVersion(u8),
    /// A record field is longer than the four-byte frame prefix can express.
    #[error("record field is too large to encode")]
    RecordTooLarge,
    /// A record is structurally invalid and cannot be decoded.
    #[error("malformed record: {0}")]
    MalformedRecord(&'static str),
    /// The store's own bookkeeping disagrees with itself.
    ///
    /// This is distinct from [`Self::MalformedRecord`]: it means a key, a stored block number or
    /// the horizon has a shape this crate never writes, so the environment was written by
    /// something else or was damaged.
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
    /// A horizon write would move the published horizon backwards.
    ///
    /// A node that has pruned cannot un-prune, so a backwards move is refused rather than
    /// ignored. The current and requested numbers are both carried for the caller.
    #[error("horizon would move backwards from {current} to {requested}")]
    HorizonRegression {
        /// The horizon that is already published.
        current: u64,
        /// The lower number that was requested.
        requested: u64,
    },
}
