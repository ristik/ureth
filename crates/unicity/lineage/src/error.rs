//! The typed refusals of the lineage verifier.
//!
//! Every refusal names a [`Kind`]. The kinds carry the names of the Go sentinels in `bft-core`'s
//! `q3format` package (`ErrFormat`, `ErrActivation`, ...), so the conformance suite can require
//! that Rust refuses each Go negative vector for the same reason, not merely that it refuses.

use std::fmt;

/// The class of a refusal; [`Kind::go_name`] is the Go sentinel it corresponds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Malformed, truncated, noncanonical or trailing-garbage input, or a field of the wrong kind.
    Format,
    /// A size or count limit was exceeded (checked before any allocation).
    TooLarge,
    /// An unknown or unsupported version or domain.
    Version,
    /// A protocol tuple that is not exactly the one Q3 tuple.
    Config,
    /// A V3 body that fails its own checks.
    Body,
    /// A prior trust-base reference that cannot be a predecessor.
    Prior,
    /// Links that repeat or skip an epoch, or an inconsistent envelope.
    Envelope,
    /// An envelope link naming an epoch the history already holds, differently.
    Conflict,
    /// A link that does not extend the verified history, or a history that cannot be started.
    History,
    /// A link that skips an epoch the verified history does not hold.
    MissingHistory,
    /// An epoch or round outside the verified history; never means scheme 1.
    UnknownEpoch,
    /// Ordinary work outside the epoch's `[A*, next A*)` interval.
    OutsideInterval,
    /// A body or tuple names a network other than the history authority's.
    Network,
    /// A tuple names a root genesis other than the history's.
    Genesis,
    /// The committed record that would activate a body is not authenticated by the previous
    /// committee.
    Activation,
    /// An authenticated record does not bind the body, predecessor, boundary or candidate
    /// presented with it.
    Binding,
    /// The previous epoch's signing scheme has no verifier here yet; there is no fallback to
    /// scheme 1.
    Scheme,
    /// A readiness context that is not the one of the body it is checked against.
    ReceiptContext,
    /// A successor member without a readiness receipt.
    ReceiptMissing,
    /// A duplicate readiness receipt.
    ReceiptDuplicate,
    /// A readiness receipt from a signer that is not a successor member.
    ReceiptUnknown,
    /// A readiness receipt whose signature does not verify under the member's root key.
    ReceiptSignature,
    /// A signing statement that violates the consensus relations the preimage assumes (Q1
    /// votesig).
    Statement,
}

impl Kind {
    /// The name of the matching Go sentinel in `bft-core/q3format` (or `votesig` for
    /// [`Kind::Statement`]).
    pub const fn go_name(self) -> &'static str {
        match self {
            Self::Format => "ErrFormat",
            Self::TooLarge => "ErrTooLarge",
            Self::Version => "ErrVersion",
            Self::Config => "ErrConfig",
            Self::Body => "ErrBody",
            Self::Prior => "ErrPrior",
            Self::Envelope => "ErrEnvelope",
            Self::Conflict => "ErrConflict",
            Self::History => "ErrHistory",
            Self::MissingHistory => "ErrMissingHistory",
            Self::UnknownEpoch => "ErrUnknownEpoch",
            Self::OutsideInterval => "ErrOutsideInterval",
            Self::Network => "ErrNetwork",
            Self::Genesis => "ErrGenesis",
            Self::Activation => "ErrActivation",
            Self::Binding => "ErrBinding",
            Self::Scheme => "ErrScheme",
            Self::ReceiptContext => "ErrReceiptContext",
            Self::ReceiptMissing => "ErrReceiptMissing",
            Self::ReceiptDuplicate => "ErrReceiptDuplicate",
            Self::ReceiptUnknown => "ErrReceiptUnknown",
            Self::ReceiptSignature => "ErrReceiptSignature",
            Self::Statement => "ErrStatement",
        }
    }
}

/// A typed refusal with a human-readable detail.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", .kind.go_name())]
pub struct Error {
    kind: Kind,
    detail: String,
}

impl Error {
    pub(crate) fn new(kind: Kind, detail: impl fmt::Display) -> Self {
        Self { kind, detail: detail.to_string() }
    }

    /// The class of the refusal.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The Go sentinel name of the class.
    pub const fn go_name(&self) -> &'static str {
        self.kind.go_name()
    }
}

/// Result alias of this crate.
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn format(detail: impl fmt::Display) -> Error {
    Error::new(Kind::Format, detail)
}
