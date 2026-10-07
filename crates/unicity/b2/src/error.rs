//! Error taxonomy of the bridge profile. Variant names equal the sentinel names
//! of the Go oracle (`bridgeprofile/errors.go`) so conformance vectors can name
//! the exact reason.

/// Failure family: malformed encoding, relation outside the profile or wrong,
/// or a direct-verification budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Framing or encoding failure.
    Malformed,
    /// Well formed but outside the launch profile or wrong.
    Invalid,
    /// A DEV-DEFAULT direct-verification ceiling.
    Budget,
}

macro_rules! errors {
    ($($(#[$m:meta])* $name:ident => $fam:ident),* $(,)?) => {
        /// A profile failure; the variant name is the Go sentinel name.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(missing_docs)]
        pub enum BridgeError { $($(#[$m])* $name),* }

        impl BridgeError {
            /// The sentinel name used by the conformance vectors.
            pub const fn name(&self) -> &'static str {
                match self { $(BridgeError::$name => concat!("Err", stringify!($name))),* }
            }
            /// The failure family.
            pub const fn family(&self) -> Family {
                match self { $(BridgeError::$name => Family::$fam),* }
            }
        }
    };
}

errors! {
    Truncated => Malformed, Trailing => Malformed, NonCanonical => Malformed,
    ForbiddenCBOR => Malformed, Shape => Malformed, Tag => Malformed, Version => Malformed,
    Length => Malformed, IntRange => Malformed, ABIFraming => Malformed, BadOperation => Malformed,
    InputTooLarge => Budget, TooManyTx => Budget, TooManyItems => Budget, TooDeep => Budget,
    Predicate => Invalid, MintShape => Invalid, MintJustif => Invalid, MintSalt => Invalid,
    MintType => Invalid, MintData => Invalid, TransferData => Invalid, CDMismatch => Invalid,
    Unlock => Invalid, UnlockLength => Invalid, UnlockScalars => Invalid, UnlockRecovery => Invalid,
    UnlockKey => Invalid, MinterKey => Invalid, RepeatedSID => Invalid, NoTransfers => Invalid,
    HasTransfers => Invalid, BurnNotFinal => Invalid, NotBurn => Invalid, BurnReason => Invalid,
    ReturnData => Invalid, ReturnAmount => Invalid, ReturnRecip => Invalid, LockInput => Invalid,
    ZeroDigest => Invalid,
}

impl core::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for BridgeError {}

/// Result alias of the bridge module.
pub(crate) type Result<T> = core::result::Result<T, BridgeError>;
