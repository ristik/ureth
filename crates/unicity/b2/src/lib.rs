//! Inactive, stateless 0x0104 SDK 3.0.1 semantics. No node factory registers it.
//!
//! Successful semantics exports untrusted leaf obligations, not certified issuance.
//! Composition must authenticate the anchor and its `InputRecord` opening with B1,
//! compare each reference time to that timestamp and prove every raw leaf value.
mod abi;
mod cbor;
pub mod provider;
mod semantics;

use sha2::{Digest, Sha256};

/// Exact protocol snapshot with sealed candidate corpus; upstream merge is pending.
pub const PROTOCOL_REVISION: &str = "4ccb290b44a373f4a5a8f997b05300231dd9bc00";
/// This address remains inactive in all production node factories.
pub const ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("0000000000000000000000000000000000000104");
/// Maximum direct ABI request size.
pub const MAX_INPUT: usize = MAX_HISTORY + 4096;
/// Maximum semantic projection size.
pub const MAX_HISTORY: usize = 131072;
/// Maximum transfers, including terminal burn.
pub const MAX_TRANSFERS: u64 = 64;

/// Deterministic failure identity, shared where applicable with sdk-ext/oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Error {
    Deadline,
    DeadlineMismatch,
    LockProofShape,
    LockProofTooLarge,
    JustificationTooLarge,
    OutOfGas,
    ABIFraming,
    BadOperation,
    Truncated,
    Trailing,
    NonCanonical,
    ForbiddenCBOR,
    Shape,
    Tag,
    Version,
    Length,
    IntRange,
    InputTooLarge,
    TooManyTx,
    TooManyItems,
    TooDeep,
    ProofTooLarge,
    CfgMismatch,
    Predicate,
    MintShape,
    MintJustif,
    MintSalt,
    MintType,
    MintData,
    TransferData,
    CDMismatch,
    Unlock,
    UnlockLength,
    UnlockScalars,
    UnlockRecovery,
    UnlockKey,
    MinterKey,
    RepeatedSID,
    NoTransfers,
    HasTransfers,
    BurnNotFinal,
    NotBurn,
    BurnReason,
    ReturnData,
    ReturnAmount,
    ReturnRecip,
    LockInput,
    ZeroDigest,
    DeadlineExpired,
    LockProofCfg,
}
impl Error {
    /// Relation failures return the canonical all-zero false result. Framing,
    /// unsupported budgets and OOG are exceptional halts, as for B1.
    pub const fn is_invalid(self) -> bool {
        matches!(
            self,
            Self::CfgMismatch |
                Self::Predicate |
                Self::MintShape |
                Self::MintJustif |
                Self::MintSalt |
                Self::MintType |
                Self::MintData |
                Self::TransferData |
                Self::CDMismatch |
                Self::Unlock |
                Self::UnlockLength |
                Self::UnlockScalars |
                Self::UnlockRecovery |
                Self::UnlockKey |
                Self::MinterKey |
                Self::RepeatedSID |
                Self::NoTransfers |
                Self::HasTransfers |
                Self::BurnNotFinal |
                Self::NotBurn |
                Self::BurnReason |
                Self::ReturnData |
                Self::ReturnAmount |
                Self::ReturnRecip |
                Self::LockInput |
                Self::ZeroDigest |
                Self::DeadlineExpired |
                Self::LockProofShape |
                Self::DeadlineMismatch |
                Self::LockProofCfg
        )
    }
}
/// Native kernel result.
pub type Result<T> = core::result::Result<T, Error>;

/// One ordered, unauthenticated leaf obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// Source state ID, never a caller-selected key.
    pub sid: [u8; 32],
    /// Hash of exact tagged transaction bytes.
    pub tx_hash: [u8; 32],
    /// Original service-reported reference time.
    pub reference_time: u64,
    /// Raw SHA256(CBOR([b(txHash), referenceTime])).
    pub value: [u8; 32],
}
/// Pure outcome, before ABI encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Configuration digest.
    pub cfg: [u8; 32],
    /// Nonzero u64 lock nonce, encoded as uint256.
    pub nonce: u64,
    /// Amount, encoded as uint256.
    pub amount: [u8; 32],
    /// Derived token identity.
    pub token_id: [u8; 32],
    /// Derived mint salt.
    pub salt: [u8; 32],
    /// Hash of the first signature predicate.
    pub first_predicate_hash: [u8; 32],
    /// Permanent lock digest.
    pub lock_digest: [u8; 32],
    /// Terminal recipient, zero for prepare/mint.
    pub release_to: [u8; 20],
    /// Burn nullifier, zero for prepare/mint.
    pub nullifier: [u8; 32],
    /// Empty for prepare; one for mint; all for return.
    pub leaves: Vec<Leaf>,
}
/// A fully charged EVM success, including shaped false.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    /// Provisional deterministic charge. No cache/late-failure discounts.
    pub gas: u64,
    /// Exactly 448+128*m canonical bytes.
    pub bytes: Vec<u8>,
    /// Diagnostic only; never part of the ABI.
    pub invalid: Option<Error>,
}

/// Scan before crypto and reserve the complete charge. The revised provisional
/// schedule is 26000+20*inputBytes+14000*leaves; it includes an extra 4/byte
/// scan allowance and 2000/leaf for SDK3 reference-time/leaf/SID work. Production
/// activation still requires native x86-64/arm64 full-transaction measurements.
pub fn run(input: &[u8], gas: u64) -> Result<Output> {
    if input.len() > MAX_INPUT {
        return Err(Error::InputTooLarge);
    }
    let base = 26000 + 20 * input.len() as u64;
    if gas < base {
        return Err(Error::OutOfGas);
    }
    let call = abi::decode(input)?;
    let mut tokens = 0;
    let cfg = cbor::one(call.cfg, &mut tokens)?;
    semantics::check_cfg_network(cfg)?;
    let payload = cbor::one(call.payload, &mut tokens)?;
    // Count before any point parsing, public-key derivation, hash or recovery.
    let m = if call.op == 0 {
        0
    } else {
        let h = payload.array::<2>()?;
        1 + h[1].count(MAX_TRANSFERS)?
    };
    let charge = base + 14000 * m;
    if gas < charge {
        return Err(Error::OutOfGas);
    }
    let evaluated = semantics::evaluate(call.op, cfg, payload, &mut tokens);
    match evaluated {
        Ok(out) => Ok(Output { gas: charge, bytes: abi::encode(true, &out), invalid: None }),
        Err(e) if e.is_invalid() => Ok(Output {
            gas: charge,
            bytes: abi::encode(false, &Outcome::default()),
            invalid: Some(e),
        }),
        Err(e) => Err(e),
    }
}
fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod corpus_tests;
