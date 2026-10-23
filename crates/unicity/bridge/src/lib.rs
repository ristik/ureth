//! `BRIDGE_COMPOSE_V1` at `0x0105`: the whole composed relation of one bridge redemption, natively
//! (B7 direct path, bft-core briefs/dev4-b7-native-compose-spec.md). The relation is exactly
//! bft-core `bridgeprofile.Compose`: framing and the resource policy, the policy body, the B2
//! kernel, the anchor table, one `CERT_BATCH_V2` evaluation against the registry in the journal,
//! the IR openings and leaf times, and one RSMT membership per leaf. It reuses the B1 and B2
//! kernels; it adds no rule of its own.
//!
//! The output is fixed-size whatever the history length. A refused redemption is a successful call
//! carrying a nonzero status and paying for the work it caused; only out-of-gas and a
//! non-canonical call input halt.
mod abi;
mod cfg;
mod compose;
pub mod provider;

use reth_unicity_b2::Outcome;

/// Reserved address, registered by the Unicity EVM factory only.
pub const ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("0000000000000000000000000000000000000105");
/// `bytes32("UNICITY_BRIDGE_COMPOSE_V1")`.
pub const MARKER: [u8; 32] = *b"UNICITY_BRIDGE_COMPOSE_V1\0\0\0\0\0\0\0";
/// Exactly twelve words.
pub const OUTPUT_BYTES: usize = 384;
/// `bytes32("UNICITY_BRIDGE_COMPOSE_V2")`.
pub const MARKER_V2: [u8; 32] = *b"UNICITY_BRIDGE_COMPOSE_V2\0\0\0\0\0\0\0";
/// Fifteen words: the twelve of V1 (the root's), then partTokenId, partAmount, splitDepth.
pub const OUTPUT_BYTES_V2: usize = 480;

// The resource policy of bft-core `bridgeprofile/limits.go` (owner §36): the composition streams
// the history and the anchor table. It is bounded by the envelope (the ingress bound), the u16
// anchor wire width and its gas; the rest are per-object bounds.
pub(crate) const MAX_ANCHORS: usize = u16::MAX as usize;
pub(crate) const MAX_ENVELOPE_BYTES: usize = 2 << 20;
pub(crate) const MAX_CFG_BYTES: usize = 1024;
pub(crate) const MAX_POLICY_BYTES: usize = 512;
pub(crate) const MAX_ANCHOR_UC_BYTES: usize = 8 << 10;
pub(crate) const MAX_INPUT_RECORD_BYTES: usize = 512;
pub(crate) const MAX_RSMT_SIBLINGS: usize = 32;
pub(crate) const MAX_SUMMARY_BYTES: usize = 256;

/// The relation status: [`Status::Ok`] holds; any other value names the first failed check. The
/// codes are bft-core `bridgeprofile.ComposeStatus` (append-only, the discriminant is the code);
/// the corpus `config/compose-status.json` pins them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Status {
    Ok = 0,
    Truncated,
    Trailing,
    NonCanonical,
    ForbiddenCBOR,
    Shape,
    Tag,
    Version,
    Length,
    IntRange,
    ABIFraming,
    BadOperation,
    Deadline,
    InputTooLarge,
    TooManyTx,
    TooManyItems,
    TooDeep,
    TooManyPaths,
    JustificationTooLarge,
    LockProofTooLarge,
    CfgMismatch,
    PolicyHash,
    PolicyTuple,
    PolicyAnchors,
    PolicyLeafIndex,
    PolicyLeafCount,
    PolicyPartition,
    Predicate,
    MintShape,
    LockProofShape,
    LockProofCfg,
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
    DeadlineMismatch,
    DeadlineExpired,
    IROpening,
    IRShape,
    IRState,
    IRTime,
    PathBitmap,
    AnchorAuth,
    LeafProof,
    // Protocol 6 (BRIDGE_COMPOSE_V2): the split reasons, then the certificate-codec reasons of an
    // embedded ancestor proof. Never produced by BRIDGE_COMPOSE_V1.
    SplitJustif,
    SplitProofCount,
    SplitProofShape,
    SplitManifest,
    SplitBurn,
    SplitProof,
    SplitSum,
    CertScan,
    CertSigLength,
}
impl Status {
    /// The oracle's sentinel name of a nonzero status.
    pub const NAMES: [&'static str; 62] = [
        "ErrTruncated",
        "ErrTrailing",
        "ErrNonCanonical",
        "ErrForbiddenCBOR",
        "ErrShape",
        "ErrTag",
        "ErrVersion",
        "ErrLength",
        "ErrIntRange",
        "ErrABIFraming",
        "ErrBadOperation",
        "ErrDeadline",
        "ErrInputTooLarge",
        "ErrTooManyTx",
        "ErrTooManyItems",
        "ErrTooDeep",
        "ErrTooManyPaths",
        "ErrJustificationTooLarge",
        "ErrLockProofTooLarge",
        "ErrCfgMismatch",
        "ErrPolicyHash",
        "ErrPolicyTuple",
        "ErrPolicyAnchors",
        "ErrPolicyLeafIndex",
        "ErrPolicyLeafCount",
        "ErrPolicyPartition",
        "ErrPredicate",
        "ErrMintShape",
        "ErrLockProofShape",
        "ErrLockProofCfg",
        "ErrMintJustif",
        "ErrMintSalt",
        "ErrMintType",
        "ErrMintData",
        "ErrTransferData",
        "ErrCDMismatch",
        "ErrUnlock",
        "ErrUnlockLength",
        "ErrUnlockScalars",
        "ErrUnlockRecovery",
        "ErrUnlockKey",
        "ErrMinterKey",
        "ErrRepeatedSID",
        "ErrNoTransfers",
        "ErrHasTransfers",
        "ErrBurnNotFinal",
        "ErrNotBurn",
        "ErrBurnReason",
        "ErrReturnData",
        "ErrReturnAmount",
        "ErrReturnRecip",
        "ErrLockInput",
        "ErrZeroDigest",
        "ErrDeadlineMismatch",
        "ErrDeadlineExpired",
        "ErrIROpening",
        "ErrIRShape",
        "ErrIRState",
        "ErrIRTime",
        "ErrPathBitmap",
        "ErrAnchorAuth",
        "ErrLeafProof",
    ];
    /// The names of the codes `BRIDGE_COMPOSE_V2` appends to [`Status::NAMES`], from code 63.
    pub const NAMES_V2: [&'static str; 9] = [
        "ErrSplitJustif",
        "ErrSplitProofCount",
        "ErrSplitProofShape",
        "ErrSplitManifest",
        "ErrSplitBurn",
        "ErrSplitProof",
        "ErrSplitSum",
        "ErrCertScan",
        "ErrCertSigLength",
    ];
    /// The numeric code.
    pub const fn code(self) -> u64 {
        self as u64
    }
    /// The oracle's sentinel name (`""` for [`Status::Ok`]).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "",
            s if (s as usize) <= Self::NAMES.len() => Self::NAMES[s as usize - 1],
            s => Self::NAMES_V2[s as usize - Self::NAMES.len() - 1],
        }
    }
}

/// The status of a B2 kernel failure: the kernel's identities are the oracle's sentinels without
/// `Err`. Its out-of-gas never reaches here (the composition does not let B2 meter).
pub(crate) fn status_of_b2(e: reth_unicity_b2::Error) -> Status {
    use reth_unicity_b2::Error as E;
    match e {
        E::Deadline => Status::Deadline,
        E::DeadlineMismatch => Status::DeadlineMismatch,
        E::LockProofShape => Status::LockProofShape,
        E::LockProofTooLarge => Status::LockProofTooLarge,
        E::JustificationTooLarge => Status::JustificationTooLarge,
        E::ABIFraming => Status::ABIFraming,
        E::BadOperation => Status::BadOperation,
        E::Truncated => Status::Truncated,
        E::Trailing => Status::Trailing,
        E::NonCanonical => Status::NonCanonical,
        E::ForbiddenCBOR => Status::ForbiddenCBOR,
        E::Shape => Status::Shape,
        E::Tag => Status::Tag,
        E::Version => Status::Version,
        E::Length => Status::Length,
        E::IntRange => Status::IntRange,
        // B2's blob bound is the oracle's input-size refusal.
        E::InputTooLarge | E::ProofTooLarge => Status::InputTooLarge,
        E::TooManyTx => Status::TooManyTx,
        E::TooManyItems => Status::TooManyItems,
        E::TooDeep => Status::TooDeep,
        E::CfgMismatch => Status::CfgMismatch,
        E::Predicate => Status::Predicate,
        E::MintShape => Status::MintShape,
        E::MintJustif => Status::MintJustif,
        E::MintSalt => Status::MintSalt,
        E::MintType => Status::MintType,
        E::MintData => Status::MintData,
        E::TransferData => Status::TransferData,
        E::CDMismatch => Status::CDMismatch,
        E::Unlock => Status::Unlock,
        E::UnlockLength => Status::UnlockLength,
        E::UnlockScalars => Status::UnlockScalars,
        E::UnlockRecovery => Status::UnlockRecovery,
        E::UnlockKey => Status::UnlockKey,
        E::MinterKey => Status::MinterKey,
        E::RepeatedSID => Status::RepeatedSID,
        E::NoTransfers => Status::NoTransfers,
        E::HasTransfers => Status::HasTransfers,
        E::BurnNotFinal => Status::BurnNotFinal,
        E::NotBurn => Status::NotBurn,
        E::BurnReason => Status::BurnReason,
        E::ReturnData => Status::ReturnData,
        E::ReturnAmount => Status::ReturnAmount,
        E::ReturnRecip => Status::ReturnRecip,
        E::LockInput => Status::LockInput,
        E::ZeroDigest => Status::ZeroDigest,
        E::DeadlineExpired => Status::DeadlineExpired,
        E::LockProofCfg => Status::LockProofCfg,
        E::SplitJustif => Status::SplitJustif,
        E::SplitProofCount => Status::SplitProofCount,
        E::SplitProofShape => Status::SplitProofShape,
        E::SplitManifest => Status::SplitManifest,
        E::SplitBurn => Status::SplitBurn,
        E::SplitProof => Status::SplitProof,
        E::SplitSum => Status::SplitSum,
        E::CertScan => Status::CertScan,
        E::CertSigLength => Status::CertSigLength,
        // The composition never lets B2 meter.
        E::OutOfGas => unreachable!("B2 is never metered inside the composition"),
    }
}

/// A call that ends without a status.
#[derive(Debug, PartialEq, Eq)]
pub enum Halt<E> {
    /// The caller forwarded too little gas for the next stage.
    OutOfGas,
    /// The call input is not the canonical `abi.encode(uint8, bytes, bytes)`.
    Malformed,
    /// Database or historical state unavailable.
    Host(E),
    /// Impossible registry state following authenticated admission (as `CERT_BATCH_V2`).
    Registry,
}

/// The anchor table's one `CERT_BATCH_V2` verdict: against the registry in the journal in
/// production, against a supplied claim set in the corpus replay.
pub trait Verdict {
    /// Host failure.
    type Error;
    /// Whether every claim of `request` (a `CERT_BATCH_V2` request) authenticates.
    fn batch(&mut self, request: &[u8]) -> Result<bool, Halt<Self::Error>>;
}

/// The redemption result, fixed-size: the B2 outcome without its leaves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fixed {
    /// Configuration digest.
    pub cfg: [u8; 32],
    /// Lock nonce.
    pub nonce: u64,
    /// Amount.
    pub amount: [u8; 32],
    /// Token identity.
    pub token_id: [u8; 32],
    /// Mint salt.
    pub salt: [u8; 32],
    /// First signature predicate hash.
    pub first_predicate_hash: [u8; 32],
    /// Lock digest.
    pub lock_digest: [u8; 32],
    /// Terminal recipient, zero for a mint.
    pub release_to: [u8; 20],
    /// Burn nullifier, zero for a mint.
    pub nullifier: [u8; 32],
    /// Leaves proven.
    pub leaf_count: u64,
}
impl Fixed {
    const fn of(o: &Outcome) -> Self {
        Self {
            cfg: o.cfg,
            nonce: o.nonce,
            amount: o.amount,
            token_id: o.token_id,
            salt: o.salt,
            first_predicate_hash: o.first_predicate_hash,
            lock_digest: o.lock_digest,
            release_to: o.release_to,
            nullifier: o.nullifier,
            leaf_count: o.leaves.len() as u64,
        }
    }
    fn encode(&self, status: u64) -> [u8; OUTPUT_BYTES] {
        let mut out = [0; OUTPUT_BYTES];
        out[..32].copy_from_slice(&MARKER);
        out[56..64].copy_from_slice(&status.to_be_bytes());
        if status != 0 {
            return out;
        }
        out[64..96].copy_from_slice(&self.cfg);
        out[120..128].copy_from_slice(&self.nonce.to_be_bytes());
        out[128..160].copy_from_slice(&self.amount);
        out[160..192].copy_from_slice(&self.token_id);
        out[192..224].copy_from_slice(&self.salt);
        out[224..256].copy_from_slice(&self.first_predicate_hash);
        out[256..288].copy_from_slice(&self.lock_digest);
        out[300..320].copy_from_slice(&self.release_to);
        out[320..352].copy_from_slice(&self.nullifier);
        out[376..384].copy_from_slice(&self.leaf_count.to_be_bytes());
        out
    }
}

/// The V2 result: the root lock's fields, the leaf count and the redeemed part (protocol 6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedV2 {
    /// Words 2 to 11: the root lock's, as [`Fixed`].
    pub root: Fixed,
    /// The redeemed token (the root at depth 0).
    pub part_token_id: [u8; 32],
    /// Its whole amount.
    pub part_amount: [u8; 32],
    /// The split depth.
    pub depth: u64,
}
impl FixedV2 {
    const fn of(o: &Outcome) -> Self {
        Self {
            root: Fixed::of(o),
            part_token_id: o.part_token_id,
            part_amount: o.part_amount,
            depth: o.depth,
        }
    }
    fn encode(&self, status: u64) -> [u8; OUTPUT_BYTES_V2] {
        let mut out = [0; OUTPUT_BYTES_V2];
        out[..OUTPUT_BYTES].copy_from_slice(&self.root.encode(status));
        out[..32].copy_from_slice(&MARKER_V2);
        if status == 0 {
            out[384..416].copy_from_slice(&self.part_token_id);
            out[416..448].copy_from_slice(&self.part_amount);
            out[472..480].copy_from_slice(&self.depth.to_be_bytes());
        }
        out
    }
}

/// Incremental metering against the forwarded gas (spec section 4, a trial schedule).
#[derive(Debug)]
pub(crate) struct Meter {
    limit: u64,
    used: u64,
}
impl Meter {
    pub(crate) const BASE: u64 = 100_000;
    pub(crate) const PER_BYTE: u64 = 2;
    pub(crate) const PER_ITEM: u64 = 20;
    pub(crate) const PER_LEAF: u64 = 16_000;
    pub(crate) const PER_SIGNATURE: u64 = 6_000;
    pub(crate) const PER_EPOCH: u64 = 29_900;
    pub(crate) const PER_CLAIM: u64 = 2_000;
    pub(crate) const PER_STEP: u64 = 250;
    pub(crate) const PER_GROUPING: u64 = 50;

    pub(crate) const fn charge<E>(&mut self, gas: u64) -> Result<(), Halt<E>> {
        match self.used.checked_add(gas) {
            Some(used) if used <= self.limit => {
                self.used = used;
                Ok(())
            }
            _ => Err(Halt::OutOfGas),
        }
    }
    /// The batch terms: signatures over distinct seals, distinct epochs and claims, certificate
    /// steps, and the sort-based grouping of the K occurrences.
    pub(crate) fn batch(d: &reth_unicity_b1::batch::Dimensions) -> u64 {
        let log2 = if d.k <= 1 { 0 } else { 64 - u64::from((d.k - 1).leading_zeros()) };
        Self::PER_SIGNATURE * d.q +
            Self::PER_EPOCH * d.e +
            Self::PER_CLAIM * d.a +
            Self::PER_STEP * d.p +
            Self::PER_GROUPING * d.k * log2
    }
}

/// A complete call: the gas charged, the 384 output bytes and the status.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    /// Gas charged up to the end of the call (or the failed check).
    pub gas: u64,
    /// Exactly [`OUTPUT_BYTES`].
    pub bytes: [u8; OUTPUT_BYTES],
    /// The status the bytes carry.
    pub status: Status,
}

/// The largest call input: the three head words, both length words, the Cfg and the envelope.
pub const MAX_INPUT_BYTES: usize = 5 * 32 + MAX_CFG_BYTES + MAX_ENVELOPE_BYTES;

/// Evaluate one call with `gas` forwarded. A halt consumes all of it.
pub fn run<V: Verdict>(input: &[u8], gas: u64, verdict: &mut V) -> Result<Output, Halt<V::Error>> {
    let mut meter = Meter { limit: gas, used: 0 };
    let result = (|| {
        meter.charge(
            Meter::BASE.saturating_add(Meter::PER_BYTE.saturating_mul(input.len() as u64)),
        )?;
        if input.len() > MAX_INPUT_BYTES {
            return Ok(Err(Status::InputTooLarge));
        }
        let call = abi::decode_call(input).ok_or(Halt::Malformed)?;
        match compose::compose(call, &mut meter, verdict) {
            Ok(f) => Ok(Ok(f)),
            Err(compose::Stop::Status(s)) => Ok(Err(s)),
            Err(compose::Stop::Halt(h)) => Err(h),
        }
    })()?;
    let (fixed, status) = match result {
        Ok(f) => (f, Status::Ok),
        Err(s) => (Fixed::default(), s),
    };
    Ok(Output { gas: meter.used, bytes: fixed.encode(status.code()), status })
}

/// A complete V2 call: the gas charged, the 480 output bytes and the status.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputV2 {
    /// Gas charged up to the end of the call (or the failed check).
    pub gas: u64,
    /// Exactly [`OUTPUT_BYTES_V2`].
    pub bytes: [u8; OUTPUT_BYTES_V2],
    /// The status the bytes carry.
    pub status: Status,
}

/// Evaluate one `BRIDGE_COMPOSE_V2` call (protocol 6) with `gas` forwarded: [`run`]'s composition
/// with the lineage relation for a return. A halt consumes all of the gas.
pub fn run_v2<V: Verdict>(
    input: &[u8],
    gas: u64,
    verdict: &mut V,
) -> Result<OutputV2, Halt<V::Error>> {
    let mut meter = Meter { limit: gas, used: 0 };
    let result = (|| {
        meter.charge(
            Meter::BASE.saturating_add(Meter::PER_BYTE.saturating_mul(input.len() as u64)),
        )?;
        if input.len() > MAX_INPUT_BYTES {
            return Ok(Err(Status::InputTooLarge));
        }
        let call = abi::decode_call(input).ok_or(Halt::Malformed)?;
        match compose::compose_v2(call, &mut meter, verdict) {
            Ok(f) => Ok(Ok(f)),
            Err(compose::Stop::Status(s)) => Ok(Err(s)),
            Err(compose::Stop::Halt(h)) => Err(h),
        }
    })()?;
    let (fixed, status) = match result {
        Ok(f) => (f, Status::Ok),
        Err(s) => (FixedV2::default(), s),
    };
    Ok(OutputV2 { gas: meter.used, bytes: fixed.encode(status.code()), status })
}

#[cfg(test)]
mod tests;
