//! Inactive B1 A′ kernel. No node factory installs these precompiles.
//!
//! Authority comes exclusively from the current EVM journal after authenticated
//! block admission. This crate neither authenticates history nor enables a fork.
mod cbor;
mod certificate;
pub mod provider;
mod registry;
mod rsmt;

pub use registry::{entry_slot, fixed_slot, member_slot, RegistryRead, REGISTRY};
use sha2::{Digest, Sha256};

/// Caller failures are exceptional halts, never execution/host errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Incomplete framing or object.
    Truncated,
    /// Unsupported wire version.
    Version,
    /// Unsupported flags.
    Flags,
    /// Wrong operation cardinality.
    Count,
    /// Bytes remain after the object.
    Trailing,
    /// Hard resource limit exceeded.
    Limit,
    /// Nonminimal encoding, map disorder or duplicate keys.
    Canonical,
    /// Forbidden CBOR type.
    Cbor,
    /// Invalid UTF-8.
    Utf8,
    /// Wrong native schema, width, tag or arity.
    Shape,
    /// Invalid shard terminator/depth.
    Shard,
    /// Invalid signature length or recovery suffix.
    Signature,
}

/// Full result before EVM status conversion.
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// Caller malformed input.
    Malformed(Malformed),
    /// Caller forwarded too little gas.
    OutOfGas,
    /// Database or historical state unavailable.
    Host(E),
    /// Impossible state following authenticated admission.
    Registry,
}
impl<E> From<Malformed> for Error<E> {
    fn from(value: Malformed) -> Self {
        Self::Malformed(value)
    }
}

/// Reserved operation; no operation activates itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// One certificate.
    Uc,
    /// One common complete seal for up to eight claims.
    Shared,
    /// Stateless RSMT membership under a caller-supplied root.
    Member,
}
impl Operation {
    /// Reserved call address. No factory registers it automatically.
    pub const fn address(self) -> alloy_primitives::Address {
        let mut bytes = [0u8; 20];
        bytes[18] = 1;
        bytes[19] = match self {
            Self::Uc => 0,
            Self::Shared => 1,
            Self::Member => 2,
        };
        alloy_primitives::Address::new(bytes)
    }
}

/// A successful call, including shaped false relations.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    /// Complete candidate charge, independent of warmth or verdict.
    pub gas: u64,
    /// Exactly abi.encode(uint256(1),bool(valid)).
    pub bytes: [u8; 64],
}
impl Output {
    fn new(gas: u64, valid: bool) -> Self {
        let mut bytes = [0; 64];
        bytes[31] = 1;
        bytes[63] = u8::from(valid);
        Self { gas, bytes }
    }
}

/// Scan the complete request and reserve its entire charge before journal reads,
/// point parsing, signatures or hashing. Infrastructure errors have no EVM result.
pub fn run<R: RegistryRead>(
    op: Operation,
    input: &[u8],
    gas: u64,
    state: &mut R,
) -> Result<Output, Error<R::Error>> {
    let (cap, base) = if op == Operation::Member { (12392, 2000) } else { (262144, 60000) };
    if input.len() > cap {
        return Err(Malformed::Limit.into());
    }
    if gas < base + 16 * input.len() as u64 {
        return Err(Error::OutOfGas);
    }
    if op == Operation::Member {
        return rsmt::run(input, gas);
    }
    let call = certificate::scan(input, op == Operation::Shared)?;
    if gas < call.gas {
        return Err(Error::OutOfGas);
    }
    certificate::evaluate(call, state)
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

struct Reader<'a> {
    data: &'a [u8],
}
impl<'a> Reader<'a> {
    const fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if n > self.data.len() {
            return Err(Malformed::Truncated);
        }
        let (v, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(v)
    }
    fn uint(&mut self, n: usize) -> Result<u64, Malformed> {
        Ok(self.take(n)?.iter().fold(0, |v, b| (v << 8) | u64::from(*b)))
    }
    fn header(&mut self) -> Result<usize, Malformed> {
        if self.uint(1)? != 1 {
            return Err(Malformed::Version);
        }
        if self.uint(1)? != 0 {
            return Err(Malformed::Flags);
        }
        Ok(self.uint(2)? as usize)
    }
}
