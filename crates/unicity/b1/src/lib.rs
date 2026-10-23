//! B1 A′ kernel: the `CERT_BATCH_V2` certificate batch and the RSMT membership check.
//!
//! Authority comes exclusively from the current EVM journal after authenticated
//! block admission. This crate neither authenticates history nor enables a fork.
pub mod batch;
/// Borrowed native CBOR views, shared with the composition (`reth-unicity-bridge`); not a stable
/// API.
#[doc(hidden)]
pub mod cbor;
mod certificate;
pub use certificate::scan_certificate;
pub mod provider;
mod registry;
mod rsmt;

pub use registry::{
    entry_slot, fixed_slot, member_slot, Pins, RegistryRead, MAX_MEMBERS, REGISTRY,
};
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

/// A reserved B1 call address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// `CERT_BATCH_V2`: the sole certificate operation (1..16 claim occurrences). `0x0101` is
    /// reserved and inactive.
    CertBatch,
    /// Stateless RSMT membership under a caller-supplied root.
    Member,
}
impl Operation {
    /// Reserved call address. No factory registers it automatically.
    pub const fn address(self) -> alloy_primitives::Address {
        let mut bytes = [0u8; 20];
        bytes[18] = 1;
        bytes[19] = match self {
            Self::CertBatch => 0,
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
        Self::versioned(gas, 1, valid)
    }
    /// abi.encode(uint256(version),bool(valid)).
    fn versioned(gas: u64, version: u8, valid: bool) -> Self {
        let mut bytes = [0; 64];
        bytes[31] = version;
        bytes[63] = u8::from(valid);
        Self { gas, bytes }
    }
}

/// Stateless RSMT membership. The charge is reserved against the request alone, before any hashing.
pub fn membership<E>(input: &[u8], gas: u64) -> Result<Output, Error<E>> {
    if input.len() > 12392 {
        return Err(Malformed::Limit.into());
    }
    if gas < 2000 + 16 * input.len() as u64 {
        return Err(Error::OutOfGas);
    }
    rsmt::run(input, gas)
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
