//! `CERT_BATCH_V2` (address 0x0100): one registry-backed verdict for 1..=16 certificate claims of
//! any age (briefs/b1-any-age-contract.md sections 2, 3 and 5).
//!
//! The request is scanned and grouped completely, and the whole charge is reserved, before any
//! registry read, point parse or signature check. The charge depends on the request alone.
use crate::{
    certificate::{folds, parse_claim, shard_depth, Claim},
    hash,
    registry::{self, Entry, Pins},
    Error, Malformed, Reader, RegistryRead,
};
use secp256k1::{ecdsa::Signature, Message, Secp256k1};

pub use crate::Output;

/// The reserved call address of `CERT_BATCH_V2`.
pub const ADDRESS: alloy_primitives::Address = crate::Operation::Uc.address();
use crate::Output as Out;

/// Largest accepted request, in bytes.
pub const MAX_BYTES: usize = 262_144;
/// Largest claim count of one call (and so of distinct epochs, seals and claims).
pub const MAX_CLAIMS: usize = 16;
/// Largest total signature count over the distinct seals of one call.
pub const MAX_SIGNATURES: u64 = 256;
/// Largest signature count of one seal.
pub const MAX_SEAL_SIGNATURES: u64 = 16;
/// Largest cumulative sibling plus step count over all raw occurrences.
pub const MAX_RAW_PATHS: u64 = 4_608;
/// Price of one registry word, subsidised and provisional until `any_age_cold_registry_v1` passes.
pub const READ_GAS: u64 = 100;
/// The registry words of one epoch at the committee ceiling: 11 metadata and 8 per member.
const EPOCH_WORDS: u64 = 11 + 8 * registry::MAX_MEMBERS;
/// The eleven common words.
const COMMON_WORDS: u64 = 11;

/// `60,000 + 16*C + 500*K*(K-1)`: the allowance for scanning and grouping.
pub const fn scan_gas(bytes: u64, claims: u64) -> u64 {
    60_000 + 16 * bytes + 500 * claims * (claims - 1)
}
/// The whole charge of a structurally accepted request.
pub const fn batch_gas(bytes: u64, k: u64, e: u64, q: u64, a: u64, p: u64) -> u64 {
    scan_gas(bytes, k) +
        READ_GAS * COMMON_WORDS +
        (1_000 * registry::MAX_MEMBERS + READ_GAS * EPOCH_WORDS) * e +
        6_000 * q +
        2_000 * a +
        250 * p
}

/// The request dimensions every implementation computes identically (contract section 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dimensions {
    /// Request bytes.
    pub c: u64,
    /// Claim occurrences.
    pub k: u64,
    /// Distinct declared epochs, usable or not.
    pub e: u64,
    /// Distinct complete seals.
    pub s: u64,
    /// Signatures over the distinct seals.
    pub q: u64,
    /// Distinct claims.
    pub a: u64,
    /// Siblings plus steps over the distinct claims.
    pub p: u64,
}
impl Dimensions {
    /// Complete charge of these dimensions.
    pub const fn gas(&self) -> u64 {
        batch_gas(self.c, self.k, self.e, self.q, self.a, self.p)
    }
}

/// Work actually performed, for the instrumentation the contract requires. Malformed and
/// out-of-gas requests leave every counter zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Epoch entries loaded.
    pub epoch_loads: u64,
    /// Member keys parsed.
    pub key_parses: u64,
    /// Seals whose quorum relation was evaluated.
    pub quorums: u64,
    /// Signatures verified.
    pub signatures: u64,
    /// Distinct claims evaluated.
    pub claims: u64,
    /// Claim folds computed.
    pub folds: u64,
    /// Registry words read.
    pub reads: u64,
}

struct Scanned<'a> {
    claims: Vec<Claim<'a>>,
    /// The complete packed bytes of each occurrence.
    packed: Vec<&'a [u8]>,
    dims: Dimensions,
}

fn scan(input: &[u8], gas: u64) -> Result<Scanned<'_>, Error<core::convert::Infallible>> {
    let mut r = Reader { data: input };
    if r.uint(1)? != 2 {
        return Err(Malformed::Version.into());
    }
    if r.uint(1)? != 0 {
        return Err(Malformed::Flags.into());
    }
    let k = r.uint(2)? as usize;
    if k == 0 || k > MAX_CLAIMS {
        return Err(Malformed::Count.into());
    }
    let c = input.len() as u64;
    if gas < scan_gas(c, k as u64) {
        return Err(Error::OutOfGas);
    }
    let mut tokens = 0;
    let mut raw_paths = 0;
    let mut claims = Vec::with_capacity(k);
    let mut packed = Vec::with_capacity(k);
    let mut paths = Vec::with_capacity(k);
    let mut sigs = Vec::with_capacity(k);
    for _ in 0..k {
        let before = r.data;
        let p = parse_claim(&mut r, &mut tokens)?;
        packed.push(&before[..before.len() - r.data.len()]);
        raw_paths += p.paths;
        if raw_paths > MAX_RAW_PATHS || p.sigs > MAX_SEAL_SIGNATURES {
            return Err(Malformed::Limit.into());
        }
        // The shard's own depth fixes the sibling count; a different count is structural.
        let depth = shard_depth(p.claim.shard_cert[1].data)?;
        if p.claim.shard_cert[2].collection(4, 256)? != depth as u64 {
            return Err(Malformed::Limit.into());
        }
        paths.push(p.paths);
        sigs.push(p.sigs);
        claims.push(p.claim);
    }
    if !r.data.is_empty() {
        return Err(Malformed::Trailing.into());
    }
    // Canonical grouping: first-occurrence indexing on exact byte identities.
    let mut a = 0;
    let mut p = 0;
    let mut seals: Vec<&[u8]> = Vec::new();
    let mut epochs: Vec<u64> = Vec::new();
    let mut q = 0;
    for i in 0..k {
        if (0..i).any(|j| packed[j] == packed[i]) {
            continue;
        }
        a += 1;
        p += paths[i];
        let raw = claims[i].seal.raw;
        if !seals.contains(&raw) {
            seals.push(raw);
            q += sigs[i];
        }
        let epoch = claims[i].seal_fields[3].arg;
        if !epochs.contains(&epoch) {
            epochs.push(epoch);
        }
    }
    if q > MAX_SIGNATURES {
        return Err(Malformed::Limit.into());
    }
    let dims =
        Dimensions { c, k: k as u64, e: epochs.len() as u64, s: seals.len() as u64, q, a, p };
    Ok(Scanned { claims, packed, dims })
}

/// Scan and group a request without touching any state, returning its dimensions and charge.
/// Used by oracles, gate preflights and tests; consensus code calls [`run`].
pub fn dimensions(input: &[u8]) -> Result<Dimensions, Malformed> {
    if input.len() > MAX_BYTES {
        return Err(Malformed::Limit);
    }
    match scan(input, u64::MAX) {
        Ok(s) => Ok(s.dims),
        Err(Error::Malformed(m)) => Err(m),
        Err(_) => unreachable!("scan reads no state and has unlimited gas"),
    }
}

/// Evaluate one `CERT_BATCH_V2` call. `counters`, when supplied, receives the work performed.
pub fn run<R: RegistryRead>(
    input: &[u8],
    gas: u64,
    pins: &Pins,
    state: &mut R,
    counters: Option<&mut Counters>,
) -> Result<Out, Error<R::Error>> {
    let mut local = Counters::default();
    let counters = counters.unwrap_or(&mut local);
    *counters = Counters::default();
    if input.len() > MAX_BYTES {
        return Err(Malformed::Limit.into());
    }
    if gas < 60_000 + 16 * input.len() as u64 {
        return Err(Error::OutOfGas);
    }
    let scanned = scan(input, gas).map_err(widen)?;
    let charge = scanned.dims.gas();
    if gas < charge {
        return Err(Error::OutOfGas);
    }
    let valid = evaluate(&scanned, pins, state, counters)?;
    Ok(Out::versioned(charge, 2, valid))
}

fn widen<E>(e: Error<core::convert::Infallible>) -> Error<E> {
    match e {
        Error::Malformed(m) => Error::Malformed(m),
        Error::OutOfGas => Error::OutOfGas,
        Error::Host(never) => match never {},
        Error::Registry => Error::Registry,
    }
}

struct Loaded {
    epoch: u64,
    entry: Entry,
}

fn evaluate<R: RegistryRead>(
    s: &Scanned<'_>,
    pins: &Pins,
    state: &mut R,
    counters: &mut Counters,
) -> Result<bool, Error<R::Error>> {
    let common = registry::common_v2(state, pins)?;
    counters.reads += 11;
    if common.phase == 1 || !common.ready {
        return Ok(false);
    }
    // Distinct claims in first-use order, with the declared epochs they use.
    let k = s.claims.len();
    let distinct: Vec<usize> =
        (0..k).filter(|&i| !(0..i).any(|j| s.packed[j] == s.packed[i])).collect();
    let mut epochs: Vec<u64> = Vec::new();
    for &i in &distinct {
        let e = s.claims[i].seal_fields[3].arg;
        if !epochs.contains(&e) {
            epochs.push(e);
        }
    }
    // Load and validate every requested epoch inside [g,U] before any cryptography.
    let mut loaded: Vec<Loaded> = Vec::new();
    for &e in &epochs {
        if e < common.genesis || e > common.origin {
            continue;
        }
        let Some(entry) = registry::entry(state, e)? else {
            return Err(Error::Registry);
        };
        counters.epoch_loads += 1;
        counters.key_parses += entry.members.len() as u64;
        counters.reads += 11 + 8 * entry.members.len() as u64;
        let closed = entry.end;
        let impossible = if e < common.origin {
            closed.is_none_or(|end| end > common.round) || entry.start > common.round
        } else {
            closed.is_some() || entry.start > common.round
        };
        if impossible {
            return Err(Error::Registry);
        }
        loaded.push(Loaded { epoch: e, entry });
    }
    let find = |e: u64| loaded.iter().find(|l| l.epoch == e).map(|l| &l.entry);
    let mut valid = true;
    // Distinct claims: every one is folded, whatever the others do.
    for &i in &distinct {
        counters.claims += 1;
        counters.folds += 1;
        valid &= folds(&s.claims[i]);
    }
    // Two different claims for one shard under one seal can never both hold.
    for (n, &i) in distinct.iter().enumerate() {
        for &j in &distinct[..n] {
            let (a, b) = (&s.claims[j], &s.claims[i]);
            if a.seal.raw == b.seal.raw && a.partition == b.partition && a.shard == b.shard {
                valid = false;
            }
        }
    }
    // Distinct seals, each evaluated once.
    let mut seen: Vec<&[u8]> = Vec::new();
    for &i in &distinct {
        let c = &s.claims[i];
        if seen.contains(&c.seal.raw) {
            continue;
        }
        seen.push(c.seal.raw);
        let f = c.seal_fields;
        let Some(entry) = find(f[3].arg) else {
            valid = false;
            continue;
        };
        let r = f[2].arg;
        if f[1].arg != common.network ||
            r < entry.start ||
            entry.end.is_some_and(|end| r >= end) ||
            r > common.round
        {
            valid = false;
            continue;
        }
        counters.quorums += 1;
        valid &= quorum(c, entry, counters);
    }
    Ok(valid)
}

/// Verify every supplied signature of one seal and its weighted quorum. No early exit on quorum:
/// a bad or unknown extra signer fails the seal.
fn quorum(c: &Claim<'_>, e: &Entry, counters: &mut Counters) -> bool {
    let sig_map = c.seal_fields[7];
    if sig_map.null() || sig_map.arg == 0 {
        return false;
    }
    // Canonical tagged seal prefix is preserved verbatim; only the signature map is replaced
    // with the native null item. No domain prefix or second digest.
    let prefix = &c.seal.raw[..c.seal.raw.len() - sig_map.raw.len()];
    let message = Message::from_digest(hash(&[prefix, &[0xf6]]));
    let secp = Secp256k1::verification_only();
    let mut good = 0u64;
    let mut valid = true;
    let mut sigs = sig_map.children();
    while let Some(id) = sigs.next() {
        let sig = sigs.next().expect("scanned signature pair");
        let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else {
            valid = false;
            continue;
        };
        let Ok(signature) = Signature::from_compact(&sig.data[..64]) else {
            valid = false;
            continue;
        };
        let mut low = signature;
        low.normalize_s();
        counters.signatures += 1;
        if low != signature || secp.verify_ecdsa(&message, &signature, &member.key).is_err() {
            valid = false;
            continue;
        }
        good += member.weight;
    }
    valid && good >= e.total - (e.total - 1) / 3
}
