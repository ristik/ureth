use crate::Error;
use alloy_primitives::{address, keccak256, Address, U256};
use secp256k1::PublicKey;

/// Fresh authenticated registry address.
pub const REGISTRY: Address = address!("ff00000000000000000000000000000000000002");
/// A journal-aware source. Implementations must retain normal account/slot warmth
/// and propagate unavailable state. The production adapter uses `EvmInternals`.
pub trait RegistryRead {
    /// Infrastructure error.
    type Error;
    /// Read a present value from the current journal, with normal warming.
    fn sload(&mut self, key: U256) -> Result<U256, Self::Error>;
}
/// Fresh fixed-word domain; no old layout fallback.
pub fn fixed_slot(name: &str) -> U256 {
    U256::from_be_bytes(
        keccak256([b"unicity.seal-registry/".as_slice(), name.as_bytes()].concat()).0,
    )
}
fn derived(name: &str, words: &[u64]) -> U256 {
    let mut bytes = fixed_slot(name).to_be_bytes::<32>().to_vec();
    for w in words {
        bytes.extend_from_slice(&U256::from(*w).to_be_bytes::<32>());
    }
    U256::from_be_bytes(keccak256(bytes).0)
}
/// Entry metadata slot E(epoch,field).
pub fn entry_slot(epoch: u64, field: u64) -> U256 {
    derived("b1.entry", &[epoch, field])
}
/// Full member slot M(epoch,index,field).
pub fn member_slot(epoch: u64, index: u64, field: u64) -> U256 {
    derived("b1.member", &[epoch, index, field])
}

#[derive(Debug)]
pub(crate) struct Common {
    pub phase: u64,
    pub network: u64,
    pub window: u64,
    pub round: u64,
    pub origin: u64,
}
fn small<E>(v: U256) -> Result<u64, Error<E>> {
    u64::try_from(v).map_err(|_| Error::Registry)
}
fn read<R: RegistryRead>(r: &mut R, k: U256) -> Result<U256, Error<R::Error>> {
    r.sload(k).map_err(Error::Host)
}
pub(crate) fn common<R: RegistryRead>(r: &mut R) -> Result<Common, Error<R::Error>> {
    let mut w = [U256::ZERO; 8];
    for (dst, name) in w.iter_mut().zip([
        "genesisCommitment",
        "phase",
        "b1.initialized",
        "b1.network",
        "b1.wCert",
        "b1.profileHash",
        "clock.rootRound",
        "origin.rootEpoch",
    ]) {
        *dst = read(r, fixed_slot(name))?;
    }
    let phase = small(w[1])?;
    let network = small(w[3])?;
    if w[0].is_zero() ||
        w[5].is_zero() ||
        w[2] != U256::from(1) ||
        !matches!(phase, 1 | 2) ||
        network > u64::from(u16::MAX)
    {
        return Err(Error::Registry);
    }
    Ok(Common { phase, network, window: small(w[4])?, round: small(w[6])?, origin: small(w[7])? })
}
#[derive(Debug)]
pub(crate) struct Entry {
    pub start: u64,
    pub end: Option<u64>,
    pub total: u64,
    pub members: Vec<Member>,
}
#[derive(Debug)]
pub(crate) struct Member {
    pub id: String,
    pub key: PublicKey,
    pub weight: u64,
}
pub(crate) fn entry<R: RegistryRead>(
    r: &mut R,
    epoch: u64,
) -> Result<Option<Entry>, Error<R::Error>> {
    let mut w = [U256::ZERO; 11];
    for (i, dst) in w.iter_mut().enumerate() {
        *dst = read(r, entry_slot(epoch, i as u64))?;
    }
    if w[0].is_zero() {
        if w.iter().any(|v| !v.is_zero()) {
            return Err(Error::Registry);
        }
        return Ok(None);
    }
    let kind = small(w[1])?;
    let start = small(w[4])?;
    let end = small(w[5])?;
    let has_end = small(w[6])?;
    let scheme = small(w[7])?;
    let count = small(w[9])?;
    let total = small(w[10])?;
    if w[0] != U256::from(1) ||
        !(1..=3).contains(&kind) ||
        w[2].is_zero() ||
        w[8].is_zero() ||
        (kind == 1) != w[3].is_zero() ||
        !matches!(scheme, 1 | 2) ||
        !(1..=64).contains(&count) ||
        has_end > 1 ||
        (has_end == 0 && end != 0) ||
        (has_end == 1 && end <= start)
    {
        return Err(Error::Registry);
    }
    let mut members: Vec<Member> = Vec::with_capacity(count as usize);
    let mut sum = 0u64;
    for j in 0..count {
        let mut m = [[0u8; 32]; 8];
        for (f, dst) in m.iter_mut().enumerate() {
            *dst = read(r, member_slot(epoch, j, f as u64))?.to_be_bytes::<32>();
        }
        let len = small(U256::from_be_bytes(m[0]))? as usize;
        if !(1..=128).contains(&len) {
            return Err(Error::Registry);
        }
        let mut id_bytes = [0; 128];
        for i in 0..4 {
            id_bytes[i * 32..(i + 1) * 32].copy_from_slice(&m[i + 1]);
        }
        if id_bytes[len..].iter().any(|b| *b != 0) || m[6][1..].iter().any(|b| *b != 0) {
            return Err(Error::Registry);
        }
        let id = core::str::from_utf8(&id_bytes[..len]).map_err(|_| Error::Registry)?.to_owned();
        let mut key = [0u8; 33];
        key[..32].copy_from_slice(&m[5]);
        key[32] = m[6][0];
        let key = PublicKey::from_slice(&key).map_err(|_| Error::Registry)?;
        let weight = small(U256::from_be_bytes(m[7]))?;
        if weight == 0 ||
            members.last().is_some_and(|prev| prev.id >= id) ||
            members.iter().any(|prev| prev.key == key)
        {
            return Err(Error::Registry);
        }
        sum = sum.checked_add(weight).ok_or(Error::Registry)?;
        members.push(Member { id, key, weight });
    }
    if sum != total {
        return Err(Error::Registry);
    }
    Ok(Some(Entry { start, end: (has_end == 1).then_some(end), total, members }))
}
