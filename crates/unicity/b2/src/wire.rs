//! Canonical ABI framing, staged debit and bounded borrowed preflight.
use crate::{
    cfg::Cfg,
    error::{BridgeError as E, Family},
    history::{prepare_lock, verify_mint, verify_return, Outcome},
    limits::*,
};
use reth_unicity_b1::cbor::Item;

/// Reserved 0x0104 address; no registration or activation occurs here.
pub const fn address() -> [u8; 20] {
    let mut address = [0; 20];
    address[18] = 1;
    address[19] = 4;
    address
}

/// Exceptional failure, with no ABI success result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid framing or encoding, carrying the exact profile reason.
    Malformed(E),
    /// A finite direct-verification ceiling, never a semantic-invalid verdict.
    BudgetExceeded(E),
    /// Gas insufficient at either debit, before expensive work.
    OutOfGas,
}

/// Stateless call result. A false relation pays the same complete candidate gas.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    /// Provisional full charge, independent of verdict.
    pub gas: u64,
    /// Canonical ABI marker, validity and Result tuple.
    pub bytes: Vec<u8>,
    /// Exact diagnostic for a shaped false result; not part of the ABI.
    pub reason: Option<E>,
}

const fn classify(e: E) -> Error {
    match e.family() {
        Family::Budget => Error::BudgetExceeded(e),
        _ => Error::Malformed(e),
    }
}

fn word(input: &[u8], offset: usize) -> Result<usize, Error> {
    let bytes = input.get(offset..offset + 32).ok_or(Error::Malformed(E::ABIFraming))?;
    // All wire lengths are bounded by 64 KiB; reject high limbs before conversion.
    if bytes[..24].iter().any(|b| *b != 0) {
        return Err(Error::Malformed(E::ABIFraming));
    }
    usize::try_from(u64::from_be_bytes(bytes[24..].try_into().expect("eight bytes")))
        .map_err(|_| Error::Malformed(E::ABIFraming))
}
fn blob(input: &[u8], offset: usize) -> Result<(&[u8], usize), Error> {
    let n = word(input, offset)?;
    let start = offset.checked_add(32).ok_or(Error::Malformed(E::ABIFraming))?;
    let end = start.checked_add(n).ok_or(Error::Malformed(E::ABIFraming))?;
    let padded = end.checked_add(31).ok_or(Error::Malformed(E::ABIFraming))? / 32 * 32;
    let bytes = input.get(start..end).ok_or(Error::Malformed(E::ABIFraming))?;
    let padding = input.get(end..padded).ok_or(Error::Malformed(E::ABIFraming))?;
    if padding.iter().any(|b| *b != 0) {
        return Err(Error::Malformed(E::ABIFraming));
    }
    Ok((bytes, padded))
}

fn scan<'a>(bytes: &'a [u8], tokens: &mut usize) -> Result<Item<'a>, E> {
    crate::scan::scan_shared(bytes, tokens).map(|i| i.0)
}
fn array<const N: usize>(item: Item<'_>) -> Result<[Item<'_>; N], Error> {
    item.array().map_err(|_| Error::Malformed(E::Shape))
}
// Embedded justification/data are semantic payloads, not automatically accepted
// CBOR. Scan their whole tree now for cumulative resource ceilings. Encoding
// failures are left to the exact profile relation (MintJustif/MintData/ReturnData).
fn embedded(item: Item<'_>, tokens: &mut usize) -> Result<(), Error> {
    if item.major == 2 &&
        let Err(e) = scan(item.data, tokens) &&
        e.family() == Family::Budget
    {
        return Err(classify(e));
    }
    Ok(())
}
fn preflight(op: usize, cfg: &[u8], payload: &[u8]) -> Result<usize, Error> {
    let mut tokens = 0;
    scan(cfg, &mut tokens).map_err(classify)?;
    let root = scan(payload, &mut tokens).map_err(classify)?;
    if op == 0 {
        array::<3>(root)?;
        return Ok(0);
    }
    let [mint_pair, transfers] = array::<2>(root)?;
    let [mint, _] = array::<2>(mint_pair)?;
    if transfers.major != 4 {
        return Err(Error::Malformed(E::Shape));
    }
    if transfers.arg > MAX_TRANSFERS as u64 {
        return Err(Error::BudgetExceeded(E::TooManyTx));
    }
    // Scan all embedded bytes before an earlier false predicate can mask a cap.
    if mint.major == 6 &&
        let Some(content) = mint.children().next() &&
        let Ok(fields) = content.array::<7>()
    {
        embedded(fields[5], &mut tokens)?;
        embedded(fields[6], &mut tokens)?;
    }
    for pair in transfers.children() {
        let [tx, _] = array::<2>(pair)?;
        if tx.major == 6 &&
            let Some(content) = tx.children().next() &&
            let Ok(fields) = content.array::<4>()
        {
            embedded(fields[3], &mut tokens)?;
        }
    }
    Ok(transfers.arg as usize + 1)
}

/// Run canonical `abi.encode(uint8 operation,bytes Cfg,bytes payload)`.
/// Reserve `20000+16*input.len()` before bounded scanning and the remaining
/// `6000+13000*leaves` before allocations, hashing or secp256k1 operations.
/// Outer malformed CBOR/ABI halts; unsupported or false relations return the
/// marker and false with an entirely zero/empty Result. All caps are provisional.
pub fn run(input: &[u8], gas: u64) -> Result<Output, Error> {
    if input.len() > MAX_SEMANTIC_BYTES {
        return Err(Error::BudgetExceeded(E::InputTooLarge));
    }
    let base = 20000 + 16 * input.len() as u64;
    if gas < base {
        return Err(Error::OutOfGas);
    }
    let op = word(input, 0)?;
    if op > 2 {
        return Err(Error::Malformed(E::BadOperation));
    }
    if word(input, 32)? != 96 {
        return Err(Error::Malformed(E::ABIFraming));
    }
    let (cfg_bytes, next) = blob(input, 96)?;
    if word(input, 64)? != next {
        return Err(Error::Malformed(E::ABIFraming));
    }
    let (payload, end) = blob(input, next)?;
    if end != input.len() {
        return Err(Error::Malformed(E::ABIFraming));
    }
    let leaves = preflight(op, cfg_bytes, payload)?;
    let charge = base + 6000 + 13000 * leaves as u64;
    if gas < charge {
        return Err(Error::OutOfGas);
    }
    let cfg = Cfg::from_bytes(cfg_bytes).map_err(classify)?;
    let result = match op {
        0 => {
            let root = crate::scan::scan_one(payload).map_err(classify)?;
            let fields = root.array::<3>().map_err(classify)?;
            let n = fields[0].uint_max(u64::MAX).map_err(classify)?;
            let amount = fields[1].bytes().map_err(classify)?;
            prepare_lock(&cfg, n, amount, fields[2].raw(payload))
        }
        1 => verify_mint(&cfg, payload),
        _ => verify_return(&cfg, payload),
    };
    match result {
        Ok(out) => Ok(Output { gas: charge, bytes: encode_result(Some(&out)), reason: None }),
        Err(e) if e.family() == Family::Invalid => {
            Ok(Output { gas: charge, bytes: encode_result(None), reason: Some(e) })
        }
        Err(e) => Err(classify(e)),
    }
}

fn push_word(bytes: &mut Vec<u8>, n: u64) {
    bytes.extend_from_slice(&[0; 24]);
    bytes.extend_from_slice(&n.to_be_bytes());
}
fn push_padded(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.resize(bytes.len() + 32 - value.len(), 0);
    bytes.extend_from_slice(value);
}
fn encode_result(out: Option<&Outcome>) -> Vec<u8> {
    let count = out.map_or(0, |o| o.leaves.len());
    let mut bytes = Vec::with_capacity(448 + count * 64);
    let mut marker = [0; 32];
    marker[..23].copy_from_slice(b"UNICITY_TOKEN_SEMANTICS");
    bytes.extend_from_slice(&marker);
    push_word(&mut bytes, u64::from(out.is_some()));
    push_word(&mut bytes, 96); // Result is dynamic.
    if let Some(o) = out {
        bytes.extend_from_slice(&o.cfg);
        push_word(&mut bytes, o.nonce);
        push_padded(&mut bytes, &o.amount);
        bytes.extend_from_slice(&o.token_id);
        bytes.extend_from_slice(&o.salt);
        bytes.extend_from_slice(&o.first_predicate_hash);
        bytes.extend_from_slice(&o.lock_digest);
        push_padded(&mut bytes, &o.release_to);
        bytes.extend_from_slice(&o.nullifier);
    } else {
        bytes.resize(bytes.len() + 9 * 32, 0);
    }
    push_word(&mut bytes, 320); // leaves relative to Result.
    push_word(&mut bytes, count as u64);
    if let Some(o) = out {
        for (sid, tx) in &o.leaves {
            bytes.extend_from_slice(sid);
            bytes.extend_from_slice(tx);
        }
    }
    bytes
}
