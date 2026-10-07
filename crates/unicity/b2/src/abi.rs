use crate::{Error, Outcome, Result, MAX_HISTORY};

pub(crate) struct Call<'a> {
    pub op: u8,
    pub cfg: &'a [u8],
    pub payload: &'a [u8],
}
fn number(b: &[u8], at: usize) -> Result<usize> {
    let w = b.get(at..at.checked_add(32).ok_or(Error::ABIFraming)?).ok_or(Error::ABIFraming)?;
    if w[..24].iter().any(|x| *x != 0) {
        return Err(Error::ABIFraming);
    }
    usize::try_from(u64::from_be_bytes(w[24..].try_into().expect("word")))
        .map_err(|_| Error::ABIFraming)
}
fn blob(b: &[u8], off: usize) -> Result<(&[u8], usize)> {
    let n = number(b, off)?;
    let start = off.checked_add(32).ok_or(Error::ABIFraming)?;
    let end = start.checked_add(n).ok_or(Error::ABIFraming)?;
    let padded = end.checked_add(31).ok_or(Error::ABIFraming)? / 32 * 32;
    let data = b.get(start..end).ok_or(Error::ABIFraming)?;
    let padding = b.get(end..padded).ok_or(Error::ABIFraming)?;
    if padding.iter().any(|v| *v != 0) {
        return Err(Error::ABIFraming);
    }
    Ok((data, padded))
}
pub(crate) fn decode(b: &[u8]) -> Result<Call<'_>> {
    let op = number(b, 0)?;
    if op > 255 {
        return Err(Error::ABIFraming);
    }
    if op > 2 {
        return Err(Error::BadOperation);
    }
    if number(b, 32)? != 96 {
        return Err(Error::ABIFraming);
    }
    let (cfg, end) = blob(b, 96)?;
    if number(b, 64)? != end {
        return Err(Error::ABIFraming);
    }
    let (payload, end) = blob(b, end)?;
    if end != b.len() {
        return Err(Error::ABIFraming);
    }
    if payload.len() > MAX_HISTORY || cfg.len() > 1024 {
        return Err(Error::InputTooLarge);
    }
    Ok(Call { op: op as u8, cfg, payload })
}
pub(crate) fn word(n: u64) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
pub(crate) fn encode(valid: bool, out: &Outcome) -> Vec<u8> {
    let mut b = vec![0; 448 + 128 * out.leaves.len()];
    b[..23].copy_from_slice(b"UNICITY_TOKEN_SEMANTICS");
    b[63] = u8::from(valid);
    b[64..96].copy_from_slice(&word(96));
    for (i, w) in [
        out.cfg,
        word(out.nonce),
        out.amount,
        out.token_id,
        out.salt,
        out.first_predicate_hash,
        out.lock_digest,
    ]
    .iter()
    .enumerate()
    {
        b[96 + i * 32..128 + i * 32].copy_from_slice(w);
    }
    b[332..352].copy_from_slice(&out.release_to);
    b[352..384].copy_from_slice(&out.nullifier);
    b[384..416].copy_from_slice(&word(320));
    b[416..448].copy_from_slice(&word(out.leaves.len() as u64));
    for (i, leaf) in out.leaves.iter().enumerate() {
        let off = 448 + i * 128;
        b[off..off + 32].copy_from_slice(&leaf.sid);
        b[off + 32..off + 64].copy_from_slice(&leaf.tx_hash);
        b[off + 64..off + 96].copy_from_slice(&word(leaf.reference_time));
        b[off + 96..off + 128].copy_from_slice(&leaf.value);
    }
    b
}
