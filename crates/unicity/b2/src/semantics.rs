use crate::{
    cbor::{self, array, bytes, tag, uint, Item},
    hash, Error as E, Leaf, Outcome, Result,
};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature, SigningKey, VerifyingKey,
};

struct Cfg<'a> {
    raw: &'a [u8],
    network: u64,
    chain: u64,
    vault: &'a [u8],
    ty: &'a [u8],
    aid: &'a [u8],
}
impl<'a> Cfg<'a> {
    fn parse(it: Item<'a>) -> Result<Self> {
        let a = it.array::<16>()?;
        if a[0].blob(32)? != b"UNICITY_BR_CFG" {
            return Err(E::CfgMismatch);
        }
        let network = a[1].uint(65535)?;
        a[2].bytes(32)?;
        let chain = a[3].uint(u64::MAX)?;
        a[4].bytes(32)?;
        a[5].uint(u64::from(u32::MAX))?;
        let shard = a[6].blob(33)?;
        if shard.is_empty() || shard.last() == Some(&0) || (shard.len() == 33 && shard[32] != 0x80)
        {
            return Err(E::CfgMismatch);
        }
        let vault = a[7].bytes(20)?;
        if vault == [0; 20] || a[8].bytes(20)? != [0; 20] {
            return Err(E::CfgMismatch);
        }
        let ty = a[9].bytes(32)?;
        let aid = a[10].bytes(32)?;
        for i in [11, 13, 14, 15] {
            a[i].bytes(32)?;
        }
        a[12].bytes(20)?;
        let mut d = format!("{network}:");
        for b in a[2].data {
            use core::fmt::Write;
            write!(&mut d, "{b:02x}").expect("String write");
        }
        d.push(':');
        for b in a[4].data {
            use core::fmt::Write;
            write!(&mut d, "{b:02x}").expect("String write");
        }
        d.push_str(&format!(":{chain}:0000000000000000000000000000000000000000"));
        if ty != hash(format!("unicity-bridge:unicity-native:{d}").as_bytes()) ||
            aid != hash(format!("unicity-bridge-coin:unicity-native:{d}").as_bytes())
        {
            return Err(E::CfgMismatch);
        }
        Ok(Self { raw: it.raw, network, chain, vault, ty, aid })
    }
}
fn amount(it: Item<'_>) -> Result<&[u8]> {
    let b = it.blob(crate::MAX_HISTORY)?;
    if b.is_empty() || b.len() > 32 || b[0] == 0 {
        return Err(E::IntRange);
    }
    Ok(b)
}
fn deadline(it: Item<'_>) -> Result<Option<u64>> {
    if it.null() {
        return Ok(None);
    }
    let e = it.uint(u64::MAX).map_err(|_| E::Deadline)?;
    if e == 0 {
        return Err(E::Deadline);
    }
    Ok(Some(e))
}
fn predicate(it: Item<'_>) -> Result<(u8, &[u8])> {
    let a = it.tagged::<3>(39032, 1)?;
    let code = a[1].blob(1)?;
    let params = a[2].blob(33)?;
    match code {
        [1] if params.len() == 33 && matches!(params[0], 2 | 3) => Ok((1, params)),
        [2] if params.len() == 32 => Ok((2, params)),
        _ => Err(E::Predicate),
    }
}
fn key(params: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(params).map_err(|_| E::Predicate)
}
fn signature_pred(key: &VerifyingKey) -> Vec<u8> {
    tag(39032, &array(&[&uint(1), &bytes(&[1]), &bytes(key.to_encoded_point(true).as_bytes())]))
}
fn hash_array(parts: &[&[u8]]) -> [u8; 32] {
    hash(&array(parts))
}
fn derive(cfg: &Cfg<'_>, n: u64, amt: &[u8], p: Item<'_>) -> Result<Outcome> {
    if n == 0 {
        return Err(E::LockInput);
    }
    let (typ, params) = predicate(p)?;
    if typ != 1 {
        return Err(E::Predicate);
    }
    key(params)?;
    let ch = hash(cfg.raw);
    let salt = hash_array(&[&bytes(b"UNICITY_BR_SALT"), &bytes(&ch), &uint(n)]);
    let id = hash_array(&[&bytes(&salt), &uint(cfg.network)]);
    let first = hash(p.raw);
    let k = array(&[
        &bytes(&[0; 20]),
        &bytes(cfg.ty),
        &bytes(cfg.aid),
        &bytes(amt),
        &bytes(&id),
        &bytes(&first),
    ]);
    let d = hash_array(&[&bytes(b"UNICITY_BR_LOCK"), &bytes(&ch), &uint(n), &k]);
    if d == [0; 32] {
        return Err(E::ZeroDigest);
    }
    let mut amount = [0; 32];
    amount[32 - amt.len()..].copy_from_slice(amt);
    Ok(Outcome {
        cfg: ch,
        nonce: n,
        amount,
        token_id: id,
        salt,
        first_predicate_hash: first,
        lock_digest: d,
        ..Default::default()
    })
}

// This only parses the immutable witness, bounds it and binds its cfg. Authority,
// UC trees, header and Ethereum MPT verification belong to offline issuance, not
// the pure 0x0104 kernel. Return composition compares the permanent on-chain lock.
const fn preserve_budget(e: E, fallback: E) -> E {
    if matches!(e, E::TooManyItems | E::TooDeep | E::ProofTooLarge | E::InputTooLarge) {
        e
    } else {
        fallback
    }
}
fn proof_blob(it: Item<'_>, max: usize) -> Result<&[u8]> {
    let b = it.blob(max).map_err(|e| {
        if e == E::ProofTooLarge {
            E::LockProofTooLarge
        } else {
            E::LockProofShape
        }
    })?;
    if b.is_empty() {
        return Err(E::LockProofShape);
    }
    Ok(b)
}
fn justification(cfg: &Cfg<'_>, b: &[u8], tokens: &mut usize) -> Result<u64> {
    if b.len() > 65536 {
        return Err(E::JustificationTooLarge);
    }
    let j = cbor::one(b, tokens)
        .and_then(|it| it.tagged::<6>(39049, 2))
        .map_err(|e| preserve_budget(e, E::MintJustif))?;
    let n = (|| {
        if j[1].uint(u64::MAX)? != cfg.chain ||
            j[2].bytes(20)? != cfg.vault ||
            j[3].bytes(20)? != [0; 20]
        {
            return Err(E::MintJustif);
        }
        let n = j[4].uint(u64::MAX)?;
        if n == 0 {
            return Err(E::MintJustif);
        }
        Ok(n)
    })()
    .map_err(|_| E::MintJustif)?;
    let p = j[5].array::<8>().map_err(|_| E::LockProofShape)?;
    if p[0].uint(u64::MAX).map_err(|_| E::LockProofShape)? != 1 {
        return Err(E::LockProofShape);
    }
    if p[1].bytes(32).map_err(|_| E::LockProofShape)? != hash(cfg.raw) {
        return Err(E::LockProofCfg);
    }
    p[2].bytes(32).map_err(|_| E::LockProofShape)?; // opaque trustBaseId; no authority installed here
    proof_blob(p[3], 16384)?;
    proof_blob(p[4], 16384)?;
    proof_blob(p[5], 2048)?;
    let mut total = 0;
    for trie in &p[6..8] {
        let count = trie.count(65).map_err(|e| {
            if e == E::TooManyTx {
                E::LockProofTooLarge
            } else {
                E::LockProofShape
            }
        })?;
        if count == 0 {
            return Err(E::LockProofShape);
        }
        for node in trie.children() {
            total += proof_blob(node, 1024)?.len();
        }
    }
    if total > 24576 {
        return Err(E::LockProofTooLarge);
    }
    Ok(n)
}
fn mint_data<'a>(cfg: &Cfg<'_>, b: &'a [u8], tokens: &mut usize) -> Result<&'a [u8]> {
    (|| {
        let d = cbor::one(b, tokens)?.tagged::<3>(39050, 1)?;
        let a = d[1].array::<1>()?[0].array::<2>()?;
        if a[0].bytes(32)? != cfg.aid || !d[2].null() {
            return Err(E::MintData);
        }
        amount(a[1])
    })()
    .map_err(|e| preserve_budget(e, E::MintData))
}
struct Tx<'a> {
    raw: &'a [u8],
    pred: Item<'a>,
    mask: &'a [u8],
    data: Option<&'a [u8]>,
    e: Option<u64>,
}
struct Cd<'a> {
    pred: Item<'a>,
    source: &'a [u8],
    tx: &'a [u8],
    e: Option<u64>,
    unlock: &'a [u8],
}
fn cd(it: Item<'_>) -> Result<Cd<'_>> {
    let a = it.tagged::<6>(39031, 2)?;
    predicate(a[1])?;
    Ok(Cd {
        pred: a[1],
        source: a[2].bytes(32)?,
        tx: a[3].bytes(32)?,
        e: deadline(a[4])?,
        unlock: a[5].blob(65)?,
    })
}
fn transfer(it: Item<'_>) -> Result<Tx<'_>> {
    let a = it.tagged::<5>(39045, 2)?;
    predicate(a[1])?;
    Ok(Tx {
        raw: it.raw,
        pred: a[1],
        mask: a[2].bytes(32)?,
        data: if a[3].null() { None } else { Some(a[3].blob(crate::MAX_HISTORY)?) },
        e: deadline(a[4])?,
    })
}
fn unlock(k: &VerifyingKey, source: &[u8], tx: &[u8], u: &[u8]) -> Result<()> {
    if u.len() != 65 {
        return Err(E::UnlockLength);
    }
    let sig = Signature::from_slice(&u[..64]).map_err(|_| E::UnlockScalars)?;
    if sig.normalize_s().is_some() {
        return Err(E::UnlockScalars);
    }
    let rid = RecoveryId::from_byte(u[64]).ok_or(E::UnlockRecovery)?;
    let msg = hash_array(&[&bytes(source), &bytes(tx)]);
    let recovered =
        VerifyingKey::recover_from_prehash(&msg, &sig, rid).map_err(|_| E::UnlockKey)?;
    if recovered != *k {
        return Err(E::UnlockKey);
    }
    k.verify_prehash(&msg, &sig).map_err(|_| E::Unlock)
}
#[allow(clippy::too_many_arguments)]
fn step(
    pred: &[u8],
    source: &[u8; 32],
    raw: &[u8],
    e: Option<u64>,
    cd: &Cd<'_>,
    t: u64,
    k: &VerifyingKey,
    seen: &mut Vec<[u8; 32]>,
) -> Result<Leaf> {
    let th = hash(raw);
    if cd.pred.raw != pred || cd.source != source || cd.tx != th {
        return Err(E::CDMismatch);
    }
    if cd.e != e {
        return Err(E::DeadlineMismatch);
    }
    if e.is_some_and(|e| t >= e) {
        return Err(E::DeadlineExpired);
    }
    unlock(k, source, &th, cd.unlock)?;
    let sid = hash_array(&[pred, &bytes(source)]);
    insert_sid(seen, sid)?;
    Ok(Leaf { sid, tx_hash: th, reference_time: t, value: hash_array(&[&bytes(&th), &uint(t)]) })
}
fn insert_sid(seen: &mut Vec<[u8; 32]>, sid: [u8; 32]) -> Result<()> {
    if seen.contains(&sid) {
        return Err(E::RepeatedSID);
    }
    seen.push(sid);
    Ok(())
}
fn output_state(source: &[u8; 32], mask: &[u8]) -> [u8; 32] {
    let mut imprint = [0; 34];
    imprint[2..].copy_from_slice(source);
    hash_array(&[&bytes(&imprint), &bytes(mask)])
}
fn burn_inner(cfg: &Cfg<'_>, out: &mut Outcome, tx: &Tx<'_>, tokens: &mut usize) -> Result<()> {
    let (typ, params) = predicate(tx.pred)?;
    if typ != 2 {
        return Err(E::NotBurn);
    }
    let data = tx.data.ok_or(E::ReturnData)?;
    let r = cbor::one(data, tokens)?.tagged::<11>(39048, 1)?;
    if r[1].uint(u64::MAX)? != cfg.chain ||
        r[2].bytes(20)? != cfg.vault ||
        r[3].bytes(20)? != [0; 20] ||
        r[4].bytes(32)? != cfg.ty ||
        r[5].bytes(32)? != cfg.aid ||
        r[8].bytes(20)? != [0; 20] ||
        !r[9].bytes(0)?.is_empty() ||
        r[10].uint(u64::MAX)? != 0
    {
        return Err(E::ReturnData);
    }
    let a = amount(r[7])?;
    let mut aw = [0; 32];
    aw[32 - a.len()..].copy_from_slice(a);
    if aw != out.amount {
        return Err(E::ReturnAmount);
    }
    let to = r[6].bytes(20)?;
    if to == [0; 20] || to == cfg.vault {
        return Err(E::ReturnRecip);
    }
    if params != hash(data) {
        return Err(E::BurnReason);
    }
    out.release_to.copy_from_slice(to);
    Ok(())
}
fn burn(cfg: &Cfg<'_>, out: &mut Outcome, tx: &Tx<'_>, tokens: &mut usize) -> Result<()> {
    burn_inner(cfg, out, tx, tokens).map_err(|e| {
        if e.is_invalid() {
            e
        } else {
            preserve_budget(e, E::ReturnData)
        }
    })
}
pub(crate) fn evaluate(
    op: u8,
    cfg: Item<'_>,
    payload: Item<'_>,
    tokens: &mut usize,
) -> Result<Outcome> {
    let cfg = Cfg::parse(cfg)?;
    if op == 0 {
        let a = payload.array::<3>()?;
        return derive(&cfg, a[0].uint(u64::MAX)?, amount(a[1])?, a[2]);
    }
    let h = payload.array::<2>()?;
    let g = h[0].array::<3>()?;
    let count = h[1].count(crate::MAX_TRANSFERS)?;
    if op == 1 && count != 0 {
        return Err(E::HasTransfers);
    }
    if op == 2 && count == 0 {
        return Err(E::NoTransfers);
    }
    let m = g[0].tagged::<8>(39041, 2)?;
    let network = m[1].uint(65535)?;
    predicate(m[2])?;
    m[3].bytes(32)?;
    m[4].bytes(32)?;
    let j = m[5].blob(65536).map_err(|e| {
        if e == E::ProofTooLarge {
            E::JustificationTooLarge
        } else {
            E::MintJustif
        }
    })?;
    let d = m[6].blob(crate::MAX_HISTORY).map_err(|e| preserve_budget(e, E::MintData))?;
    let e = deadline(m[7])?;
    let cd0 = cd(g[1])?;
    let t0 = g[2].uint(u64::MAX)?;
    // Validate every tuple and embedded CBOR, including malformed-last input,
    // before minter derivation or any signature recovery.
    let n = justification(&cfg, j, tokens)?;
    let amt = mint_data(&cfg, d, tokens)?;
    let mut transfers = Vec::with_capacity(count as usize);
    for tuple in h[1].children() {
        let a = tuple.array::<3>()?;
        let tx = transfer(a[0])?;
        let cert = cd(a[1])?;
        let t = a[2].uint(u64::MAX)?;
        if let Some(data) = tx.data {
            cbor::one(data, tokens)?;
        }
        transfers.push((tx, cert, t));
    }
    if network != cfg.network {
        return Err(E::MintShape);
    }
    if m[4].data != cfg.ty {
        return Err(E::MintType);
    }
    let mut out = derive(&cfg, n, amt, m[2])?;
    if m[3].data != out.salt {
        return Err(E::MintSalt);
    }
    let secret = hash_array(&[&bytes(b"I_AM_UNIVERSAL_MINTER_FOR_"), &bytes(&out.token_id)]);
    let mk = SigningKey::from_slice(&secret).map_err(|_| E::MinterKey)?;
    let mp = signature_pred(mk.verifying_key());
    let source = hash_array(&[&bytes(&out.token_id), &bytes(&hash(b"TOKENID"))]);
    let mut seen = Vec::with_capacity(count as usize + 1);
    out.leaves.push(step(&mp, &source, g[0].raw, e, &cd0, t0, mk.verifying_key(), &mut seen)?);
    let mut state = output_state(&source, &out.token_id);
    let mut owner = m[2];
    for (i, (tx, cert, t)) in transfers.iter().enumerate() {
        let (_, params) = predicate(owner)?;
        let k = key(params)?;
        let leaf = step(owner.raw, &state, tx.raw, tx.e, cert, *t, &k, &mut seen)?;
        if i + 1 == transfers.len() {
            burn(&cfg, &mut out, tx, tokens)?;
            let btid = hash_array(&[
                &bytes(b"unicity-burn-transition:v1"),
                &bytes(&leaf.sid),
                &bytes(&leaf.tx_hash),
            ]);
            out.nullifier =
                hash_array(&[&bytes(b"UNICITY_BR_NUL"), &bytes(&out.cfg), &bytes(&btid)]);
            if out.nullifier == [0; 32] {
                return Err(E::ZeroDigest);
            }
        } else {
            let (typ, p) = predicate(tx.pred)?;
            if typ != 1 {
                return Err(E::BurnNotFinal);
            }
            key(p)?;
            if tx.data.is_some() {
                return Err(E::TransferData);
            }
        }
        out.leaves.push(leaf);
        state = output_state(&state, tx.mask);
        owner = tx.pred;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_sid_is_exact_error() {
        let mut seen = Vec::new();
        assert_eq!(insert_sid(&mut seen, [1; 32]), Ok(()));
        assert_eq!(insert_sid(&mut seen, [1; 32]), Err(E::RepeatedSID));
        assert_eq!(insert_sid(&mut seen, [2; 32]), Ok(()));
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::*;
    #[test]
    fn recovery_ids_two_three_require_and_accept_actual_matching_key() {
        // x = n+r must fit the curve field. Small r deliberately exercises the
        // rare overflow-x recovery branch; random signatures cannot cover it.
        let source = [3; 32];
        let th = [4; 32];
        let msg = hash_array(&[&bytes(&source), &bytes(&th)]);
        for id in [2, 3] {
            let mut found = false;
            for r in 1u8..100 {
                let mut u = [0; 65];
                u[31] = r;
                u[63] = 1;
                u[64] = id;
                let sig = Signature::from_slice(&u[..64]).unwrap();
                if let Ok(k) = VerifyingKey::recover_from_prehash(
                    &msg,
                    &sig,
                    RecoveryId::from_byte(id).unwrap(),
                ) {
                    assert_eq!(unlock(&k, &source, &th, &u), Ok(()));
                    u[64] ^= 1;
                    assert_eq!(unlock(&k, &source, &th, &u), Err(E::UnlockKey));
                    found = true;
                    break;
                }
            }
            assert!(found, "construct overflow-x point");
        }
    }
    #[test]
    fn scalars_zero_order_and_high_s_are_rejected() {
        let k = SigningKey::from_slice(&[9; 32]).unwrap();
        let source = [3; 32];
        let th = [4; 32];
        let msg = hash_array(&[&bytes(&source), &bytes(&th)]);
        let (sig, id) = k.sign_prehash_recoverable(&msg).unwrap();
        let mut u = [0; 65];
        u[..64].copy_from_slice(&sig.to_bytes());
        u[64] = id.to_byte();
        assert_eq!(unlock(k.verifying_key(), &source, &th, &u), Ok(()));
        let order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut high = u;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let n = i16::from(order[i]) - i16::from(u[32 + i]) - borrow;
            high[32 + i] = n as u8;
            borrow = i16::from(n < 0);
        }
        high[64] ^= 1;
        assert_eq!(unlock(k.verifying_key(), &source, &th, &high), Err(E::UnlockScalars));
        for off in [0, 32] {
            let mut bad = u;
            bad[off..off + 32].fill(0);
            assert_eq!(unlock(k.verifying_key(), &source, &th, &bad), Err(E::UnlockScalars));
            bad[off..off + 32].copy_from_slice(&order);
            assert_eq!(unlock(k.verifying_key(), &source, &th, &bad), Err(E::UnlockScalars));
        }
    }
}
