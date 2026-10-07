//! The compact history projection `C([M,CD0],[[T1,CD1],...])` and the pure
//! token-semantics relation: prepare-lock, mint and return.
//!
//! The relation reconstructs every source state and owner, checks byte equality
//! with each certification data item, recomputes the transaction hash and sid,
//! validates each unlock by recovery equality and exports every leaf
//! obligation. It does not check inclusion, the lock's existence or aggregator
//! admission.

use std::{collections::BTreeSet, vec::Vec};

use secp256k1::{PublicKey, SecretKey, SECP256K1};

use super::{
    cfg::*,
    error::{BridgeError as E, Result},
    h,
    limits::*,
    scan::{scan_one, Item},
    unlock::{parse_key, verify_unlock},
};
use crate::encode::{encode_array, encode_byte_string, encode_tag, encode_uint};

/// An admitted predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pred {
    pub(crate) typ: u8,
    pub(crate) params: Vec<u8>,
}

impl Pred {
    /// `tag(39032,[1,b(encode_uint(type)),b(params)])`.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        encode_tag(
            TAG_PREDICATE,
            &encode_array(&[
                &encode_uint(1),
                &encode_byte_string(&encode_uint(self.typ as u64)),
                &encode_byte_string(&self.params),
            ]),
        )
    }
    pub(crate) fn signature(key33: &[u8]) -> Self {
        Self { typ: PRED_SIGNATURE, params: key33.to_vec() }
    }
}

fn decode_predicate(it: &Item<'_>) -> Result<Pred> {
    let c = it.tag_content(TAG_PREDICATE)?;
    let k = c.array::<3>().map_err(|_| E::Shape)?;
    if k[0].uint_max(u64::MAX)? != 1 {
        return Err(E::Predicate);
    }
    let code = k[1].bytes()?;
    let params = k[2].bytes()?;
    if code.len() != 1 || (code[0] != PRED_SIGNATURE && code[0] != PRED_BURN) {
        return Err(E::Predicate);
    }
    match code[0] {
        PRED_SIGNATURE => {
            parse_key(params)?;
        }
        _ => {
            if params.len() != 32 {
                return Err(E::Predicate);
            }
        }
    }
    Ok(Pred { typ: code[0], params: params.to_vec() })
}

/// Decoded mint transaction.
#[derive(Debug, Clone)]
pub(crate) struct Mint {
    pub(crate) network: u16,
    pub(crate) recipient: Pred,
    pub(crate) salt: [u8; 32],
    pub(crate) ty: [u8; 32],
    pub(crate) justification: Option<Vec<u8>>,
    pub(crate) data: Option<Vec<u8>>,
}

/// Decoded transfer transaction.
#[derive(Debug, Clone)]
pub(crate) struct Transfer {
    pub(crate) recipient: Pred,
    pub(crate) mask: [u8; 32],
    pub(crate) data: Option<Vec<u8>>,
}

/// Decoded certification data.
#[derive(Debug, Clone)]
pub(crate) struct Cd {
    pub(crate) source: Pred,
    pub(crate) source_hash: [u8; 32],
    pub(crate) tx_hash: [u8; 32],
    pub(crate) unlock: Vec<u8>,
}

fn nullable(it: &Item<'_>) -> Result<Option<Vec<u8>>> {
    if it.0.null() {
        Ok(None)
    } else {
        Ok(Some(it.bytes()?.to_vec()))
    }
}

fn fixed<const N: usize>(it: &Item<'_>) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(it.bytes_n(N)?);
    Ok(out)
}

fn decode_cd(it: &Item<'_>) -> Result<Cd> {
    let c = it.tag_content(TAG_CERTIFICATION)?;
    let k = c.array::<5>().map_err(|_| E::Shape)?;
    k[0].version()?;
    let source = decode_predicate(&k[1])?;
    Ok(Cd {
        source,
        source_hash: fixed(&k[2])?,
        tx_hash: fixed(&k[3])?,
        unlock: k[4].bytes().map_err(|_| E::Shape)?.to_vec(),
    })
}

fn decode_mint(it: &Item<'_>) -> Result<Mint> {
    let c = it.tag_content(TAG_MINT)?;
    let k = c.array::<7>().map_err(|_| E::Shape)?;
    k[0].version()?;
    Ok(Mint {
        network: k[1].uint_max(0xffff)? as u16,
        recipient: decode_predicate(&k[2])?,
        salt: fixed(&k[3])?,
        ty: fixed(&k[4])?,
        justification: nullable(&k[5])?,
        data: nullable(&k[6])?,
    })
}

fn decode_transfer(it: &Item<'_>) -> Result<Transfer> {
    let c = it.tag_content(TAG_TRANSFER)?;
    let k = c.array::<4>().map_err(|_| E::Shape)?;
    k[0].version()?;
    Ok(Transfer {
        recipient: decode_predicate(&k[1])?,
        mask: fixed(&k[2])?,
        data: nullable(&k[3])?,
    })
}

/// A decoded history with the raw transaction encodings its hashes cover.
#[derive(Debug, Clone)]
pub(crate) struct History {
    pub(crate) mint: Mint,
    pub(crate) mint_cd: Cd,
    pub(crate) transfers: Vec<Transfer>,
    pub(crate) cds: Vec<Cd>,
    mint_raw: Vec<u8>,
    transfers_raw: Vec<Vec<u8>>,
}

impl History {
    /// Strictly decode a history; the transfer count is bounded before any
    /// transfer is decoded.
    pub(crate) fn decode(b: &[u8]) -> Result<Self> {
        let root = scan_one(b)?;
        let k = root.array::<2>().map_err(|_| E::Shape)?;
        let head = k[0].array::<2>().map_err(|_| E::Shape)?;
        let list = k[1].any_array()?;
        let mint = decode_mint(&head[0])?;
        let mint_raw = head[0].raw(b).to_vec();
        let mint_cd = decode_cd(&head[1])?;
        let (mut transfers, mut cds, mut transfers_raw) = (Vec::new(), Vec::new(), Vec::new());
        for p in list {
            let pair = Item(p).array::<2>().map_err(|_| E::Shape)?;
            transfers.push(decode_transfer(&pair[0])?);
            cds.push(decode_cd(&pair[1])?);
            transfers_raw.push(pair[0].raw(b).to_vec());
        }
        Ok(Self { mint, mint_cd, transfers, cds, mint_raw, transfers_raw })
    }
}

/// A kernel result: `(cfg, nonce, amount, tokenId, salt, firstPredicateHash,
/// lockDigest, releaseTo, nullifier, Leaf[])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) cfg: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) amount: Vec<u8>,
    pub(crate) token_id: [u8; 32],
    pub(crate) salt: [u8; 32],
    pub(crate) first_predicate_hash: [u8; 32],
    pub(crate) lock_digest: [u8; 32],
    pub(crate) release_to: [u8; 20],
    pub(crate) nullifier: [u8; 32],
    /// `(sid, txHash)` per transaction, in order.
    pub(crate) leaves: Vec<([u8; 32], [u8; 32])>,
}

fn state_id(source: &Pred, source_hash: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[&source.to_bytes(), &encode_byte_string(source_hash)]))
}

fn result_state(source_hash: &[u8; 32], mask: &[u8]) -> [u8; 32] {
    let mut imprint = [0u8; 34];
    imprint[2..].copy_from_slice(source_hash);
    h(&encode_array(&[&encode_byte_string(&imprint), &encode_byte_string(mask)]))
}

fn mint_source_hash(id: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[&encode_byte_string(id), &encode_byte_string(&h(b"TOKENID"))]))
}

fn minter_key(id: &[u8; 32]) -> Result<SecretKey> {
    let k = h(&encode_array(&[
        &encode_byte_string(b"I_AM_UNIVERSAL_MINTER_FOR_"),
        &encode_byte_string(id),
    ]));
    minter_scalar(&k)
}

fn minter_scalar(k: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_byte_array(k).map_err(|_| E::MinterKey)
}
fn nonzero_digest(digest: &[u8; 32]) -> Result<()> {
    if *digest == [0; 32] {
        return Err(E::ZeroDigest);
    }
    Ok(())
}

const fn amount_ok(a: &[u8]) -> bool {
    !a.is_empty() && a.len() <= MAX_AMOUNT_BYTES && a[0] != 0
}

/// `prepareLock`: validate a lock request and derive the values the vault
/// compares with its own.
pub(crate) fn prepare_lock(cfg: &Cfg, n: u64, amount: &[u8], p0: &[u8]) -> Result<Outcome> {
    if n == 0 || !amount_ok(amount) {
        return Err(E::LockInput);
    }
    let root = scan_one(p0)?;
    let pred = decode_predicate(&root)?;
    if pred.typ != PRED_SIGNATURE {
        return Err(E::Predicate);
    }
    let ch = cfg.hash();
    let salt = derive_salt(&ch, n);
    let id = derive_token_id(&salt, cfg.network);
    let first = h(p0);
    let digest = lock_digest(
        &ch,
        n,
        &lock_record(&cfg.zero_address, &cfg.ty, &cfg.aid, amount, &id, &first),
    );
    nonzero_digest(&digest)?;
    Ok(Outcome {
        cfg: ch,
        nonce: n,
        amount: amount.to_vec(),
        token_id: id,
        salt,
        first_predicate_hash: first,
        lock_digest: digest,
        release_to: [0; 20],
        nullifier: [0; 32],
        leaves: Vec::new(),
    })
}

/// The mint operation: the history must hold zero transfers.
pub(crate) fn verify_mint(cfg: &Cfg, history: &[u8]) -> Result<Outcome> {
    let h = History::decode(history)?;
    if !h.transfers.is_empty() {
        return Err(E::HasTransfers);
    }
    verify_history(cfg, &h)
}

/// The return operation: at least the final burn is required.
pub(crate) fn verify_return(cfg: &Cfg, history: &[u8]) -> Result<Outcome> {
    let h = History::decode(history)?;
    if h.transfers.is_empty() {
        return Err(E::NoTransfers);
    }
    verify_history(cfg, &h)
}

fn parse_justification(cfg: &Cfg, j: Option<&[u8]>) -> Result<u64> {
    let j = j.ok_or(E::MintJustif)?;
    let root = scan_one(j).map_err(|_| E::MintJustif)?;
    let c = root.tag_content(TAG_MINT_LOCK).map_err(|_| E::MintJustif)?;
    let k = c.array::<5>().map_err(|_| E::MintJustif)?;
    k[0].version().map_err(|_| E::MintJustif)?;
    let chain = k[1].uint_max(u64::MAX).map_err(|_| E::MintJustif)?;
    let vault: [u8; 20] = fixed(&k[2]).map_err(|_| E::MintJustif)?;
    let zero: [u8; 20] = fixed(&k[3]).map_err(|_| E::MintJustif)?;
    let n = k[4].uint_max(u64::MAX).map_err(|_| E::MintJustif)?;
    if chain != cfg.chain_id || vault != cfg.vault || zero != cfg.zero_address || n == 0 {
        return Err(E::MintJustif);
    }
    Ok(n)
}

fn parse_mint_data(cfg: &Cfg, d: Option<&[u8]>) -> Result<Vec<u8>> {
    let d = d.ok_or(E::MintData)?;
    let root = scan_one(d).map_err(|_| E::MintData)?;
    let k = root.array::<2>().map_err(|_| E::MintData)?;
    let aid: [u8; 32] = fixed(&k[0]).map_err(|_| E::MintData)?;
    if aid != cfg.aid {
        return Err(E::MintData);
    }
    Ok(k[1].amount().map_err(|_| E::MintData)?.to_vec())
}

fn check_step(
    source: &Pred,
    source_hash: &[u8; 32],
    tx_raw: &[u8],
    cd: &Cd,
    key: &PublicKey,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<([u8; 32], [u8; 32])> {
    if cd.source.to_bytes() != source.to_bytes() || cd.source_hash != *source_hash {
        return Err(E::CDMismatch);
    }
    let tx_hash = h(tx_raw);
    if cd.tx_hash != tx_hash {
        return Err(E::CDMismatch);
    }
    verify_unlock(key, source_hash, &tx_hash, &cd.unlock)?;
    let sid = state_id(source, source_hash);
    if !seen.insert(sid) {
        return Err(E::RepeatedSID);
    }
    Ok((sid, tx_hash))
}

fn verify_history(cfg: &Cfg, hist: &History) -> Result<Outcome> {
    let ch = cfg.hash();
    let m = &hist.mint;
    if m.network != cfg.network || m.recipient.typ != PRED_SIGNATURE {
        return Err(E::MintShape);
    }
    if m.ty != cfg.ty {
        return Err(E::MintType);
    }
    let n = parse_justification(cfg, m.justification.as_deref())?;
    let salt = derive_salt(&ch, n);
    if m.salt != salt {
        return Err(E::MintSalt);
    }
    let id = derive_token_id(&salt, cfg.network);
    let amount = parse_mint_data(cfg, m.data.as_deref())?;
    let first = h(&m.recipient.to_bytes());
    let digest = lock_digest(
        &ch,
        n,
        &lock_record(&cfg.zero_address, &cfg.ty, &cfg.aid, &amount, &id, &first),
    );
    nonzero_digest(&digest)?;
    let mut out = Outcome {
        cfg: ch,
        nonce: n,
        amount,
        token_id: id,
        salt,
        first_predicate_hash: first,
        lock_digest: digest,
        release_to: [0; 20],
        nullifier: [0; 32],
        leaves: Vec::new(),
    };

    let mk = minter_key(&id)?;
    let mk_pub = PublicKey::from_secret_key(SECP256K1, &mk);
    let minter_pred = Pred::signature(&mk_pub.serialize());
    let h0 = mint_source_hash(&id);
    let mut seen = BTreeSet::new();
    out.leaves.push(check_step(
        &minter_pred,
        &h0,
        &hist.mint_raw,
        &hist.mint_cd,
        &mk_pub,
        &mut seen,
    )?);
    let mut state = result_state(&h0, &id);
    let mut owner = m.recipient.clone();

    for (i, t) in hist.transfers.iter().enumerate() {
        let last = i == hist.transfers.len() - 1;
        // The owner is the mint recipient or the previous intermediate recipient,
        // both already required to be signature predicates.
        let key = parse_key(&owner.params)?;
        let leaf =
            check_step(&owner, &state, &hist.transfers_raw[i], &hist.cds[i], &key, &mut seen)?;
        out.leaves.push(leaf);
        if last {
            check_return(cfg, &mut out, t)?;
            let btid = burn_id(&leaf.0, &leaf.1);
            out.nullifier = nullifier(&ch, &btid);
            nonzero_digest(&out.nullifier)?;
        } else {
            if t.recipient.typ != PRED_SIGNATURE {
                return Err(E::BurnNotFinal);
            }
            if t.data.is_some() {
                return Err(E::TransferData);
            }
        }
        state = result_state(&state, &t.mask);
        owner = t.recipient.clone();
    }
    Ok(out)
}

fn check_return(cfg: &Cfg, out: &mut Outcome, t: &Transfer) -> Result<()> {
    if t.recipient.typ != PRED_BURN {
        return Err(E::NotBurn);
    }
    let data = t.data.as_deref().ok_or(E::ReturnData)?;
    let root = scan_one(data).map_err(|_| E::ReturnData)?;
    let c = root.tag_content(TAG_RETURN_REASON).map_err(|_| E::ReturnData)?;
    let k = c.array::<11>().map_err(|_| E::ReturnData)?;
    k[0].version().map_err(|_| E::ReturnData)?;
    let chain = k[1].uint_max(u64::MAX).map_err(|_| E::ReturnData)?;
    if chain != cfg.chain_id {
        return Err(E::ReturnData);
    }
    let bad = |_| E::ReturnData;
    let vault: [u8; 20] = fixed(&k[2]).map_err(bad)?;
    let zero: [u8; 20] = fixed(&k[3]).map_err(bad)?;
    let ty: [u8; 32] = fixed(&k[4]).map_err(bad)?;
    let aid: [u8; 32] = fixed(&k[5]).map_err(bad)?;
    let recip: [u8; 20] = fixed(&k[6]).map_err(bad)?;
    if vault != cfg.vault || zero != cfg.zero_address || ty != cfg.ty || aid != cfg.aid {
        return Err(E::ReturnData);
    }
    let amt = k[7].amount().map_err(|_| E::ReturnAmount)?;
    if amt != out.amount {
        return Err(E::ReturnAmount);
    }
    let zero2: [u8; 20] = fixed(&k[8]).map_err(bad)?;
    let empty_ok = k[9].bytes().is_ok_and(|b| b.is_empty());
    let zero_ok = k[10].uint_max(u64::MAX) == Ok(0);
    if zero2 != cfg.zero_address || !empty_ok || !zero_ok {
        return Err(E::ReturnData);
    }
    if recip == [0u8; 20] || recip == cfg.vault {
        return Err(E::ReturnRecip);
    }
    // Every field above is typed and compared and the strict scanner fixes the
    // heads, so the bytes equal return_reason(...) by construction.
    if t.recipient.params != h(data) {
        return Err(E::BurnReason);
    }
    out.release_to = recip;
    Ok(())
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    #[test]
    fn zero_sentinels_and_invalid_minter_scalars() {
        assert_eq!(nonzero_digest(&[0; 32]), Err(E::ZeroDigest));
        assert_eq!(nonzero_digest(&[1; 32]), Ok(()));
        assert_eq!(minter_scalar(&[0; 32]), Err(E::MinterKey));
        assert_eq!(minter_scalar(&[255; 32]), Err(E::MinterKey));
        assert!(minter_scalar(&[1; 32]).is_ok());
    }
    #[test]
    fn repeated_sid_is_rejected_by_step_guard() {
        let m: serde_json::Value =
            serde_json::from_str(include_str!("../tests/testdata/go-9136c661.json")).unwrap();
        let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "mint-valid").unwrap();
        let input = v["input"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let hist = History::decode(&input).unwrap();
        let cd = &hist.mint_cd;
        let key = parse_key(&cd.source.params).unwrap();
        let mut seen = BTreeSet::new();
        let first =
            check_step(&cd.source, &cd.source_hash, &hist.mint_raw, cd, &key, &mut seen).unwrap();
        assert_eq!(first.0, state_id(&cd.source, &cd.source_hash));
        assert_eq!(
            check_step(&cd.source, &cd.source_hash, &hist.mint_raw, cd, &key, &mut seen),
            Err(E::RepeatedSID)
        );
    }
}

#[cfg(test)]
mod field_guard_tests {
    use super::*;
    use crate::encode::{
        encode_array as a, encode_byte_string as b, encode_tag as tag, encode_uint as u,
    };
    fn fixture() -> (Cfg, History, Outcome) {
        let m: serde_json::Value =
            serde_json::from_str(include_str!("../tests/testdata/go-9136c661.json")).unwrap();
        let hx = |s: &str| {
            s.as_bytes()
                .chunks_exact(2)
                .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let cfg = Cfg::from_bytes(&hx(m["fixtures"][0]["cfg"].as_str().unwrap())).unwrap();
        let v =
            m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "return-valid-0").unwrap();
        let raw = hx(v["input"].as_str().unwrap());
        let history = History::decode(&raw).unwrap();
        let out = verify_return(&cfg, &raw).unwrap();
        (cfg, history, out)
    }
    #[test]
    fn every_return_field_is_bound_independently() {
        let (cfg, hist, out) = fixture();
        let t = &hist.transfers[0];
        let data = t.data.as_deref().unwrap();
        let fields =
            scan_one(data).unwrap().tag_content(TAG_RETURN_REASON).unwrap().array::<11>().unwrap();
        for (index, changed, expected) in [
            (1, u(cfg.chain_id + 1), E::ReturnData),
            (2, b(&[1; 20]), E::ReturnData),
            (3, b(&[1; 20]), E::ReturnData),
            (4, b(&[1; 32]), E::ReturnData),
            (5, b(&[1; 32]), E::ReturnData),
            (6, b(&[0; 20]), E::ReturnRecip),
            (6, b(&cfg.vault), E::ReturnRecip),
            (7, b(&[1]), E::ReturnAmount),
            (8, b(&[1; 20]), E::ReturnData),
            (9, b(&[1]), E::ReturnData),
            (10, u(1), E::ReturnData),
        ] {
            let mut raw: Vec<&[u8]> = fields.iter().map(|f| f.raw(data)).collect();
            raw[index] = &changed;
            let data = tag(TAG_RETURN_REASON, &a(&raw));
            let mut mutated = t.clone();
            mutated.recipient.params = h(&data).to_vec();
            mutated.data = Some(data);
            assert_eq!(
                check_return(&cfg, &mut out.clone(), &mutated),
                Err(expected),
                "field {index}"
            );
        }
    }
    #[test]
    fn every_justification_field_is_bound_independently() {
        let (cfg, hist, _) = fixture();
        let data = hist.mint.justification.as_deref().unwrap();
        let fields =
            scan_one(data).unwrap().tag_content(TAG_MINT_LOCK).unwrap().array::<5>().unwrap();
        for (index, changed) in
            [(1, u(cfg.chain_id + 1)), (2, b(&[1; 20])), (3, b(&[1; 20])), (4, u(0))]
        {
            let mut raw: Vec<&[u8]> = fields.iter().map(|f| f.raw(data)).collect();
            raw[index] = &changed;
            assert_eq!(
                parse_justification(&cfg, Some(&tag(TAG_MINT_LOCK, &a(&raw)))),
                Err(E::MintJustif),
                "field {index}"
            );
        }
    }
    #[test]
    fn predicate_dispatch_is_closed_and_burn_width_fixed() {
        for (engine, code, params, expected) in [
            (u(1), b(&[1]), b(&[255; 33]), E::Predicate),
            (u(2), b(&[1]), b(&[2; 33]), E::Predicate),
            (u(1), b(&[3]), b(&[]), E::Predicate),
            (u(1), b(&[]), b(&[]), E::Predicate),
            (u(1), b(&[2]), b(&[1; 31]), E::Predicate),
        ] {
            let data = tag(TAG_PREDICATE, &a(&[&engine, &code, &params]));
            assert_eq!(decode_predicate(&scan_one(&data).unwrap()), Err(expected));
        }
    }
}
