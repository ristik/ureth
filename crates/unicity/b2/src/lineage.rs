//! The lineage relation of protocol 6 (bft-core `docs/design/bridge-split-lineage-spec.md`, oracle
//! `bridgeprofile/lineage.go`): a redeemed part whose mint reason is a split reason carrying its
//! burned parent, down to the lock-backed root. Walk from the part to the root through the exact
//! justification bytes, then verify root first with one lineage-wide state-ID set, a split burn per
//! parent, an allocation edge per child and the return burn of the part.
//!
//! Ancestors arrive as complete SDK tokens inside the justification. Each is projected to the
//! compact history form from the token's own item bytes, so every transaction, certification and
//! reference time the relation reads is the exact byte string its descendant's mint hash commits
//! to.
use crate::{
    cbor::{self, array, bytes, uint, Items},
    hash,
    semantics::{self, Cfg},
    Error as E, Leaf, Outcome, Result,
};
use reth_unicity_b1::{cbor as native, Malformed};
use std::collections::HashSet;

/// Per byte of the outer mint and of every justification descended into (scan and hash of the
/// nested prefixes). Trial values, as the oracle's `lineage.go`.
pub const SPLIT_PER_BYTE: u64 = 16;
/// Per CBOR item of a split justification's own scan.
pub const PER_ITEM: u64 = 20;
/// Per certified leaf of an ancestor token.
pub const PER_LEAF: u64 = 16_000;
/// Per allocation edge.
pub const EDGE_BASE: u64 = 20_000;
/// Per sum-proof step.
pub const EDGE_PER_STEP: u64 = 1_500;

const TAG_LOCK: u64 = 39049;
const TAG_SPLIT: u64 = 39044;
const TAG_MANIFEST: u64 = 39046;
const TAG_TOKEN: u64 = 39040;
const TAG_INCLUSION: u64 = 39033;
const MAX_PROOF_UC_BYTES: usize = 24 << 10;
const MAX_STEPS: usize = 256;

/// A 256-bit unsigned amount, big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256([u8; 32]);
impl U256 {
    /// A positive minimal big-endian amount of at most 32 bytes.
    fn amount(b: &[u8]) -> Option<Self> {
        if b.is_empty() || b.len() > 32 || b[0] == 0 {
            return None;
        }
        let mut w = [0; 32];
        w[32 - b.len()..].copy_from_slice(b);
        Some(Self(w))
    }
    fn checked_add(self, o: Self) -> Option<Self> {
        let mut out = [0; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let v = u16::from(self.0[i]) + u16::from(o.0[i]) + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        (carry == 0).then_some(Self(out))
    }
}

fn leaf_hash(key: &[u8; 32], data: &[u8; 32], v: &U256) -> [u8; 32] {
    let mut b = Vec::with_capacity(97);
    b.push(0x10);
    b.extend_from_slice(key);
    b.extend_from_slice(data);
    b.extend_from_slice(&v.0);
    hash(&b)
}
fn node_hash(depth: u8, l: (&[u8; 32], &U256), r: (&[u8; 32], &U256)) -> Option<([u8; 32], U256)> {
    let sum = l.1.checked_add(*r.1)?;
    let mut b = Vec::with_capacity(130);
    b.push(0x11);
    b.push(depth);
    b.extend_from_slice(l.0);
    b.extend_from_slice(&l.1 .0);
    b.extend_from_slice(r.0);
    b.extend_from_slice(&r.1 .0);
    Some((hash(&b), sum))
}
fn key_bit(key: &[u8; 32], i: u8) -> bool {
    key[usize::from(i / 8)] >> (7 - i % 8) & 1 == 1
}

struct Step {
    depth: u8,
    hash: [u8; 32],
    sum: U256,
}
/// Leaf-first allocation proof; verification returns the reconstructed root sum.
struct Proof(Vec<Step>);
impl Proof {
    fn verify(
        &self,
        key: &[u8; 32],
        data: &[u8; 32],
        value: &U256,
        root: &[u8; 32],
    ) -> Option<U256> {
        let mut h = leaf_hash(key, data, value);
        let mut sum = *value;
        let mut prev = 256u16;
        for s in &self.0 {
            if u16::from(s.depth) >= prev {
                return None;
            }
            (h, sum) = if key_bit(key, s.depth) {
                node_hash(s.depth, (&s.hash, &s.sum), (&h, &sum))?
            } else {
                node_hash(s.depth, (&h, &sum), (&s.hash, &s.sum))?
            };
            prev = u16::from(s.depth);
        }
        (h == *root).then_some(sum)
    }
}

const fn nerr(e: Malformed) -> E {
    match e {
        Malformed::Truncated => E::Truncated,
        Malformed::Trailing => E::Trailing,
        Malformed::Canonical => E::NonCanonical,
        Malformed::Cbor | Malformed::Utf8 => E::ForbiddenCBOR,
        Malformed::Limit => E::TooManyItems,
        Malformed::Version => E::Version,
        _ => E::Shape,
    }
}

fn decode_proof(it: native::Item<'_>) -> Result<Proof> {
    if it.major != 4 {
        return Err(E::Shape);
    }
    if it.arg > MAX_STEPS as u64 {
        return Err(E::SplitProofShape);
    }
    let mut steps = Vec::with_capacity(it.arg as usize);
    let mut prev = 256u16;
    for k in it.children() {
        let f = k.array::<3>().map_err(nerr)?;
        let depth = f[0].uint(255).map_err(|_| E::SplitProofShape)?;
        if depth as u16 >= prev {
            return Err(E::SplitProofShape);
        }
        prev = depth as u16;
        let hash: [u8; 32] = f[1].bytes(32).map_err(nerr)?.try_into().expect("32 bytes");
        if f[2].major != 2 {
            return Err(E::SplitProofShape);
        }
        let sum = U256::amount(f[2].data).ok_or(E::SplitProofShape)?;
        steps.push(Step { depth: depth as u8, hash, sum });
    }
    Ok(Proof(steps))
}

/// The head of a justification: the tag number, if it starts with a tag.
fn justification_tag(j: &[u8]) -> Option<u64> {
    let first = *j.first()?;
    if first >> 5 != 6 {
        return None;
    }
    let ai = first & 31;
    match ai {
        0..=23 => Some(u64::from(ai)),
        24..=27 => {
            let len = 1usize << (ai - 24);
            let b = j.get(1..=len)?;
            Some(b.iter().fold(0, |v, x| (v << 8) | u64::from(*x)))
        }
        _ => None,
    }
}

fn inclusion<'a>(it: native::Item<'a>) -> Result<(native::Item<'a>, u64)> {
    // tag(39033, [1, CD, t, b(path), UC])
    if it.major != 6 {
        return Err(E::Shape);
    }
    if it.arg != TAG_INCLUSION {
        return Err(E::Tag);
    }
    let f = it.tagged::<5>(TAG_INCLUSION).map_err(nerr)?;
    // Document order, as the oracle's `decodeProof`: the certification data, then the reference
    // time.
    cd_strict(cbor::one(f[1].raw, &mut Items::native(Items::MAX))?)?;
    let t = f[2].uint(u64::MAX).map_err(nerr)?;
    if f[3].major != 2 {
        return Err(E::Shape);
    }
    let path = f[3].data;
    if path.len() < 32 || path.len() % 32 != 0 {
        return Err(E::Length);
    }
    let pop: usize = path[..32].iter().map(|b| b.count_ones() as usize).sum();
    if path.len() != 32 + 32 * pop {
        return Err(E::Length);
    }
    let uc = f[4];
    if uc.raw.len() > MAX_PROOF_UC_BYTES {
        return Err(E::InputTooLarge);
    }
    if uc.major != 6 {
        return Err(E::Shape);
    }
    reth_unicity_b1::scan_certificate(uc.raw).map_err(|e| match e {
        Malformed::Signature => E::CertSigLength,
        _ => E::CertScan,
    })?;
    Ok((f[1], t))
}

use semantics::{cd_strict, decode_mint, transfer_strict};

/// The oracle's `DecodeHistory`: every wire field of the mint and of every tuple, in document
/// order, and none of the relation.
fn decode_history(history: &[u8]) -> Result<()> {
    let p = cbor::one(history, &mut Items::per_object(usize::MAX))?;
    let h = p.array::<2>()?;
    let g = h[0].array::<3>()?;
    h[1].count(u64::MAX)?;
    decode_mint(g[0])?;
    cd_strict(g[1])?;
    g[2].uint(u64::MAX)?;
    for tuple in h[1].children() {
        let a = tuple.array::<3>()?;
        transfer_strict(a[0])?;
        cd_strict(a[1])?;
        a[2].uint(u64::MAX)?;
    }
    Ok(())
}

/// The SDK token's version field is 2, which the shared `tagged` helper (version 1) cannot express,
/// so the token is opened by hand.
fn open_token<'a>(token: native::Item<'a>) -> Result<[native::Item<'a>; 3]> {
    if token.major != 6 {
        return Err(E::Shape);
    }
    if token.arg != TAG_TOKEN {
        return Err(E::Tag);
    }
    let inner = native::one_loose(token.data, &mut 0, usize::MAX).map_err(nerr)?;
    let a = inner.array::<3>().map_err(nerr)?;
    if a[0].uint(u64::MAX).map_err(nerr)? != 2 {
        return Err(E::Version);
    }
    Ok([a[0], a[1], a[2]])
}

fn project(token: native::Item<'_>) -> Result<(Vec<u8>, u64)> {
    let [_, genesis, txs] = open_token(token)?;
    let g = genesis.array::<2>().map_err(nerr)?;
    decode_mint(cbor::one(g[0].raw, &mut Items::native(Items::MAX))?)?;
    let (cd0, t0) = inclusion(g[1])?;
    let mut triples = Vec::new();
    if txs.major != 4 {
        return Err(E::Shape);
    }
    let mut count = 0u64;
    for p in txs.children() {
        let pair = p.array::<2>().map_err(nerr)?;
        transfer_strict(cbor::one(pair[0].raw, &mut Items::native(Items::MAX))?)?;
        let (cd, t) = inclusion(pair[1])?;
        triples.push(array(&[pair[0].raw, cd.raw, &uint(t)]));
        count += 1;
    }
    let refs: Vec<&[u8]> = triples.iter().map(Vec::as_slice).collect();
    let mint = array(&[g[0].raw, cd0.raw, &uint(t0)]);
    Ok((array(&[&mint, &array(&refs)]), 1 + count))
}

/// One verified token.
struct Verified {
    /// The leaf of the terminal transfer.
    last: Leaf,
    id: [u8; 32],
    amount: [u8; 32],
    base: Option<Outcome>,
    leaves: Vec<Leaf>,
    network: u64,
    recipient: Vec<u8>,
    salt: [u8; 32],
    ty: [u8; 32],
    data: Vec<u8>,
}

/// A token's mint and complete transfer history as `semantics::evaluate` verifies it, except that
/// the terminal transfer is classified by `terminal` (a split burn for a parent, the return for the
/// part). A root's reason is the lock reason with the derived salt; a child's salt is free.
fn level(
    cfg: &Cfg<'_>,
    payload: &[u8],
    root: bool,
    seen: &mut HashSet<[u8; 32]>,
    tokens: &mut Items,
) -> Result<Verified> {
    let payload = cbor::one(payload, tokens)?;
    let h = payload.array::<2>()?;
    let g = h[0].array::<3>()?;
    let count = h[1].count(u64::MAX)?;
    // The whole history is decoded before any of it is verified, as `semantics::evaluate` does.
    let mint = decode_mint(g[0])?;
    let cd0 = cd_strict(g[1])?;
    let t0 = g[2].uint(u64::MAX)?;
    let mut transfers = Vec::with_capacity(count as usize);
    for tuple in h[1].children() {
        let a = tuple.array::<3>()?;
        let tx = transfer_strict(a[0])?;
        let cert = cd_strict(a[1])?;
        let t = a[2].uint(u64::MAX)?;
        transfers.push((tx, cert, t));
    }
    if count == 0 {
        return Err(E::NoTransfers);
    }
    let m = mint.fields;
    let e = mint.deadline;
    let (n, amt) = semantics::verify_mint(cfg, &mint, root, tokens)?;
    let (id, base) = if let Some(n) = n {
        let out = semantics::derive(cfg, n, amt, m[2])?;
        (out.token_id, Some(out))
    } else {
        (semantics::hash_array(&[&bytes(m[3].data), &uint(cfg.network)]), None)
    };
    let mut amount = [0; 32];
    amount[32 - amt.len()..].copy_from_slice(amt);
    let secret = semantics::hash_array(&[&bytes(b"I_AM_UNIVERSAL_MINTER_FOR_"), &bytes(&id)]);
    let mk = k256::ecdsa::SigningKey::from_slice(&secret).map_err(|_| E::MinterKey)?;
    let mp = semantics::signature_pred(mk.verifying_key());
    let source = semantics::hash_array(&[&bytes(&id), &bytes(&hash(b"TOKENID"))]);
    let mut leaves = Vec::with_capacity(transfers.len() + 1);
    leaves.push(semantics::step(&mp, &source, g[0].raw, e, &cd0, t0, mk.verifying_key(), seen)?);
    let mut state = semantics::output_state(&source, &id);
    let mut owner = m[2];
    for (i, (tx, cert, t)) in transfers.iter().enumerate() {
        let (_, params) = semantics::predicate(owner)?;
        let k = semantics::key(params)?;
        let leaf = semantics::step(owner.raw, &state, tx.raw, tx.e, cert, *t, &k, seen)?;
        if i + 1 != transfers.len() {
            let (typ, p) = semantics::predicate(tx.pred)?;
            if typ != 1 {
                return Err(E::BurnNotFinal);
            }
            semantics::key(p)?;
            if tx.data.is_some() {
                return Err(E::TransferData);
            }
        }
        leaves.push(leaf);
        state = semantics::output_state(&state, tx.mask);
        owner = tx.pred;
    }
    Ok(Verified {
        last: leaves.last().cloned().expect("the mint leaf"),
        id,
        amount,
        base,
        leaves,
        network: m[1].arg,
        recipient: m[2].raw.to_vec(),
        salt: m[3].data.try_into().expect("32 bytes"),
        ty: m[4].data.try_into().expect("32 bytes"),
        data: mint.data.expect("verified").to_vec(),
    })
}

/// `splitOutputCommitment`.
fn commitment(source: &[u8; 32], child: &Verified) -> [u8; 32] {
    semantics::hash_array(&[
        &bytes(b"UNICITY_SPLIT_OUTPUT"),
        &bytes(source),
        &uint(child.network),
        &bytes(&child.recipient),
        &bytes(&child.salt),
        &bytes(&child.id),
        &bytes(&child.ty),
        &bytes(&child.data),
    ])
}

/// The manifest root of a split burn's data: `tag(39046, [b(root32)])`, nothing else.
fn manifest_root(data: &[u8]) -> Result<[u8; 32]> {
    let bad = |_| E::SplitManifest;
    let root = cbor::one(data, &mut Items::default()).map_err(bad)?;
    if root.major != 6 || root.arg != TAG_MANIFEST {
        return Err(E::SplitManifest);
    }
    let inner = cbor::one(root.data, &mut Items::default()).map_err(bad)?;
    let a = inner.array::<1>().map_err(bad)?;
    a[0].bytes(32).map_err(bad)?.try_into().map_err(|_| E::SplitManifest)
}

struct Walked<'a> {
    /// The justification of `projs[i]`, i < depth.
    proofs: Vec<Proof>,
    projs: Vec<std::borrow::Cow<'a, [u8]>>,
}

/// The lineage relation. `charge` is paid, in the oracle's order and before the work it pays for,
/// the byte, item, leaf and edge terms; it fails with [`E::OutOfGas`] to end the call.
pub fn relation(
    cfg_bytes: &[u8],
    history: &[u8],
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Outcome> {
    let mut objects = Items::per_object(Items::MAX);
    let cfg_item = cbor::one(cfg_bytes, &mut objects)?;
    semantics::check_cfg_network(cfg_item)?;
    let cfg = Cfg::parse(cfg_item)?;
    decode_history(history)?;
    let payload = cbor::one(history, &mut Items::per_object(usize::MAX))?;
    let top = payload.array::<2>()?;
    if top[1].count(u64::MAX)? == 0 {
        return Err(E::NoTransfers);
    }

    // Walk: part to root.
    let mut w = Walked { proofs: Vec::new(), projs: vec![std::borrow::Cow::Borrowed(history)] };
    let outer_mint = top[0].array::<3>()?[0];
    charge(SPLIT_PER_BYTE * outer_mint.raw.len() as u64)?;
    loop {
        let cur = w.projs.last().expect("one level");
        let mut o = Items::per_object(usize::MAX);
        let p = cbor::one(cur, &mut o)?;
        let m = p.array::<2>()?[0].array::<3>()?[0].tagged::<8>(39041, 2)?;
        let j = m[5].blob(usize::MAX).map_err(|_| E::MintJustif)?;
        match justification_tag(j) {
            Some(TAG_LOCK) => break,
            Some(TAG_SPLIT) => {}
            _ => return Err(E::MintJustif),
        }
        charge(SPLIT_PER_BYTE * j.len() as u64)?;
        let mut items = 0;
        let sj = native::one_loose(j, &mut items, usize::MAX).map_err(|_| E::SplitJustif)?;
        if sj.major != 6 || sj.arg != TAG_SPLIT {
            return Err(E::SplitJustif);
        }
        let body = native::one_loose(sj.data, &mut 0, usize::MAX).map_err(|_| E::SplitJustif)?;
        if body.major != 4 || body.arg != 2 {
            return Err(E::SplitJustif);
        }
        let mut kids = body.children();
        let (token, proofs) = (kids.next().expect("two"), kids.next().expect("two"));
        if token.major != 6 || proofs.major != 4 {
            return Err(E::SplitJustif);
        }
        if proofs.arg != 1 {
            return Err(E::SplitProofCount);
        }
        let proof = decode_proof(proofs.children().next().expect("one"))?;
        charge(PER_ITEM * items as u64)?;
        let (proj, leaves) = project(token)?;
        charge(PER_LEAF * leaves)?;
        w.proofs.push(proof);
        w.projs.push(std::borrow::Cow::Owned(proj));
    }

    // Verify: root to part.
    let d = w.projs.len() - 1;
    let mut seen = HashSet::new();
    let mut out = Outcome { depth: d as u64, ..Default::default() };
    let mut parent: Option<([u8; 32], [u8; 32], [u8; 32])> = None; // id, amount, manifest root
    for i in (0..=d).rev() {
        let proj_bytes: &[u8] = &w.projs[i];
        let lv = level(&cfg, proj_bytes, i == d, &mut seen, &mut Items::per_object(Items::MAX))?;
        if i < d {
            let (pid, pamount, proot) = parent.expect("root first");
            charge(EDGE_BASE + EDGE_PER_STEP * w.proofs[i].0.len() as u64)?;
            let data = commitment(&pid, &lv);
            let value = U256(lv.amount);
            let sum = w.proofs[i].verify(&lv.id, &data, &value, &proot).ok_or(E::SplitProof)?;
            if sum.0 != pamount {
                return Err(E::SplitSum);
            }
        }
        // The terminal transfer, after the edge: a split burn for a parent, the return for the
        // part.
        let proj = cbor::one(proj_bytes, &mut Items::per_object(usize::MAX))?;
        let last = proj.array::<2>()?[1].children().last().expect("a terminal transfer");
        let tx = semantics::transfer(last.array::<3>()?[0])?;
        let mut split_root = [0; 32];
        if i == 0 {
            let mut tmp = Outcome { amount: lv.amount, ..Default::default() };
            semantics::burn(&cfg, &mut tmp, &tx, &mut Items::default())?;
            let btid = semantics::hash_array(&[
                &bytes(b"unicity-burn-transition:v1"),
                &bytes(&lv.last.sid),
                &bytes(&lv.last.tx_hash),
            ]);
            out.nullifier = semantics::hash_array(&[
                &bytes(b"UNICITY_BR_NUL"),
                &bytes(&hash(cfg.raw)),
                &bytes(&btid),
            ]);
            if out.nullifier == [0; 32] {
                return Err(E::ZeroDigest);
            }
            out.release_to = tmp.release_to;
            out.part_token_id = lv.id;
            out.part_amount = lv.amount;
        } else {
            let (typ, params) = semantics::predicate(tx.pred).map_err(|_| E::SplitBurn)?;
            let data = match (typ, tx.data) {
                (2, Some(data)) => data,
                _ => return Err(E::SplitBurn),
            };
            split_root = manifest_root(data)?;
            if params != hash(data) {
                return Err(E::SplitBurn);
            }
        }
        out.leaves.extend(lv.leaves.iter().cloned());
        if i == d {
            let base = lv.base.as_ref().expect("root has a base");
            out.cfg = base.cfg;
            out.nonce = base.nonce;
            out.amount = base.amount;
            out.token_id = base.token_id;
            out.salt = base.salt;
            out.first_predicate_hash = base.first_predicate_hash;
            out.lock_digest = base.lock_digest;
        }
        parent = Some((lv.id, lv.amount, split_root));
    }
    Ok(out)
}
