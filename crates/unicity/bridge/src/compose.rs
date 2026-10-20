//! The composition, in bft-core `bridgeprofile.Compose` order. The first failure decides the
//! status; every stage is paid before it runs.
use crate::{
    abi::{self, Anchor, Call, Envelope, LeafProof},
    cfg::{self, hash, Cfg},
    status_of_b2, Fixed, Halt, Meter, Status, Verdict, MAX_ANCHORS, MAX_ANCHOR_UC_BYTES,
    MAX_INPUT_RECORD_BYTES, MAX_POLICY_BYTES, MAX_RSMT_SIBLINGS, MAX_SEMANTIC_BYTES,
    MAX_SUMMARY_BYTES, MAX_TRANSFERS,
};
use reth_unicity_b1::{batch, cbor as native};
use reth_unicity_b2::{cbor, Outcome};

/// A stage's outcome: a relation status, or a halt that ends the call.
pub(crate) enum Stop<E> {
    Status(Status),
    Halt(Halt<E>),
}
impl<E> From<Status> for Stop<E> {
    fn from(s: Status) -> Self {
        Self::Status(s)
    }
}

pub(crate) fn compose<V: Verdict>(
    call: Call<'_>,
    meter: &mut Meter,
    verdict: &mut V,
) -> Result<Fixed, Stop<V::Error>> {
    let mut pay = |gas: u64| meter.charge(gas).map_err(Stop::Halt);
    if call.op != 1 && call.op != 2 {
        return Err(Status::BadOperation.into());
    }
    let cfg = cfg::decode(call.cfg)?;
    pay(Meter::PER_ITEM * items(call.cfg))?;
    cfg::validate(call.cfg)?;
    let env = abi::decode_envelope(call.envelope)?;
    let partition = check_policy(&cfg, &env)?;
    pay(Meter::PER_ITEM * items(env.policy_body))?;
    // The kernel: the history's items and its leaf count are paid before any of its work.
    pay(Meter::PER_ITEM * items(env.history) + Meter::PER_LEAF * history_leaves(env.history))?;
    if env.history.len() > MAX_SEMANTIC_BYTES {
        return Err(Status::InputTooLarge.into());
    }
    let outcome = reth_unicity_b2::relation(call.op, call.cfg, env.history, |_| Ok(()))
        .map_err(status_of_b2)?;
    let leaf_anchor = plan_anchors(partition, &env, &outcome)?;
    // The scans of `computeGate`, in its order.
    for a in &env.anchors {
        scan_anchor(a)?;
    }
    bridge_j(call.cfg, &env)?;
    pay(Meter::PER_ITEM *
        env.anchors.iter().map(|a| items(a.uc) + items(a.input_record)).sum::<u64>())?;
    let request = batch_request(&env.anchors);
    let dims = batch::dimensions(&request).map_err(|_| Status::AnchorAuth)?;
    pay(Meter::batch(&dims))?;
    let mut steps = Vec::with_capacity(env.leaf_proofs.len());
    for p in &env.leaf_proofs {
        steps.push(leaf_path(p)?);
    }
    match verdict.batch(&request) {
        Ok(true) => {}
        Ok(false) => return Err(Status::AnchorAuth.into()),
        Err(h) => return Err(Stop::Halt(h)),
    }
    let mut times = Vec::with_capacity(env.anchors.len());
    for a in &env.anchors {
        times.push(open_anchor(a)?);
    }
    for (leaf, &j) in outcome.leaves.iter().zip(&leaf_anchor) {
        if leaf.reference_time > times[j] {
            return Err(Status::IRTime.into());
        }
    }
    for (((leaf, &j), p), s) in
        outcome.leaves.iter().zip(&leaf_anchor).zip(&env.leaf_proofs).zip(steps)
    {
        pay(Meter::PER_STEP * s)?;
        let input = member_input(env.anchors[j].expected_state_root, &leaf.sid, &leaf.value, p);
        let valid = reth_unicity_b1::membership::<core::convert::Infallible>(&input, u64::MAX)
            .is_ok_and(|out| out.bytes[63] == 1);
        if !valid {
            return Err(Status::LeafProof.into());
        }
    }
    Ok(Fixed::of(&outcome))
}

/// `BridgeItems`: an object's item heads under the native scan, zero if it does not scan (an
/// object is paid only once it scans).
fn items(b: &[u8]) -> u64 {
    let mut n = 0;
    native::one(b, &mut n).map_or(0, |_| n as u64)
}

/// `historyLeaves`: one plus the transfers of a history that scans as `[genesis, [tx...]]` within
/// the transfer bound, otherwise zero (the kernel then refuses it).
fn history_leaves(history: &[u8]) -> u64 {
    let Ok(root) = native::one(history, &mut 0) else { return 0 };
    let Ok([_, txs]) = root.array::<2>() else { return 0 };
    if txs.major != 4 || txs.arg > MAX_TRANSFERS {
        return 0;
    }
    1 + txs.arg
}

const POLICY_DOMAIN: &[u8] = b"UNICITY_BR_AGG_PARTITION";

/// `CheckPolicyBody`: hash first, interpretation second.
fn check_policy(cfg: &Cfg, env: &Envelope<'_>) -> Result<u32, Status> {
    if env.policy_body.len() > MAX_POLICY_BYTES {
        return Err(Status::InputTooLarge);
    }
    if hash(env.policy_body) != cfg.aggregator_policy_hash {
        return Err(Status::PolicyHash);
    }
    let root = cbor::one(env.policy_body, &mut 0).map_err(status_of_b2)?;
    let k = root.array::<3>().map_err(|_| Status::Shape)?;
    if k[0].major != 2 || k[0].data != POLICY_DOMAIN {
        return Err(Status::Shape);
    }
    if k[1].uint(u64::MAX).map_err(status_of_b2)? != 2 {
        return Err(Status::Version);
    }
    let partition = k[2].uint(u64::from(u32::MAX)).map_err(status_of_b2)? as u32;
    if partition == 0 {
        return Err(Status::IntRange);
    }
    if partition == cfg.evm_partition {
        return Err(Status::PolicyPartition);
    }
    if env.anchors.len() > MAX_ANCHORS {
        return Err(Status::TooManyPaths);
    }
    if env.anchors.is_empty() {
        return Err(Status::PolicyAnchors);
    }
    Ok(partition)
}

/// The depth of a canonical native shard ID, or `None`.
fn shard_depth(shard: &[u8]) -> Option<usize> {
    let last = *shard.last()?;
    if last == 0 || shard.len() > 33 {
        return None;
    }
    let d = 8 * shard.len() - last.trailing_zeros() as usize - 1;
    (d <= 256).then_some(d)
}

fn in_shard(shard: &[u8], sid: &[u8; 32]) -> bool {
    let Some(d) = shard_depth(shard) else { return false };
    (0..d).all(|i| (shard[i / 8] >> (7 - i % 8)) & 1 == (sid[i / 8] >> (7 - i % 8)) & 1)
}

/// `PlanAnchors`: each leaf's anchor, numbered by first use in leaf order, none unused, the leaf
/// inside its anchor's shard prefix. Distinctness is by complete UC bytes, compared by digest in a
/// sorted list (no pairwise scan).
fn plan_anchors(
    partition: u32,
    env: &Envelope<'_>,
    outcome: &Outcome,
) -> Result<Vec<usize>, Status> {
    let sids = &outcome.leaves;
    if env.leaf_proofs.len() != sids.len() {
        return Err(Status::PolicyLeafCount);
    }
    if env.anchors.len() > MAX_ANCHORS {
        return Err(Status::TooManyPaths);
    }
    if env.anchors.is_empty() || env.anchors.len() > sids.len() {
        return Err(Status::PolicyAnchors);
    }
    let mut digests = Vec::with_capacity(env.anchors.len());
    for a in &env.anchors {
        if shard_depth(a.shard).is_none() || a.partition != partition {
            return Err(Status::PolicyTuple);
        }
        let h = hash(a.uc);
        if digests.contains(&h) {
            return Err(Status::PolicyAnchors);
        }
        digests.push(h);
    }
    let mut plan = Vec::with_capacity(sids.len());
    let mut next = 0;
    for (leaf, p) in sids.iter().zip(&env.leaf_proofs) {
        let idx = usize::from(p.anchor_index);
        if idx >= env.anchors.len() || idx > next || !in_shard(env.anchors[idx].shard, &leaf.sid) {
            return Err(Status::PolicyLeafIndex);
        }
        if idx == next {
            next += 1;
        }
        plan.push(idx);
    }
    if next != env.anchors.len() {
        return Err(Status::PolicyAnchors);
    }
    Ok(plan)
}

/// `ScanAnchor`: the bridge's byte bounds, then the UC's own shard equal to the anchor's.
fn scan_anchor(a: &Anchor<'_>) -> Result<(), Status> {
    if a.uc.len() > MAX_ANCHOR_UC_BYTES || a.input_record.len() > MAX_INPUT_RECORD_BYTES {
        return Err(Status::InputTooLarge);
    }
    let shard = native::one(a.uc, &mut 0)
        .and_then(|uc| uc.tagged::<7>(39001))
        .and_then(|uc| uc[4].tagged::<3>(39003))
        .map(|sc| sc[1].data)
        .map_err(|_| Status::AnchorAuth)?;
    if shard != a.shard {
        return Err(Status::AnchorAuth);
    }
    Ok(())
}

/// `bridgeJ`'s refusals: each of the Cfg, the policy body, every anchor UC and every IR opening
/// scans natively, within its own item bound.
fn bridge_j(cfg: &[u8], env: &Envelope<'_>) -> Result<(), Status> {
    let scan = |b: &[u8], malformed: Status| match native::one(b, &mut 0) {
        Ok(_) => Ok(()),
        Err(reth_unicity_b1::Malformed::Limit) => Err(Status::TooManyItems),
        Err(_) => Err(malformed),
    };
    scan(cfg, Status::Shape)?;
    scan(env.policy_body, Status::Shape)?;
    for a in &env.anchors {
        scan(a.uc, Status::AnchorAuth)?;
        scan(a.input_record, Status::IRShape)?;
    }
    Ok(())
}

/// `LeafPathGas`'s bounds: the bitmap's popcount equals the siblings, at most the per-leaf bound.
fn leaf_path(p: &LeafProof<'_>) -> Result<u64, Status> {
    let pop: usize = p.bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if pop != p.sibling_count() {
        return Err(Status::PathBitmap);
    }
    if pop > MAX_RSMT_SIBLINGS {
        return Err(Status::TooManyPaths);
    }
    Ok(pop as u64)
}

/// The `CERT_BATCH_V2` request of the anchor table, in table order.
fn batch_request(anchors: &[Anchor<'_>]) -> Vec<u8> {
    let mut out = vec![2, 0];
    out.extend_from_slice(&(anchors.len() as u16).to_be_bytes());
    for a in anchors {
        out.extend_from_slice(&a.partition.to_be_bytes());
        out.extend_from_slice(&(a.shard.len() as u16).to_be_bytes());
        out.extend_from_slice(a.shard);
        out.extend_from_slice(a.shard_conf_hash);
        out.extend_from_slice(a.expected_state_root);
        out.extend_from_slice(a.expected_ir_hash);
        out.extend_from_slice(&(a.uc.len() as u32).to_be_bytes());
        out.extend_from_slice(a.uc);
    }
    out
}

/// `OpenAnchor`: the exact canonical IR bytes hash to the anchor's expectedIRHash, decode under
/// B1's rules and open to its expectedStateRoot. Returns the timestamp.
fn open_anchor(a: &Anchor<'_>) -> Result<u64, Status> {
    if a.input_record.is_empty() || a.input_record.len() > MAX_INPUT_RECORD_BYTES {
        return Err(Status::IRShape);
    }
    if hash(a.input_record) != a.expected_ir_hash {
        return Err(Status::IROpening);
    }
    let shape = || -> Option<(u64, &[u8])> {
        let root = cbor::one(a.input_record, &mut 0).ok()?;
        if root.major != 6 || root.arg != 39002 {
            return None;
        }
        let k = cbor::one(root.data, &mut 0).ok()?.array::<10>().ok()?;
        if k[0].uint(u64::MAX).ok()? != 1 {
            return None;
        }
        for i in [1, 2, 6, 8] {
            k[i].uint(u64::MAX).ok()?;
        }
        for i in [3, 7, 9] {
            if !k[i].null() {
                k[i].bytes(32).ok()?;
            }
        }
        let state = k[4].bytes(32).ok()?;
        if !k[5].null() && k[5].blob(MAX_SUMMARY_BYTES).is_err() {
            return None;
        }
        Some((k[6].arg, state))
    };
    let (timestamp, state) = shape().ok_or(Status::IRShape)?;
    if state != a.expected_state_root {
        return Err(Status::IRState);
    }
    Ok(timestamp)
}

/// `RSMT_MEMBER_V1`: header | root | key | valueLength | value | bitmap | siblings.
fn member_input(root: &[u8], key: &[u8; 32], value: &[u8; 32], p: &LeafProof<'_>) -> Vec<u8> {
    let mut in_ = Vec::with_capacity(4 + 32 * 3 + 4 + 32 + p.siblings.len());
    in_.extend_from_slice(&[1, 0, 0, 1]);
    in_.extend_from_slice(root);
    in_.extend_from_slice(key);
    in_.extend_from_slice(&32u32.to_be_bytes());
    in_.extend_from_slice(value);
    in_.extend_from_slice(p.bitmap);
    in_.extend_from_slice(p.siblings);
    in_
}
