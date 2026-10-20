//! Strict canonical ABI: the call input and the proof envelope. Every offset must be the one the
//! canonical encoder writes, every padding byte zero, every narrow integer in range and nothing may
//! follow the last element; counts are bounded before anything is collected.
use crate::{Status, MAX_ANCHORS, MAX_ENVELOPE_BYTES, MAX_LEAVES};

/// `abi.encode(uint8 op, bytes cfg, bytes envelope)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Call<'a> {
    pub op: u8,
    pub cfg: &'a [u8],
    pub envelope: &'a [u8],
}

/// One anchor tuple `(uint32, bytes, bytes32, bytes32, bytes32, bytes, bytes)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Anchor<'a> {
    pub partition: u32,
    pub shard: &'a [u8],
    pub shard_conf_hash: &'a [u8],
    pub expected_state_root: &'a [u8],
    pub expected_ir_hash: &'a [u8],
    pub uc: &'a [u8],
    pub input_record: &'a [u8],
}

/// One leaf proof tuple `(uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings)`; the siblings
/// are the borrowed `32*n` bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LeafProof<'a> {
    pub anchor_index: u16,
    pub bitmap: &'a [u8],
    pub siblings: &'a [u8],
}
impl LeafProof<'_> {
    pub(crate) const fn sibling_count(&self) -> usize {
        self.siblings.len() / 32
    }
}

/// `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[] leafProofs)`.
#[derive(Debug)]
pub(crate) struct Envelope<'a> {
    pub policy_body: &'a [u8],
    pub history: &'a [u8],
    pub anchors: Vec<Anchor<'a>>,
    pub leaf_proofs: Vec<LeafProof<'a>>,
}

const fn pad32(n: usize) -> usize {
    n.div_ceil(32) * 32
}

/// A word of `b` at `off` read as an integer of at most 64 bits; `None` past the end or above.
fn word(b: &[u8], off: usize) -> Option<u64> {
    let w = b.get(off..off.checked_add(32)?)?;
    if w[..24].iter().any(|x| *x != 0) {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().expect("8 bytes")))
}

/// The word at `off` as a length or offset that fits the input.
fn size(b: &[u8], off: usize) -> Option<usize> {
    let v = usize::try_from(word(b, off)?).ok()?;
    (v <= b.len()).then_some(v)
}

/// The canonical `bytes` at `at`: the length word, the data and zero padding. Returns the data and
/// the position after the padding.
fn bytes_at(b: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let len = size(b, at)?;
    let start = at.checked_add(32)?;
    let end = start.checked_add(len)?;
    let padded = start.checked_add(pad32(len))?;
    let data = b.get(start..end)?;
    if b.get(end..padded)?.iter().any(|x| *x != 0) {
        return None;
    }
    Some((data, padded))
}

/// The call input. Anything but the canonical encoding of the three fields is `None` (a halt).
pub(crate) fn decode_call(b: &[u8]) -> Option<Call<'_>> {
    let op = word(b, 0)?;
    if op > u64::from(u8::MAX) || word(b, 32)? != 96 {
        return None;
    }
    let (cfg, after_cfg) = bytes_at(b, 96)?;
    if size(b, 64)? != after_cfg {
        return None;
    }
    let (envelope, end) = bytes_at(b, after_cfg)?;
    (end == b.len()).then_some(Call { op: op as u8, cfg, envelope })
}

/// The envelope under the PR 1 resource policy, in the oracle's order of refusals: size, framing,
/// then the anchor, leaf and declared-sibling counts read from the head words before any
/// allocation, then the canonical layout itself.
pub(crate) fn decode_envelope(b: &[u8]) -> Result<Envelope<'_>, Status> {
    if b.len() > MAX_ENVELOPE_BYTES {
        return Err(Status::InputTooLarge);
    }
    if !b.len().is_multiple_of(32) || b.len() < 4 * 32 {
        return Err(Status::ABIFraming);
    }
    bound_counts(b)?;
    layout(b).ok_or(Status::ABIFraming)
}

/// `boundEnvelopeCounts`: the declared anchor and leaf counts and the declared siblings in sum,
/// which can never exceed the envelope's words.
fn bound_counts(b: &[u8]) -> Result<(), Status> {
    let n = b.len() as u64;
    let w = |off: u64| -> Result<u64, Status> {
        usize::try_from(off).ok().and_then(|o| word(b, o)).ok_or(Status::ABIFraming)
    };
    let add = |a: u64, c: u64| a.checked_add(c).ok_or(Status::ABIFraming);
    let (off_anchors, off_leaves) = (w(64)?, w(96)?);
    if off_anchors > n || off_leaves > n {
        return Err(Status::ABIFraming);
    }
    let na = w(off_anchors)?;
    if na > n {
        return Err(Status::ABIFraming);
    }
    if na > MAX_ANCHORS as u64 {
        return Err(Status::TooManyPaths);
    }
    let nl = w(off_leaves)?;
    if nl > n {
        return Err(Status::ABIFraming);
    }
    if nl > MAX_LEAVES as u64 {
        return Err(Status::TooManyPaths);
    }
    let (room, mut steps) = (n / 32, 0u64);
    for i in 0..nl {
        let rel = w(add(off_leaves, 32 + 32 * i)?)?;
        let t = add(off_leaves + 32, rel)?;
        let s_off = add(t, w(add(t, 64)?)?)?;
        let ns = w(s_off)?;
        if ns > room - steps {
            return Err(Status::TooManyPaths);
        }
        steps += ns;
    }
    Ok(())
}

/// The canonical layout, after the counts are known to be bounded.
fn layout(b: &[u8]) -> Option<Envelope<'_>> {
    if size(b, 0)? != 128 {
        return None;
    }
    let (policy_body, at) = bytes_at(b, 128)?;
    if size(b, 32)? != at {
        return None;
    }
    let (history, at) = bytes_at(b, at)?;
    if size(b, 64)? != at {
        return None;
    }
    let (anchors, at) = anchor_array(b, at)?;
    if size(b, 96)? != at {
        return None;
    }
    let (leaf_proofs, end) = leaf_array(b, at)?;
    (end == b.len()).then_some(Envelope { policy_body, history, anchors, leaf_proofs })
}

/// A dynamic tuple array at `at`: the count, one offset per element (relative to the word after
/// the count) and the elements in order, each starting where the previous one ended.
fn tuple_array<'a, T>(
    b: &'a [u8],
    at: usize,
    elem: impl Fn(&'a [u8], usize) -> Option<(T, usize)>,
) -> Option<(Vec<T>, usize)> {
    let n = size(b, at)?;
    let base = at.checked_add(32)?;
    let mut next = base.checked_add(n.checked_mul(32)?)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if size(b, base + 32 * i)? != next - base {
            return None;
        }
        let (v, end) = elem(b, next)?;
        out.push(v);
        next = end;
    }
    Some((out, next))
}

fn word32(b: &[u8], off: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(32)?)
}

fn anchor_array(b: &[u8], at: usize) -> Option<(Vec<Anchor<'_>>, usize)> {
    tuple_array(b, at, |b, t| {
        let partition = u32::try_from(word(b, t)?).ok()?;
        if size(b, t + 32)? != 224 {
            return None;
        }
        let (shard, after_shard) = bytes_at(b, t + 224)?;
        if size(b, t + 160)? != after_shard - t {
            return None;
        }
        let (uc, after_uc) = bytes_at(b, after_shard)?;
        if size(b, t + 192)? != after_uc - t {
            return None;
        }
        let (input_record, end) = bytes_at(b, after_uc)?;
        Some((
            Anchor {
                partition,
                shard,
                shard_conf_hash: word32(b, t + 64)?,
                expected_state_root: word32(b, t + 96)?,
                expected_ir_hash: word32(b, t + 128)?,
                uc,
                input_record,
            },
            end,
        ))
    })
}

fn leaf_array(b: &[u8], at: usize) -> Option<(Vec<LeafProof<'_>>, usize)> {
    tuple_array(b, at, |b, t| {
        let anchor_index = u16::try_from(word(b, t)?).ok()?;
        if size(b, t + 64)? != 96 {
            return None;
        }
        let n = size(b, t + 96)?;
        let start = t + 128;
        let end = start.checked_add(n.checked_mul(32)?)?;
        Some((
            LeafProof { anchor_index, bitmap: word32(b, t + 32)?, siblings: b.get(start..end)? },
            end,
        ))
    })
}
