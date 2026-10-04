//! The V1 root trust base (a committee of keys with weights and one threshold), which is both the
//! pinned genesis and the verifier projection of every later epoch, and the strict signature quorum
//! rule.

use crate::{
    cbor::{parse, Items, Limits, Value},
    error::{format, Error, Kind, Result},
    sig::{sha256, valid_key, verify},
};

/// go-base `UnicityTrustBaseTag`.
const TRUST_BASE_TAG: u64 = 39000;
const GENESIS_LIMITS: Limits = Limits { bytes: 1 << 20, depth: 8, array: 1024, map: 1024 };

/// One committee member of a trust base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) id: String,
    pub(crate) key: Vec<u8>,
    pub(crate) weight: u64,
}

/// A committee and its quorum threshold; members are strictly ordered by node id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustBase {
    pub(crate) network: u64,
    pub(crate) epoch: u64,
    pub(crate) epoch_start: u64,
    pub(crate) nodes: Vec<Node>,
    pub(crate) threshold: u64,
}

/// A signature map entry: node id to signature.
pub(crate) type Signatures = Vec<(String, Vec<u8>)>;

impl TrustBase {
    /// Weight of `id` if `sig` verifies over `data` under its key; `None` for an unknown node or a
    /// bad signature.
    fn weigh(&self, data: &[u8], sig: &[u8], id: &str) -> Option<u64> {
        let node =
            self.nodes.binary_search_by(|n| n.id.as_str().cmp(id)).ok().map(|i| &self.nodes[i])?;
        verify(&node.key, data, sig).then_some(node.weight)
    }

    /// The D3 certificate check: a signer that is not a member rejects the certificate, the weights
    /// of the verified signatures are added with overflow refusal, and the sum must reach the
    /// threshold. With `strict` an invalid signature from a known member is refused too;
    /// otherwise it carries no weight (the v1 rule). Returns the verified signer weight.
    pub(crate) fn verify_signed(
        &self,
        data: &[u8],
        sigs: &Signatures,
        strict: bool,
    ) -> core::result::Result<u64, String> {
        if self.threshold == 0 {
            return Err("zero threshold".into());
        }
        let mut order: Vec<&(String, Vec<u8>)> = sigs.iter().collect();
        order.sort_by(|a, b| a.0.cmp(&b.0));
        let mut total: u64 = 0;
        for (id, sig) in order {
            match self.weigh(data, sig, id) {
                Some(w) => total = total.checked_add(w).ok_or("weight overflow")?,
                None if !self.nodes.iter().any(|n| &n.id == id) => {
                    return Err(format!("unknown signer {id:?}"))
                }
                None if strict => return Err(format!("invalid signature from {id:?}")),
                None => {}
            }
        }
        if total >= self.threshold {
            Ok(total)
        } else {
            Err(format!("quorum not reached, signed {total}, threshold {}", self.threshold))
        }
    }
}

fn history_err(detail: impl std::fmt::Display) -> Error {
    Error::new(Kind::History, detail)
}

/// The decoded pinned genesis: the unit committee, and its identity (SHA-256 of the canonical
/// tagged encoding, signatures included).
pub(crate) struct Genesis {
    pub(crate) trust_base: TrustBase,
    pub(crate) id: [u8; 32],
}

impl Genesis {
    /// Decodes and validates the epoch-1 trust base: a unit committee with valid, unique keys
    /// strictly ordered by node id, a threshold in `[floor(2n/3)+1, n]`, self-signed by a
    /// quorum of its own members.
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        let v = parse(raw, GENESIS_LIMITS)?;
        if v.encode() != raw {
            return Err(format("genesis is not the canonical encoding"));
        }
        let Value::Tag(TRUST_BASE_TAG, inner) = &v else {
            return Err(history_err("genesis is not a tagged trust base"));
        };
        let mut f = Items::of(inner, Some(10))?;
        if f.uint()? != 1 {
            return Err(history_err("trust base version"));
        }
        let network = f.uint()?;
        let epoch = f.uint()?;
        let epoch_start = f.uint()?;
        let mut nodes = Vec::new();
        for n in f.array(1024)? {
            let mut n = Items::of(n, Some(3))?;
            nodes.push(Node {
                id: n.text(usize::MAX)?.to_owned(),
                key: n.bytes_max(64)?.to_vec(),
                weight: n.uint()?,
            });
            n.done()?;
        }
        let threshold = f.uint()?;
        for _ in 0..3 {
            f.opt_bytes(usize::MAX)?;
        }
        let Value::Map(pairs) = f.take()? else {
            return Err(history_err("genesis carries no signatures"));
        };
        let mut sigs = Signatures::new();
        for (k, s) in pairs {
            let (Value::Text(k), Value::Bytes(s)) = (k, s) else {
                return Err(format("signature map entry"));
            };
            sigs.push((k.clone(), s.clone()));
        }
        f.done()?;
        if epoch != 1 {
            return Err(history_err(format_args!(
                "genesis trust base epoch must be 1, got {epoch}"
            )));
        }
        let tb = TrustBase { network, epoch, epoch_start, nodes, threshold };
        check_unit_committee(&tb)?;
        // the signed bytes are the tagged encoding with the signature field null
        let Value::Array(mut fields) = (**inner).clone() else { unreachable!("checked above") };
        let last = fields.len() - 1;
        fields[last] = Value::Null;
        let sig_bytes = Value::Tag(TRUST_BASE_TAG, Box::new(Value::Array(fields))).encode();
        tb.verify_signed(&sig_bytes, &sigs, false)
            .map_err(|e| history_err(format_args!("genesis signatures: {e}")))?;
        Ok(Self { trust_base: tb, id: sha256(raw) })
    }
}

fn check_unit_committee(tb: &TrustBase) -> Result<()> {
    if tb.nodes.is_empty() {
        return Err(history_err("empty committee"));
    }
    for (i, n) in tb.nodes.iter().enumerate() {
        if n.id.is_empty() || n.weight != 1 || !valid_key(&n.key) {
            return Err(history_err(format_args!("genesis member {i} is not a valid unit member")));
        }
        if i > 0 && tb.nodes[i - 1].id >= n.id {
            return Err(history_err("genesis members are not strictly ordered by node id"));
        }
    }
    let total = tb.nodes.len() as u64;
    let want = 2 * total / 3 + 1;
    if tb.threshold < want || tb.threshold > total {
        return Err(history_err(format_args!(
            "genesis threshold {}, want {want}..{total}",
            tb.threshold
        )));
    }
    Ok(())
}

/// The projected committee of a V3 epoch, for the scheme-2 verifier that follows.
pub(crate) fn project(
    members: &[crate::body::Member],
    network: u64,
    epoch: u64,
    start: u64,
    threshold: u64,
) -> TrustBase {
    let mut nodes: Vec<Node> = members
        .iter()
        .map(|m| Node { id: m.node_id.clone(), key: m.consensus_key.clone(), weight: m.weight })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    TrustBase { network, epoch, epoch_start: start, nodes, threshold }
}
