//! The explicit, ordered, verified chain of epochs from the pinned root genesis
//! (`q3format/history.go`).
//!
//! An [`Entry`] can be built only by [`History::new`] and [`History::with_v3`], each of which
//! authenticates it; a caller cannot construct an activation. The history is immutable: extending
//! it returns a copy.

use crate::{
    body::{BodyV3, Prior, BODY_VERSION},
    cbor::Writer,
    config::ProtocolConfig,
    envelope::{Claim, Envelope, Evidence, Link},
    error::{Error, Kind, Result},
    proof::{OldCommitProof, Record},
    receipt::{verify_receipts, ReceiptContext},
    sig::sha256,
    trustbase::{project, Genesis, TrustBase},
};

/// One verified epoch of the history.
#[derive(Clone, Debug)]
pub struct Entry {
    epoch: u64,
    start: u64,
    version: u64,
    scheme: u64,
    prior_version: u64,
    config: Option<ProtocolConfig>,
    body_id: [u8; 32],
    commit_id: [u8; 32],
    anchor_id: [u8; 32],
    prior_id: [u8; 32],
    tb: TrustBase,
}

impl Entry {
    /// The root epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The actual activation boundary A*.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// The body version: 1 for the genesis trust base, 3 for a V3 body.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// The explicit signing scheme of the epoch: 1 for every legacy epoch, the tuple's for a V3
    /// epoch.
    pub const fn scheme(&self) -> u64 {
        self.scheme
    }

    /// The body identity (the genesis id for epoch 1).
    pub const fn body_id(&self) -> [u8; 32] {
        self.body_id
    }

    /// The activation commit id: the id of the committed record that activated the epoch.
    pub const fn activation_commit_id(&self) -> [u8; 32] {
        self.commit_id
    }

    /// The epoch-anchor id, distinct from the body identity and the tuple identity.
    pub const fn anchor_id(&self) -> [u8; 32] {
        self.anchor_id
    }

    /// The protocol tuple of a V3 epoch; legacy epochs have none.
    pub const fn config(&self) -> Option<&ProtocolConfig> {
        self.config.as_ref()
    }

    /// The epoch-qualified coordinate the successor's first ordinary work is anchored at: `(E,
    /// A*-1)`. The genesis epoch has no predecessor to anchor on.
    pub const fn anchor(&self) -> (u64, u64) {
        if self.start == 0 {
            (self.epoch, 0)
        } else {
            (self.epoch, self.start - 1)
        }
    }

    const fn claim(&self) -> Claim {
        Claim {
            epoch: self.epoch,
            start: self.start,
            body_id: self.body_id,
            commit_id: self.commit_id,
            prior_version: self.prior_version,
            prior_id: self.prior_id,
        }
    }
}

/// The explicit, ordered, verified chain of epochs from the root genesis. Its network and genesis
/// identity are the authority every later body is checked against.
#[derive(Clone, Debug)]
pub struct History {
    network: u64,
    genesis: [u8; 32],
    entries: Vec<Entry>,
}

impl History {
    /// Starts a history at the locally pinned genesis trust base: epoch 1, a unit committee
    /// self-signed by a quorum of its own members. `pinned_id` is the SHA-256 of the canonical
    /// genesis encoding that the deployment pins; bytes with another identity are
    /// [`Kind::Genesis`]. No later bootstrap anchor exists.
    pub fn new(genesis_trust_base: &[u8], pinned_id: [u8; 32]) -> Result<Self> {
        if sha256(genesis_trust_base) != pinned_id {
            return Err(Error::new(Kind::Genesis, "genesis trust base is not the pinned one"));
        }
        let g = Genesis::decode(genesis_trust_base)?;
        let e = Entry {
            epoch: 1,
            start: g.trust_base.epoch_start,
            version: 1,
            scheme: 1,
            prior_version: 0,
            config: None,
            body_id: g.id,
            commit_id: [0; 32],
            anchor_id: [0; 32],
            prior_id: [0; 32],
            tb: g.trust_base.clone(),
        };
        Ok(Self { network: g.trust_base.network, genesis: g.id, entries: vec![e] })
    }

    /// The network authority bodies are checked against.
    pub const fn network(&self) -> u64 {
        self.network
    }

    /// The root-genesis identity.
    pub const fn genesis(&self) -> [u8; 32] {
        self.genesis
    }

    /// The latest verified entry.
    pub fn tip(&self) -> &Entry {
        self.entries.last().unwrap_or_else(|| unreachable!("a history always holds the genesis"))
    }

    /// The verified entry of an epoch, or [`Kind::UnknownEpoch`]. An absent epoch is never a legacy
    /// default.
    pub fn for_epoch(&self, epoch: u64) -> Result<&Entry> {
        self.entries
            .iter()
            .find(|e| e.epoch == epoch)
            .ok_or_else(|| Error::new(Kind::UnknownEpoch, format_args!("epoch {epoch}")))
    }

    /// The entry whose interval `[A*, next A*)` holds `round`.
    pub fn for_round(&self, round: u64) -> Result<&Entry> {
        self.entries
            .iter()
            .rev()
            .find(|e| round >= e.start)
            .ok_or_else(|| Error::new(Kind::UnknownEpoch, format_args!("round {round}")))
    }

    /// Admits ordinary work at `(epoch, round)` only inside the epoch's own interval. Old suffix
    /// certificates beyond A* are old handoff evidence, authenticated by the commit-proof
    /// verifier, never ordinary old work. Bare rounds are never compared across epochs.
    pub fn ordinary(&self, epoch: u64, round: u64) -> Result<()> {
        let e = self.for_epoch(epoch)?;
        if round < e.start {
            return Err(Error::new(
                Kind::OutsideInterval,
                format_args!("round {round} before A*={} of epoch {epoch}", e.start),
            ));
        }
        if let Ok(next) = self.for_epoch(epoch + 1) &&
            round >= next.start
        {
            return Err(Error::new(
                Kind::OutsideInterval,
                format_args!("round {round} at or after the boundary {}", next.start),
            ));
        }
        Ok(())
    }

    fn extend(&self, e: Entry) -> Self {
        let mut entries = self.entries.clone();
        entries.push(e);
        Self { network: self.network, genesis: self.genesis, entries }
    }

    /// Appends one V3 epoch. An activation is minted only from a record the previous epoch's
    /// committee committed: the previous epoch's keys, weights and scheme come solely from this
    /// history, the commit proof and its control leaf are verified under them, and only then
    /// are the record's body, predecessor, boundary and candidate compared with the presented
    /// link. The body's network and tuple are checked against the history authority, never
    /// against the link's own claim.
    pub fn with_v3(&self, l: &Link) -> Result<Self> {
        let (tip, b) = (self.tip(), &l.body);
        b.validate()?;
        if b.network != self.network {
            return Err(Error::new(
                Kind::Network,
                format_args!("body {}, authority {}", b.network, self.network),
            ));
        }
        if b.config.genesis != self.genesis {
            return Err(Error::new(
                Kind::Genesis,
                "root genesis differs from the history authority",
            ));
        }
        if b.epoch > tip.epoch + 1 {
            return Err(Error::new(
                Kind::MissingHistory,
                format_args!("epoch {} after {}", b.epoch, tip.epoch),
            ));
        }
        if b.epoch != tip.epoch + 1 {
            return Err(Error::new(
                Kind::History,
                format_args!("epoch {} does not follow {}", b.epoch, tip.epoch),
            ));
        }
        let prior = Prior {
            network: self.network,
            epoch: tip.epoch,
            body_version: tip.version,
            identity: tip.body_id.to_vec(),
        };
        if prior.hash().map_or(true, |want| want != b.predecessor_hash) {
            return Err(Error::new(Kind::Prior, "body predecessor is not the tip's"));
        }
        if tip.scheme != 1 {
            return Err(Error::new(Kind::Scheme, format_args!("scheme {}", tip.scheme)));
        }
        let p = OldCommitProof::decode(&l.proof)?;
        let v = p.verify(&tip.tb)?;
        let (r, id) = (p.record(), b.identity());
        if r.next_body_id != id {
            return Err(Error::new(Kind::Binding, "record names another body"));
        }
        if r.predecessor_body_id != tip.body_id {
            return Err(Error::new(Kind::Binding, "record names another predecessor"));
        }
        if r.activation_round < b.earliest_activation {
            return Err(Error::new(
                Kind::Binding,
                format_args!("A*={} before A_min={}", r.activation_round, b.earliest_activation),
            ));
        }
        if r.activation_round <= tip.start {
            return Err(Error::new(
                Kind::Binding,
                format_args!(
                    "A*={} does not follow the epoch start {}",
                    r.activation_round, tip.start
                ),
            ));
        }
        bind_candidate(b, r, &l.evidence)?;
        let candidate = <[u8; 32]>::try_from(l.evidence.candidate_digest.as_slice())
            .map_err(|_| Error::new(Kind::Binding, "candidate digest"))?;
        verify_receipts(b, &ReceiptContext::for_body(b, r.attempt, candidate), &l.receipts)?;
        let tb = project(&b.members, b.network, b.epoch, r.activation_round, b.root_threshold);
        let anchor = epoch_genesis_id(r, b, &v.state_root, &v.control_digest, &id, &v.record_id);
        let e = Entry {
            epoch: b.epoch,
            start: r.activation_round,
            version: BODY_VERSION,
            scheme: b.config.signing_scheme,
            prior_version: tip.version,
            config: Some(b.config.clone()),
            body_id: id,
            commit_id: v.record_id,
            anchor_id: anchor,
            prior_id: tip.body_id,
            tb,
        };
        Ok(self.extend(e))
    }

    /// Extends `self` with the envelope's lineage and returns the extended history, leaving `self`
    /// untouched. A link for an epoch the history already holds is a reference to a retained
    /// verified entry: it must be that entry exactly ([`Kind::Conflict`] otherwise). Any other
    /// link must extend the tip and passes [`History::with_v3`]; an epoch the history lacks,
    /// with nothing supplied before it, is [`Kind::MissingHistory`]. The envelope's claim for
    /// each link must equal the derived activation field for field. The result is rooted in the
    /// pinned genesis: no segment becomes a trust anchor.
    pub fn verify_envelope(&self, e: &Envelope) -> Result<Self> {
        let mut cur = self.clone();
        for l in &e.links {
            if let Ok(have) = cur.for_epoch(l.body.epoch) {
                if have.claim() != l.claim {
                    return Err(Error::new(Kind::Conflict, format_args!("epoch {}", l.body.epoch)));
                }
                continue;
            }
            let next = cur.with_v3(l)?;
            if next.tip().claim() != l.claim {
                return Err(Error::new(
                    Kind::Binding,
                    format_args!(
                        "claim for epoch {} differs from the derived activation",
                        l.body.epoch
                    ),
                ));
            }
            cur = next;
        }
        Ok(cur)
    }
}

/// The committed record's frozen identity and the body's change-record hash must be those of the
/// evidence: the same candidate, attempt, predecessor and boundary bound before the old committee
/// ordered the commit.
fn bind_candidate(b: &BodyV3, r: &Record, ev: &Evidence) -> Result<()> {
    let max = crate::body::MAX_FIELD;
    if ev.candidate_digest.len() != 32 ||
        ev.summary.is_empty() ||
        ev.frozen_parent.is_empty() ||
        ev.summary.len() > max ||
        ev.frozen_parent.len() > max
    {
        return Err(Error::new(Kind::Binding, "incomplete or oversize evidence"));
    }
    let id = b.identity();
    let mut w = Writer::new();
    w.array(7)
        .text("UNICITY_HANDOFF_FROZEN")
        .bytes(&id)
        .bytes(&ev.summary)
        .bytes(&ev.frozen_parent)
        .bytes(&ev.candidate_digest)
        .uint(r.attempt)
        .bytes(&r.predecessor_body_id);
    if sha256(&w.finish()).as_slice() != r.frozen_id.as_slice() {
        return Err(Error::new(Kind::Binding, "frozen identity"));
    }
    let mut w = Writer::new();
    w.array(7)
        .text("UNICITY_HANDOFF_CANDIDATE_CONTEXT")
        .uint(1)
        .uint(r.network)
        .bytes(&r.predecessor_body_id)
        .uint(r.attempt)
        .bytes(&ev.candidate_digest)
        .uint(b.earliest_activation);
    if sha256(&w.finish()).as_slice() != b.change_record_hash.as_slice() {
        return Err(Error::new(Kind::Binding, "candidate context"));
    }
    Ok(())
}

/// The id of the epoch-genesis checkpoint the successor is anchored at.
fn epoch_genesis_id(
    r: &Record,
    b: &BodyV3,
    root: &[u8],
    control_digest: &[u8],
    body_id: &[u8],
    record_id: &[u8],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.array(12)
        .text("UNICITY_EPOCH_GENESIS")
        .uint(1)
        .uint(r.network)
        .uint(b.epoch)
        .bytes(body_id)
        .uint(r.activation_round)
        .bytes(record_id)
        .uint(r.ordered_round)
        .bytes(root)
        .bytes(control_digest)
        .bytes(&r.frozen_id)
        .bytes(&r.successor_tr_hash);
    sha256(&w.finish())
}
