//! The old-committee commit proof (`handoff/old_commit_proof.go`): the committed handoff record,
//! the control leaf that carries it, the unicity-tree path from that leaf to the state root a
//! root-chain quorum certificate signed, and the certificate itself, verified under the
//! **previous** epoch's committee.

use crate::{
    cbor::{parse, Items, Limits, Value, Writer},
    envelope::MAX_OLD_COMMIT_PROOF,
    error::{format, Error, Kind, Result},
    sig::sha256,
    trustbase::{Signatures, TrustBase},
};

/// The D4 profile of the proof.
const D4_PROFILE: u64 = 2;
/// The control partition: the reserved leaf of the unicity tree that carries the handoff control
/// state.
const CONTROL_PARTITION: u64 = 0xffff_ffff;
/// The minimum distance between the ordered round and the activation round.
const PIPELINE_DEPTH: u64 = 3;
/// go-base tags.
const TREE_CERT_TAG: u64 = 39004;
const SEAL_TAG: u64 = 39005;
const ROUND_INFO_TAG: u64 = 39007;
/// The earliest valid certificate timestamp (go-base `GenesisTime`).
const GENESIS_TIME: u64 = 1_681_971_084;
const GENESIS_ROOT_ROUND: u64 = 1;
const LIMITS: Limits = Limits { bytes: MAX_OLD_COMMIT_PROOF, depth: 12, array: 4096, map: 1024 };

fn proof_err(detail: impl std::fmt::Display) -> Error {
    Error::new(Kind::Activation, detail)
}

/// The ordered handoff record the old committee committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) network: u64,
    pub(crate) epoch: u64,
    pub(crate) attempt: u64,
    pub(crate) ordered_round: u64,
    pub(crate) activation_round: u64,
    pub(crate) predecessor_body_id: Vec<u8>,
    pub(crate) frozen_id: Vec<u8>,
    pub(crate) next_body_id: Vec<u8>,
    pub(crate) successor_tr_hash: Vec<u8>,
    pub(crate) kind: String,
}

impl Record {
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(9)
            .text("UNICITY_ORDERED_HANDOFF_RECORD")
            .uint(1)
            .uint(self.network)
            .uint(self.epoch)
            .bytes(&self.predecessor_body_id)
            .uint(self.attempt)
            .text(&self.kind)
            .uint(self.ordered_round)
            .array(4)
            .bytes(&self.frozen_id)
            .bytes(&self.next_body_id)
            .uint(self.activation_round)
            .bytes(&self.successor_tr_hash);
        w.finish()
    }

    /// The activation commit id: SHA-256 of the record's canonical bytes.
    pub(crate) fn id(&self) -> [u8; 32] {
        sha256(&self.bytes())
    }

    fn valid(&self) -> bool {
        self.kind == "commit" &&
            self.ordered_round > 0 &&
            self.activation_round >= self.ordered_round &&
            self.activation_round - self.ordered_round >= PIPELINE_DEPTH &&
            [
                &self.predecessor_body_id,
                &self.frozen_id,
                &self.next_body_id,
                &self.successor_tr_hash,
            ]
            .iter()
            .all(|b| b.len() == 32)
    }
}

/// The handoff control leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Control {
    network: u64,
    epoch: u64,
    attempt: u64,
    ordered_round: u64,
    predecessor_body_id: Vec<u8>,
    phase: String,
    record_bytes: Vec<u8>,
    previous_digest: Vec<u8>,
    frozen_parent: Vec<u8>,
}

impl Control {
    fn bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(if self.frozen_parent.is_empty() { 10 } else { 11 })
            .text("UNICITY_ROOT_HANDOFF_STATE")
            .uint(1)
            .uint(self.network)
            .uint(self.epoch)
            .bytes(&self.predecessor_body_id)
            .uint(self.attempt)
            .text(&self.phase)
            .uint(self.ordered_round)
            .bytes(&self.record_bytes)
            .bytes(&self.previous_digest);
        if !self.frozen_parent.is_empty() {
            w.bytes(&self.frozen_parent);
        }
        w.finish()
    }

    fn digest(&self) -> [u8; 32] {
        sha256(&self.bytes())
    }

    fn matches(&self, r: &Record) -> bool {
        self.phase == "committed" &&
            self.network == r.network &&
            self.epoch == r.epoch &&
            self.attempt == r.attempt &&
            self.ordered_round == r.ordered_round &&
            self.predecessor_body_id == r.predecessor_body_id &&
            self.record_bytes == r.bytes()
    }
}

/// A root-chain round info (`RoundInfo`).
#[derive(Clone, Debug)]
struct VoteInfo {
    version: u64,
    round: u64,
    epoch: u64,
    timestamp: u64,
    parent: u64,
    root_hash: Vec<u8>,
}

impl VoteInfo {
    fn hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.tag(ROUND_INFO_TAG)
            .array(6)
            .uint(self.version)
            .uint(self.round)
            .uint(self.epoch)
            .uint(self.timestamp)
            .uint(self.parent)
            .opt_bytes((!self.root_hash.is_empty()).then_some(self.root_hash.as_slice()));
        sha256(&w.finish())
    }

    /// `RoundInfo.IsValid`.
    const fn is_valid(&self) -> bool {
        self.round != 0 &&
            !(self.parent == 0 && self.round > 1) &&
            self.round > self.parent &&
            self.timestamp != 0
    }
}

/// A unicity seal, as the ledger commit info of a quorum certificate (its signature map is never
/// signed).
#[derive(Clone, Debug)]
struct Seal {
    version: u64,
    network: u64,
    round: u64,
    epoch: u64,
    timestamp: u64,
    previous_hash: Vec<u8>,
    hash: Vec<u8>,
}

impl Seal {
    /// `UnicitySeal.SigBytes`: the seal with its signature map null.
    fn sig_bytes(&self) -> Vec<u8> {
        let nz = |b: &[u8]| (!b.is_empty()).then_some(b.to_vec());
        let mut w = Writer::new();
        w.tag(SEAL_TAG)
            .array(8)
            .uint(self.version)
            .uint(self.network)
            .uint(self.round)
            .uint(self.epoch)
            .uint(self.timestamp)
            .opt_bytes(nz(&self.previous_hash).as_deref())
            .opt_bytes(nz(&self.hash).as_deref())
            .null();
        w.finish()
    }
}

/// A root-chain quorum certificate (`QuorumCert`).
#[derive(Clone, Debug)]
struct Qc {
    vote: Option<VoteInfo>,
    seal: Option<Seal>,
    signatures: Signatures,
}

/// A decoded, canonical old-commit proof.
#[derive(Clone, Debug)]
pub(crate) struct OldCommitProof {
    profile: u64,
    record: Record,
    control: Control,
    path: Option<Path>,
    commit_qc: Option<Qc>,
    optional_qc: Option<Qc>,
}

#[derive(Clone, Debug)]
struct Path {
    partition: u64,
    steps: Vec<(u64, Vec<u8>)>,
}

/// What a verified proof establishes; the caller compares it with the body, predecessor and
/// candidate.
pub(crate) struct Verified {
    pub(crate) record_id: [u8; 32],
    pub(crate) state_root: [u8; 32],
    pub(crate) control_digest: [u8; 32],
}

fn uint(v: &Value) -> Result<u64> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(format("expected an unsigned integer")),
    }
}

fn bytes_or_null(v: &Value) -> Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        Value::Null => Ok(Vec::new()),
        _ => Err(format("expected a byte string or null")),
    }
}

fn text(v: &Value) -> Result<String> {
    match v {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(format("expected a text string")),
    }
}

/// A map with exactly the given text keys (a Go struct without a toarray tag); values come back in
/// key order. Anything else cannot re-encode to the same bytes, which Go refuses as noncanonical.
fn struct_map<'a>(v: &'a Value, keys: &[&str]) -> Result<Vec<&'a Value>> {
    let Value::Map(pairs) = v else {
        return Err(format("expected a struct map"));
    };
    if pairs.len() != keys.len() {
        return Err(format("struct map with the wrong set of fields"));
    }
    keys.iter()
        .map(|k| {
            pairs
                .iter()
                .find_map(|(pk, pv)| matches!(pk, Value::Text(t) if t == k).then_some(pv))
                .ok_or_else(|| format(format_args!("struct map without field {k}")))
        })
        .collect()
}

fn read_record(v: &Value) -> Result<Record> {
    let f = struct_map(
        v,
        &[
            "Network",
            "Epoch",
            "Attempt",
            "OrderedRound",
            "ActivationRound",
            "PredecessorBodyID",
            "FrozenID",
            "NextBodyID",
            "SuccessorTRHash",
            "Kind",
        ],
    )?;
    Ok(Record {
        network: uint(f[0])?,
        epoch: uint(f[1])?,
        attempt: uint(f[2])?,
        ordered_round: uint(f[3])?,
        activation_round: uint(f[4])?,
        predecessor_body_id: bytes_or_null(f[5])?,
        frozen_id: bytes_or_null(f[6])?,
        next_body_id: bytes_or_null(f[7])?,
        successor_tr_hash: bytes_or_null(f[8])?,
        kind: text(f[9])?,
    })
}

fn read_control(v: &Value) -> Result<Control> {
    let f = struct_map(
        v,
        &[
            "Network",
            "Epoch",
            "Attempt",
            "OrderedRound",
            "PredecessorBodyID",
            "Phase",
            "RecordBytes",
            "PreviousDigest",
            "FrozenParent",
        ],
    )?;
    Ok(Control {
        network: uint(f[0])?,
        epoch: uint(f[1])?,
        attempt: uint(f[2])?,
        ordered_round: uint(f[3])?,
        predecessor_body_id: bytes_or_null(f[4])?,
        phase: text(f[5])?,
        record_bytes: bytes_or_null(f[6])?,
        previous_digest: bytes_or_null(f[7])?,
        frozen_parent: bytes_or_null(f[8])?,
    })
}

/// go-base decodes only version 1 of these structures; any other version fails the decode.
fn versioned(version: u64, what: &str) -> Result<u64> {
    if version == 1 {
        Ok(version)
    } else {
        Err(format(format_args!("{what} version {version}")))
    }
}

fn tagged<'a>(v: &'a Value, tag: u64, n: usize) -> Result<Items<'a>> {
    match v {
        Value::Tag(t, inner) if *t == tag => Items::of(inner, Some(n)),
        _ => Err(format(format_args!("expected tag {tag}"))),
    }
}

fn read_path(v: &Value) -> Result<Option<Path>> {
    if matches!(v, Value::Null) {
        return Ok(None);
    }
    let mut f = tagged(v, TREE_CERT_TAG, 3)?;
    let version = f.uint()?;
    let partition = f.uint()?;
    if version != 1 {
        return Err(format(format_args!("unicity tree certificate version {version}")));
    }
    if partition > u64::from(u32::MAX) {
        return Err(format("tree certificate field out of range"));
    }
    let mut steps = Vec::new();
    for s in f.array(4096)? {
        let mut s = Items::of(s, Some(2))?;
        let key = s.uint()?;
        if key > u64::from(u32::MAX) {
            return Err(format("path key out of range"));
        }
        steps.push((key, s.bytes_max(1024)?.to_vec()));
        s.done()?;
    }
    f.done()?;
    Ok(Some(Path { partition, steps }))
}

fn read_qc(v: &Value) -> Result<Option<Qc>> {
    if matches!(v, Value::Null) {
        return Ok(None);
    }
    let mut f = Items::of(v, Some(3))?;
    let vote = match f.take()? {
        Value::Null => None,
        v => {
            let mut r = tagged(v, ROUND_INFO_TAG, 6)?;
            let vi = VoteInfo {
                version: versioned(r.uint()?, "round info")?,
                round: r.uint()?,
                epoch: r.uint()?,
                timestamp: r.uint()?,
                parent: r.uint()?,
                root_hash: r.opt_bytes(usize::MAX)?.map(<[u8]>::to_vec).unwrap_or_default(),
            };
            r.done()?;
            Some(vi)
        }
    };
    let seal = match f.take()? {
        Value::Null => None,
        v => {
            let mut r = tagged(v, SEAL_TAG, 8)?;
            let s = Seal {
                version: versioned(r.uint()?, "unicity seal")?,
                network: r.uint()?,
                round: r.uint()?,
                epoch: r.uint()?,
                timestamp: r.uint()?,
                previous_hash: r.opt_bytes(usize::MAX)?.map(<[u8]>::to_vec).unwrap_or_default(),
                hash: r.opt_bytes(usize::MAX)?.map(<[u8]>::to_vec).unwrap_or_default(),
            };
            // the embedded seal's own signature map is never signed or used, but it is typed like
            // go-base's `SignatureMap` (text signer ids, byte-string signatures):
            // anything else fails Go's typed decode
            match r.take()? {
                Value::Null => {}
                Value::Map(pairs) => {
                    for (k, sig) in pairs {
                        if !matches!((k, sig), (Value::Text(_), Value::Bytes(_))) {
                            return Err(format(
                                "seal signature map entry is not (text, byte string)",
                            ));
                        }
                    }
                }
                _ => return Err(format("seal signatures")),
            }
            r.done()?;
            Some(s)
        }
    };
    let signatures = match f.take()? {
        Value::Null => Signatures::new(),
        Value::Map(pairs) => pairs
            .iter()
            .map(|(k, s)| match (k, s) {
                (Value::Text(k), Value::Bytes(s)) => Ok((k.clone(), s.clone())),
                _ => Err(format("quorum certificate signature entry")),
            })
            .collect::<Result<_>>()?,
        _ => return Err(format("quorum certificate signatures")),
    };
    Ok(Some(Qc { vote, seal, signatures }))
}

impl OldCommitProof {
    /// Decodes the canonical proof bytes. An empty or oversize proof is [`Kind::TooLarge`];
    /// anything that is not the canonical encoding of the proof structure is [`Kind::Format`].
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_OLD_COMMIT_PROOF {
            return Err(Error::new(Kind::TooLarge, format_args!("proof of {} bytes", raw.len())));
        }
        let v = parse(raw, LIMITS)?;
        let mut f = Items::of(&v, Some(6))?;
        let profile = f.uint()?;
        let record = read_record(f.take()?)?;
        let control = read_control(f.take()?)?;
        let path = read_path(f.take()?)?;
        let commit_qc = read_qc(f.take()?)?;
        let optional_qc = read_qc(f.take()?)?;
        f.done()?;
        Ok(Self { profile, record, control, path, commit_qc, optional_qc })
    }

    /// The record the proof commits.
    pub(crate) const fn record(&self) -> &Record {
        &self.record
    }

    /// Verifies the proof under the **previous** epoch's committee `tb`: the record, the control
    /// leaf that carries it, the path from that leaf to the signed state root, the commit QC's
    /// rounds, epoch, network and timestamps, and a strict quorum of the committee's signatures
    /// on the commit info.
    pub(crate) fn verify(&self, tb: &TrustBase) -> Result<Verified> {
        let (p, r) = (self, &self.record);
        let zero = [0u8; 32];
        if p.profile != D4_PROFILE ||
            !r.valid() ||
            r.network != tb.network ||
            r.epoch != tb.epoch ||
            !p.control.matches(r) ||
            p.control.previous_digest.len() != 32 ||
            r.frozen_id == zero ||
            r.next_body_id == zero ||
            r.successor_tr_hash == zero
        {
            return Err(proof_err("record, profile or control leaf"));
        }
        let path = p.path.as_ref().ok_or_else(|| proof_err("no control path"))?;
        if path.partition != CONTROL_PARTITION {
            return Err(proof_err("control path partition"));
        }
        let digest = p.control.digest();
        let mut w = Writer::new();
        w.bytes(&digest);
        let leaf_hash = sha256(&w.finish());
        if path.steps.iter().any(|(key, _)| *key == CONTROL_PARTITION) {
            return Err(proof_err("control partition inside its own path"));
        }
        let root = index_tree_output(&leaf_hash, &path.steps);
        let (Some(qc), Some(vote), Some(seal)) = (
            p.commit_qc.as_ref(),
            p.commit_qc.as_ref().and_then(|q| q.vote.as_ref()),
            p.commit_qc.as_ref().and_then(|q| q.seal.as_ref()),
        ) else {
            return Err(proof_err("no commit certificate"));
        };
        let c = seal.round;
        if c == 0 ||
            c < r.ordered_round ||
            c == u64::MAX ||
            vote.round != c + 1 ||
            vote.parent != c ||
            vote.epoch != r.epoch ||
            vote.timestamp == 0 ||
            seal.network != tb.network ||
            seal.epoch != r.epoch ||
            seal.timestamp == 0 ||
            seal.timestamp > vote.timestamp ||
            seal.hash != root ||
            vote.root_hash != root
        {
            return Err(proof_err("commit certificate does not carry the control root"));
        }
        verify_old_qc(qc, tb)?;
        if let Some(opt) = &p.optional_qc {
            let Some(ov) = &opt.vote else {
                return Err(proof_err("optional certificate without vote info"));
            };
            if ov.round != c ||
                ov.epoch != r.epoch ||
                ov.timestamp != seal.timestamp ||
                ov.root_hash != root
            {
                return Err(proof_err("optional certificate does not match the commit"));
            }
            verify_old_qc(opt, tb)?;
        }
        Ok(Verified { record_id: r.id(), state_root: root, control_digest: digest })
    }
}

/// `verifyOldQC`: structure, vote-info hash chain and a strict signature quorum under the old
/// committee.
fn verify_old_qc(qc: &Qc, tb: &TrustBase) -> Result<()> {
    let (Some(vote), Some(seal)) = (&qc.vote, &qc.seal) else {
        return Err(proof_err("certificate without vote or commit info"));
    };
    if vote.round <= GENESIS_ROOT_ROUND || qc.signatures.is_empty() {
        return Err(proof_err("genesis-round or unsigned certificate"));
    }
    if vote.timestamp < GENESIS_TIME || seal.timestamp < GENESIS_TIME {
        return Err(proof_err("certificate timestamp before the genesis time"));
    }
    if !vote.is_valid() || seal.previous_hash.is_empty() {
        return Err(proof_err("invalid vote info"));
    }
    if vote.hash().as_slice() != seal.previous_hash.as_slice() {
        return Err(proof_err("vote info hash differs from the commit info's previous hash"));
    }
    tb.verify_signed(&seal.sig_bytes(), &qc.signatures, true)
        .map(drop)
        .map_err(|e| proof_err(format_args!("quorum: {e}")))
}

/// `imt.IndexTreeOutput` for the control partition's key: the root of an indexed Merkle path,
/// hashing CBOR byte strings as go-base does. `leaf_hash` is the data hash of the control leaf.
fn index_tree_output(leaf_hash: &[u8], steps: &[(u64, Vec<u8>)]) -> [u8; 32] {
    let part = |k: u64| u32::try_from(k).unwrap_or(u32::MAX).to_be_bytes();
    let h = |tag: u8, parts: &[&[u8]]| {
        let mut w = Writer::new();
        w.bytes(&[tag]);
        for p in parts {
            w.bytes(p);
        }
        sha256(&w.finish())
    };
    let key = part(CONTROL_PARTITION);
    let mut acc = h(1, &[&key, leaf_hash]);
    for (k, hash) in steps {
        let k = part(*k);
        acc = if key > k { h(0, &[&k, hash, &acc]) } else { h(0, &[&k, &acc, hash]) };
    }
    acc
}
