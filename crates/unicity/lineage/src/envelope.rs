//! `Q3ExecutionProofV1` (`q3format/envelope.go`): the bounded, versioned, proof-bearing companion.
//!
//! Decoding is not authentication. [`Envelope::decode`] only reads the bytes within the limits; the
//! lineage it carries is authenticated by [`crate::History::verify_envelope`].

use crate::{
    body::{BodyV3, MAX_MEMBERS},
    cbor::{parse, Items, Limits},
    error::{format, Error, Kind, Result},
    receipt::Receipt,
};

/// The envelope version.
pub const ENVELOPE_VERSION: u64 = 1;
/// At most 64 lineage links per envelope; a longer history travels in consecutive segments.
pub const MAX_LINKS: usize = 64;
/// At most 16 MiB per envelope.
pub const MAX_ENVELOPE_BYTES: usize = 16 << 20;
/// At most 64 compact transitions.
pub const MAX_TRANSITIONS: usize = 64;
/// At most 1 MiB per old-commit proof.
pub const MAX_OLD_COMMIT_PROOF: usize = 1 << 20;
const ENVELOPE_DOMAIN: &str = "UNICITY_Q3_EXECUTION_PROOF";
const MAX_ROOT_INPUT: usize = 1 << 20;
const MAX_TRANSITION: usize = 64 << 10;
const MAX_EVIDENCE: usize = crate::body::MAX_FIELD;
const MAX_TEXT: usize = 64;
const MAX_SIGNATURE: usize = 128;

const LIMITS: Limits = Limits { bytes: MAX_ENVELOPE_BYTES, depth: 8, array: 1024, map: 0 };

/// The frozen-state input the committed record binds: the pre-freeze summary, the frozen EVM parent
/// and the candidate digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Pre-freeze summary.
    pub summary: Vec<u8>,
    /// Frozen EVM parent.
    pub frozen_parent: Vec<u8>,
    /// Candidate digest.
    pub candidate_digest: Vec<u8>,
}

/// What an envelope asserts about an entry; the verifier derives the same value and compares every
/// field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// Epoch.
    pub epoch: u64,
    /// The actual activation round A*.
    pub start: u64,
    /// V3 body identity.
    pub body_id: [u8; 32],
    /// Activation commit id (the committed record's id).
    pub commit_id: [u8; 32],
    /// Version of the predecessor body (1, 2 or 3).
    pub prior_version: u64,
    /// Predecessor identity.
    pub prior_id: [u8; 32],
}

/// Everything one V3 activation needs beyond the history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The V3 body.
    pub body: BodyV3,
    /// The evidence its candidate rests on.
    pub evidence: Evidence,
    /// Canonical `OldCommitProof` bytes of the previous committee.
    pub proof: Vec<u8>,
    /// Readiness receipts of every successor member, ordered by node id.
    pub receipts: Vec<Receipt>,
    /// The claim the sender makes about the result.
    pub claim: Claim,
}

/// The canonical root input and compact transitions an execution job rests on, the target EVM
/// parent (and the block, for an import or replay), and an ordered lineage segment. The
/// root-genesis anchor and the execution genesis are pinned locally and never supplied by an
/// envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Canonical root-input bytes (opaque here).
    pub root_input: Vec<u8>,
    /// Compact transitions (opaque here).
    pub transitions: Vec<Vec<u8>>,
    /// The target EVM parent identity.
    pub target_parent: [u8; 32],
    /// The block identity; `None` for a build job.
    pub block_id: Option<[u8; 32]>,
    /// Strictly consecutive epochs.
    pub links: Vec<Link>,
}

fn digest(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| format("expected 32 bytes"))
}

impl Envelope {
    /// Parses a canonical envelope within the limits, checking every count and length before it is
    /// used. It refuses an unknown version, noncanonical or truncated bytes, an invalid
    /// embedded body, and links that are not strictly consecutive epochs, which also excludes
    /// duplicate and conflicting entries.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let v = parse(raw, LIMITS)?;
        let mut r = Items::of(&v, None)?;
        if r.text(MAX_TEXT)? != ENVELOPE_DOMAIN {
            return Err(Error::new(Kind::Version, "envelope domain"));
        }
        let version = r.uint()?;
        if version != ENVELOPE_VERSION {
            return Err(Error::new(Kind::Version, format_args!("envelope version {version}")));
        }
        let root_input = r.bytes_max(MAX_ROOT_INPUT)?.to_vec();
        let mut transitions = Vec::new();
        let mut t = Items::over(r.array(MAX_TRANSITIONS)?);
        for _ in 0..t.len() {
            transitions.push(t.bytes_max(MAX_TRANSITION)?.to_vec());
        }
        let target_parent = digest(r.bytes_exact(32)?)?;
        let block_id = match r.opt_bytes(32)? {
            None => None,
            Some(b) if b.len() == 32 => Some(digest(b)?),
            Some(b) => return Err(format(format_args!("block identity of {} bytes", b.len()))),
        };
        let mut links: Vec<Link> = Vec::new();
        for l in r.array(MAX_LINKS)? {
            let link = read_link(Items::of(l, Some(5))?)?;
            if links.last().is_some_and(|p| link.body.epoch != p.body.epoch.wrapping_add(1)) {
                return Err(Error::new(Kind::Envelope, "links must be consecutive epochs"));
            }
            links.push(link);
        }
        r.done()?;
        Ok(Self { root_input, transitions, target_parent, block_id, links })
    }
}

fn read_link(mut f: Items<'_>) -> Result<Link> {
    let body = f.bytes_max(MAX_ENVELOPE_BYTES)?;
    let mut c = f.sub(6)?;
    let claim = Claim {
        epoch: c.uint()?,
        start: c.uint()?,
        body_id: digest(c.bytes_exact(32)?)?,
        commit_id: digest(c.bytes_exact(32)?)?,
        prior_version: c.uint()?,
        prior_id: digest(c.bytes_exact(32)?)?,
    };
    let mut ev = f.sub(3)?;
    let evidence = Evidence {
        summary: ev.bytes_max(MAX_EVIDENCE)?.to_vec(),
        frozen_parent: ev.bytes_max(MAX_EVIDENCE)?.to_vec(),
        candidate_digest: ev.bytes_max(MAX_EVIDENCE)?.to_vec(),
    };
    let proof = f.bytes_max(MAX_OLD_COMMIT_PROOF)?.to_vec();
    let receipts = read_receipts(&mut f)?;
    c.done()?;
    ev.done()?;
    f.done()?;
    Ok(Link { body: BodyV3::decode(body)?, evidence, proof, receipts, claim })
}

/// Reads receipts strictly ordered by node id, at most [`MAX_MEMBERS`].
fn read_receipts(r: &mut Items<'_>) -> Result<Vec<Receipt>> {
    let mut out: Vec<Receipt> = Vec::new();
    for e in r.array(MAX_MEMBERS)? {
        let mut e = Items::of(e, Some(2))?;
        let rc = Receipt {
            node_id: e.text(MAX_TEXT)?.to_owned(),
            signature: e.bytes_max(MAX_SIGNATURE)?.to_vec(),
        };
        e.done()?;
        if out.last().is_some_and(|p| p.node_id.as_bytes() >= rc.node_id.as_bytes()) {
            return Err(format("receipts are not strictly ordered by node id"));
        }
        out.push(rc);
    }
    Ok(out)
}
