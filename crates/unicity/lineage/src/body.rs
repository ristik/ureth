//! The V3 trust-base body and its predecessor rule (`q3format/body.go`).

use crate::{
    cbor::{parse, Items, Limits, Value, Writer},
    config::ProtocolConfig,
    error::{format, Error, Kind, Result},
    sig::{sha256, valid_key, KEY_LEN},
};
use std::collections::HashSet;

/// The version of `TrustBaseBodyV3`.
pub const BODY_VERSION: u64 = 3;
const BODY_DOMAIN: &str = "UNICITY_TRUSTBASE_V3";
const TO_V3_DOMAIN: &str = "UNICITY_TRUSTBASE_TO_V3";
/// The member limit: the existing assignment limit, so a coupled root/EVM set always fits.
pub const MAX_MEMBERS: usize = 64;
const MAX_BODY_LEN: usize = 64 << 10;
const MAX_TEXT: usize = 64;
/// The longest optional byte field of a body.
pub(crate) const MAX_FIELD: usize = 64;
/// The weight of one member is at most 2^40.
pub const MAX_MEMBER_WEIGHT: u64 = 1 << 40;
/// The total weight is at most 2^48.
pub const MAX_TOTAL_WEIGHT: u64 = 1 << 48;

pub(crate) const FORMAT_LIMITS: Limits =
    Limits { bytes: MAX_BODY_LEN, depth: 8, array: 1024, map: 0 };

/// One root member of a body: staking identity, node identity, secp256k1 consensus key and weight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Staking identity.
    pub staking_id: String,
    /// Node identity.
    pub node_id: String,
    /// Compressed secp256k1 root key.
    pub consensus_key: Vec<u8>,
    /// Weight in `1..=2^40`.
    pub weight: u64,
}

/// The distinct canonical V3 body: every V2 semantic field plus the protocol tuple. It carries no
/// signature, endorsement or readiness witness, so its identity is stable across all of them. The
/// actual activation A* is not in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyV3 {
    /// Network identifier.
    pub network: u64,
    /// Root epoch the body activates.
    pub epoch: u64,
    /// `A_min`, a lower bound on the activation round.
    pub earliest_activation: u64,
    /// Root members; encoded sorted by node id.
    pub members: Vec<Member>,
    /// Exact weighted root threshold.
    pub root_threshold: u64,
    /// State summary.
    pub state_summary: Vec<u8>,
    /// Change-record hash.
    pub change_record_hash: Vec<u8>,
    /// Predecessor hash (see [`Prior::hash`]).
    pub predecessor_hash: Vec<u8>,
    /// The protocol tuple.
    pub config: ProtocolConfig,
}

fn body_err(detail: impl std::fmt::Display) -> Error {
    Error::new(Kind::Body, detail)
}

impl BodyV3 {
    /// The canonical body, `["UNICITY_TRUSTBASE_V3", fields]`: the V2 field array with version 3
    /// and the ordered protocol tuple appended as its final field, members sorted by node id as
    /// in V2.
    pub fn encode(&self) -> Vec<u8> {
        let mut members: Vec<&Member> = self.members.iter().collect();
        members.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        fn opt(v: &[u8]) -> Option<&[u8]> {
            (!v.is_empty()).then_some(v)
        }
        let mut w = Writer::new();
        w.array(2)
            .text(BODY_DOMAIN)
            .array(10)
            .uint(BODY_VERSION)
            .uint(self.network)
            .uint(self.epoch)
            .uint(self.earliest_activation);
        w.array(members.len());
        for m in members {
            w.array(4).text(&m.staking_id).text(&m.node_id).bytes(&m.consensus_key).uint(m.weight);
        }
        w.uint(self.root_threshold)
            .opt_bytes(opt(&self.state_summary))
            .opt_bytes(opt(&self.change_record_hash))
            .opt_bytes(opt(&self.predecessor_hash));
        self.config.write_fields(&mut w);
        w.finish()
    }

    /// SHA-256 of [`BodyV3::encode`].
    pub fn identity(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// The total member weight, with overflow refusal.
    fn total_weight(&self) -> Result<u64> {
        self.members
            .iter()
            .try_fold(0u64, |t, m| t.checked_add(m.weight))
            .filter(|t| *t <= MAX_TOTAL_WEIGHT)
            .ok_or_else(|| body_err("total weight above 2^48"))
    }

    /// Checks the tuple, that its network is the body's, the bounded weights and member identities,
    /// and that the recorded threshold is exactly the weighted one, `floor(2W/3)+1`.
    pub fn validate(&self) -> Result<()> {
        if self.epoch < 2 || self.earliest_activation == 0 || self.predecessor_hash.len() != 32 {
            return Err(body_err(
                "network, epoch, earliest activation and a 32-byte predecessor are required",
            ));
        }
        self.config.validate()?;
        if self.config.network != self.network {
            return Err(body_err(format_args!(
                "tuple network {} is not the body's {}",
                self.config.network, self.network
            )));
        }
        if self.members.len() > MAX_MEMBERS {
            return Err(Error::new(
                Kind::TooLarge,
                format_args!("{} members, limit {MAX_MEMBERS}", self.members.len()),
            ));
        }
        if self.members.is_empty() {
            return Err(body_err("empty member set"));
        }
        let (mut nodes, mut stakings, mut keys) = (HashSet::new(), HashSet::new(), HashSet::new());
        for m in &self.members {
            if m.node_id.is_empty() || m.staking_id.is_empty() {
                return Err(body_err("member with an empty node or staking identity"));
            }
            if m.consensus_key.len() != KEY_LEN || !valid_key(&m.consensus_key) {
                return Err(body_err(format_args!(
                    "member {:?} has an invalid consensus key",
                    m.node_id
                )));
            }
            if !nodes.insert(m.node_id.as_str()) ||
                !stakings.insert(m.staking_id.as_str()) ||
                !keys.insert(m.consensus_key.as_slice())
            {
                return Err(body_err(format_args!(
                    "member {:?} repeats a node id, staking id or key",
                    m.node_id
                )));
            }
            if m.weight == 0 || m.weight > MAX_MEMBER_WEIGHT {
                return Err(body_err(format_args!(
                    "member {:?} weight {} out of [1, 2^40]",
                    m.node_id, m.weight
                )));
            }
        }
        let total = self.total_weight()?;
        let want = 2 * total / 3 + 1;
        if self.root_threshold != want {
            return Err(body_err(format_args!(
                "threshold {}, want {want} of {total}",
                self.root_threshold
            )));
        }
        Ok(())
    }

    /// Parses a canonical V3 body and validates it. Another version is [`Kind::Version`], a
    /// noncanonical or oversize encoding [`Kind::Format`] or [`Kind::TooLarge`].
    pub fn decode(raw: &[u8]) -> Result<Self> {
        match body_version(raw)? {
            BODY_VERSION => {}
            v => return Err(Error::new(Kind::Version, format_args!("body version {v}"))),
        }
        let v = parse(raw, FORMAT_LIMITS)?;
        let mut r = Items::of(&v, None)?;
        if r.text(MAX_TEXT)? != BODY_DOMAIN {
            return Err(Error::new(Kind::Version, "body domain"));
        }
        let mut f = r.sub(10)?;
        r.done()?;
        let version = f.uint()?;
        if version != BODY_VERSION {
            return Err(Error::new(Kind::Version, format_args!("body version {version}")));
        }
        let network = f.uint()?;
        let epoch = f.uint()?;
        let earliest_activation = f.uint()?;
        let mut members = Vec::new();
        for m in f.array(MAX_MEMBERS)? {
            let mut m = Items::of(m, Some(4))?;
            members.push(Member {
                staking_id: m.text(MAX_TEXT)?.to_owned(),
                node_id: m.text(MAX_TEXT)?.to_owned(),
                consensus_key: m.bytes_exact(KEY_LEN)?.to_vec(),
                weight: m.uint()?,
            });
            m.done()?;
        }
        let root_threshold = f.uint()?;
        let opt = |o: Option<&[u8]>| o.map(<[u8]>::to_vec).unwrap_or_default();
        let state_summary = opt(f.opt_bytes(MAX_FIELD)?);
        let change_record_hash = opt(f.opt_bytes(MAX_FIELD)?);
        let predecessor_hash = opt(f.opt_bytes(MAX_FIELD)?);
        let config = ProtocolConfig::read(&mut f)?;
        f.done()?;
        let body = Self {
            network,
            epoch,
            earliest_activation,
            members,
            root_threshold,
            state_summary,
            change_record_hash,
            predecessor_hash,
            config,
        };
        // members are sorted by encode, so an unordered or noncanonical encoding differs here
        if body.encode() != raw {
            return Err(format("not the canonical encoding"));
        }
        body.validate()?;
        Ok(body)
    }
}

/// The body version of a canonical encoding: 3 for the V3 domain array, 2 for the V2 field array
/// (whose first field is its version). V1 is the go-base tagged trust base and is not a body.
/// Anything else is [`Kind::Version`].
pub fn body_version(raw: &[u8]) -> Result<u64> {
    let v = parse(raw, FORMAT_LIMITS)?;
    if let Value::Array(items) = &v {
        match items.first() {
            Some(Value::Text(t)) if t == BODY_DOMAIN => return Ok(3),
            Some(Value::Uint(2)) if items.len() == 9 => return Ok(2),
            _ => {}
        }
    }
    Err(Error::new(Kind::Version, "not a V2 or V3 body"))
}

/// Names the trust base a V3 body succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prior {
    /// Network identifier.
    pub network: u64,
    /// Epoch of the prior trust base.
    pub epoch: u64,
    /// 1 for a V1 trust base (identity includes signatures), 2 or 3 for a body identity.
    pub body_version: u64,
    /// The prior identity.
    pub identity: Vec<u8>,
}

impl Prior {
    /// The `predecessor_hash` a V3 body must carry: the identity of a V3 prior directly, and for
    /// the first V3 body `SHA256(CBOR(["UNICITY_TRUSTBASE_TO_V3", N, priorEpoch,
    /// priorBodyVersion, priorIdentity]))`, so that no V1 or V2 bytes are reinterpreted as V3.
    pub fn hash(&self) -> Result<Vec<u8>> {
        if self.network == 0 ||
            self.epoch == 0 ||
            self.identity.len() != 32 ||
            self.body_version < 1 ||
            self.body_version > BODY_VERSION
        {
            return Err(Error::new(
                Kind::Prior,
                "network, epoch, version 1..3 and a 32-byte identity are required",
            ));
        }
        if self.body_version == BODY_VERSION {
            return Ok(self.identity.clone());
        }
        let mut w = Writer::new();
        w.array(5)
            .text(TO_V3_DOMAIN)
            .uint(self.network)
            .uint(self.epoch)
            .uint(self.body_version)
            .bytes(&self.identity);
        Ok(sha256(&w.finish()).to_vec())
    }
}
