//! The domain-bound signing scheme of root votes and timeouts (Q1 signing scheme 2): the exact
//! bytes that are signed and the signature checks, byte-for-byte those of bft-core's
//! `rootchain/consensus/votesig`.
//!
//! Nothing here activates scheme 2. The lineage verifier refuses a link whose previous epoch signed
//! under scheme 2 ([`crate::Kind::Scheme`]); these encoders exist so Ureth can check the Q1 vectors
//! now and so the scheme-2 commit verifier has one oracle to be built on.

use crate::{
    cbor::Writer,
    error::{Error, Kind, Result},
    sig::{sha256, verify},
};

/// Every message signed before the activation boundary.
pub const SCHEME_LEGACY: u64 = 1;
/// The domain-bound scheme.
pub const SCHEME_DOMAIN_BOUND: u64 = 2;
const VOTE_TAG: &str = "UNICITY_POS_VOTE";
const TIMEOUT_TAG: &str = "UNICITY_POS_TIMEOUT";

fn statement(detail: impl std::fmt::Display) -> Error {
    Error::new(Kind::Statement, detail)
}

/// The authenticated signing configuration of one root epoch: the network and the fixed root-chain
/// genesis identity G (pinned by the genesis configuration, not the changing epoch-anchor id).
/// Scheme 2 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Network identifier.
    pub network: u64,
    /// The root-chain genesis identity G.
    pub genesis: [u8; 32],
}

/// The signed consensus round data, `VI = C([N, Dv, votingEpoch, votingRound, parentRound,
/// execStateHash])`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteInfo {
    /// Voting epoch.
    pub epoch: u64,
    /// Voting round.
    pub round: u64,
    /// Parent round.
    pub parent: u64,
    /// Execution state hash.
    pub exec: [u8; 32],
}

/// The commit side of a vote. A non-committing vote has no hash and round 0; a half-empty pair is
/// refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    /// The committed state hash.
    pub hash: Option<[u8; 32]>,
    /// The committed root round.
    pub round: u64,
}

/// The epoch anchor an anchor timeout names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Anchor genesis id.
    pub genesis_id: [u8; 32],
    /// Anchor epoch.
    pub epoch: u64,
    /// Anchor slot.
    pub slot: u64,
}

/// The signed timeout statement. `anchor` is `None` for a normal timeout, whose `high_qc_round` is
/// the verified round of the signer's high QC; for an anchor timeout `epoch` is the anchor epoch
/// and `high_qc_round` the slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeout {
    /// Timeout epoch.
    pub epoch: u64,
    /// Timeout round.
    pub round: u64,
    /// The signer's high QC round.
    pub high_qc_round: u64,
    /// The anchor, for an anchor timeout.
    pub anchor: Option<Anchor>,
    /// The signing author.
    pub author: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Config {
    /// `Dv = "root-vote/" + lowercase hex(G)`.
    pub fn vote_domain(&self) -> String {
        format!("root-vote/{}", hex(&self.genesis))
    }

    /// `Dt = "root-timeout/" + lowercase hex(G)`.
    pub fn timeout_domain(&self) -> String {
        format!("root-timeout/{}", hex(&self.genesis))
    }

    fn require_genesis(&self) -> Result<()> {
        if self.genesis == [0; 32] {
            return Err(Error::new(Kind::Config, "scheme 2 needs a root-chain genesis identity"));
        }
        Ok(())
    }

    /// `VI`.
    pub fn vote_info_bytes(&self, v: &VoteInfo) -> Result<Vec<u8>> {
        self.require_genesis()?;
        if v.round == 0 {
            return Err(statement("voting round is zero"));
        }
        if v.parent >= v.round {
            return Err(statement(format_args!(
                "parent round {} is not below voting round {}",
                v.parent, v.round
            )));
        }
        let mut w = Writer::new();
        w.array(6)
            .uint(self.network)
            .text(&self.vote_domain())
            .uint(v.epoch)
            .uint(v.round)
            .uint(v.parent)
            .bytes(&v.exec);
        Ok(w.finish())
    }

    /// `VH = SHA-256(VI)`, the value `LedgerCommitInfo.PreviousHash` must carry.
    pub fn vote_info_hash(&self, v: &VoteInfo) -> Result<[u8; 32]> {
        Ok(sha256(&self.vote_info_bytes(v)?))
    }

    /// `PV = C(["UNICITY_POS_VOTE", N, Dv, VH, commitStateHash|null, commitRound])`. The vote
    /// signature is the secp256k1 signature of this byte string (the signer hashes it with
    /// SHA-256 itself).
    pub fn vote_preimage(&self, v: &VoteInfo, m: &Commit) -> Result<Vec<u8>> {
        let vh = self.vote_info_hash(v)?;
        match (&m.hash, m.round) {
            (None, 0) => {}
            (Some(_), r) if r != 0 && r < v.round => {}
            (Some(_), r) if r >= v.round => {
                return Err(statement(format_args!(
                    "commit round {r} is not below voting round {}",
                    v.round
                )))
            }
            _ => return Err(statement("half-empty commit pair")),
        }
        let mut w = Writer::new();
        w.array(6)
            .text(VOTE_TAG)
            .uint(self.network)
            .text(&self.vote_domain())
            .bytes(&vh)
            .opt_bytes(m.hash.as_ref().map(<[u8; 32]>::as_slice))
            .uint(m.round);
        Ok(w.finish())
    }

    /// `PT = C(["UNICITY_POS_TIMEOUT", N, Dt, epoch, round, signerHighQCRound, A, author])` with `A
    /// = null` or `[anchor.genesisId, anchor.epoch, anchor.slot]`.
    pub fn timeout_preimage(&self, t: &Timeout) -> Result<Vec<u8>> {
        self.require_genesis()?;
        if t.author.is_empty() {
            return Err(statement("timeout author is empty"));
        }
        if t.round <= t.high_qc_round {
            return Err(statement(format_args!(
                "timeout round {} does not exceed high QC round {}",
                t.round, t.high_qc_round
            )));
        }
        if t.anchor.is_some_and(|anchor| (anchor.epoch, anchor.slot) != (t.epoch, t.high_qc_round))
        {
            return Err(statement("anchor timeout must carry the anchor epoch and slot"));
        }
        let mut w = Writer::new();
        w.array(8)
            .text(TIMEOUT_TAG)
            .uint(self.network)
            .text(&self.timeout_domain())
            .uint(t.epoch)
            .uint(t.round)
            .uint(t.high_qc_round);
        match t.anchor {
            None => w.null(),
            Some(a) => w.array(3).bytes(&a.genesis_id).uint(a.epoch).uint(a.slot),
        };
        w.text(&t.author);
        Ok(w.finish())
    }
}

/// Accepts a 64-byte signature or a 65-byte one whose recovery byte is 0 or 1.
pub fn check_signature_shape(sig: &[u8]) -> Result<()> {
    match sig.len() {
        64 => Ok(()),
        65 if sig[64] <= 1 => Ok(()),
        n => Err(Error::new(
            Kind::Format,
            format_args!("signature of {n} bytes or with a bad recovery byte"),
        )),
    }
}

/// `H(preimage)`, the value a digest-taking signer API receives.
pub fn digest(preimage: &[u8]) -> [u8; 32] {
    sha256(preimage)
}

/// Whether `signature` is a valid signature of `preimage` (hashed with SHA-256) under the
/// compressed `key`, with the scheme-2 shape rule applied first.
pub fn verify_preimage(key: &[u8], preimage: &[u8], signature: &[u8]) -> bool {
    check_signature_shape(signature).is_ok() && verify(key, preimage, signature)
}

/// The compressed public key that produced a 65-byte `R || S || V` signature of `preimage`,
/// recovered from the signature itself. It does not authenticate the signer: the caller compares it
/// with a trusted committee key.
pub fn recover_signer(preimage: &[u8], signature: &[u8]) -> Option<[u8; 33]> {
    crate::sig::recover(&sha256(preimage), signature)
}
