//! Candidate-bound readiness receipts (`q3format/receipt.go`): the exact bytes a successor member's
//! root key signs, and the check that every successor member signed exactly once.

use crate::{
    body::BodyV3,
    cbor::Writer,
    error::{Error, Kind, Result},
    sig::verify,
};
use std::collections::{HashMap, HashSet};

const RECEIPT_DOMAIN: &str = "UNICITY_Q3_READINESS_V1";

/// What one readiness receipt is bound to: the chain (network and root genesis), the predecessor
/// and attempt of the handoff, the candidate digest, the V3 body identity and the identity of the
/// required protocol tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptContext {
    /// Network identifier.
    pub network: u64,
    /// Root genesis identity.
    pub genesis: [u8; 32],
    /// The body's predecessor hash.
    pub predecessor: [u8; 32],
    /// Handoff attempt.
    pub attempt: u64,
    /// Candidate digest.
    pub candidate_digest: [u8; 32],
    /// V3 body identity.
    pub body_id: [u8; 32],
    /// Protocol tuple identity.
    pub config: [u8; 32],
}

impl ReceiptContext {
    /// The receipt context of `body` for a handoff attempt and candidate. The predecessor is the
    /// body's own.
    pub fn for_body(body: &BodyV3, attempt: u64, candidate_digest: [u8; 32]) -> Self {
        let mut predecessor = [0u8; 32];
        let n = body.predecessor_hash.len().min(32);
        predecessor[..n].copy_from_slice(&body.predecessor_hash[..n]);
        Self {
            network: body.network,
            genesis: body.config.genesis,
            predecessor,
            attempt,
            candidate_digest,
            body_id: body.identity(),
            config: body.config.identity(),
        }
    }

    /// The exact bytes the root key of `node_id` signs.
    pub fn message(&self, node_id: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(10)
            .text(RECEIPT_DOMAIN)
            .uint(1)
            .uint(self.network)
            .bytes(&self.genesis)
            .bytes(&self.predecessor)
            .uint(self.attempt)
            .bytes(&self.candidate_digest)
            .bytes(&self.body_id)
            .bytes(&self.config)
            .text(node_id);
        w.finish()
    }
}

/// One successor member's signed readiness declaration; an accountable statement, not an
/// attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The member's node id.
    pub node_id: String,
    /// The signature over [`ReceiptContext::message`].
    pub signature: Vec<u8>,
}

/// Requires `ctx` to be the context of `body`, then exactly one valid receipt from every successor
/// member: a missing, duplicate or unknown signer, or a signature by another key, is refused.
pub fn verify_receipts(body: &BodyV3, ctx: &ReceiptContext, receipts: &[Receipt]) -> Result<()> {
    body.validate()?;
    if *ctx != ReceiptContext::for_body(body, ctx.attempt, ctx.candidate_digest) {
        return Err(Error::new(Kind::ReceiptContext, "readiness context does not match the body"));
    }
    let members: HashMap<&str, &[u8]> =
        body.members.iter().map(|m| (m.node_id.as_str(), m.consensus_key.as_slice())).collect();
    let mut seen = HashSet::new();
    for r in receipts {
        let Some(key) = members.get(r.node_id.as_str()) else {
            return Err(Error::new(Kind::ReceiptUnknown, format_args!("{:?}", r.node_id)));
        };
        if !seen.insert(r.node_id.as_str()) {
            return Err(Error::new(Kind::ReceiptDuplicate, format_args!("{:?}", r.node_id)));
        }
        if !verify(key, &ctx.message(&r.node_id), &r.signature) {
            return Err(Error::new(Kind::ReceiptSignature, format_args!("{:?}", r.node_id)));
        }
    }
    for m in &body.members {
        if !seen.contains(m.node_id.as_str()) {
            return Err(Error::new(Kind::ReceiptMissing, format_args!("{:?}", m.node_id)));
        }
    }
    Ok(())
}
