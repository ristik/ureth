//! Immutable configuration `Cfg` and every
//! cfg-bound derivation of the profile.

use std::vec::Vec;

use super::{
    error::{BridgeError as E, Result},
    h,
    scan::{scan_one, Item},
};
use crate::encode::{encode_array, encode_byte_string, encode_uint};

const CFG_DOMAIN: &[u8] = b"UNICITY_BR_CFG";

/// Immutable bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cfg {
    pub(crate) network: u16,
    pub(crate) root_genesis: [u8; 32],
    pub(crate) chain_id: u64,
    pub(crate) execution_genesis: [u8; 32],
    pub(crate) evm_partition: u32,
    pub(crate) evm_shard: Vec<u8>,
    pub(crate) vault: [u8; 20],
    pub(crate) zero_address: [u8; 20],
    pub(crate) ty: [u8; 32],
    pub(crate) aid: [u8; 32],
    pub(crate) semantic_profile_hash: [u8; 32],
    pub(crate) token_verifier_address: [u8; 20],
    pub(crate) token_verifier_code_hash: [u8; 32],
    pub(crate) b1_profile_hash: [u8; 32],
    pub(crate) aggregator_policy_hash: [u8; 32],
}

fn fixed<const N: usize>(it: &Item<'_>) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(it.bytes_n(N)?);
    Ok(out)
}

impl Cfg {
    /// The exact canonical Cfg encoding.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(CFG_DOMAIN),
            &encode_uint(self.network as u64),
            &encode_byte_string(&self.root_genesis),
            &encode_uint(self.chain_id),
            &encode_byte_string(&self.execution_genesis),
            &encode_uint(self.evm_partition as u64),
            &encode_byte_string(&self.evm_shard),
            &encode_byte_string(&self.vault),
            &encode_byte_string(&self.zero_address),
            &encode_byte_string(&self.ty),
            &encode_byte_string(&self.aid),
            &encode_byte_string(&self.semantic_profile_hash),
            &encode_byte_string(&self.token_verifier_address),
            &encode_byte_string(&self.token_verifier_code_hash),
            &encode_byte_string(&self.b1_profile_hash),
            &encode_byte_string(&self.aggregator_policy_hash),
        ])
    }

    /// `cfg = H(Cfg)`.
    pub(crate) fn hash(&self) -> [u8; 32] {
        h(&self.to_bytes())
    }

    /// Strictly decode Cfg bytes.
    pub(crate) fn from_bytes(b: &[u8]) -> Result<Self> {
        let root = scan_one(b)?;
        let k = root.array::<16>().map_err(|_| E::Shape)?;
        if k[0].bytes().map_err(|_| E::Shape)? != CFG_DOMAIN {
            return Err(E::Shape);
        }
        Ok(Self {
            network: k[1].uint_max(0xffff)? as u16,
            root_genesis: fixed(&k[2])?,
            chain_id: k[3].uint_max(u64::MAX)?,
            execution_genesis: fixed(&k[4])?,
            evm_partition: k[5].uint_max(0xffff_ffff)? as u32,
            evm_shard: k[6].bytes()?.to_vec(),
            vault: fixed(&k[7])?,
            zero_address: fixed(&k[8])?,
            ty: fixed(&k[9])?,
            aid: fixed(&k[10])?,
            semantic_profile_hash: fixed(&k[11])?,
            token_verifier_address: fixed(&k[12])?,
            token_verifier_code_hash: fixed(&k[13])?,
            b1_profile_hash: fixed(&k[14])?,
            aggregator_policy_hash: fixed(&k[15])?,
        })
    }
}

/// `salt = H(C("UNICITY_BR_SALT", b(cfg), n))`.
pub(crate) fn derive_salt(cfg: &[u8; 32], n: u64) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_SALT"),
        &encode_byte_string(cfg),
        &encode_uint(n),
    ]))
}

/// `id = H(C(b(salt), network))`.
pub(crate) fn derive_token_id(salt: &[u8; 32], network: u16) -> [u8; 32] {
    h(&encode_array(&[&encode_byte_string(salt), &encode_uint(network as u64)]))
}

/// Lock record `K = [b(zero), b(ty), b(aid), b(amount), b(id), b(rcpt)]`.
pub(crate) fn lock_record(
    zero: &[u8; 20],
    ty: &[u8; 32],
    aid: &[u8; 32],
    amount: &[u8],
    id: &[u8; 32],
    rcpt: &[u8; 32],
) -> Vec<u8> {
    encode_array(&[
        &encode_byte_string(zero),
        &encode_byte_string(ty),
        &encode_byte_string(aid),
        &encode_byte_string(amount),
        &encode_byte_string(id),
        &encode_byte_string(rcpt),
    ])
}

/// `d = H(C("UNICITY_BR_LOCK", b(cfg), n, K))`; binds cfg.
pub(crate) fn lock_digest(cfg: &[u8; 32], n: u64, k: &[u8]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_LOCK"),
        &encode_byte_string(cfg),
        &encode_uint(n),
        k,
    ]))
}

/// `btid = H(C("unicity-burn-transition:v1", b(sid), b(txHash)))`.
pub(crate) fn burn_id(sid: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"unicity-burn-transition:v1"),
        &encode_byte_string(sid),
        &encode_byte_string(tx_hash),
    ]))
}

/// `eta = H(C("UNICITY_BR_NUL", b(cfg), b(btid)))`.
pub(crate) fn nullifier(cfg: &[u8; 32], btid: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_NUL"),
        &encode_byte_string(cfg),
        &encode_byte_string(btid),
    ]))
}
