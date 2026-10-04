//! secp256k1 verification with the semantics of go-base's `VerifyBytes`: the data is hashed with
//! SHA-256, a 65-byte signature loses its recovery byte, and the 64-byte compact form must be low-S
//! (libsecp256k1 refuses high-S), so a signature Go refuses is refused here too.

use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub(crate) const KEY_LEN: usize = 33;

/// SHA-256 of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Whether `key` is a valid 33-byte compressed secp256k1 public key.
pub(crate) fn valid_key(key: &[u8]) -> bool {
    key.len() == KEY_LEN && VerifyingKey::from_sec1_bytes(key).is_ok()
}

fn compact(sig: &[u8]) -> Option<Signature> {
    let sig = if sig.len() == 65 { &sig[..64] } else { sig };
    let s = Signature::from_slice(sig).ok()?;
    s.normalize_s().is_none().then_some(s)
}

/// Whether `sig` is a valid signature of SHA-256(`data`) under the compressed public key `key`.
pub(crate) fn verify(key: &[u8], data: &[u8], sig: &[u8]) -> bool {
    verify_prehash(key, &sha256(data), sig)
}

/// Whether `sig` is a valid signature of the 32-byte digest under `key`.
pub(crate) fn verify_prehash(key: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
    let (Some(s), Ok(k)) = (compact(sig), VerifyingKey::from_sec1_bytes(key)) else {
        return false;
    };
    k.verify_prehash(digest, &s).is_ok()
}

/// Recovers the compressed public key from a 65-byte `R || S || V` signature of the digest.
pub(crate) fn recover(digest: &[u8; 32], sig: &[u8]) -> Option<[u8; KEY_LEN]> {
    if sig.len() != 65 {
        return None;
    }
    let s = compact(sig)?;
    let id = RecoveryId::from_byte(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(digest, &s, id).ok()?;
    key.to_encoded_point(true).as_bytes().try_into().ok()
}
