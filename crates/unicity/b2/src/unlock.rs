//! Token signatures deliberately differ from B1 seal suffix semantics.
use crate::{
    encode::{encode_array, encode_byte_string},
    error::{BridgeError as E, Result},
    h,
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, PublicKey, SECP256K1,
};

pub(crate) fn parse_key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return Err(E::Predicate);
    }
    PublicKey::from_slice(bytes).map_err(|_| E::Predicate)
}

pub(crate) fn unlock_message(source: &[u8; 32], tx: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[&encode_byte_string(source), &encode_byte_string(tx)]))
}

pub(crate) fn verify_unlock(
    key: &PublicKey,
    source: &[u8; 32],
    tx: &[u8; 32],
    unlock: &[u8],
) -> Result<()> {
    if unlock.len() != 65 {
        return Err(E::UnlockLength);
    }
    let sig = Signature::from_compact(&unlock[..64]).map_err(|_| E::UnlockScalars)?;
    // libsecp accepts zero scalars in parsing, but they are not valid signatures.
    if unlock[..32].iter().all(|b| *b == 0) || unlock[32..64].iter().all(|b| *b == 0) {
        return Err(E::UnlockScalars);
    }
    let mut low = sig;
    low.normalize_s();
    if low != sig {
        return Err(E::UnlockScalars);
    }
    let rid = RecoveryId::try_from(i32::from(unlock[64])).map_err(|_| E::UnlockRecovery)?;
    let recoverable =
        RecoverableSignature::from_compact(&unlock[..64], rid).map_err(|_| E::UnlockScalars)?;
    let digest = Message::from_digest(unlock_message(source, tx));
    let recovered = SECP256K1.recover_ecdsa(&digest, &recoverable).map_err(|_| E::UnlockKey)?;
    if recovered != *key {
        return Err(E::UnlockKey);
    }
    verify_compact(&digest, &sig, key)
}

fn verify_compact(digest: &Message, sig: &Signature, key: &PublicKey) -> Result<()> {
    SECP256K1.verify_ecdsa(digest, sig, key).map_err(|_| E::Unlock)
}
#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    #[test]
    fn compact_verification_is_independently_enforced() {
        let key = SecretKey::from_byte_array(&[1; 32]).unwrap();
        let wrong =
            PublicKey::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[2; 32]).unwrap());
        let msg = Message::from_digest([3; 32]);
        let sig = SECP256K1.sign_ecdsa(&msg, &key);
        assert_eq!(verify_compact(&msg, &sig, &wrong), Err(E::Unlock));
        assert_eq!(
            verify_compact(&msg, &sig, &PublicKey::from_secret_key(SECP256K1, &key)),
            Ok(())
        );
    }
    #[test]
    fn keys_must_be_valid_and_compressed() {
        let key =
            PublicKey::from_secret_key(SECP256K1, &SecretKey::from_byte_array(&[1; 32]).unwrap());
        assert_eq!(parse_key(&key.serialize_uncompressed()), Err(E::Predicate));
        assert_eq!(parse_key(&[2; 32]), Err(E::Predicate));
        let mut invalid = [255; 33];
        invalid[0] = 2;
        assert_eq!(parse_key(&invalid), Err(E::Predicate));
        assert_eq!(parse_key(&key.serialize()), Ok(key));
    }
}
