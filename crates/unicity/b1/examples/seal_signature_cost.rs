//! Wall-clock cost of one seal signature under the upstream rule (one key recovery + comparison)
//! against the compact ECDSA verification it replaced, on the same keys and digests. The price per
//! supplied signature is 6,000 gas (`certgroups`/`b1ref` schedules); this prints the
//! measured microseconds so the margin can be judged. Run: `cargo run --release -p reth-unicity-b1
//! --example seal_signature_cost`.
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use std::time::Instant;

fn main() {
    let secp = Secp256k1::new();
    const N: usize = 4000;
    let mut cases = Vec::with_capacity(N);
    for i in 0..N {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        k[31] = 1;
        let sk = SecretKey::from_slice(&k).unwrap();
        let pk = sk.public_key(&secp);
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&(i as u64 * 7 + 3).to_be_bytes());
        let msg = Message::from_digest(d);
        let rec = secp.sign_ecdsa_recoverable(&msg, &sk);
        let std = rec.to_standard();
        cases.push((msg, pk, rec, std));
    }
    let v = Secp256k1::verification_only();
    let t = Instant::now();
    let mut ok = 0;
    for (m, pk, rec, _) in &cases {
        let r: &RecoverableSignature = rec;
        let std = r.to_standard();
        let mut low = std;
        low.normalize_s();
        if low == std && v.recover_ecdsa(m, r).is_ok_and(|q| q == *pk) {
            ok += 1;
        }
    }
    let rec_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    let t = Instant::now();
    for (m, pk, _, std) in &cases {
        if v.verify_ecdsa(m, std, pk).is_ok() {
            ok += 1;
        }
    }
    let ver_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    // a legal recovery ID that does not recover the member's key (parity flipped): the failing path
    let t = Instant::now();
    let mut bad = 0;
    for (m, pk, rec, _) in &cases {
        let (id, compact) = rec.serialize_compact();
        let other = secp256k1::ecdsa::RecoveryId::try_from(i32::from(id) ^ 1).unwrap();
        let wrong = RecoverableSignature::from_compact(&compact, other).unwrap();
        if !v.recover_ecdsa(m, &wrong).is_ok_and(|q| q == *pk) {
            bad += 1;
        }
    }
    let bad_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    println!("recover + compare (valid): {rec_us:.1} us; compact verify (old rule): {ver_us:.1} us; recover with the other parity (failing): {bad_us:.1} us; ok {ok} bad {bad} of {N} each");
}
