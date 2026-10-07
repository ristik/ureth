//! Independent storage construction from the written A′ layout and explicit scalars.
use alloy_primitives::{keccak256, U256};
use reth_unicity_b1::{entry_slot, fixed_slot, member_slot};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;
use std::collections::BTreeMap;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn word(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
const fn identity(n: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[0] = n;
    b
}
fn slot(name: &str, ns: &[u64]) -> [u8; 32] {
    let fixed = keccak256(format!("unicity.seal-registry/{name}"));
    if ns.is_empty() {
        return fixed.0;
    }
    let mut b = fixed.to_vec();
    for n in ns {
        b.extend(word(*n));
    }
    keccak256(b).0
}
fn entry(epoch: u64, start: u64, weight: u64) -> BTreeMap<String, String> {
    let secp = Secp256k1::new();
    let public = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&word(1)).unwrap())
        .serialize();
    let mut out = BTreeMap::new();
    let metadata = [
        word(1),
        word(if epoch == 0 { 1 } else { 2 }),
        identity(epoch as u8 + 1),
        if epoch == 0 { [0; 32] } else { identity(epoch as u8 + 10) },
        word(start),
        word(0),
        word(0),
        word(1),
        identity(9),
        word(1),
        word(weight),
    ];
    for (f, w) in metadata.iter().enumerate() {
        let key = slot("b1.entry", &[epoch, f as u64]);
        assert_eq!(entry_slot(epoch, f as u64), U256::from_be_bytes(key));
        out.insert(hex(&key), hex(w));
    }
    let mut members = [[0; 32]; 8];
    members[0] = word(128);
    for w in &mut members[1..5] {
        *w = [b'a'; 32];
    }
    members[5].copy_from_slice(&public[..32]);
    members[6][0] = public[32];
    members[7] = word(weight);
    for (f, w) in members.iter().enumerate() {
        let key = slot("b1.member", &[epoch, 0, f as u64]);
        assert_eq!(member_slot(epoch, 0, f as u64), U256::from_be_bytes(key));
        out.insert(hex(&key), hex(w));
    }
    out
}
#[test]
fn every_genesis_member_and_changed_entry_word_matches_go() {
    let go: Value =
        serde_json::from_str(include_str!("testdata/go-projection-4ba487e.json")).unwrap();
    for (epoch, start, weight, field) in [(0, 7, 1, "genesisWords"), (2, 9, 7, "changedWords")] {
        for (k, v) in entry(epoch, start, weight) {
            assert_eq!(go[field][k], v, "epoch {epoch}");
        }
    }
    for name in [
        "b1.network",
        "b1.wCert",
        "b1.profileHash",
        "b1.initialized",
        "b1.head",
        "b1.count",
        "clock.rootRound",
        "origin.rootEpoch",
        "assignment.rootEpoch",
        "phase",
    ] {
        assert_eq!(fixed_slot(name), U256::from_be_bytes(slot(name, &[])));
        assert!(go["genesisWords"][hex(&slot(name, &[]))].is_string());
    }
    for f in 0..11 {
        assert_eq!(go["changedWords"][hex(&slot("b1.entry", &[0, f]))], hex(&word(0)));
    }
    for f in 0..8 {
        assert_eq!(go["changedWords"][hex(&slot("b1.member", &[0, 0, f]))], hex(&word(0)));
    }
}
