//! `any_age_cold_registry_v1` harness (briefs/b1-any-age-contract.md section 5).
//!
//! `cargo run --release -p reth-unicity-b1 --example any_age_cold_registry [out.json]`
//!
//! This binary measures the CPU half of the pin gate: the time of complete `CERT_BATCH_V2` calls
//! (scan, grouping, point parsing, signatures, folds) for the worst valid batch and the cheapest
//! structurally accepted false batches that still force every entry read and key parse, at the
//! corner cases E = 1, 4, 8, 16, with the registry served from memory, against the same-binary
//! references (secp256k1 recovery at 3000 gas, SHA-256 over 1 KiB at 444 gas). It also prints the
//! number of registry words each case reads, so the cold half can be priced exactly.
//!
//! The cold half (registry words fetched from the real execution-journal/trie/database path on the
//! minimum supported node hardware, a working state larger than the page cache, fresh disjoint
//! epochs per sample, at least 100 samples, compared with a same-build cold-SLOAD block workload
//! at 2,100 gas per word) needs a dedicated node and is NOT run by this binary; its verdict is
//! recorded in `briefs/any-age-evidence/cold-registry-v1.json`. Results depend on the host CPU.
use alloy_primitives::U256;
use reth_unicity_b1::{
    batch::{self, Counters},
    entry_slot, fixed_slot, member_slot, Pins, RegistryRead,
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, hint::black_box, time::Instant};

#[path = "../tests/support/uc.rs"]
mod uc;

const WARMUP: usize = 200;
const ITERATIONS: usize = 2_000;
const PINS: Pins = Pins {
    genesis_commitment: U256::from_limbs([1, 0, 0, 0]),
    profile_hash: U256::from_limbs([2, 0, 0, 0]),
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
#[derive(Default)]
struct State {
    words: BTreeMap<U256, U256>,
    reads: u64,
}
impl RegistryRead for State {
    type Error = ();
    fn sload(&mut self, k: U256) -> Result<U256, ()> {
        self.reads += 1;
        Ok(self.words.get(&k).copied().unwrap_or_default())
    }
}
/// Epochs `1..=epochs` of 16 members each, the last open; root round `10_000`.
fn registry(epochs: u64, signers: &[uc::Signer]) -> State {
    let mut s = State::default();
    for (n, v) in [
        ("genesisCommitment", 1),
        ("phase", 2),
        ("b1.initialized", 1),
        ("b1.network", 3),
        ("b1.profileHash", 2),
        ("b1.format", 2),
        ("b1.genesisEpoch", 1),
        ("b1.importedTipEpoch", epochs),
        ("b1.originReady", 1),
        ("clock.rootRound", 10_000),
        ("origin.rootEpoch", epochs),
    ] {
        s.words.insert(fixed_slot(n), U256::from(v));
    }
    for e in 1..=epochs {
        let start = 100 * e;
        let end = if e == epochs { 0 } else { start + 100 };
        let f = [1, 2, 0xb0d1, 3, start, end, u64::from(end != 0), 1, 4, 16, 16];
        for (i, x) in f.into_iter().enumerate() {
            s.words.insert(entry_slot(e, i as u64), U256::from(x));
        }
        for (j, m) in signers.iter().enumerate() {
            let key = m.public();
            let mut word = [[0u8; 32]; 8];
            word[0] = U256::from(m.id.len()).to_be_bytes::<32>();
            word[1][..m.id.len()].copy_from_slice(m.id.as_bytes());
            word[5].copy_from_slice(&key[..32]);
            word[6][0] = key[32];
            word[7] = U256::from(1).to_be_bytes::<32>();
            for (f, x) in word.into_iter().enumerate() {
                s.words.insert(member_slot(e, j as u64, f as u64), U256::from_be_bytes(x));
            }
        }
    }
    s
}
fn time(mut f: impl FnMut()) -> (u128, u128, u128) {
    for _ in 0..WARMUP {
        f();
    }
    let mut t: Vec<u128> = (0..ITERATIONS)
        .map(|_| {
            let s = Instant::now();
            f();
            s.elapsed().as_nanos()
        })
        .collect();
    t.sort_unstable();
    (t[ITERATIONS / 2], t[ITERATIONS * 99 / 100], t[ITERATIONS - 1])
}
fn request(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![2, 0];
    v.extend((parts.len() as u16).to_be_bytes());
    for p in parts {
        v.extend(p);
    }
    v
}
fn main() {
    let manifest: Value =
        serde_json::from_str(include_str!("../tests/testdata/go-b3reprice.json")).unwrap();
    let v = manifest["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "cert.single.ok");
    let req = hex(v.unwrap()["request"].as_str().unwrap());
    let sl = u16::from_be_bytes([req[8], req[9]]) as usize;
    let ul_at = 4 + 6 + sl + 96;
    let ul = u32::from_be_bytes(req[ul_at..ul_at + 4].try_into().unwrap()) as usize;
    let base = req[4..ul_at + 4 + ul].to_vec();

    let sig = RecoverableSignature::from_compact(&[7u8; 64], RecoveryId::Zero).unwrap();
    let msg = Message::from_digest([9u8; 32]);
    let (ec, _, _) = time(|| {
        let _ = black_box(SECP256K1.recover_ecdsa(&msg, &sig));
    });
    let kib = [0x5au8; 1024];
    let (sh, _, _) = time(|| {
        black_box(Sha256::digest(black_box(&kib)));
    });
    let (ref_ec, ref_sha) = (3000.0 / ec as f64, 444.0 / sh as f64);
    let required = 2.0 * ref_ec.min(ref_sha);
    println!("reference gas/ns: ecrecover {ref_ec:.4} sha256(1KiB) {ref_sha:.4}; required >= {required:.4}");

    let signers: Vec<uc::Signer> =
        (0..16).map(|i| uc::Signer::new(&format!("m{i:02}"), i as u64 + 1)).collect();
    let all: Vec<&uc::Signer> = signers.iter().collect();
    let mut rows = Vec::new();
    let mut pass_all = true;
    for e in [1u64, 4, 8, 16] {
        // Sixteen claims over `e` epochs (round 100*epoch + 50), full signatures or one signature.
        for (label, sigs) in [("valid", 16usize), ("cheapest-false", 1)] {
            let parts: Vec<Vec<u8>> = (0..16u64)
                .map(|i| {
                    let epoch = 1 + (i % e);
                    // A distinct round per claim keeps every seal distinct (S = A = 16).
                    uc::reseal(&base, epoch, 100 * epoch + 10 + i, &all[..sigs], |_| {})
                })
                .collect();
            let input = request(&parts);
            let d = batch::dimensions(&input).unwrap();
            let mut st = registry(e, &signers);
            let mut c = Counters::default();
            let out = batch::run(&input, u64::MAX, &PINS, &mut st, Some(&mut c)).unwrap();
            let valid = out.bytes[63] == 1;
            let (med, p99, max) = time(|| {
                black_box(batch::run(black_box(&input), u64::MAX, &PINS, &mut st, None).unwrap());
            });
            let ratio = out.gas as f64 / med as f64;
            let pass = ratio >= required;
            pass_all &= pass;
            println!(
                "E={e} {label}: valid={valid} gas {} median {med}ns p99 {p99}ns gas/ns {ratio:.4} reads {} sigs {} {}",
                out.gas, c.reads, c.signatures, if pass { "ok" } else { "UNDERPRICED" }
            );
            rows.push(json!({"E": e, "case": label, "valid": valid, "gas": out.gas, "dimensions": format!("{d:?}"),
                "registryWordsRead": c.reads, "keyParses": c.key_parses, "signatures": c.signatures,
                "medianNs": med, "p99Ns": p99, "maxNs": max, "gasPerNs": ratio, "pass": pass}));
        }
    }
    let out = json!({"harness": "any_age_cold_registry_v1 (CPU half; registry served from memory)",
        "arch": std::env::consts::ARCH, "os": std::env::consts::OS, "warmups": WARMUP, "iterations": ITERATIONS,
        "referenceGasPerNs": {"ecrecover": ref_ec, "sha256_1KiB": ref_sha}, "required": required,
        "cases": rows, "pass": pass_all});
    if let Some(p) = std::env::args().nth(1) {
        std::fs::write(p, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
}
