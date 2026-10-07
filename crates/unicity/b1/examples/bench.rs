//! CPU measurement of the native kernels against same-binary references.
//!
//! `cargo run --release -p reth-unicity-b1 --example bench [out.json]`
//!
//! For the maximal requests of the pinned manifest it times `run` (1000 warmups, 10000 timed
//! iterations, median/p99/max, registry reads served from memory so storage retrieval is
//! excluded) and reports gas per nanosecond. The same binary times secp256k1 recovery (3000 gas)
//! and SHA-256 over 1 KiB (444 gas); a kernel passes when its gas per nanosecond is at least twice
//! the slower of the two references' ratios, i.e. it is priced at least twice as generously.
//! Results depend on the host CPU; run it on each target architecture.
use alloy_primitives::U256;
use reth_unicity_b1::{entry_slot, fixed_slot, member_slot, run, Operation, RegistryRead};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, hint::black_box, time::Instant};

const WARMUP: usize = 1000;
const ITERATIONS: usize = 10_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
struct State(BTreeMap<U256, U256>);
impl RegistryRead for State {
    type Error = ();
    fn sload(&mut self, k: U256) -> Result<U256, ()> {
        Ok(self.0.get(&k).copied().unwrap_or_default())
    }
}
fn state(v: &Value) -> State {
    let mut w = BTreeMap::new();
    for (n, x) in
        [("genesisCommitment", 1u64), ("phase", 2), ("b1.initialized", 1), ("b1.profileHash", 2)]
    {
        w.insert(fixed_slot(n), U256::from(x));
    }
    for (n, f) in [
        ("b1.network", "network"),
        ("b1.wCert", "wCert"),
        ("clock.rootRound", "clockRound"),
        ("origin.rootEpoch", "origin"),
    ] {
        w.insert(fixed_slot(n), U256::from(v[f].as_u64().unwrap_or(0)));
    }
    for e in v["epochs"].as_array().into_iter().flatten() {
        let epoch = e["epoch"].as_u64().unwrap();
        let ms = e["members"].as_array().unwrap();
        let total: u64 = ms.iter().map(|m| m["weight"].as_u64().unwrap()).sum();
        let end = e["end"].as_u64().unwrap();
        let f = [
            1,
            2,
            0,
            3,
            e["start"].as_u64().unwrap(),
            end,
            u64::from(end != 0),
            1,
            4,
            ms.len() as u64,
            total,
        ];
        for (i, x) in f.into_iter().enumerate() {
            let val = if i == 2 {
                U256::from_be_slice(&hex(e["bodyID"].as_str().unwrap()))
            } else {
                U256::from(x)
            };
            w.insert(entry_slot(epoch, i as u64), val);
        }
        for (j, m) in ms.iter().enumerate() {
            let id = m["nodeID"].as_str().unwrap().as_bytes();
            let key = hex(m["key"].as_str().unwrap());
            let mut word = [[0u8; 32]; 8];
            word[0] = U256::from(id.len()).to_be_bytes::<32>();
            for (i, b) in id.iter().enumerate() {
                word[1 + i / 32][i % 32] = *b;
            }
            word[5].copy_from_slice(&key[..32]);
            word[6][0] = key[32];
            word[7] = U256::from(m["weight"].as_u64().unwrap()).to_be_bytes::<32>();
            for (f, x) in word.into_iter().enumerate() {
                w.insert(member_slot(epoch, j as u64, f as u64), U256::from_be_bytes(x));
            }
        }
    }
    State(w)
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
fn main() {
    let manifest: Value =
        serde_json::from_str(include_str!("../tests/testdata/go-4ba487e.json")).unwrap();
    // References in the same binary.
    let sig = RecoverableSignature::from_compact(&[7u8; 64], RecoveryId::Zero).unwrap();
    let msg = Message::from_digest([9u8; 32]);
    let (ec, _, _) = time(|| {
        let _ = black_box(SECP256K1.recover_ecdsa(&msg, &sig));
    });
    let kib = [0x5au8; 1024];
    let (sh, _, _) = time(|| {
        black_box(Sha256::digest(black_box(&kib)));
    });
    let ref_ec = 3000.0 / ec as f64;
    let ref_sha = 444.0 / sh as f64;
    let slower = ref_ec.min(ref_sha);
    println!(
        "reference gas/ns: ecrecover {ref_ec:.4} sha256(1KiB) {ref_sha:.4}; required >= {:.4}",
        2.0 * slower
    );
    let mut rows = Vec::new();
    let mut ok = true;
    for id in [
        "cert.single.ok",
        "cert.shared.max-8.ok",
        "quorum.max.all",
        "paths.shard-depth-256.ok",
        "rsmt.depth-256.ok",
    ] {
        let v = manifest["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
        let input = hex(v["request"].as_str().unwrap());
        let op = match v["op"].as_str().unwrap() {
            "UC_V1" => Operation::Uc,
            "SHARED_SEAL_V1" => Operation::Shared,
            _ => Operation::Member,
        };
        let gas = v["expected"]["gas"].as_u64().unwrap();
        let mut s = state(&v["preState"]);
        let (med, p99, max) = time(|| {
            black_box(run(op, black_box(&input), u64::MAX, &mut s).unwrap());
        });
        let ratio = gas as f64 / med as f64;
        let pass = ratio >= 2.0 * slower;
        ok &= pass;
        println!(
            "{id}: gas {gas} median {med}ns p99 {p99}ns max {max}ns gas/ns {ratio:.4} {}",
            if pass { "ok" } else { "UNDERPRICED" }
        );
        rows.push(json!({"id": id, "gas": gas, "medianNs": med, "p99Ns": p99, "maxNs": max, "gasPerNs": ratio, "pass": pass}));
    }
    let out = json!({"arch": std::env::consts::ARCH, "os": std::env::consts::OS, "warmups": WARMUP, "iterations": ITERATIONS,
        "referenceGasPerNs": {"ecrecover": ref_ec, "sha256_1KiB": ref_sha}, "kernels": rows, "pass": ok});
    if let Some(p) = std::env::args().nth(1) {
        std::fs::write(p, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
    assert!(ok, "a kernel is priced below twice the slower reference ratio on this CPU");
}
