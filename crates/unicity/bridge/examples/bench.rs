//! B7 PR 3 measurement (bft-core briefs/dev4-b7-pr3-plan.md): each `BRIDGE_COMPOSE_V1` (protocol 5,
//! unregistered since protocol 6) case of bft-core `cmd/genbench` through the production provider,
//! with the B1 registry in the journal of a fresh EVM context per call (a cold journal, as for one
//! transaction). It reports wall time per call, nanoseconds per charged gas and the peak heap
//! allocated during the call, next to ECRECOVER and SHA256 on the same machine. Status and gas must
//! equal the oracle's.
//!
//! `cargo run --release -p reth-unicity-bridge --example bench -- CASES.json ITERATIONS OUT.json`
use alloy_evm::{
    eth::EthEvmContext,
    precompiles::{Precompile, PrecompileInput},
    EvmInternals,
};
use alloy_primitives::{hex, Address, U256};
use reth_unicity_b1::{Pins, REGISTRY};
use reth_unicity_bridge::{provider::ComposePrecompile, ADDRESS};
use revm::{
    database::InMemoryDB,
    precompile::{hash::sha256_run, secp256k1::ec_recover_run},
};
use serde_json::{json, Value};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

/// Counts live heap bytes and their high-water mark.
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
// SAFETY: forwards every call to the system allocator unchanged and only updates counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is passed through to System.
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: the caller's contract is passed through to System.
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;

fn word(v: &Value) -> U256 {
    U256::from_be_slice(&hex::decode(v.as_str().unwrap()).unwrap())
}

fn stats(mut ns: Vec<u128>) -> (u128, u128, u128) {
    ns.sort_unstable();
    (ns[0], ns[ns.len() / 2], ns[(ns.len() * 9) / 10])
}

/// A precompile of revm's Ethereum set: median ns per gas over `n` calls.
fn baseline(n: usize, f: impl Fn() -> u64) -> Value {
    let mut ns = Vec::with_capacity(n);
    let mut gas = 0;
    for _ in 0..n {
        let t = Instant::now();
        gas = f();
        ns.push(t.elapsed().as_nanos());
    }
    let (min, median, p90) = stats(ns);
    json!({"gas": gas, "minNs": min, "medianNs": median, "p90Ns": p90, "nsPerGas": median as f64 / gas as f64})
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cases: Value = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let iterations: usize = args[2].parse().unwrap();
    // The valid recovery of the geth precompile vectors: a full point recovery every call.
    let ecrecover_in = hex::decode(concat!(
        "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3",
        "000000000000000000000000000000000000000000000000000000000000001c",
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac80388256084",
        "f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    ))
    .unwrap();
    assert!(!ec_recover_run(&ecrecover_in, 3_000).unwrap().bytes.is_empty(), "ecrecover vector");
    let sha_in = vec![0xab_u8; 1024];
    let baselines = json!({
        "ecrecover": baseline(2_000, || ec_recover_run(&ecrecover_in, 3_000).unwrap().gas_used),
        "sha256_1KiB": baseline(2_000, || sha256_run(&sha_in, u64::MAX).unwrap().gas_used),
    });
    eprintln!("baselines {baselines}");
    let mut out = Vec::new();
    for c in cases.as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let input = hex::decode(c["input"].as_str().unwrap()).unwrap();
        let pins = Pins {
            genesis_commitment: word(&c["pins"]["genesisCommitment"]),
            profile_hash: word(&c["pins"]["profileHash"]),
        };
        let words: Vec<(U256, U256)> = c["registry"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (U256::from_be_slice(&hex::decode(k).unwrap()), word(v)))
            .collect();
        let pc = ComposePrecompile::new(pins);
        let (mut ns, mut peak, mut gas, mut status) = (Vec::new(), 0, 0, u64::MAX);
        for _ in 0..iterations {
            let mut db = InMemoryDB::default();
            for (k, v) in &words {
                db.insert_account_storage(REGISTRY, *k, *v).unwrap();
            }
            let mut ctx = EthEvmContext::new(db, Default::default());
            let base = LIVE.load(Relaxed);
            PEAK.store(base, Relaxed);
            let t = Instant::now();
            let o = pc
                .call(PrecompileInput {
                    data: &input,
                    gas: u64::MAX,
                    reservoir: 0,
                    caller: Address::ZERO,
                    value: U256::ZERO,
                    is_static: true,
                    internals: EvmInternals::from_context(&mut ctx),
                    target_address: ADDRESS,
                    bytecode_address: ADDRESS,
                })
                .expect("no host failure");
            ns.push(t.elapsed().as_nanos());
            peak = peak.max(PEAK.load(Relaxed).saturating_sub(base));
            gas = o.gas_used;
            status = U256::from_be_slice(&o.bytes[32..64]).to::<u64>();
        }
        assert_eq!(
            (status, gas),
            (c["status"].as_u64().unwrap(), c["gas"].as_u64().unwrap()),
            "{id}"
        );
        let (min, median, p90) = stats(ns);
        let row = json!({
            "id": id, "leaves": c["leaves"], "anchors": c["anchors"], "shards": c["shards"],
            "inputBytes": c["inputBytes"], "status": status, "gas": gas,
            "minNs": min, "medianNs": median, "p90Ns": p90,
            "nsPerGas": median as f64 / gas as f64, "peakHeapBytes": peak,
        });
        eprintln!("{row}");
        out.push(row);
    }
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.to_owned()))
        .unwrap_or_default();
    let report = json!({
        "cpu": cpu,
        "threads": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "iterations": iterations,
        "baselines": baselines,
        "cases": out,
    });
    std::fs::write(&args[3], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
