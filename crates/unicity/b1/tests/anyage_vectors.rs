//! Byte parity with bft-core's `b1-vectors/any-age-v1` corpus
//! (`b1ref/testdata/b1-vectors-anyage.json`, SHA-256 below): verdict, status, charge, output bytes,
//! the portable work counters of valid batches, the exact-gas and gas-1 boundaries, and zero
//! registry reads for structural failures.
use alloy_primitives::U256;
use reth_unicity_b1::{
    batch::{self, Counters},
    membership, Error, Pins, RegistryRead,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const CORPUS: &str = include_str!("testdata/b1-vectors-anyage.json");
const CORPUS_SHA256: &str = "8c969f585f1eb1b3e5c814126706c31689ee282439d025401f458b9f7e32d028";

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn word(s: &str) -> U256 {
    U256::from_be_slice(&hex(s))
}

struct State {
    words: BTreeMap<U256, U256>,
    reads: u64,
}
impl RegistryRead for State {
    type Error = ();
    fn sload(&mut self, key: U256) -> Result<U256, ()> {
        self.reads += 1;
        Ok(*self.words.get(&key).unwrap_or(&U256::ZERO))
    }
}
fn state(pre: &Value) -> State {
    let words = pre["storage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (word(w["slot"].as_str().unwrap()), word(w["value"].as_str().unwrap())))
        .collect();
    State { words, reads: 0 }
}

#[test]
fn the_corpus_is_the_pinned_file() {
    assert_eq!(format!("{:x}", Sha256::digest(CORPUS.as_bytes())), CORPUS_SHA256);
}

#[test]
fn certificate_batch_matches_the_any_age_corpus() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    for v in corpus["vectors"].as_array().unwrap() {
        if v["op"] != "CERT_BATCH_V2" {
            continue;
        }
        checked += 1;
        let id = v["id"].as_str().unwrap();
        let input = hex(v["request"].as_str().unwrap());
        let pre = &v["preState"];
        let pins = Pins {
            genesis_commitment: word(pre["pinnedGenesisCommitment"].as_str().unwrap()),
            profile_hash: word(pre["pinnedProfileHash"].as_str().unwrap()),
        };
        let want = &v["expected"];
        let mut s = state(pre);
        let mut c = Counters::default();
        let got = batch::run(&input, u64::MAX, &pins, &mut s, Some(&mut c));
        match want["status"].as_str().unwrap() {
            "error" => {
                if !matches!(got, Err(Error::Malformed(_))) || s.reads != 0 {
                    failures.push(format!("{id}: {got:?} reads {}, want malformed", s.reads));
                }
                continue;
            }
            "registry" => {
                if got != Err(Error::Registry) {
                    failures.push(format!("{id}: {got:?}, want Registry"));
                }
                continue;
            }
            _ => {}
        }
        let gas = want["gas"].as_u64().unwrap();
        let valid = want["valid"].as_bool().unwrap();
        match &got {
            Ok(out)
                if out.gas == gas &&
                    out.bytes.as_slice() == hex(want["output"].as_str().unwrap()) &&
                    (out.bytes[63] == 1) == valid => {}
            r => {
                failures.push(format!("{id}: {r:?}, want gas {gas} valid {valid}"));
                continue;
            }
        }
        let g = &want["grouping"];
        let d = batch::dimensions(&input).unwrap();
        let dims = [d.c, d.k, d.e, d.s, d.q, d.a, d.p];
        let wanted = ["C", "K", "E", "S", "Q", "A", "P"].map(|k| g[k].as_u64().unwrap());
        if dims != wanted || d.gas() != gas {
            failures
                .push(format!("{id}: dimensions {dims:?} gas {}, want {wanted:?} {gas}", d.gas()));
        }
        if valid {
            let k = &want["counters"];
            let have = [c.claims, c.epoch_loads, c.folds, c.key_parses, c.quorums, c.signatures];
            let need = ["claim", "epoch-load", "fold", "key-parse", "quorum", "signature"]
                .map(|n| k[n].as_u64().unwrap());
            if have != need {
                failures.push(format!("{id}: counters {have:?}, want {need:?}"));
            }
        }
        // The boundary is exact whatever the verdict.
        let mut exact = state(pre);
        if batch::run(&input, gas, &pins, &mut exact, None).is_err() {
            failures.push(format!("{id}: exact gas refused"));
        }
        let mut short = state(pre);
        if batch::run(&input, gas - 1, &pins, &mut short, None) != Err(Error::OutOfGas) {
            failures.push(format!("{id}: gas-1 accepted"));
        }
        if short.reads != 0 && gas - 1 < d.gas() {
            failures.push(format!("{id}: reads {} after the debit failed", short.reads));
        }
    }
    assert!(checked > 150, "only {checked} certificate vectors");
    assert!(failures.is_empty(), "{} of {checked}:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn membership_matches_the_any_age_corpus() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let mut checked = 0;
    for v in corpus["vectors"].as_array().unwrap() {
        if v["op"] != "RSMT_MEMBER_V1" {
            continue;
        }
        checked += 1;
        let id = v["id"].as_str().unwrap();
        let input = hex(v["request"].as_str().unwrap());
        let want = &v["expected"];
        let got = membership::<()>(&input, u64::MAX);
        if want["status"] == "error" {
            assert!(matches!(got, Err(Error::Malformed(_))), "{id}: {got:?}");
            continue;
        }
        let out = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(out.gas, want["gas"].as_u64().unwrap(), "{id}");
        assert_eq!(out.bytes.as_slice(), hex(want["output"].as_str().unwrap()), "{id}");
        assert_eq!(membership::<()>(&input, out.gas - 1), Err(Error::OutOfGas), "{id}: gas-1");
    }
    assert!(checked > 20, "only {checked} membership vectors");
}
