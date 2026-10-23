//! Differential replay of the oracle's `native-compose` cases (bft-core `NativeCompose`): the same
//! status, the same 384 bytes and the same metered gas, or the same halt.
use super::*;
use alloy_primitives::hex;
use serde_json::Value;
use std::collections::BTreeSet;

/// The corpus B1: an anchor table authenticates iff every claim's (expectedStateRoot,
/// expectedIRHash) is in the case's set (bft-core `ClaimsB1`).
struct Claims(BTreeSet<[u8; 64]>);
impl Verdict for Claims {
    type Error = core::convert::Infallible;
    fn batch(&mut self, r: &[u8]) -> Result<bool, Halt<Self::Error>> {
        let k = usize::from(u16::from_be_bytes([r[2], r[3]]));
        let mut at = 4;
        for _ in 0..k {
            let sl = usize::from(u16::from_be_bytes([r[at + 4], r[at + 5]]));
            let claim = at + 6 + sl + 32;
            let mut key = [0; 64];
            key.copy_from_slice(&r[claim..claim + 64]);
            if !self.0.contains(&key) {
                return Ok(false);
            }
            let ul = u32::from_be_bytes(r[claim + 64..claim + 68].try_into().unwrap()) as usize;
            at = claim + 68 + ul;
        }
        Ok(true)
    }
}

fn claims(aux: &Value) -> Claims {
    let mut set = BTreeSet::new();
    for pair in aux["claims"].as_str().unwrap_or("").split(';').filter(|p| !p.is_empty()) {
        let (r, i) = pair.split_once(':').unwrap();
        let mut key = [0; 64];
        key[..32].copy_from_slice(&hex::decode(r).unwrap());
        key[32..].copy_from_slice(&hex::decode(i).unwrap());
        set.insert(key);
    }
    Claims(set)
}

fn corpus() -> Value {
    serde_json::from_str(include_str!("../testdata/native-compose.json")).unwrap()
}

#[test]
fn the_status_table_is_the_oracles() {
    let c = corpus();
    let table = c["status"].as_array().unwrap();
    assert_eq!(table.len(), Status::NAMES.len() + 1);
    assert_eq!(table[0]["name"], "ok");
    for (i, name) in Status::NAMES.iter().enumerate() {
        assert_eq!(table[i + 1]["code"], i as u64 + 1);
        assert_eq!(table[i + 1]["name"], *name, "code {}", i + 1);
    }
}

#[test]
fn every_native_compose_case_replays_exactly() {
    let c = corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 55);
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let input = hex::decode(case["input"].as_str().unwrap()).unwrap();
        let limit = case["aux"]["gasLimit"].as_str().map_or(u64::MAX, |v| v.parse().unwrap());
        let got = run(&input, limit, &mut claims(&case["aux"]));
        let want = &case["expected"];
        let ok = match (want["status"].as_str().unwrap(), &got) {
            ("halt", Err(Halt::Malformed)) => want["values"]["halt"] == "abi",
            ("halt", Err(Halt::OutOfGas)) => want["values"]["halt"] == "out-of-gas",
            ("ok", Ok(out)) => {
                let same = want["values"]["status"].as_str().unwrap() ==
                    out.status.code().to_string() &&
                    want["values"]["gas"].as_str().unwrap() == out.gas.to_string() &&
                    want["output"].as_str().unwrap() == hex::encode(out.bytes);
                if !same {
                    failures.push(format!(
                        "{id}: want status {} gas {}, got {:?} ({}) gas {}",
                        want["values"]["statusName"],
                        want["values"]["gas"],
                        out.status,
                        out.status.code(),
                        out.gas
                    ));
                }
                continue;
            }
            _ => false,
        };
        if !ok {
            failures.push(format!("{id}: want {want}, got {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

// Protocol 6 (BRIDGE_COMPOSE_V2): the oracle's split corpus (bft-core
// `bridgeprofile/testdata/split-corpus`).
fn split_corpus() -> Value {
    serde_json::from_str(include_str!("../testdata/split-v2.json")).unwrap()
}

#[test]
fn the_v2_status_table_is_the_oracles() {
    let c = split_corpus();
    let table = c["status"].as_array().unwrap();
    assert_eq!(table.len(), Status::NAMES.len() + Status::NAMES_V2.len() + 1);
    for (i, name) in Status::NAMES.iter().chain(Status::NAMES_V2.iter()).enumerate() {
        assert_eq!(table[i + 1]["code"], i as u64 + 1);
        assert_eq!(table[i + 1]["name"], *name, "code {}", i + 1);
    }
    assert_eq!(Status::CertSigLength.name(), "ErrCertSigLength");
    assert_eq!(Status::LeafProof.name(), "ErrLeafProof");
}

#[test]
fn every_split_native_case_replays_exactly() {
    let c = split_corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 45);
    let mut failures = Vec::new();
    let mut with_split = 0;
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let input = hex::decode(case["input"].as_str().unwrap()).unwrap();
        let limit = case["aux"]["gasLimit"].as_str().map_or(u64::MAX, |v| v.parse().unwrap());
        let got = run_v2(&input, limit, &mut claims(&case["aux"]));
        let want = &case["expected"];
        let ok = match (want["status"].as_str().unwrap(), &got) {
            ("halt", Err(Halt::Malformed)) => want["values"]["halt"] == "abi",
            ("halt", Err(Halt::OutOfGas)) => want["values"]["halt"] == "out-of-gas",
            ("ok", Ok(out)) => {
                with_split += usize::from(out.bytes[479] != 0 && out.status == Status::Ok);
                want["values"]["status"].as_str().unwrap() == out.status.code().to_string() &&
                    want["values"]["statusName"].as_str().unwrap() == out.status.name() &&
                    want["values"]["gas"].as_str().unwrap() == out.gas.to_string() &&
                    want["output"].as_str().unwrap() == hex::encode(out.bytes)
            }
            _ => false,
        };
        if !ok {
            failures.push(format!("{id}: want {want}, got {:?}", got.map(|o| (o.status, o.gas))));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    assert!(with_split > 0, "the corpus exercises successful split redemptions");
}

#[test]
fn every_seeded_mutation_of_a_depth_two_input_replays_exactly() {
    let c = split_corpus();
    let m = &c["mutation"];
    let base = hex::decode(m["base"].as_str().unwrap()).unwrap();
    let aux = serde_json::json!({ "claims": m["claims"] });
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for case in m["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let mut input = base.clone();
        for p in case["patch"].as_array().unwrap() {
            input[p["o"].as_u64().unwrap() as usize] ^= p["x"].as_u64().unwrap() as u8;
        }
        let want = &case["expected"];
        let got = run_v2(&input, u64::MAX >> 1, &mut claims(&aux));
        let ok = match (want["status"].as_str().unwrap(), &got) {
            ("halt", Err(Halt::Malformed)) => true,
            ("ok", Ok(out)) => {
                seen.insert(out.status.name());
                want["values"]["statusName"].as_str().unwrap() == out.status.name() &&
                    want["values"]["gas"].as_str().unwrap() == out.gas.to_string()
            }
            _ => false,
        };
        if !ok {
            failures.push(format!("{id}: want {want}, got {:?}", got.map(|o| (o.status, o.gas))));
        }
    }
    assert!(failures.is_empty(), "{} differ:\n{}", failures.len(), failures.join("\n"));
    assert!(seen.contains("ErrCertScan"), "the certificate scan is exercised: {seen:?}");
}

// Parity with the oracle on malformed input (ureth#85): the seeded patches on which the verifier
// once differed in status or gas, replayed through V1 (`run`) and V2 (`run_v2`).
#[test]
fn the_cases_of_issue_85_replay_exactly() {
    let c: Value = serde_json::from_str(include_str!("../testdata/parity-85.json")).unwrap();
    let mut failures = Vec::new();
    let mut n = 0;
    for (key, v2) in [("v1", false), ("v2", true)] {
        for f in c[key].as_array().unwrap() {
            let base = hex::decode(f["base"].as_str().unwrap()).unwrap();
            let aux = serde_json::json!({ "claims": f["claims"] });
            for case in f["cases"].as_array().unwrap() {
                n += 1;
                let id = case["id"].as_str().unwrap();
                let mut input = base.clone();
                for p in case["patch"].as_array().unwrap() {
                    input[p["o"].as_u64().unwrap() as usize] ^= p["x"].as_u64().unwrap() as u8;
                }
                let want = &case["expected"];
                let (status, gas) = if v2 {
                    run_v2(&input, u64::MAX >> 1, &mut claims(&aux)).map(|o| (o.status, o.gas))
                } else {
                    run(&input, u64::MAX >> 1, &mut claims(&aux)).map(|o| (o.status, o.gas))
                }
                .unwrap_or((Status::Ok, 0));
                if want["status"] != "ok" ||
                    want["values"]["statusName"].as_str().unwrap() != status.name() ||
                    want["values"]["gas"].as_str().unwrap() != gas.to_string()
                {
                    failures.push(format!("{id}: want {want}, got {status:?} gas {gas}"));
                }
            }
        }
    }
    assert!(n >= 250, "{n} cases");
    assert!(failures.is_empty(), "{} of {n} differ:\n{}", failures.len(), failures.join("\n"));
}
