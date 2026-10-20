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
