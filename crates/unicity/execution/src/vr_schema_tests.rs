//! Consumer of bft-core's validator-registry schema v1 vectors (VT-16, bft-core#1156).
//!
//! The vectors are copied byte-identical from bft-core `testvectors/validator-registry/` into
//! `testdata/vr-schema-v1/` with their `MANIFEST.sha256`. Every vector is
//! `{name, op, input, expect}`; this module consumes the record and fee ops that ureth owns:
//!
//! - `record.width`: kinds 1 to 5 against [`payload_width`]; kinds 6 to 8 are the VT-15 target and
//!   `payload_width` still refuses them;
//! - `record.decode`: payload length plus the canonical word rules and the per-kind range rules of
//!   kinds 6 to 8, in a local checker (the production decoder of kinds 6 to 8 is VT-15);
//! - `fee.validate`: [`BlockProfile::validate`];
//! - `fee.nextBaseFee`: [`ParentExecutionOutcome::reconcile`] and [`next_base_fee`];
//! - `fee.transition`: the parent reconciles under F(N-1) and the child base fee under F(N). The
//!   F(N) selection itself is VT-06c; this test derives it from the vector's boundary.
//!
//! The remaining ops (codecs, digests, handoff, arithmetic of the registry) are VR-side.

use crate::{
    block::{next_base_fee, BlockAccountingError, BlockProfile, ParentExecutionOutcome},
    records::payload_width,
    sha256,
};
use alloy_primitives::{hex, B256};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

const MANIFEST: &str = include_str!("../testdata/vr-schema-v1/MANIFEST.sha256");
const ENCODING: &[u8] = include_bytes!("../testdata/vr-schema-v1/encoding.json");
const ARITHMETIC: &[u8] = include_bytes!("../testdata/vr-schema-v1/arithmetic.json");
const FILES: [(&str, &[u8]); 2] = [("encoding.json", ENCODING), ("arithmetic.json", ARITHMETIC)];

/// Record kinds 6 to 8 and the widths VT-15 must give them in [`payload_width`].
const VT15_TARGET_WIDTHS: [(u64, usize); 3] = [(6, 224), (7, 128), (8, 128)];

/// Elasticity is fixed at 2 for every generation.
const ELASTICITY: u64 = 2;

/// The system reservation used to place the vectors' ordinary capacity inside a profile.
const SYSTEM_GAS: u64 = 2_000_000;

#[derive(Deserialize)]
struct VectorFile {
    schema: String,
    version: u64,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    op: String,
    input: Value,
    expect: Value,
}

fn vectors(file: &[u8]) -> Vec<Vector> {
    let parsed: VectorFile = serde_json::from_slice(file).unwrap();
    assert_eq!(parsed.schema, "unicity.vr.schema/v1");
    assert_eq!(parsed.version, 1);
    parsed.vectors
}

/// The vectors of `op` across both files; at least one must exist.
fn by_op(op: &str) -> Vec<Vector> {
    let found: Vec<Vector> =
        FILES.iter().flat_map(|(_, file)| vectors(file)).filter(|v| v.op == op).collect();
    assert!(!found.is_empty(), "no {op} vectors");
    found
}

/// A u64 carried as a decimal string (wide values) or a JSON number (small values).
fn int(value: &Value) -> u64 {
    match value {
        Value::String(s) => s.parse().unwrap(),
        Value::Number(n) => n.as_u64().unwrap(),
        other => panic!("not an integer: {other}"),
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// The Go error name; empty when the reference accepted.
fn expect_error(expect: &Value) -> &str {
    expect.get("error").map(text).unwrap_or("")
}

fn error_name(result: Result<u64, BlockAccountingError>) -> String {
    result.err().map(|e| format!("{e:?}")).unwrap_or_default()
}

#[test]
fn vr_schema_files_match_manifest() {
    let manifest: BTreeMap<&str, &str> = MANIFEST
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (digest, name) = line.split_once("  ").unwrap();
            (name.trim(), digest)
        })
        .collect();
    for (name, bytes) in FILES {
        let want: B256 = manifest.get(name).unwrap().parse().unwrap();
        assert_eq!(sha256(bytes), want, "{name} differs from its MANIFEST.sha256 line");
    }
}

// ---- records ----

/// Word types per kind, as frozen by the `record.width` vectors.
fn word_types() -> BTreeMap<u64, Vec<String>> {
    by_op("record.width")
        .into_iter()
        .map(|v| {
            let types = v.input["types"].as_array().unwrap().iter().map(|t| text(t).to_owned());
            (int(&v.input["kind"]), types.collect())
        })
        .collect()
}

#[test]
fn vr_schema_record_widths() {
    for v in by_op("record.width") {
        let kind = int(&v.input["kind"]);
        let width = int(&v.expect["width"]) as usize;
        assert_eq!(width, 32 * v.input["types"].as_array().unwrap().len(), "{}", v.name);
        if let Some((_, target)) = VT15_TARGET_WIDTHS.iter().find(|(k, _)| *k == kind) {
            assert_eq!(width, *target, "{}: VT-15 target width", v.name);
            // VT-15 adds kinds 6 to 8; it flips this to `Some(width)`.
            assert_eq!(payload_width(kind), None, "{}: kind {kind} is VT-15's", v.name);
        } else {
            assert!((1..=5).contains(&kind), "{}: unexpected kind {kind}", v.name);
            assert_eq!(payload_width(kind), Some(width), "{}", v.name);
        }
    }
}

/// The 64-bit value of a narrow word, or `None` when a high byte is nonzero.
fn word_u64(word: &[u8]) -> Option<u64> {
    if word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[24..].try_into().unwrap()))
}

/// The local checker of a root-record payload. The error is the reference's error category.
fn check_record(
    types: &BTreeMap<u64, Vec<String>>,
    kind: u64,
    data: &[u8],
) -> Result<(), &'static str> {
    let Some(ts) = types.get(&kind) else { return Err("unknown kind") };
    let width = payload_width(kind).unwrap_or(32 * ts.len());
    assert_eq!(width, 32 * ts.len(), "kind {kind}: payload_width disagrees with the word types");
    if data.len() != width {
        return Err("wrong length");
    }
    let mut values = Vec::with_capacity(ts.len());
    for (word, t) in data.as_chunks::<32>().0.iter().zip(ts) {
        let bits = match t.as_str() {
            "bytes32" => {
                values.push(None);
                continue;
            }
            "uint64" => 64,
            "uint16" => 16,
            "uint8" => 8,
            "bool" => {
                match word_u64(word) {
                    Some(v @ (0 | 1)) => values.push(Some(v)),
                    _ => return Err("non-canonical bool"),
                }
                continue;
            }
            other => panic!("kind {kind}: unknown word type {other}"),
        };
        match word_u64(word) {
            Some(v) if bits == 64 || v >> bits == 0 => values.push(Some(v)),
            _ => return Err("non-canonical narrow field"),
        }
    }
    let zero_word = |i: usize| data[32 * i..32 * (i + 1)].iter().all(|b| *b == 0);
    let value = |i: usize| values[i].unwrap();
    let in_range = match kind {
        // Boundary: nonzero result id; a primary installs J, a recovery J + 1.
        6 => !zero_word(0) && value(1).checked_add(value(5)) == Some(value(2)),
        // OutputRejected: nonzero result id; reason 1 (Expired) to 3 (Invalid); memberId only for
        // Invalid; readyBitmap only for Expired.
        7 => {
            let reason = value(1);
            !zero_word(0) &&
                (1..=3).contains(&reason) &&
                (value(2) == 0 || reason == 3) &&
                (value(3) == 0 || reason == 1)
        }
        // HolderRetirement: holder < MAX_HOLDERS (8).
        8 => value(0) < 8,
        _ => true,
    };
    if !in_range {
        return Err("value out of range");
    }
    Ok(())
}

#[test]
fn vr_schema_record_decode() {
    let types = word_types();
    for v in by_op("record.decode") {
        let kind = int(&v.input["kind"]);
        let data = hex::decode(text(&v.input["data"])).unwrap();
        let got = check_record(&types, kind, &data);
        let ok = v.expect["ok"].as_bool().unwrap();
        assert_eq!(got.is_ok(), ok, "{}: {got:?} vs {}", v.name, v.expect);
        match got {
            Ok(()) => assert_eq!(int(&v.expect["width"]) as usize, data.len(), "{}", v.name),
            Err(category) => {
                let want = expect_error(&v.expect);
                assert!(want.contains(category), "{}: {category} vs {want}", v.name);
            }
        }
    }
}

// ---- fees ----

/// A fee profile over the vectors' fixed generation fields.
const fn profile(max_gas: u64, system_gas: u64, floor: u64, denominator: u64) -> BlockProfile {
    BlockProfile {
        max_gas,
        system_gas,
        base_fee_floor: floor,
        elasticity: ELASTICITY,
        change_denominator: denominator,
    }
}

#[test]
fn vr_schema_fee_validate() {
    for v in by_op("fee.validate") {
        let want = expect_error(&v.expect);
        // The fee collector is a VR-side FeeParams field (the queue-time check of a change);
        // ureth's BlockProfile carries no collector, so a collector-only refusal has no ureth
        // counterpart.
        if want == "ZeroFeeCollector" {
            continue;
        }
        let got = profile(
            int(&v.input["maxGas"]),
            int(&v.input["systemGas"]),
            int(&v.input["baseFeeFloor"]),
            int(&v.input["changeDenominator"]),
        )
        .validate();
        assert_eq!(got.is_ok(), v.expect["ok"].as_bool().unwrap(), "{}: {got:?}", v.name);
        assert_eq!(error_name(got.map(|_| 0)), want, "{}", v.name);
    }
}

/// The child base fee of a parent with `ordinary_used` of `ordinary_capacity` under `floor` and
/// `denominator`, through the reconciled [`next_base_fee`] path.
///
/// ureth's single profile reconciles the parent against the same floor the child clamps to, so a
/// child floor above the parent's base fee (an upward F(N) floor change, VT-06c) is not expressible
/// directly. The parent is reconciled with the floor lowered to `min(floor, parent_base_fee)` and
/// the child floor is applied afterwards; since `floor >= min(floor, parent_base_fee)` this is
/// exactly `clamp(eip1559, floor, MAX_BASE_FEE)`, and it is the plain path whenever the parent
/// meets the floor.
fn child_base_fee(
    parent_base_fee: u64,
    ordinary_used: u64,
    ordinary_capacity: u64,
    floor: u64,
    denominator: u64,
) -> Result<u64, BlockAccountingError> {
    let max_gas =
        ordinary_capacity.checked_add(SYSTEM_GAS).ok_or(BlockAccountingError::Overflow)?;
    let header = ordinary_used.checked_add(SYSTEM_GAS).ok_or(BlockAccountingError::Overflow)?;
    let reconcile_floor = floor.min(parent_base_fee);
    let parent = ParentExecutionOutcome::reconcile(
        profile(max_gas, SYSTEM_GAS, reconcile_floor, denominator),
        B256::ZERO,
        header,
        SYSTEM_GAS,
        parent_base_fee,
    )?;
    Ok(next_base_fee(parent)?.max(floor))
}

#[test]
fn vr_schema_fee_next_base_fee() {
    for v in by_op("fee.nextBaseFee") {
        let got = child_base_fee(
            int(&v.input["parentBaseFee"]),
            int(&v.input["ordinaryUsed"]),
            int(&v.input["ordinaryCapacity"]),
            int(&v.input["baseFeeFloor"]),
            int(&v.input["changeDenominator"]),
        );
        let want = expect_error(&v.expect);
        assert_eq!(error_name(got), want, "{}: {got:?}", v.name);
        if want.is_empty() {
            assert_eq!(got.unwrap(), int(&v.expect["nextBaseFee"]), "{}", v.name);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FeeParams {
    floor: u64,
    denominator: u64,
    collector: [u8; 20],
}

impl FeeParams {
    fn from_json(value: &Value) -> Self {
        Self {
            floor: int(&value["baseFeeFloor"]),
            denominator: int(&value["changeDenominator"]),
            collector: hex::decode(text(&value["feeCollector"])).unwrap().try_into().unwrap(),
        }
    }
}

#[test]
fn vr_schema_fee_transition() {
    for v in by_op("fee.transition") {
        let previous = FeeParams::from_json(&v.input["previous"]);
        let new = FeeParams::from_json(&v.input["new"]);
        let used = int(&v.input["ordinaryUsed"]);
        let capacity = int(&v.input["ordinaryCapacity"]);
        // The Boundary applied in B_ack takes effect in the next block (VT-06c).
        let effective = int(&v.input["bAck"]) + 1;
        assert_eq!(int(&v.expect["effectiveBlock"]), effective, "{}", v.name);
        // F(N): `new` from the effective block on, `previous` before it.
        let fees_for = |n: u64| if n >= effective { new } else { previous };

        let mut chained: Option<u64> = None;
        for row in v.expect["blocks"].as_array().unwrap() {
            let n = int(&row["block"]);
            let at = format!("{} block {n}", v.name);
            let (f_n, f_parent) = (fees_for(n), fees_for(n - 1));
            assert_eq!(FeeParams::from_json(&row["fN"]), f_n, "{at}: F(N)");
            assert_eq!(FeeParams::from_json(&row["fNminus1"]), f_parent, "{at}: F(N-1)");
            assert_eq!(
                hex::decode(text(&row["beneficiary"])).unwrap(),
                f_n.collector,
                "{at}: beneficiary"
            );

            let parent_base_fee = int(&row["parentBaseFee"]);
            if let Some(previous_child) = chained {
                assert_eq!(parent_base_fee, previous_child, "{at}: parent is the previous child");
            }
            let reconciles = ParentExecutionOutcome::reconcile(
                profile(capacity + SYSTEM_GAS, SYSTEM_GAS, f_parent.floor, f_parent.denominator),
                B256::ZERO,
                used + SYSTEM_GAS,
                SYSTEM_GAS,
                parent_base_fee,
            )
            .is_ok();
            assert_eq!(reconciles, row["parentReconciles"].as_bool().unwrap(), "{at}");

            let child = child_base_fee(parent_base_fee, used, capacity, f_n.floor, f_n.denominator);
            let want = expect_error(row);
            assert_eq!(error_name(child), want, "{at}: {child:?}");
            if want.is_empty() {
                assert_eq!(child.unwrap(), int(&row["childBaseFee"]), "{at}");
            }
            chained = Some(int(&row["childBaseFee"]));
        }
    }
}
