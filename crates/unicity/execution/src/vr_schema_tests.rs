//! Consumer of bft-core's validator-registry schema v1 vectors (VT-16, bft-core#1156).
//!
//! The vectors are copied byte-identical from bft-core `testvectors/validator-registry/` into
//! `testdata/vr-schema-v1/` with their `MANIFEST.sha256`. Every vector is
//! `{name, op, input, expect}`; this module consumes the record and fee ops that ureth owns:
//!
//! - `record.width`: kinds 1 to 8 against [`payload_width`] and [`word_types`];
//! - `record.decode`: the production payload check of the import scan ([`payload_width`] and
//!   [`check_payload`]), and for kinds 6 to 8 the strict decoder ([`decode_registry_record`]);
//! - `record.gas`: the import's pricing constants;
//! - `fee.validate`: [`BlockProfile::validate`];
//! - `fee.nextBaseFee`: [`ParentExecutionOutcome::reconcile`] and [`next_base_fee`];
//! - `fee.transition`: the parent reconciles under F(N-1) and the child base fee under F(N). The
//!   F(N) selection itself is VT-06c; this test derives it from the vector's boundary.
//!
//! The remaining ops (codecs, digests, handoff, arithmetic of the registry) are VR-side.

use crate::{
    block::{next_base_fee, BlockAccountingError, BlockProfile, ParentExecutionOutcome},
    records::{
        check_payload, decode_registry_record, payload_width, word_types, PayloadError, WordType,
        ENTRY_GAS, MAX_IMPORT_BYTES, MAX_IMPORT_ENTRIES, SCAN_BASE_GAS, SCAN_BYTE_GAS,
    },
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

fn word_type_name(t: WordType) -> &'static str {
    match t {
        WordType::Bytes32 => "bytes32",
        WordType::Uint64 => "uint64",
        WordType::Uint8 => "uint8",
        WordType::Uint16 => "uint16",
        WordType::Bool => "bool",
    }
}

#[test]
fn vr_schema_record_widths() {
    let mut kinds = 0u32;
    for v in by_op("record.width") {
        let kind = int(&v.input["kind"]);
        let width = int(&v.expect["width"]) as usize;
        let types: Vec<&str> = v.input["types"].as_array().unwrap().iter().map(text).collect();
        assert_eq!(width, 32 * types.len(), "{}", v.name);
        assert_eq!(payload_width(kind), Some(width), "{}", v.name);
        let ours: Vec<&str> =
            word_types(kind).unwrap().iter().map(|t| word_type_name(*t)).collect();
        assert_eq!(ours, types, "{}", v.name);
        kinds |= 1 << kind;
    }
    assert_eq!(kinds, 0b1_1111_1110, "kinds 1 to 8");
    assert_eq!(payload_width(9), None);
}

/// The error category of a production refusal, in the reference's words.
fn category(error: PayloadError) -> &'static str {
    match error {
        PayloadError::NonCanonicalWord { .. } => "non-canonical narrow field",
        PayloadError::NonCanonicalBool { .. } => "non-canonical bool",
        _ => "value out of range",
    }
}

#[test]
fn vr_schema_record_decode() {
    let (mut accepted, mut refused) = (0, 0);
    for v in by_op("record.decode") {
        let kind = int(&v.input["kind"]);
        let data = hex::decode(text(&v.input["data"])).unwrap();
        let got = match payload_width(kind) {
            None => Err("unknown kind"),
            Some(width) if width != data.len() => Err("wrong length"),
            Some(_) => check_payload(kind as u8, &data).map_err(category),
        };
        if (6..=8).contains(&kind) {
            let strict = decode_registry_record(kind as u8, &data).unwrap();
            assert_eq!(strict.is_ok(), got.is_ok(), "{}: the strict decoder agrees", v.name);
        }
        let ok = v.expect["ok"].as_bool().unwrap();
        assert_eq!(got.is_ok(), ok, "{}: {got:?} vs {}", v.name, v.expect);
        match got {
            Ok(()) => {
                assert_eq!(int(&v.expect["width"]) as usize, data.len(), "{}", v.name);
                accepted += 1;
            }
            Err(category) => {
                let want = expect_error(&v.expect);
                assert!(want.contains(category), "{}: {category} vs {want}", v.name);
                refused += 1;
            }
        }
    }
    assert_eq!((accepted, refused), (8, 17));
}

#[test]
fn vr_schema_record_gas() {
    let v = by_op("record.gas");
    assert_eq!(v.len(), 1);
    let (input, expect) = (&v[0].input, &v[0].expect);
    assert_eq!(int(&input["scanBase"]), SCAN_BASE_GAS);
    assert_eq!(int(&input["scanByte"]), SCAN_BYTE_GAS);
    assert_eq!(int(&input["entry"]), ENTRY_GAS);
    assert_eq!(int(&input["maxBytes"]) as usize, MAX_IMPORT_BYTES);
    assert_eq!(int(&input["maxEntries"]) as usize, MAX_IMPORT_ENTRIES);
    assert_eq!(int(&expect["maxAdmission"]), crate::records::MAX_ADMISSION_GAS);
    let widest = (6..=8).map(|k| word_types(k).unwrap().len()).max().unwrap();
    assert_eq!(widest as u64, int(&expect["widestNewKindWords"]));
    let measured = word_types(3).unwrap().len();
    assert_eq!(measured as u64, int(&expect["executionBoundWords"]));
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
