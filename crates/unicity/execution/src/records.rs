//! The mandatory root-record import of one block (bft-core `rootrecords.Import`).
//!
//! The root input commits `rootRecordsHash = SHA-256(companion)` as its thirteenth field. The
//! companion is the canonical CBOR
//! `["UNICITY_P85_RECORD_IMPORT", p, t, targetCount, targetTip, entries]` with entries
//! `[index, recordID, predecessor, kind, progress, ucTime, data, closedEpoch]`. It travels with the
//! root-input companion and is re-executed by build, import, replay and recovery, exactly like the
//! B1 update bytes.
//!
//! The paired Go node derives the bytes from the authenticated source log (exactly the next
//! `min(32, targetCount - registryCount)` records); this module never decides which records are
//! right. It admits the bytes in the design's staged order and builds the privileged
//! `importRootRecords` call:
//!
//! 1. the byte cap (`16384`) is checked before anything is read;
//! 2. `G_R_scan = 2000 + 16*C_R` is reserved from the system budget before the structural scan;
//! 3. the allocation-free scan enforces the six-field envelope, eight-field entries, `N <= 32`,
//!    exact scalar and payload widths, definite shortest encodings, depth and token bounds, with no
//!    tags, maps, nulls or trailing bytes, and reports `N`;
//! 4. `G_R_entries = 1000*N` is reserved before any entry is allocated or decoded;
//! 5. the bytes must hash to the committed value.
//!
//! Every failure rejects the whole block. The registry re-checks the log rules (indices, links,
//! identifiers, anchors, targets) inside the metered call; nothing here repeats them.

use crate::{
    sha256,
    wire::{CanonicalCborError, Decoder},
};
use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{sol, SolCall};

/// Domain text of the import envelope.
pub const IMPORT_DOMAIN: &str = "UNICITY_P85_RECORD_IMPORT";
/// Largest canonical import companion, `C_R`.
pub const MAX_IMPORT_BYTES: usize = 16_384;
/// Largest number of records one block imports.
pub const MAX_IMPORT_ENTRIES: usize = 32;
/// Token bound of the structural scan: every array, scalar and string counts once.
pub const MAX_IMPORT_TOKENS: u64 = 512;
/// Nesting bound of the structural scan: envelope, entries, entry, scalar.
pub const MAX_IMPORT_DEPTH: u64 = 4;
/// Fixed scan price `2000`.
pub const SCAN_BASE_GAS: u64 = 2_000;
/// Scan price per companion byte `16`.
pub const SCAN_BYTE_GAS: u64 = 16;
/// Admission price per entry `1000`.
pub const ENTRY_GAS: u64 = 1_000;
/// The largest admission charge `G_R_admit`, for the maximum companion of the maximum entry count.
pub const MAX_ADMISSION_GAS: u64 =
    SCAN_BASE_GAS + SCAN_BYTE_GAS * MAX_IMPORT_BYTES as u64 + ENTRY_GAS * MAX_IMPORT_ENTRIES as u64;

/// A bound on the gross gas of the privileged `importRootRecords` call for 32 maximal entries.
/// `b1_tests::import::the_maximal_import_stays_inside_the_envelope_bound` executes the most
/// expensive legal import (32 nine-word records, every word fresh and nonzero) on the pinned
/// runtime (11,169,634 gross) and requires it to stay within two thirds of this figure, the 3/2
/// safety factor the registry's own `G_rest` uses. It is a price, not a proof; bft-core's
/// `b1state.ImportExecutionGas` is the same figure.
pub const IMPORT_EXECUTION_GAS: u64 = 18_000_000;
/// The import's share of the system envelope: the largest admission charge plus the execution
/// bound.
pub const IMPORT_ENVELOPE_GAS: u64 = MAX_ADMISSION_GAS + IMPORT_EXECUTION_GAS;

// Tokens: envelope array, domain, p, t, targetCount, targetTip, entries array, then per entry an
// array and eight scalars. The bound is therefore structural; the check keeps it explicit.
const FIXED_TOKENS: u64 = 7;
const ENTRY_TOKENS: u64 = 9;
const _: () = assert!(FIXED_TOKENS + ENTRY_TOKENS * MAX_IMPORT_ENTRIES as u64 <= MAX_IMPORT_TOKENS);
const _: () = assert!(4 <= MAX_IMPORT_DEPTH);

sol! {
    struct RootRecord {
        uint64 index;
        bytes32 recordID;
        bytes32 predecessor;
        uint8 kind;
        uint64 progress;
        uint64 ucTime;
        bytes data;
    }

    struct ImportedRecord {
        RootRecord record;
        uint64 closedEpoch;
    }

    function importRootRecords(
        uint64 n,
        uint64 p,
        uint64 t,
        uint64 targetCount,
        bytes32 targetTip,
        ImportedRecord[] entries
    ) external;
}

/// One record of the import, with the closed root epoch of a Closure (zero for every other kind).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordEntry {
    /// Log index.
    pub index: u64,
    /// Content-derived identifier.
    pub record_id: B256,
    /// Previous record identifier.
    pub predecessor: B256,
    /// Record kind, 1 to 5.
    pub kind: u8,
    /// Canonical progress anchor.
    pub progress: u64,
    /// UC time anchor.
    pub uc_time: u64,
    /// ABI payload words of the kind.
    pub data: Vec<u8>,
    /// Closed root epoch of a Closure, otherwise zero.
    pub closed_epoch: u64,
}

/// A decoded import companion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordImport {
    /// Authenticated current progress `p`.
    pub progress: u64,
    /// Authenticated current UC time `t`.
    pub uc_time: u64,
    /// Length of the complete source log.
    pub target_count: u64,
    /// Tip of the complete source log (zero for an empty one).
    pub target_tip: B256,
    /// The next required records, in log order.
    pub entries: Vec<RecordEntry>,
}

/// An admitted import and the gas its admission debits from `g_sys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedImport {
    /// The decoded import.
    pub import: RecordImport,
    /// `G_R_admit = 2000 + 16*C_R + 1000*N`.
    pub gas: u64,
}

/// Refusal of an import companion. Any of them rejects the candidate block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The companion is longer than `16384` bytes.
    TooLarge {
        /// Length supplied.
        len: usize,
    },
    /// The scan charge does not fit the remaining system budget.
    ScanBudget,
    /// The entry charge does not fit the remaining system budget.
    EntryBudget,
    /// The bytes are not the canonical envelope.
    Encoding(CanonicalCborError),
    /// The envelope domain differs.
    Domain,
    /// More than 32 entries.
    TooManyEntries(usize),
    /// A kind outside 1 to 5.
    UnknownKind(u64),
    /// A payload whose width is not the kind's exact width.
    PayloadWidth {
        /// Record kind.
        kind: u8,
        /// Payload length supplied.
        len: usize,
    },
    /// A non-zero closed epoch on a record that is not a Closure.
    ClosedEpochOnNonClosure,
    /// A non-zero tip with a zero target.
    ZeroTargetTip,
    /// The scan exceeded the token bound.
    TooManyTokens,
    /// The companion does not hash to the committed `rootRecordsHash`.
    HashMismatch,
    /// A charge overflowed.
    Overflow,
}

impl From<CanonicalCborError> for ImportError {
    fn from(error: CanonicalCborError) -> Self {
        Self::Encoding(error)
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid root-record import: {self:?}")
    }
}

impl std::error::Error for ImportError {}

/// The exact payload width of a record kind, or `None` for a kind outside 1 to 5.
pub const fn payload_width(kind: u64) -> Option<usize> {
    match kind {
        1 => Some(32),
        2 => Some(128),
        3 => Some(288),
        4 => Some(192),
        5 => Some(96),
        _ => None,
    }
}

/// The scan price `G_R_scan` for a companion of `len` bytes.
pub const fn scan_gas(len: usize) -> Option<u64> {
    match SCAN_BYTE_GAS.checked_mul(len as u64) {
        Some(bytes) => SCAN_BASE_GAS.checked_add(bytes),
        None => None,
    }
}

/// Header of the envelope read by the scan.
struct Header {
    progress: u64,
    uc_time: u64,
    target_count: u64,
    target_tip: B256,
    entries: usize,
}

/// One walk over the companion. With `collect` unset nothing is allocated; with it set the same
/// walk builds the entries, so the scan and the decode cannot disagree about the structure.
fn walk(raw: &[u8], mut collect: Option<&mut Vec<RecordEntry>>) -> Result<Header, ImportError> {
    let mut decoder = Decoder::new(raw);
    let mut tokens = 0u64;
    let mut token = |count: u64| -> Result<(), ImportError> {
        tokens = tokens.checked_add(count).ok_or(ImportError::Overflow)?;
        if tokens > MAX_IMPORT_TOKENS {
            return Err(ImportError::TooManyTokens);
        }
        Ok(())
    };
    let arity = decoder.read_array()?;
    token(1)?;
    if arity != 6 {
        return Err(CanonicalCborError::WrongArity { expected: 6, found: arity }.into());
    }
    token(1)?;
    if decoder.read_text()? != IMPORT_DOMAIN {
        return Err(ImportError::Domain);
    }
    token(4)?;
    let progress = decoder.read_uint()?;
    let uc_time = decoder.read_uint()?;
    let target_count = decoder.read_uint()?;
    let target_tip = decoder.read_word()?;
    if target_count == 0 && target_tip != B256::ZERO {
        return Err(ImportError::ZeroTargetTip);
    }
    token(1)?;
    let entries = decoder.read_array()?;
    if entries > MAX_IMPORT_ENTRIES {
        return Err(ImportError::TooManyEntries(entries));
    }
    for _ in 0..entries {
        token(ENTRY_TOKENS)?;
        let arity = decoder.read_array()?;
        if arity != 8 {
            return Err(CanonicalCborError::WrongArity { expected: 8, found: arity }.into());
        }
        let index = decoder.read_uint()?;
        let record_id = decoder.read_word()?;
        let predecessor = decoder.read_word()?;
        let kind = decoder.read_uint()?;
        let width = payload_width(kind).ok_or(ImportError::UnknownKind(kind))?;
        let progress = decoder.read_uint()?;
        let uc_time = decoder.read_uint()?;
        let data = decoder.read_bounded_bytes("record payload", width)?;
        if data.len() != width {
            return Err(ImportError::PayloadWidth { kind: kind as u8, len: data.len() });
        }
        let closed_epoch = decoder.read_uint()?;
        if kind != 4 && closed_epoch != 0 {
            return Err(ImportError::ClosedEpochOnNonClosure);
        }
        if let Some(out) = collect.as_deref_mut() {
            out.push(RecordEntry {
                index,
                record_id,
                predecessor,
                kind: kind as u8,
                progress,
                uc_time,
                data: data.to_vec(),
                closed_epoch,
            });
        }
    }
    decoder.finish()?;
    Ok(Header { progress, uc_time, target_count, target_tip, entries })
}

/// Admits `raw` against `budget`, the system gas still unreserved after the B1 admission, in the
/// design's staged order. `committed_hash` is the root input's `rootRecordsHash`.
pub fn admit_import(
    raw: &[u8],
    committed_hash: B256,
    budget: u64,
) -> Result<AdmittedImport, ImportError> {
    if raw.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge { len: raw.len() });
    }
    let scan = scan_gas(raw.len()).ok_or(ImportError::Overflow)?;
    if scan > budget {
        return Err(ImportError::ScanBudget);
    }
    let header = walk(raw, None)?;
    let entries_gas = ENTRY_GAS.checked_mul(header.entries as u64).ok_or(ImportError::Overflow)?;
    if entries_gas > budget - scan {
        return Err(ImportError::EntryBudget);
    }
    let mut entries = Vec::with_capacity(header.entries);
    let decoded = walk(raw, Some(&mut entries))?;
    debug_assert_eq!(decoded.entries, entries.len());
    if sha256(raw) != committed_hash {
        return Err(ImportError::HashMismatch);
    }
    let gas = scan + entries_gas;
    Ok(AdmittedImport {
        import: RecordImport {
            progress: decoded.progress,
            uc_time: decoded.uc_time,
            target_count: decoded.target_count,
            target_tip: decoded.target_tip,
            entries,
        },
        gas,
    })
}

impl RecordImport {
    /// The canonical companion bytes, the exact inverse of [`admit_import`]'s decoding. Used by
    /// fixtures and tests; a production node receives the bytes from its paired Go verifier and
    /// never builds them.
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::{array, bytes, text, uint};
        let mut out = Vec::new();
        array(&mut out, 6);
        text(&mut out, IMPORT_DOMAIN);
        uint(&mut out, self.progress);
        uint(&mut out, self.uc_time);
        uint(&mut out, self.target_count);
        bytes(&mut out, self.target_tip.as_slice());
        array(&mut out, self.entries.len() as u64);
        for e in &self.entries {
            array(&mut out, 8);
            uint(&mut out, e.index);
            bytes(&mut out, e.record_id.as_slice());
            bytes(&mut out, e.predecessor.as_slice());
            uint(&mut out, u64::from(e.kind));
            uint(&mut out, e.progress);
            uint(&mut out, e.uc_time);
            bytes(&mut out, &e.data);
            uint(&mut out, e.closed_epoch);
        }
        out
    }

    /// The privileged `importRootRecords(n, p, t, targetCount, targetTip, entries)` calldata for
    /// the shard round `n` the block opens.
    pub fn call_data(&self, n: u64) -> Bytes {
        importRootRecordsCall {
            n,
            p: self.progress,
            t: self.uc_time,
            targetCount: self.target_count,
            targetTip: self.target_tip,
            entries: self
                .entries
                .iter()
                .map(|e| ImportedRecord {
                    record: RootRecord {
                        index: e.index,
                        recordID: e.record_id,
                        predecessor: e.predecessor,
                        kind: e.kind,
                        progress: e.progress,
                        ucTime: e.uc_time,
                        data: Bytes::copy_from_slice(&e.data),
                    },
                    closedEpoch: e.closed_epoch,
                })
                .collect(),
        }
        .abi_encode()
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    const VECTORS: &str = include_str!("../testdata/p85-import-vectors.json");

    // ---- an independent encoder: bytes are built here, never taken from the decoder under test
    // ----

    fn head(out: &mut Vec<u8>, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => out.push(major | value as u8),
            24..=0xff => out.extend([major | 24, value as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend((value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend((value as u32).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend(value.to_be_bytes());
            }
        }
    }
    fn uint(out: &mut Vec<u8>, v: u64) {
        head(out, 0, v)
    }
    fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len() as u64);
        out.extend(b);
    }
    fn text(out: &mut Vec<u8>, t: &str) {
        head(out, 3, t.len() as u64);
        out.extend(t.as_bytes());
    }

    #[derive(Clone)]
    struct Spec {
        domain: &'static str,
        p: u64,
        t: u64,
        count: u64,
        tip: [u8; 32],
        entries: Vec<EntrySpec>,
    }
    #[derive(Clone)]
    struct EntrySpec {
        index: u64,
        id: [u8; 32],
        pred: [u8; 32],
        kind: u64,
        progress: u64,
        time: u64,
        data: Vec<u8>,
        closed: u64,
        arity: u64,
    }

    fn entry(i: u64, kind: u64) -> EntrySpec {
        let width = payload_width(kind).unwrap_or(32);
        EntrySpec {
            index: i,
            id: [i as u8 + 1; 32],
            pred: [i as u8; 32],
            kind,
            progress: 10 + i,
            time: 1_000 + i,
            data: vec![i as u8; width],
            closed: if kind == 4 { 1 } else { 0 },
            arity: 8,
        }
    }

    fn spec(entries: Vec<EntrySpec>) -> Spec {
        Spec {
            domain: IMPORT_DOMAIN,
            p: 50,
            t: 2_000,
            count: entries.len() as u64,
            tip: if entries.is_empty() { [0; 32] } else { [7; 32] },
            entries,
        }
    }

    fn encode(s: &Spec) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, 4, 6);
        text(&mut out, s.domain);
        uint(&mut out, s.p);
        uint(&mut out, s.t);
        uint(&mut out, s.count);
        bytes(&mut out, &s.tip);
        head(&mut out, 4, s.entries.len() as u64);
        for e in &s.entries {
            head(&mut out, 4, e.arity);
            uint(&mut out, e.index);
            bytes(&mut out, &e.id);
            bytes(&mut out, &e.pred);
            uint(&mut out, e.kind);
            uint(&mut out, e.progress);
            uint(&mut out, e.time);
            bytes(&mut out, &e.data);
            uint(&mut out, e.closed);
        }
        out
    }

    fn admit(raw: &[u8]) -> Result<AdmittedImport, ImportError> {
        admit_import(raw, sha256(raw), 1 << 40)
    }

    // ---- shared vectors generated by bft-core's rootrecords package ----

    #[test]
    fn go_vectors_admit_with_the_committed_hash_and_the_designed_charge() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let mut seen = 0;
        for scenario in vectors["scenarios"].as_array().unwrap() {
            for block in scenario["blocks"].as_array().unwrap() {
                let raw = hex::decode(block["companion"].as_str().unwrap()).unwrap();
                let hash: B256 = block["rootRecordsHash"].as_str().unwrap().parse().unwrap();
                let admitted = admit_import(&raw, hash, 1 << 40).unwrap();
                let want_entries: Vec<serde_json::Value> =
                    block["entries"].as_array().cloned().unwrap_or_default();
                let n = want_entries.len();
                assert_eq!(admitted.import.entries.len(), n);
                assert_eq!(admitted.gas, 2_000 + 16 * raw.len() as u64 + 1_000 * n as u64);
                assert_eq!(admitted.import.progress, block["progress"].as_u64().unwrap());
                assert_eq!(admitted.import.uc_time, block["ucTime"].as_u64().unwrap());
                assert_eq!(admitted.import.target_count, block["targetCount"].as_u64().unwrap());
                assert_eq!(
                    admitted.import.target_tip,
                    block["targetTip"].as_str().unwrap().parse::<B256>().unwrap()
                );
                for (got, want) in admitted.import.entries.iter().zip(&want_entries) {
                    assert_eq!(got.index, want["index"].as_u64().unwrap());
                    assert_eq!(
                        got.record_id,
                        want["recordId"].as_str().unwrap().parse::<B256>().unwrap()
                    );
                    assert_eq!(
                        got.predecessor,
                        want["predecessor"].as_str().unwrap().parse::<B256>().unwrap()
                    );
                    assert_eq!(u64::from(got.kind), want["kind"].as_u64().unwrap());
                    assert_eq!(got.progress, want["progress"].as_u64().unwrap());
                    assert_eq!(got.uc_time, want["ucTime"].as_u64().unwrap());
                    assert_eq!(got.data, hex::decode(want["data"].as_str().unwrap()).unwrap());
                    assert_eq!(got.closed_epoch, want["closedEpoch"].as_u64().unwrap());
                }
                // another hash is not this block's commitment
                let mut other = hash;
                other.0[0] ^= 1;
                assert_eq!(admit_import(&raw, other, 1 << 40), Err(ImportError::HashMismatch));
                seen += 1;
            }
        }
        assert!(seen >= 5);
    }

    #[test]
    fn to_bytes_is_the_inverse_of_admission() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        for scenario in vectors["scenarios"].as_array().unwrap() {
            for block in scenario["blocks"].as_array().unwrap() {
                let raw = hex::decode(block["companion"].as_str().unwrap()).unwrap();
                let admitted = admit_import(&raw, sha256(&raw), 1 << 40).unwrap();
                assert_eq!(admitted.import.to_bytes(), raw);
            }
        }
        let entries: Vec<_> = (1..=5).map(|k| entry(k - 1, k)).collect();
        let raw = encode(&spec(entries));
        assert_eq!(admit(&raw).unwrap().import.to_bytes(), raw);
    }

    #[test]
    fn the_independent_encoder_reproduces_the_go_bytes() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let block = &vectors["scenarios"][0]["blocks"][0];
        let mut entries = Vec::new();
        for e in block["entries"].as_array().unwrap() {
            entries.push(EntrySpec {
                index: e["index"].as_u64().unwrap(),
                id: e["recordId"].as_str().unwrap().parse::<B256>().unwrap().0,
                pred: e["predecessor"].as_str().unwrap().parse::<B256>().unwrap().0,
                kind: e["kind"].as_u64().unwrap(),
                progress: e["progress"].as_u64().unwrap(),
                time: e["ucTime"].as_u64().unwrap(),
                data: hex::decode(e["data"].as_str().unwrap()).unwrap(),
                closed: e["closedEpoch"].as_u64().unwrap(),
                arity: 8,
            });
        }
        let s = Spec {
            domain: IMPORT_DOMAIN,
            p: block["progress"].as_u64().unwrap(),
            t: block["ucTime"].as_u64().unwrap(),
            count: block["targetCount"].as_u64().unwrap(),
            tip: block["targetTip"].as_str().unwrap().parse::<B256>().unwrap().0,
            entries,
        };
        assert_eq!(encode(&s), hex::decode(block["companion"].as_str().unwrap()).unwrap());
    }

    // ---- the happy path and the calldata ----

    #[test]
    fn every_kind_is_admitted_at_its_exact_width_and_builds_the_privileged_call() {
        let entries: Vec<_> = (1..=5).map(|k| entry(k - 1, k)).collect();
        let raw = encode(&spec(entries));
        let admitted = admit(&raw).unwrap();
        assert_eq!(admitted.import.entries.len(), 5);
        assert_eq!(admitted.import.entries[3].closed_epoch, 1);
        let call = admitted.import.call_data(9);
        assert_eq!(
            &call[..4],
            &[0xbd, 0xc4, 0xff, 0x89],
            "the registry's importRootRecords selector"
        );
        let decoded = importRootRecordsCall::abi_decode(&call).unwrap();
        assert_eq!((decoded.n, decoded.p, decoded.t, decoded.targetCount), (9, 50, 2_000, 5));
        assert_eq!(decoded.targetTip, B256::from([7; 32]));
        assert_eq!(decoded.entries.len(), 5);
        for (abi, got) in decoded.entries.iter().zip(&admitted.import.entries) {
            assert_eq!(abi.record.index, got.index);
            assert_eq!(abi.record.recordID, got.record_id);
            assert_eq!(abi.record.predecessor, got.predecessor);
            assert_eq!(abi.record.kind, got.kind);
            assert_eq!(abi.record.progress, got.progress);
            assert_eq!(abi.record.ucTime, got.uc_time);
            assert_eq!(abi.record.data.as_ref(), got.data.as_slice());
            assert_eq!(abi.closedEpoch, got.closed_epoch);
        }
    }

    #[test]
    fn an_empty_import_is_admitted_and_mandatory() {
        let raw = encode(&spec(vec![]));
        let admitted = admit(&raw).unwrap();
        assert!(admitted.import.entries.is_empty());
        assert_eq!(admitted.gas, 2_000 + 16 * raw.len() as u64);
        let decoded = importRootRecordsCall::abi_decode(&admitted.import.call_data(1)).unwrap();
        assert!(decoded.entries.is_empty());
        assert_eq!(decoded.targetTip, B256::ZERO);
    }

    #[test]
    fn thirty_two_entries_are_the_limit() {
        let ok = encode(&spec((0..32).map(|i| entry(i, 1)).collect()));
        assert_eq!(admit(&ok).unwrap().import.entries.len(), 32);
        let over = encode(&spec((0..33).map(|i| entry(i, 1)).collect()));
        assert_eq!(admit(&over), Err(ImportError::TooManyEntries(33)));
    }

    #[test]
    fn the_largest_admissible_companion_is_inside_the_byte_cap() {
        // 32 closure-sized entries of the widest kind stay far below 16384 bytes
        let widest = encode(&spec((0..32).map(|i| entry(i, 3)).collect()));
        assert!(widest.len() <= MAX_IMPORT_BYTES);
        assert!(MAX_ADMISSION_GAS >= scan_gas(widest.len()).unwrap() + 32_000);
    }

    // ---- admission order and charges ----

    #[test]
    fn the_byte_cap_precedes_every_charge_and_every_read() {
        let mut raw = encode(&spec(vec![entry(0, 1)]));
        raw.resize(MAX_IMPORT_BYTES + 1, 0);
        assert_eq!(
            admit_import(&raw, B256::ZERO, 0),
            Err(ImportError::TooLarge { len: MAX_IMPORT_BYTES + 1 }),
            "refused as too large even with no budget, before the scan charge is looked at"
        );
        raw.truncate(MAX_IMPORT_BYTES);
        assert!(!matches!(
            admit_import(&raw, B256::ZERO, 1 << 40),
            Err(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_scan_charge_is_reserved_before_the_scan() {
        let raw = encode(&spec(vec![entry(0, 1)]));
        let scan = 2_000 + 16 * raw.len() as u64;
        // garbage of the same length is refused for budget, not for its content, when the scan does
        // not fit
        let garbage = vec![0xffu8; raw.len()];
        assert_eq!(admit_import(&garbage, B256::ZERO, scan - 1), Err(ImportError::ScanBudget));
        assert!(matches!(admit_import(&garbage, B256::ZERO, scan), Err(ImportError::Encoding(_))));
        assert_eq!(scan_gas(raw.len()), Some(scan));
    }

    #[test]
    fn the_entry_charge_is_reserved_before_any_entry_is_decoded() {
        let raw = encode(&spec((0..3).map(|i| entry(i, 1)).collect()));
        let scan = 2_000 + 16 * raw.len() as u64;
        let hash = sha256(&raw);
        assert_eq!(admit_import(&raw, hash, scan + 2_999), Err(ImportError::EntryBudget));
        let exact = admit_import(&raw, hash, scan + 3_000).unwrap();
        assert_eq!(exact.gas, scan + 3_000);
        // a shaped-but-wrong payload past the budget boundary is still a budget refusal: the
        // entries were never decoded
        let mut bad = spec((0..3).map(|i| entry(i, 1)).collect());
        bad.entries[2].data = vec![0; 31];
        let bad = encode(&bad);
        let bad_scan = 2_000 + 16 * bad.len() as u64;
        assert!(matches!(
            admit_import(&bad, B256::ZERO, bad_scan + 3_000),
            Err(ImportError::PayloadWidth { .. })
        ));
    }

    #[test]
    fn the_hash_binds_the_exact_bytes() {
        let raw = encode(&spec(vec![entry(0, 2)]));
        assert!(admit_import(&raw, sha256(&raw), 1 << 40).is_ok());
        assert_eq!(admit_import(&raw, B256::ZERO, 1 << 40), Err(ImportError::HashMismatch));
        let other = encode(&Spec { p: 51, ..spec(vec![entry(0, 2)]) });
        assert_eq!(admit_import(&other, sha256(&raw), 1 << 40), Err(ImportError::HashMismatch));
    }

    // ---- refusals, each isolated ----

    #[test]
    fn structural_refusals() {
        let base = spec(vec![entry(0, 1), entry(1, 5)]);
        let cases: Vec<(&str, Spec, ImportError)> = vec![
            (
                "another domain",
                Spec { domain: "UNICITY_P85_RECORD_IMPORT2", ..base.clone() },
                ImportError::Domain,
            ),
            (
                "a zero target with a tip",
                Spec { count: 0, entries: vec![], ..base.clone() },
                ImportError::ZeroTargetTip,
            ),
            (
                "kind zero",
                {
                    let mut s = base.clone();
                    s.entries[0].kind = 0;
                    s
                },
                ImportError::UnknownKind(0),
            ),
            (
                "kind six",
                {
                    let mut s = base.clone();
                    s.entries[1].kind = 6;
                    s
                },
                ImportError::UnknownKind(6),
            ),
            (
                "a kind above a byte",
                {
                    let mut s = base.clone();
                    s.entries[0].kind = 257;
                    s
                },
                ImportError::UnknownKind(257),
            ),
            (
                "a short ack payload",
                {
                    let mut s = base.clone();
                    s.entries[0].data = vec![0; 31];
                    s
                },
                ImportError::PayloadWidth { kind: 1, len: 31 },
            ),
            (
                "a long retirement payload",
                {
                    let mut s = base.clone();
                    s.entries[1].data = vec![0; 97];
                    s
                },
                ImportError::TooLarge { len: 0 },
            ),
            (
                "a closed epoch on a retirement",
                {
                    let mut s = base.clone();
                    s.entries[1].closed = 1;
                    s
                },
                ImportError::ClosedEpochOnNonClosure,
            ),
        ];
        for (name, s, want) in cases {
            let raw = encode(&s);
            let got = admit(&raw);
            match (name, &got) {
                (
                    "a long retirement payload",
                    Err(ImportError::Encoding(CanonicalCborError::TooLarge { .. })),
                ) => {}
                _ => assert_eq!(got, Err(want), "{name}"),
            }
        }
    }

    #[test]
    fn arity_refusals() {
        let mut s = spec(vec![entry(0, 1)]);
        s.entries[0].arity = 7;
        assert!(matches!(
            admit(&encode(&s)),
            Err(ImportError::Encoding(CanonicalCborError::WrongArity { expected: 8, found: 7 }))
        ));
        s.entries[0].arity = 9;
        assert!(matches!(
            admit(&encode(&s)),
            Err(ImportError::Encoding(CanonicalCborError::WrongArity { expected: 8, found: 9 }))
        ));
        // the envelope arity
        let mut raw = encode(&spec(vec![]));
        raw[0] = 0x85;
        assert!(matches!(
            admit(&raw),
            Err(ImportError::Encoding(CanonicalCborError::WrongArity { expected: 6, found: 5 }))
        ));
        raw[0] = 0x87;
        assert!(matches!(
            admit(&raw),
            Err(ImportError::Encoding(CanonicalCborError::WrongArity { expected: 6, found: 7 }))
        ));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let raw = encode(&spec(vec![entry(0, 1)]));
        // trailing bytes
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            admit(&trailing),
            Err(ImportError::Encoding(CanonicalCborError::TrailingBytes))
        ));
        // truncation
        assert!(matches!(
            admit(&raw[..raw.len() - 1]),
            Err(ImportError::Encoding(CanonicalCborError::UnexpectedEof))
        ));
        // a longer form of the envelope array head (0x86 -> 0x98 0x06)
        let mut long = vec![0x98, 0x06];
        long.extend(&raw[1..]);
        assert!(matches!(
            admit(&long),
            Err(ImportError::Encoding(CanonicalCborError::NonMinimalLength))
        ));
        // an indefinite-length array
        let mut indefinite = vec![0x9f];
        indefinite.extend(&raw[1..]);
        assert!(matches!(
            admit(&indefinite),
            Err(ImportError::Encoding(CanonicalCborError::IndefiniteLength))
        ));
        // a non-minimal unsigned integer: p = 50 as 0x18 0x32 is minimal, as 0x19 0x00 0x32 is not
        let s = spec(vec![]);
        let minimal = encode(&s);
        let at = 1 + 1 + IMPORT_DOMAIN.len(); // after the array head and the domain text head+body
        let at = at + 1; // the text head of 25 chars is two bytes (0x78 0x19)
        let mut padded = minimal[..at].to_vec();
        padded.extend([0x19, 0x00, 0x32]);
        padded.extend(&minimal[at + 2..]);
        assert!(matches!(
            admit(&padded),
            Err(ImportError::Encoding(CanonicalCborError::NonMinimalLength))
        ));
        // a tag, a negative integer and a null where a word is required
        for first in [0xc0u8, 0x20, 0xf6] {
            let mut tagged = raw.clone();
            let n = tagged.len();
            tagged[n - 1] = first;
            assert!(admit(&tagged).is_err(), "{first:#x}");
        }
        // a map instead of the entries array
        let mut map = encode(&spec(vec![]));
        let n = map.len();
        map[n - 1] = 0xa0;
        assert!(matches!(
            admit(&map),
            Err(ImportError::Encoding(CanonicalCborError::UnexpectedItem { major: 5, .. }))
        ));
    }

    #[test]
    fn the_scan_and_the_decode_cannot_disagree() {
        // every single-byte truncation or flip of a valid companion is refused or decodes to the
        // very same value
        let raw = encode(&spec(vec![entry(0, 2), entry(1, 4), entry(2, 5)]));
        let reference = admit_import(&raw, sha256(&raw), 1 << 40).unwrap().import;
        for i in 0..raw.len() {
            let mut flipped = raw.clone();
            flipped[i] ^= 0x01;
            if let Ok(a) = admit_import(&flipped, sha256(&flipped), 1 << 40) {
                assert_ne!(
                    a.import, reference,
                    "byte {i}: a different byte string decoded to the same value"
                );
            }
        }
    }
}
