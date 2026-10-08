//! B1 registry execution: bft-core's independently modelled vectors against the real registry
//! runtime, then isolated guard mutations with exact error variants.
//!
//! Every `UpdateError` variant the admission path can return has a case here that reaches it
//! alone, and `tools/mutate_b1_guards.py` disables each guard once to prove the case notices.

use crate::{
    testing::{self, world},
    update::{admit, window_floor, B1Context, Entry, Update, UpdateBinding, UpdateError},
    ExecutionConfig, ExecutionError, ExecutionResult, RootInputV2, UpdateInput, SEAL_REGISTRY,
};
use alloy_primitives::{keccak256, B256, U256};
use revm::{
    database::{CacheDB, EmptyDB},
    DatabaseRef,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    universe: Vec<B256>,
    genesis_words: BTreeMap<B256, B256>,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    name: String,
    n: u64,
    origin_round: u64,
    origin_epoch: u64,
    parent_number: u64,
    root_input: String,
    update: String,
    update_hash: B256,
    admission_gas: u64,
    records_import: String,
    #[serde(rename = "rootRecordsHash")]
    root_records_hash: B256,
    records_admission_gas: u64,
    insert_writes: u64,
    clear_writes: u64,
    write_allowance: u64,
    #[serde(rename = "final")]
    changed: BTreeMap<B256, B256>,
    live_epochs: Vec<u64>,
}

fn hex(value: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(value.trim_start_matches("0x")).unwrap()
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../testdata/b1-vectors.json")).unwrap()
}

fn config(limit: u64) -> ExecutionConfig {
    ExecutionConfig { system_gas_limit: limit, b1: testing::b1_context() }
}

fn word(db: &CacheDB<EmptyDB>, slot: B256) -> B256 {
    B256::from(
        db.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(slot.0)).unwrap().to_be_bytes::<32>(),
    )
}

fn assert_universe(db: &CacheDB<EmptyDB>, v: &Vectors, expected: &BTreeMap<B256, B256>, at: &str) {
    for slot in &v.universe {
        assert_eq!(
            word(db, *slot),
            expected.get(slot).copied().unwrap_or_default(),
            "{at}: slot {slot}"
        );
    }
}

/// The step's decoded inputs and the state it executes on.
struct Case {
    input: RootInputV2,
    update: Update,
    parent: CacheDB<EmptyDB>,
    parent_number: u64,
}

fn run_bytes(
    input: &RootInputV2,
    bytes: &[u8],
    parent_number: u64,
    parent: &CacheDB<EmptyDB>,
    limit: u64,
) -> Result<(ExecutionResult, CacheDB<EmptyDB>), ExecutionError> {
    crate::execute_registry_transition(
        input,
        UpdateInput { bytes, records: &crate::testing::empty_import(), parent_number },
        parent,
        config(limit),
    )
}

impl Case {
    /// Executes every step before `index` and decodes step `index` on the resulting state.
    fn at(index: usize) -> Self {
        let v = vectors();
        let mut db = testing::genesis_db();
        for step in &v.steps[..index] {
            let input = RootInputV2::from_canonical_cbor(&hex(&step.root_input)).unwrap();
            db = run_bytes(&input, &hex(&step.update), step.parent_number, &db, world().system_gas)
                .unwrap()
                .1;
        }
        let step = &v.steps[index];
        let input = RootInputV2::from_canonical_cbor(&hex(&step.root_input)).unwrap();
        let admitted = admit(
            &hex(&step.update),
            &testing::b1_context(),
            &binding(&input, step.parent_number),
            world().system_gas,
        )
        .unwrap();
        Self { input, update: admitted.update, parent: db, parent_number: step.parent_number }
    }

    /// Runs the case with `mutate` applied to the update, committing the mutated bytes in the
    /// root input so only the guard under test can refuse it.
    fn with(&self, mutate: impl FnOnce(&mut Update)) -> Result<ExecutionResult, ExecutionError> {
        let mut update = self.update.clone();
        mutate(&mut update);
        let bytes = update.to_bytes();
        let mut input = self.input.clone();
        input.b1_update_hash = crate::sha256(&bytes);
        run_bytes(&input, &bytes, self.parent_number, &self.parent, world().system_gas)
            .map(|(result, _)| result)
    }
}

fn binding(input: &RootInputV2, parent_number: u64) -> UpdateBinding {
    UpdateBinding {
        committed_hash: input.b1_update_hash,
        parent_hash: input.parent_hash,
        parent_number,
        origin_epoch: input.origin.root_epoch,
        origin_round: input.origin.root_round,
        origin_identity: input.origin_identity().unwrap(),
    }
}

const QUIET: usize = 0;
const EXPIRES_GENESIS: usize = 2;
const CLOSES_AND_INSERTS: usize = 4;
const SKIPS_EXPIRED: usize = 9;

#[test]
fn genesis_words_match_bft_cores_model() {
    let v = vectors();
    assert_universe(&testing::genesis_db(), &v, &v.genesis_words, "genesis");
}

#[test]
fn every_step_reproduces_bft_cores_registry_words_and_admission_gas() {
    let v = vectors();
    let mut db = testing::genesis_db();
    let mut expected = v.genesis_words.clone();
    let mut live = vec![1u64];
    for step in &v.steps {
        let input = RootInputV2::from_canonical_cbor(&hex(&step.root_input)).unwrap();
        let bytes = hex(&step.update);
        assert_eq!(crate::sha256(&bytes), step.update_hash, "{}", step.name);
        assert_eq!(input.b1_update_hash, step.update_hash, "{}", step.name);
        assert_eq!(input.origin.root_round, step.origin_round, "{}", step.name);
        assert_eq!(input.origin.root_epoch, step.origin_epoch, "{}", step.name);
        assert_eq!(input.authorized_round, step.n, "{}", step.name);
        let (result, next) =
            run_bytes(&input, &bytes, step.parent_number, &db, world().system_gas).unwrap();
        assert_eq!(
            result.admission_gas,
            step.admission_gas + step.records_admission_gas,
            "{}",
            step.name
        );
        assert_eq!(result.records_admission_gas, step.records_admission_gas, "{}", step.name);
        assert_eq!(hex(&step.records_import), testing::empty_import().to_vec(), "{}", step.name);
        assert_eq!(input.root_records_hash, step.root_records_hash, "{}", step.name);
        assert_eq!(
            result.total_gas_spent,
            result.admission_gas +
                result.open_gas_spent +
                result.import_gas_spent +
                result.finalize_gas_spent,
            "{}",
            step.name
        );
        expected.extend(step.changed.iter().map(|(k, val)| (*k, *val)));
        assert_universe(&next, &v, &expected, &step.name);

        // Re-measurement under this client: everything except the history SSTORE rectangle must
        // fit the frozen `G_rest(a, p)` allowance of the contracts artifact (1.5x margin
        // included). `a` and `p` are the entries inserted and deleted by the step.
        let a = step.live_epochs.iter().filter(|e| !live.contains(e)).count() as u64;
        let p = live.iter().filter(|e| !step.live_epochs.contains(e)).count() as u64;
        let rest = 1_136_500 + 949_500 * a + 198_000 * p;
        let gross = result.open_gas_spent + result.finalize_gas_spent;
        assert!(
            gross <= step.write_allowance + rest,
            "{}: gross {gross} exceeds rectangle {} + G_rest {rest}",
            step.name,
            step.write_allowance
        );
        assert!(step.insert_writes + step.clear_writes > 0);
        live.clone_from(&step.live_epochs);
        db = next;
    }
}

#[test]
fn deleting_history_refunds_are_never_credited_to_the_system_budget() {
    let case = Case::at(EXPIRES_GENESIS);
    let result = case.with(|_| {}).unwrap();
    assert!(result.open_gas_refunded > 0, "pruning the genesis entry clears nonzero words");
    assert_eq!(
        result.total_gas_spent,
        result.admission_gas +
            result.open_gas_spent +
            result.import_gas_spent +
            result.finalize_gas_spent
    );
    // The gross total is the whole budget: one unit less cannot fund the last operation.
    let step = &vectors().steps[EXPIRES_GENESIS];
    let bytes = hex(&step.update);
    let exact = result.total_gas_spent;
    assert!(run_bytes(&case.input, &bytes, case.parent_number, &case.parent, exact).is_ok());
    assert!(matches!(
        run_bytes(&case.input, &bytes, case.parent_number, &case.parent, exact - 1),
        Err(ExecutionError::FinalizeFailed(_))
    ));
}

#[test]
fn admission_is_charged_before_open_and_staged_before_the_members_are_parsed() {
    let case = Case::at(EXPIRES_GENESIS);
    let bytes = case.update.to_bytes();
    let context = testing::b1_context();
    let bind = binding(&case.input, case.parent_number);
    let scan = 2000 + 16 * bytes.len() as u64;
    let members: u64 = case.update.new_entries.iter().map(|e| e.members.len() as u64).sum();
    let gas = scan + 1000 * members;
    assert_eq!(admit(&bytes, &context, &bind, gas).unwrap().gas, gas);
    assert_eq!(admit(&bytes, &context, &bind, gas - 1), Err(UpdateError::MemberBudget));
    assert_eq!(admit(&bytes, &context, &bind, scan), Err(UpdateError::MemberBudget));
    assert_eq!(admit(&bytes, &context, &bind, scan - 1), Err(UpdateError::ScanBudget));
    // The scan debit precedes any look at the bytes: garbage is a budget error, not an encoding
    // one.
    assert_eq!(admit(&[0xff; 64], &context, &bind, 1), Err(UpdateError::ScanBudget));
    // The member debit precedes semantics: a zero-weight member never gets that far on a short
    // budget.
    let mut poisoned = case.update;
    poisoned.new_entries[0].members[0].weight = 0;
    let poisoned = poisoned.to_bytes();
    assert_eq!(
        admit(&poisoned, &context, &bind, 2000 + 16 * poisoned.len() as u64),
        Err(UpdateError::MemberBudget)
    );
    // The byte cap is checked first of all.
    let cap = context.max_update_bytes().unwrap();
    assert_eq!(
        admit(&vec![0; cap as usize + 1], &context, &bind, u64::MAX),
        Err(UpdateError::TooLarge { len: cap as usize + 1, limit: cap })
    );
}

#[test]
fn the_kernel_refuses_a_system_budget_that_cannot_admit() {
    let case = Case::at(EXPIRES_GENESIS);
    let bytes = case.update.to_bytes();
    let scan = 2000 + 16 * bytes.len() as u64;
    for (limit, expected) in
        [(scan - 1, UpdateError::ScanBudget), (scan, UpdateError::MemberBudget)]
    {
        assert_eq!(
            run_bytes(&case.input, &bytes, case.parent_number, &case.parent, limit).unwrap_err(),
            ExecutionError::B1Update(expected)
        );
    }
}

#[test]
fn every_admission_binding_is_checked_alone() {
    let case = Case::at(CLOSES_AND_INSERTS);
    let cases: Vec<Mutation> = vec![
        ("network", Box::new(|u| u.network += 1), UpdateError::NetworkMismatch),
        ("genesis", Box::new(|u| u.root_genesis_id.0[0] ^= 1), UpdateError::RootGenesisMismatch),
        ("chain", Box::new(|u| u.execution_chain_id += 1), UpdateError::ChainMismatch),
        ("profile", Box::new(|u| u.profile_hash.0[0] ^= 1), UpdateError::ProfileMismatch),
        ("parent", Box::new(|u| u.parent_hash.0[0] ^= 1), UpdateError::ParentMismatch),
        ("zero parent", Box::new(|u| u.parent_hash = B256::ZERO), UpdateError::ParentMismatch),
        ("height", Box::new(|u| u.block_number += 1), UpdateError::BlockNumberMismatch),
        ("zero height", Box::new(|u| u.block_number = 0), UpdateError::BlockNumberMismatch),
        ("past height", Box::new(|u| u.block_number -= 1), UpdateError::BlockNumberMismatch),
        ("epoch", Box::new(|u| u.origin_epoch += 1), UpdateError::OriginEpochMismatch),
        ("round", Box::new(|u| u.origin_round += 1), UpdateError::OriginRoundMismatch),
        ("origin", Box::new(|u| u.origin_identity.0[0] ^= 1), UpdateError::OriginIdentityMismatch),
        (
            "zero origin",
            Box::new(|u| u.origin_identity = B256::ZERO),
            UpdateError::OriginIdentityMismatch,
        ),
    ];
    for (name, mutate, expected) in cases {
        assert_eq!(
            case.with(mutate).unwrap_err(),
            ExecutionError::B1Update(expected),
            "binding {name}"
        );
    }
}

#[test]
fn a_zero_parent_or_origin_is_never_a_binding_even_when_both_sides_agree() {
    let case = Case::at(CLOSES_AND_INSERTS);
    let mut zero_parent = case.update.clone();
    zero_parent.parent_hash = B256::ZERO;
    let bytes = zero_parent.to_bytes();
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(&bytes);
    bind.parent_hash = B256::ZERO;
    assert_eq!(
        admit(&bytes, &testing::b1_context(), &bind, world().system_gas),
        Err(UpdateError::ParentMismatch)
    );
    let mut zero_origin = case.update.clone();
    zero_origin.origin_identity = B256::ZERO;
    let bytes = zero_origin.to_bytes();
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(&bytes);
    bind.origin_identity = B256::ZERO;
    assert_eq!(
        admit(&bytes, &testing::b1_context(), &bind, world().system_gas),
        Err(UpdateError::OriginIdentityMismatch)
    );
}

#[test]
fn the_committed_hash_must_name_the_carried_bytes() {
    let case = Case::at(QUIET);
    let bytes = case.update.to_bytes();
    let mut input = case.input.clone();
    input.b1_update_hash.0[0] ^= 1;
    assert_eq!(
        run_bytes(&input, &bytes, case.parent_number, &case.parent, world().system_gas)
            .unwrap_err(),
        ExecutionError::B1Update(UpdateError::UpdateHashMismatch)
    );
}

/// A named single-field mutation of an update and the one refusal it must raise.
type Mutation = (&'static str, Box<dyn Fn(&mut Update)>, UpdateError);

fn entry_mut(u: &mut Update) -> &mut Entry {
    &mut u.new_entries[0]
}

#[test]
fn every_interval_and_member_invariant_is_checked_alone() {
    // At step 4 the parent tail is epoch 2 [10, inf); the update closes it at 20 and inserts
    // epoch 3 as the origin epoch with window floor 19.
    let case = Case::at(CLOSES_AND_INSERTS);
    assert_eq!(window_floor(20, world().w_cert), 19);
    let cases: Vec<Mutation> = vec![
        (
            "zero body id",
            Box::new(|u| entry_mut(u).body_id = B256::ZERO),
            UpdateError::EntryIdentity,
        ),
        (
            "zero config",
            Box::new(|u| entry_mut(u).signing_config_hash = B256::ZERO),
            UpdateError::EntryIdentity,
        ),
        ("body kind 0", Box::new(|u| entry_mut(u).body_kind = 0), UpdateError::EntryIdentity),
        ("body kind 4", Box::new(|u| entry_mut(u).body_kind = 4), UpdateError::EntryIdentity),
        ("scheme 3", Box::new(|u| entry_mut(u).signing_scheme = 3), UpdateError::EntryIdentity),
        (
            "zero activation",
            Box::new(|u| entry_mut(u).activation_commit_id = B256::ZERO),
            UpdateError::EntryIdentity,
        ),
        (
            "empty interval",
            Box::new(|u| entry_mut(u).end = Some(entry_mut(u).start)),
            UpdateError::EmptyInterval,
        ),
        (
            "genesis kind",
            Box::new(|u| {
                let e = entry_mut(u);
                e.body_kind = 1;
                e.activation_commit_id = B256::ZERO;
            }),
            UpdateError::GenesisKindInUpdate,
        ),
        (
            "epoch not newer",
            Box::new(|u| entry_mut(u).epoch = u.prior_tip_epoch),
            UpdateError::EpochNotNewer,
        ),
        (
            "start after origin",
            Box::new(|u| entry_mut(u).start = u.origin_round + 1),
            UpdateError::StartAfterOrigin,
        ),
        (
            "end after origin",
            Box::new(|u| entry_mut(u).end = Some(u.origin_round + 1)),
            UpdateError::EndOutsideWindow,
        ),
        (
            "end at floor",
            Box::new(|u| {
                let floor = window_floor(u.origin_round, world().w_cert);
                let e = entry_mut(u);
                e.start = floor - 1;
                e.end = Some(floor);
            }),
            UpdateError::EndOutsideWindow,
        ),
        (
            "old tip end after first start",
            Box::new(|u| u.old_tip_end = Some(entry_mut(u).start + 1)),
            UpdateError::OldTipEndMismatch,
        ),
        (
            "old tip end before successor start",
            Box::new(|u| u.old_tip_end = Some(entry_mut(u).start - 1)),
            UpdateError::OldTipEndMismatch,
        ),
        ("old tip end absent", Box::new(|u| u.old_tip_end = None), UpdateError::OldTipEndMismatch),
        (
            "closed tail",
            Box::new(|u| {
                // A valid closed interval inside the window whose successor start the former tip
                // is closed at, so only the open-tail requirement can refuse it.
                let origin = u.origin_round;
                let floor = window_floor(origin, world().w_cert);
                u.old_tip_end = Some(floor);
                let e = entry_mut(u);
                e.start = floor;
                e.end = Some(origin);
            }),
            UpdateError::TailNotOrigin,
        ),
    ];
    for (name, mutate, expected) in cases {
        assert_eq!(
            case.with(mutate).unwrap_err(),
            ExecutionError::B1Update(expected),
            "invariant {name}"
        );
    }
    // A skipped epoch leaves no successor to close the former tip early: the old-tip end may not
    // lie after the first surviving start even when the epochs are not consecutive.
    let skipping = Case::at(SKIPS_EXPIRED);
    let first_start = skipping.update.new_entries[0].start;
    assert_eq!(
        skipping.with(|u| u.old_tip_end = Some(first_start + 1)).unwrap_err(),
        ExecutionError::B1Update(UpdateError::OldTipEndMismatch)
    );
    // The tail must be the origin epoch. Re-binding the origin to epoch 4 (the update and the
    // binding agree) leaves only that relation to refuse it; the registry's own epoch check is
    // not reached because this exercises admission alone.
    let mut shifted = case.update.clone();
    shifted.origin_epoch = 4;
    let bytes = shifted.to_bytes();
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(&bytes);
    bind.origin_epoch = 4;
    assert_eq!(
        admit(&bytes, &testing::b1_context(), &bind, world().system_gas),
        Err(UpdateError::TailNotOrigin)
    );
}

#[test]
fn every_member_invariant_is_checked_alone() {
    let case = Case::at(CLOSES_AND_INSERTS);
    let cases: Vec<Mutation> = vec![
        (
            "ids not sorted",
            Box::new(|u| entry_mut(u).members.swap(0, 1)),
            UpdateError::MembersNotSorted,
        ),
        (
            "duplicate id",
            Box::new(|u| {
                let first = entry_mut(u).members[0].clone();
                entry_mut(u).members[1].node_id = first.node_id;
            }),
            UpdateError::MembersNotSorted,
        ),
        (
            "duplicate key",
            Box::new(|u| {
                let key = entry_mut(u).members[0].key;
                entry_mut(u).members[1].key = key;
            }),
            UpdateError::DuplicateKey,
        ),
        (
            "key off the curve",
            Box::new(|u| entry_mut(u).members[0].key[0] = 0x05),
            UpdateError::InvalidKey,
        ),
        (
            "uncompressed prefix",
            Box::new(|u| entry_mut(u).members[0].key[0] = 0x04),
            UpdateError::InvalidKey,
        ),
        ("zero weight", Box::new(|u| entry_mut(u).members[1].weight = 0), UpdateError::ZeroWeight),
        (
            "weight overflow",
            Box::new(|u| {
                entry_mut(u).members[0].weight = u64::MAX;
                entry_mut(u).members[1].weight = 1;
            }),
            UpdateError::WeightOverflow,
        ),
    ];
    for (name, mutate, expected) in cases {
        assert_eq!(
            case.with(mutate).unwrap_err(),
            ExecutionError::B1Update(expected),
            "member invariant {name}"
        );
    }
}

fn admit_raw(bytes: &[u8], case: &Case) -> Result<crate::update::Admitted, UpdateError> {
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(bytes);
    admit(bytes, &testing::b1_context(), &bind, world().system_gas)
}

#[test]
fn the_scan_refuses_every_structural_violation_by_name() {
    let case = Case::at(EXPIRES_GENESIS);
    let good = case.update.to_bytes();
    assert!(admit_raw(&good, &case).is_ok());
    // Offsets into the canonical encoding: array(13), then a 17-byte domain text, then the network.
    assert_eq!(&good[..2], &[0x8d, 0x71]);
    let network_at = 2 + UPDATE_DOMAIN_LEN;
    assert_eq!(good[network_at], 5);
    let mutants: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("wrong arity", [&[0x8c][..], &good[1..]].concat()),
        ("indefinite array", [&[0x9f][..], &good[1..]].concat()),
        ("wrong domain", {
            let mut m = good.clone();
            m[3] ^= 1;
            m
        }),
        (
            "non-minimal network",
            [&good[..network_at], &[0x18, 5][..], &good[network_at + 1..]].concat(),
        ),
        (
            "network above u16",
            [&good[..network_at], &[0x1a, 0, 1, 0, 0][..], &good[network_at + 1..]].concat(),
        ),
        ("negative network", {
            let mut m = good.clone();
            m[network_at] = 0x25;
            m
        }),
        ("truncated", good[..good.len() - 1].to_vec()),
        ("trailing byte", [&good[..], &[0u8][..]].concat()),
        ("text member id replaced by bytes", {
            let at = good.windows(6).position(|w| w == b"node-a").unwrap();
            let mut m = good.clone();
            m[at - 1] = 0x46; // byte string of six instead of text of six
            m
        }),
        ("invalid utf-8 id", {
            let at = good.windows(6).position(|w| w == b"node-a").unwrap();
            let mut m = good.clone();
            m[at] = 0xff;
            m
        }),
    ];
    for (name, bytes) in mutants {
        assert_eq!(admit_raw(&bytes, &case).unwrap_err(), UpdateError::Encoding, "scan {name}");
    }
}

const UPDATE_DOMAIN_LEN: usize = crate::update::UPDATE_DOMAIN.len();

#[test]
fn counts_and_sizes_are_bounded_before_anything_is_allocated() {
    let case = Case::at(CLOSES_AND_INSERTS);
    let k = testing::b1_context().k_max().unwrap();
    // More entries than the ring has slots cannot be a live set: the count is refused by the scan.
    let mut crowded = case.update.clone();
    let template = crowded.new_entries[0].clone();
    crowded.new_entries = (0..=k).map(|i| Entry { epoch: 3 + i, ..template.clone() }).collect();
    assert_eq!(admit_raw(&crowded.to_bytes(), &case).unwrap_err(), UpdateError::Encoding);
    // An entry with no members, or with more than 64, is refused by the scan, not the semantics.
    let mut empty = case.update.clone();
    empty.new_entries[0].members.clear();
    assert_eq!(admit_raw(&empty.to_bytes(), &case).unwrap_err(), UpdateError::Encoding);
    let mut wide = case.update.clone();
    let member = wide.new_entries[0].members[0].clone();
    wide.new_entries[0].members = vec![member; 65];
    assert_eq!(admit_raw(&wide.to_bytes(), &case).unwrap_err(), UpdateError::Encoding);
    // Identifiers are 1..=128 bytes.
    let mut long = case.update.clone();
    long.new_entries[0].members[0].node_id = "x".repeat(129);
    assert_eq!(admit_raw(&long.to_bytes(), &case).unwrap_err(), UpdateError::Encoding);
    let mut blank = case.update.clone();
    blank.new_entries[0].members[0].node_id.clear();
    assert_eq!(admit_raw(&blank.to_bytes(), &case).unwrap_err(), UpdateError::Encoding);
    // A maximal 128-byte identifier is accepted by the scan (its order is a semantic matter).
    let mut max = case.update.clone();
    max.new_entries[0].members[2].node_id = "z".repeat(128);
    assert!(admit_raw(&max.to_bytes(), &case).is_ok());
    // A zero-length ring entry and a token flood are bounded by the profile's token cap.
    assert!(testing::b1_context().max_tokens().unwrap() > 32);
}

#[test]
fn every_single_bit_mutation_is_refused_or_reencodes_to_exactly_itself() {
    // The reader accepts one encoding per value, so decode then re-encode is the identity on
    // everything it accepts. No separate re-encode guard exists; this is the property's test.
    let case = Case::at(CLOSES_AND_INSERTS);
    let good = case.update.to_bytes();
    let mut accepted = 0;
    for bit in 0..good.len() * 8 {
        let mut mutated = good.clone();
        mutated[bit / 8] ^= 1 << (bit % 8);
        if let Ok(admitted) = admit_raw(&mutated, &case) {
            accepted += 1;
            assert_eq!(admitted.update.to_bytes(), mutated, "bit {bit}");
        }
    }
    assert!(accepted > 0, "some flips (identities, weights) stay valid and must round-trip");
}

#[test]
fn an_unmeasured_ring_is_refused_never_truncated() {
    let big = B1Context { w_cert: 16, ..testing::b1_context() };
    assert_eq!(big.k_max(), Err(UpdateError::UnmeasuredRing(17)));
    assert_eq!(big.required_system_gas(), Err(UpdateError::UnmeasuredRing(17)));
    let edge = B1Context { w_cert: 15, ..testing::b1_context() };
    assert_eq!(edge.k_max(), Ok(16));
    assert_eq!(
        edge.required_system_gas().unwrap(),
        155_936 + 1_136_500 + (15_626_944 + 1_147_500) * 16 + crate::records::IMPORT_ENVELOPE_GAS
    );
    let overflow = B1Context { w_cert: u64::MAX, ..testing::b1_context() };
    assert_eq!(overflow.k_max(), Err(UpdateError::Overflow));
}

#[test]
fn the_registry_refuses_what_only_its_own_state_can_show() {
    // Admission is state-free. An update that is canonical, bound and internally consistent but
    // names a prior tip other than the stored tail is refused by the metered registry call.
    let case = Case::at(CLOSES_AND_INSERTS);
    match case.with(|u| u.prior_tip_epoch = 1) {
        Err(ExecutionError::OpenFailed(message)) => {
            let selector = alloy_primitives::hex::encode(&keccak256("PriorTipMismatch()")[..4]);
            assert!(message.contains(&selector), "{message}");
        }
        other => panic!("expected the registry to revert, got {other:?}"),
    }
}

#[test]
fn the_registry_profile_words_must_equal_the_pinned_profile() {
    let case = Case::at(QUIET);
    let bytes = case.update.to_bytes();
    let run = |config: ExecutionConfig, db: &CacheDB<EmptyDB>| {
        crate::execute_registry_transition(
            &case.input,
            UpdateInput {
                bytes: &bytes,
                records: &crate::testing::empty_import(),
                parent_number: case.parent_number,
            },
            db,
            config,
        )
        .map(|(result, _)| result)
    };
    let pinned = config(world().system_gas);
    assert!(run(pinned, &case.parent).is_ok());
    let wrong = [
        ("network", B1Context { network: pinned.b1.network + 1, ..pinned.b1 }),
        ("window", B1Context { w_cert: pinned.b1.w_cert + 1, ..pinned.b1 }),
        ("profile hash", B1Context { profile_hash: B256::repeat_byte(9), ..pinned.b1 }),
    ];
    for (name, b1) in wrong {
        assert!(
            matches!(
                run(ExecutionConfig { b1, ..pinned }, &case.parent),
                Err(ExecutionError::B1ProfileMismatch(_))
            ),
            "{name}"
        );
    }
    let mut uninitialized = case.parent.clone();
    uninitialized
        .insert_account_storage(
            SEAL_REGISTRY,
            reth_unicity_b1::fixed_slot("b1.initialized"),
            U256::ZERO,
        )
        .unwrap();
    assert_eq!(
        run(pinned, &uninitialized).unwrap_err(),
        ExecutionError::B1ProfileMismatch("B1 registry is not initialized")
    );
}

/// Admits `update` as if the block's origin were epoch `origin_epoch`.
fn admit_for(case: &Case, update: &Update, origin_epoch: u64) -> Result<(), UpdateError> {
    let bytes = update.to_bytes();
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(&bytes);
    bind.origin_epoch = origin_epoch;
    admit(&bytes, &testing::b1_context(), &bind, world().system_gas).map(|_| ())
}

#[test]
fn consecutive_new_entries_must_abut_and_follow_each_other_by_one_epoch() {
    // Two surviving entries at origin 20: epoch 3 over [19, 20) and the open origin epoch 4.
    let case = Case::at(CLOSES_AND_INSERTS);
    let template = case.update.new_entries[0].clone();
    let closed = Entry { epoch: 3, start: 19, end: Some(20), ..template.clone() };
    let open = Entry { epoch: 4, start: 20, end: None, ..template };
    let mut good = case.update.clone();
    good.origin_epoch = 4;
    good.old_tip_end = Some(19);
    good.new_entries = vec![closed, open];
    assert_eq!(admit_for(&case, &good, 4), Ok(()));

    let mut gap_in_time = good.clone();
    gap_in_time.new_entries[1].start = 19;
    assert_eq!(admit_for(&case, &gap_in_time, 4), Err(UpdateError::NotContiguous));

    let mut gap_in_epochs = good;
    gap_in_epochs.origin_epoch = 5;
    gap_in_epochs.new_entries[1].epoch = 5;
    assert_eq!(admit_for(&case, &gap_in_epochs, 5), Err(UpdateError::NotContiguous));
}

#[test]
fn an_empty_update_names_no_closure_and_the_origin_epoch() {
    let case = Case::at(QUIET);
    assert!(case.update.new_entries.is_empty());
    assert_eq!(
        case.with(|u| u.old_tip_end = Some(3)).unwrap_err(),
        ExecutionError::B1Update(UpdateError::EmptyUpdateMismatch)
    );
    assert_eq!(
        case.with(|u| u.prior_tip_epoch += 1).unwrap_err(),
        ExecutionError::B1Update(UpdateError::EmptyUpdateMismatch)
    );
}

#[test]
fn the_scan_stage_refuses_invalid_utf8_before_the_member_debit() {
    let case = Case::at(EXPIRES_GENESIS);
    let mut bytes = case.update.to_bytes();
    let at = bytes.windows(6).position(|w| w == b"node-a").unwrap();
    bytes[at] = 0xff;
    // With only the scan charge available, a scan that did not look at the text would report the
    // member debit instead of the encoding.
    let mut bind = binding(&case.input, case.parent_number);
    bind.committed_hash = crate::sha256(&bytes);
    let scan = 2000 + 16 * bytes.len() as u64;
    assert_eq!(admit(&bytes, &testing::b1_context(), &bind, scan), Err(UpdateError::Encoding));
}

#[test]
fn a_maximal_entry_fits_far_below_the_entry_byte_cap() {
    // 64 members with 128-byte identifiers and maximal weights: the cap needs no separate guard.
    let case = Case::at(CLOSES_AND_INSERTS);
    let mut update = case.update.clone();
    update.new_entries[0].members = (0..64)
        .map(|i| crate::update::Member {
            node_id: format!("{}{i:032}", "p".repeat(96)),
            key: case.update.new_entries[0].members[0].key,
            weight: u64::MAX / 64,
        })
        .collect();
    let single = Update { new_entries: vec![update.new_entries[0].clone()], ..update.clone() };
    let size = single.to_bytes().len() - Update { new_entries: vec![], ..single }.to_bytes().len();
    assert!(size < crate::update::MAX_ENTRY_BYTES * 3 / 4, "maximal entry is {size} bytes");
}

#[test]
fn the_system_budget_is_spent_in_stages_and_committed_without_finalize() {
    let case = Case::at(EXPIRES_GENESIS);
    let bytes = case.update.to_bytes();
    let reference = case.with(|_| {}).unwrap();
    let after_open = reference.admission_gas + reference.open_gas_spent;
    let staged = after_open + reference.import_gas_spent;
    // Open receives only what admission left: one unit less than admission plus open runs out in
    // open itself, never reaching the later budget check.
    assert!(matches!(
        run_bytes(&case.input, &bytes, case.parent_number, &case.parent, after_open - 1),
        Err(ExecutionError::OpenFailed(_))
    ));
    // The import receives only what admission and open left: one unit less than G_pre runs out
    // in the import itself.
    assert!(matches!(
        run_bytes(&case.input, &bytes, case.parent_number, &case.parent, staged - 1),
        Err(ExecutionError::ImportFailed(_))
    ));
    // The outcome commitment covers G_pre = admission + open + import, not open alone, not
    // admission plus open, and not finalize.
    assert_eq!(
        reference.registry_commitment,
        crate::system_outcome_commitment(staged, reference.input_commitment)
    );
    assert_ne!(
        reference.registry_commitment,
        crate::system_outcome_commitment(after_open, reference.input_commitment)
    );
    assert_ne!(
        reference.registry_commitment,
        crate::system_outcome_commitment(reference.open_gas_spent, reference.input_commitment)
    );
}

// ---- the root-record import, executed by the real registry runtime
// -------------------------------

mod import {
    use super::*;
    use crate::records::{RecordEntry, RecordImport, IMPORT_EXECUTION_GAS};
    use alloy_primitives::Bytes;
    use alloy_sol_types::SolValue;

    fn f(name: &str) -> B256 {
        keccak256(format!("unicity.seal-registry/{name}"))
    }

    /// `R(i, j) = keccak256(abi.encode(F("records.entry"), uint64(i), uint64(j)))`.
    fn entry_slot(i: u64, j: u64) -> B256 {
        keccak256((f("records.entry"), i, j).abi_encode_params())
    }

    fn closure_key(closed_epoch: u64, h_record: B256, h_round: u64) -> B256 {
        keccak256((f("records.closure"), closed_epoch, h_record, h_round).abi_encode_params())
    }

    fn retirement_key(id: u64, generation: u64) -> B256 {
        keccak256((f("records.retirement"), id, generation).abi_encode_params())
    }

    fn u(v: u64) -> B256 {
        B256::from(U256::from(v).to_be_bytes::<32>())
    }

    fn words(ws: &[B256]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.0).collect()
    }

    /// The identifier the registry recomputes: `keccak256(abi.encode(index, predecessor, kind,
    /// progress, ucTime, data))`, built here from the written spec, not from the registry.
    fn record_id(e: &RecordEntry) -> B256 {
        alloy_sol_types::sol! {
            function preimage(uint64 index, bytes32 predecessor, uint8 kind, uint64 progress, uint64 ucTime, bytes data) external;
        }
        let call = preimageCall {
            index: e.index,
            predecessor: e.predecessor,
            kind: e.kind,
            progress: e.progress,
            ucTime: e.uc_time,
            data: Bytes::copy_from_slice(&e.data),
        };
        use alloy_sol_types::SolCall;
        keccak256(&call.abi_encode()[4..])
    }

    type RecordMutation = (&'static str, Box<dyn Fn(&mut RecordImport)>);

    fn make(
        index: u64,
        predecessor: B256,
        kind: u8,
        progress: u64,
        uc_time: u64,
        data: Vec<u8>,
        closed: u64,
    ) -> RecordEntry {
        let mut e = RecordEntry {
            index,
            record_id: B256::ZERO,
            predecessor,
            kind,
            progress,
            uc_time,
            data,
            closed_epoch: closed,
        };
        e.record_id = record_id(&e);
        e
    }

    /// A linked log with one record of each kind, in an order custody could see.
    fn mixed() -> Vec<RecordEntry> {
        let mut out: Vec<RecordEntry> = Vec::new();
        let mut push = |kind: u8, progress: u64, time: u64, data: Vec<u8>, closed: u64| {
            let pred = out.last().map_or(B256::ZERO, |e| e.record_id);
            let e = make(out.len() as u64, pred, kind, progress, time, data, closed);
            out.push(e);
        };
        push(1, 10, 1_010, words(&[B256::repeat_byte(0x51)]), 0);
        push(2, 11, 1_020, words(&[B256::repeat_byte(0x52), u(100), u(100), u(101)]), 0);
        push(
            4,
            12,
            1_030,
            words(&[
                B256::repeat_byte(0x61),
                u(100),
                B256::repeat_byte(0x62),
                B256::repeat_byte(0x63),
                B256::repeat_byte(0x64),
                B256::repeat_byte(0x65),
            ]),
            3,
        );
        push(5, 13, 1_040, words(&[u(7), u(1), B256::repeat_byte(0x71)]), 0);
        push(
            3,
            14,
            1_050,
            words(&[
                B256::repeat_byte(0x81),
                B256::repeat_byte(0x82),
                u(100),
                u(101),
                u(130),
                u(130),
                u(131),
                u(3),
                u(3),
            ]),
            0,
        );
        out
    }

    fn import_of(entries: &[RecordEntry], target: u64, p: u64, t: u64) -> RecordImport {
        RecordImport {
            progress: p,
            uc_time: t,
            target_count: target,
            target_tip: entries.last().map_or(B256::ZERO, |e| e.record_id),
            entries: entries.to_vec(),
        }
    }

    /// Runs vector steps `0..imports.len()`, each importing the given batch, and returns the last
    /// result with its database.
    fn run_imports(
        imports: &[RecordImport],
        limit: u64,
    ) -> Result<(ExecutionResult, CacheDB<EmptyDB>), ExecutionError> {
        let v = vectors();
        let mut db = testing::genesis_db();
        let mut last = None;
        for (step, imp) in v.steps.iter().zip(imports) {
            let raw = imp.to_bytes();
            let mut input = RootInputV2::from_canonical_cbor(&hex(&step.root_input)).unwrap();
            input.root_records_hash = crate::sha256(&raw);
            let (result, next) = crate::execute_registry_transition(
                &input,
                UpdateInput {
                    bytes: &hex(&step.update),
                    records: &raw,
                    parent_number: step.parent_number,
                },
                &db,
                config(limit),
            )?;
            db = next;
            last = Some(result);
        }
        Ok((last.unwrap(), db))
    }

    fn slot_value(db: &CacheDB<EmptyDB>, slot: B256) -> B256 {
        word(db, slot)
    }

    #[test]
    fn a_mixed_log_lands_in_the_documented_registry_words() {
        let log = mixed();
        let imp = import_of(&log, 5, 20, 1_100);
        let (result, db) = run_imports(&[imp], world().system_gas).unwrap();
        assert!(result.import_gas_spent > 0);
        assert_eq!(slot_value(&db, f("records.count")), u(5));
        assert_eq!(slot_value(&db, f("records.tip")), log[4].record_id);
        assert_eq!(slot_value(&db, f("records.progress")), u(20));
        assert_eq!(slot_value(&db, f("records.ucTime")), u(1_100));
        assert_eq!(slot_value(&db, f("records.targetCount")), u(5));
        assert_eq!(slot_value(&db, f("records.targetTip")), log[4].record_id);
        assert_eq!(
            slot_value(&db, f("records.importedRound")),
            u(1),
            "the shard round that imported"
        );
        for e in &log {
            let i = e.index;
            assert_eq!(slot_value(&db, entry_slot(i, 0)), e.record_id);
            assert_eq!(slot_value(&db, entry_slot(i, 1)), e.predecessor);
            assert_eq!(slot_value(&db, entry_slot(i, 2)), u(u64::from(e.kind)));
            assert_eq!(slot_value(&db, entry_slot(i, 3)), u(e.progress));
            assert_eq!(slot_value(&db, entry_slot(i, 4)), u(e.uc_time));
            assert_eq!(slot_value(&db, entry_slot(i, 5)), u(e.data.len() as u64));
            for j in 0..9u64 {
                let want = e.data.chunks(32).nth(j as usize).map_or(B256::ZERO, B256::from_slice);
                assert_eq!(slot_value(&db, entry_slot(i, 6 + j)), want, "record {i} word {j}");
            }
            assert_eq!(slot_value(&db, entry_slot(i, 15)), u(e.closed_epoch));
        }
        // the closure and the retirement are logged under their keys with first index + 1
        let h_record = B256::from_slice(&log[2].data[64..96]);
        assert_eq!(slot_value(&db, closure_key(3, h_record, 100)), u(3));
        assert_eq!(slot_value(&db, closure_key(4, h_record, 100)), B256::ZERO, "another epoch");
        assert_eq!(slot_value(&db, retirement_key(7, 1)), u(4));
        assert_eq!(slot_value(&db, retirement_key(7, 2)), B256::ZERO, "another generation");
    }

    #[test]
    fn a_backlog_is_imported_in_the_required_prefixes_across_blocks() {
        let mut log: Vec<RecordEntry> = Vec::new();
        for i in 0..40u64 {
            let pred = log.last().map_or(B256::ZERO, |e| e.record_id);
            log.push(make(
                i,
                pred,
                1,
                10 + i,
                1_000 + i,
                words(&[B256::repeat_byte(i as u8 + 1)]),
                0,
            ));
        }
        let first = import_of(&log[..32], 40, 60, 2_000);
        let mut second = import_of(&log[32..], 40, 61, 2_001);
        second.target_tip = log[39].record_id;
        let mut first = first;
        first.target_tip = log[39].record_id; // the source log's tip as of the origin, not the batch tail
        let (_, db) = run_imports(&[first.clone()], world().system_gas).unwrap();
        assert_eq!(slot_value(&db, f("records.count")), u(32));
        assert_eq!(slot_value(&db, f("records.targetCount")), u(40));
        assert_eq!(slot_value(&db, f("records.tip")), log[31].record_id);
        let (_, db) = run_imports(&[first, second], world().system_gas).unwrap();
        assert_eq!(slot_value(&db, f("records.count")), u(40));
        assert_eq!(slot_value(&db, f("records.tip")), log[39].record_id);
        assert_eq!(slot_value(&db, f("records.importedRound")), u(2));
    }

    #[test]
    fn an_empty_import_is_accepted_and_changes_no_log_word() {
        let (_, db) = run_imports(&[import_of(&[], 0, 0, 1_000)], world().system_gas).unwrap();
        for name in ["records.count", "records.tip", "records.targetCount", "records.targetTip"] {
            assert_eq!(slot_value(&db, f(name)), B256::ZERO, "{name}");
        }
        assert_eq!(slot_value(&db, f("records.importedRound")), u(1));
        assert_eq!(slot_value(&db, f("records.ucTime")), u(1_000));
    }

    #[test]
    fn the_registry_refuses_each_mutation_alone() {
        let log = mixed();
        let good = import_of(&log, 5, 20, 1_100);
        assert!(run_imports(std::slice::from_ref(&good), world().system_gas).is_ok());
        let cases: Vec<RecordMutation> = vec![
            ("a skipped index", Box::new(|i| i.entries[2].index += 1)),
            ("a broken link", Box::new(|i| i.entries[3].predecessor.0[0] ^= 1)),
            ("an identifier that is not content", Box::new(|i| i.entries[1].record_id.0[0] ^= 1)),
            (
                "a first record naming a predecessor",
                Box::new(|i| i.entries[0].predecessor.0[0] = 1),
            ),
            (
                "a decreasing progress",
                Box::new(|i| {
                    i.entries[2].progress = 5;
                    i.entries[2].record_id = record_id(&i.entries[2]);
                }),
            ),
            ("a record time above the supplied time", Box::new(|i| i.uc_time = 1_040)),
            ("a record progress above the supplied progress", Box::new(|i| i.progress = 13)),
            (
                "a supplied time below the genesis time",
                Box::new(|i| {
                    i.entries.clear();
                    i.target_count = 0;
                    i.target_tip = B256::ZERO;
                    i.uc_time = world().genesis_uc_time - 1;
                }),
            ),
            ("a target below the imported tail", Box::new(|i| i.target_count = 4)),
            ("a caught-up tail that is not the target tip", Box::new(|i| i.target_tip.0[0] ^= 1)),
            (
                "fewer entries than the required prefix",
                Box::new(|i| {
                    i.entries.pop();
                }),
            ),
            (
                "a payload word above uint64 where the kind requires one",
                Box::new(|i| {
                    i.entries[1].data[0] = 1; // the replacedHRound word
                    i.entries[1].record_id = record_id(&i.entries[1]);
                }),
            ),
        ];
        for (name, mutate) in cases {
            let mut bad = good.clone();
            mutate(&mut bad);
            assert!(
                matches!(
                    run_imports(&[bad], world().system_gas),
                    Err(ExecutionError::ImportFailed(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn a_second_closure_or_retirement_of_a_key_is_refused_by_the_registry() {
        let mut log = mixed();
        // a second retirement of (7, 1) at the next index
        let pred = log.last().unwrap().record_id;
        log.push(make(5, pred, 5, 15, 1_060, words(&[u(7), u(1), B256::repeat_byte(0x72)]), 0));
        assert!(matches!(
            run_imports(&[import_of(&log, 6, 20, 1_100)], world().system_gas),
            Err(ExecutionError::ImportFailed(_))
        ));
    }

    #[test]
    fn the_admission_refusals_precede_the_registry() {
        let log = mixed();
        let v = vectors();
        let step = &v.steps[0];
        let raw = import_of(&log, 5, 20, 1_100).to_bytes();
        let db = testing::genesis_db();
        let mut input = RootInputV2::from_canonical_cbor(&hex(&step.root_input)).unwrap();
        input.root_records_hash = crate::sha256(&raw);
        let run = |input: &RootInputV2, records: &[u8], limit: u64| {
            crate::execute_registry_transition(
                input,
                UpdateInput {
                    bytes: &hex(&step.update),
                    records,
                    parent_number: step.parent_number,
                },
                &db,
                config(limit),
            )
        };
        assert!(run(&input, &raw, world().system_gas).is_ok());
        // the bytes must be the committed ones
        let other = import_of(&log, 5, 21, 1_100).to_bytes();
        assert!(matches!(
            run(&input, &other, world().system_gas),
            Err(ExecutionError::RecordImport(crate::records::ImportError::HashMismatch))
        ));
        // garbage under the right hash is a decoding refusal, not a registry one
        let mut garbage = input.clone();
        garbage.root_records_hash = crate::sha256(&[0xff; 8]);
        assert!(matches!(
            run(&garbage, &[0xff; 8], world().system_gas),
            Err(ExecutionError::RecordImport(crate::records::ImportError::Encoding(_)))
        ));
        // a budget that cannot cover B1 admission plus the import scan
        let b1_admission = crate::update::admit(
            &hex(&step.update),
            &testing::b1_context(),
            &binding(&input, step.parent_number),
            world().system_gas,
        )
        .unwrap()
        .gas;
        let scan = crate::records::scan_gas(raw.len()).unwrap();
        assert!(matches!(
            run(&input, &raw, b1_admission + scan - 1),
            Err(ExecutionError::RecordImport(crate::records::ImportError::ScanBudget))
        ));
        assert!(matches!(
            run(&input, &raw, b1_admission + scan + 5_000 - 1),
            Err(ExecutionError::RecordImport(crate::records::ImportError::EntryBudget))
        ));
        let admitted = b1_admission + scan + 5_000;
        assert!(
            matches!(run(&input, &raw, admitted), Err(ExecutionError::OpenFailed(_)),),
            "exactly the admission leaves open nothing"
        );
    }

    /// The most expensive legal import: thirty-two `RecoveryAck` records (nine payload words each),
    /// every word nonzero, so each entry writes fifteen fresh words.
    fn maximal() -> RecordImport {
        let mut log: Vec<RecordEntry> = Vec::new();
        for i in 0..32u64 {
            let pred = log.last().map_or(B256::ZERO, |e| e.record_id);
            let data: Vec<B256> = (0..9)
                .map(|j| {
                    if j < 2 {
                        B256::repeat_byte((i as u8) * 8 + j as u8 + 1)
                    } else {
                        u(i + 100 * j)
                    }
                })
                .collect();
            log.push(make(i, pred, 3, 10 + i, 1_000 + i, words(&data), 0));
        }
        import_of(&log, 32, 100, 2_000)
    }

    #[test]
    fn the_maximal_import_stays_inside_the_envelope_bound() {
        let imp = maximal();
        let raw = imp.to_bytes();
        assert!(raw.len() <= crate::records::MAX_IMPORT_BYTES, "{} bytes", raw.len());
        let (result, db) = run_imports(std::slice::from_ref(&imp), world().system_gas).unwrap();
        assert_eq!(slot_value(&db, f("records.count")), u(32));
        assert!(
            result.import_gas_spent <= IMPORT_EXECUTION_GAS,
            "the maximal import spends {} against the bound {IMPORT_EXECUTION_GAS}",
            result.import_gas_spent
        );
        // the bound keeps a real margin: the measured gross is at most two thirds of it
        assert!(
            result.import_gas_spent * 3 <= IMPORT_EXECUTION_GAS * 2,
            "{}",
            result.import_gas_spent
        );
        let total_admission = result.records_admission_gas;
        assert_eq!(total_admission, crate::records::scan_gas(raw.len()).unwrap() + 32_000);
        println!(
            "p85-import: maximal import gross {} admission {}",
            result.import_gas_spent, total_admission
        );
    }
}
