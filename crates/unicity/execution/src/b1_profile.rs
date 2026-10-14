//! Re-measurement of the registry's gross system gas under this client's revm.
//!
//! The contracts artifact (permanent layout) freezes `G_rest(B) = 1150000 + 250000*B` from its own
//! forge measurement and requires this client to re-measure it before activation. Each run here
//! drives the real registry runtime through the privileged `open`/`finalize` pair with maximal
//! entries (16 members, 128-byte identifiers sharing a 96-byte prefix): a first origin, a repeated
//! origin, a one-epoch import and the two-epoch supersession `B = 2` allows, and checks every gross
//! total against the profile envelope and the allowance. The registry keeps every entry forever,
//! so the only history writes are the new entries, the closure of the predecessor and the cursors.
//! Gas accounting does not depend on the backing database (warmth comes from the journal's access
//! list), so the in-memory state is the same measurement a disk-backed one gives.
//!
//! The measurements are frozen in `testdata/b1-gas-profile.json`; with
//! `B1_PROFILE_MANIFEST=<path>` they are written there instead of compared.

use crate::{
    testing::{self, Assignment, Members, Tail},
    update::B1Context,
    ExecutionConfig, ExecutionResult, InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2,
    UpdateInput, SEAL_REGISTRY,
};
use alloy_primitives::{B256, U256};
use revm::database::{CacheDB, EmptyDB};
use serde::Serialize;

fn g_rest(b: u64) -> u64 {
    crate::update::REST_GAS_BASE + crate::update::REST_GAS_PER_EPOCH * b
}

/// One measured block.
#[derive(Clone, Debug, Serialize)]
struct Measurement {
    scenario: &'static str,
    /// Epochs the update installs.
    installed: u64,
    #[serde(rename = "admissionGas")]
    admission: u64,
    #[serde(rename = "openGas")]
    open: u64,
    #[serde(rename = "finalizeGas")]
    finalize: u64,
    #[serde(rename = "grossGas")]
    total: u64,
    /// History words set, cleared and reset, counted from the storage diff.
    #[serde(rename = "historySets")]
    sets: u64,
    #[serde(rename = "historyClears")]
    clears: u64,
    #[serde(rename = "historyResets")]
    resets: u64,
    /// Gross gas minus the exact Cancun price of those history writes (22100 / 5000 / 5000):
    /// everything else the pair does, the quantity `G_rest` allows for.
    #[serde(rename = "restExact")]
    rest_exact: u64,
    #[serde(rename = "restAllowance")]
    allowance: u64,
}

/// A world whose registry has the genesis entry and nothing else.
struct World {
    context: B1Context,
    db: CacheDB<EmptyDB>,
    tail: Tail,
    assigned: Assignment,
    block: u64,
    last_round: u64,
    results: Vec<Measurement>,
}

/// Counts the history words a block changed: zero to nonzero, nonzero to zero and nonzero to
/// different. The operational registry words are excluded by their artifact keys.
fn history_diff(before: &CacheDB<EmptyDB>, after: &CacheDB<EmptyDB>) -> (u64, u64, u64) {
    let artifact: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/seal-registry.json")).unwrap();
    let operational: std::collections::HashSet<U256> = artifact["slotKeys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| !k["name"].as_str().unwrap().starts_with("b1."))
        .map(|k| k["key"].as_str().unwrap().parse::<U256>().unwrap())
        .collect();
    let storage = |db: &CacheDB<EmptyDB>| {
        db.cache.accounts.get(&SEAL_REGISTRY).map(|a| a.storage.clone()).unwrap_or_default()
    };
    let (old, new) = (storage(before), storage(after));
    let (mut sets, mut clears, mut resets) = (0, 0, 0);
    for slot in old.keys().chain(new.keys()).collect::<std::collections::BTreeSet<_>>() {
        if operational.contains(slot) {
            continue;
        }
        let was = old.get(slot).copied().unwrap_or_default();
        let now = new.get(slot).copied().unwrap_or_default();
        match (was.is_zero(), now.is_zero()) {
            (true, false) => sets += 1,
            (false, true) => clears += 1,
            (false, false) if was != now => resets += 1,
            _ => {}
        }
    }
    (sets, clears, resets)
}

impl World {
    fn new(b: u64) -> Self {
        let db = testing::genesis_db();
        let context = B1Context { max_epochs: b, ..testing::b1_context() };
        Self {
            context,
            db,
            tail: testing::GENESIS_TAIL,
            assigned: testing::genesis_assignment(),
            block: 0,
            last_round: 0,
            results: Vec::new(),
        }
    }

    fn input(&self, n: u64, round: u64, epoch: u64) -> RootInputV2 {
        let technical = TechnicalRecordV2 {
            round: n,
            epoch: self.assigned.shard_epoch,
            leader: "evm-node".into(),
            stat_hash: B256::repeat_byte(0xe0),
            fee_hash: B256::repeat_byte(0xf0),
        };
        let quiet = B256::repeat_byte(0x31);
        let mut input = RootInputV2 {
            version: 2,
            network_id: u64::from(self.context.network),
            partition_id: 8,
            shard_id: vec![],
            authorized_round: n,
            certified_epoch: self.assigned.shard_epoch,
            authorized_epoch: self.assigned.shard_epoch,
            parent_hash: crate::sha256(&n.to_be_bytes()),
            origin: RootOriginV2 {
                network_id: u64::from(self.context.network),
                root_round: round,
                root_epoch: epoch,
                reference_time: 1,
                tree_root: B256::repeat_byte(0xc0),
                input_record_version: 1,
                input_record: if n == 1 {
                    InputRecordV2 {
                        round: 0,
                        epoch: 0,
                        previous_hash: None,
                        state_hash: None,
                        timestamp: 0,
                        block_hash: None,
                    }
                } else {
                    InputRecordV2 {
                        round: n - 1,
                        epoch: self.assigned.shard_epoch,
                        previous_hash: Some(quiet),
                        state_hash: Some(quiet),
                        timestamp: 1,
                        block_hash: None,
                    }
                },
                tr_hash: crate::technical_record_hash(&technical),
                shard_conf_hash: self.assigned.conf,
            },
            technical,
            transitions: vec![],
            b1_update_hash: B256::repeat_byte(0xb1),
            root_records_hash: crate::sha256(&testing::empty_import()),
        };
        if epoch != self.assigned.root_epoch {
            self.assigned_after(&mut input);
        }
        input
    }

    fn assigned_after(&self, input: &mut RootInputV2) {
        testing::rotate(input, self.assigned);
    }

    /// Executes one block at `round` naming `epoch`, records and returns its measurement.
    fn step(&mut self, scenario: &'static str, round: u64, epoch: u64) -> Measurement {
        self.block += 1;
        let mut input = self.input(self.block, round, epoch);
        let next_assignment = if epoch == self.assigned.root_epoch {
            self.assigned
        } else {
            let mut probe = input.clone();
            testing::rotate(&mut probe, self.assigned)
        };
        let parent_number = self.block - 1;
        let update =
            testing::update_in(&self.context, &input, parent_number, self.tail, Members::Maximal);
        let a = update.new_entries.len() as u64;
        input.b1_update_hash = update.hash();
        input.root_records_hash = crate::sha256(&testing::empty_import());
        let bytes = update.to_bytes();
        let limit = self.context.required_system_gas().unwrap();
        let (result, next): (ExecutionResult, _) = crate::execute_registry_transition(
            &input,
            UpdateInput { bytes: &bytes, records: &testing::empty_import(), parent_number },
            &self.db,
            ExecutionConfig { system_gas_limit: limit, b1: self.context },
        )
        .unwrap_or_else(|error| panic!("B={} {scenario}: {error:?}", self.context.max_epochs));
        let (sets, clears, resets) = history_diff(&self.db, &next);
        let exact_writes = 22_100 * sets + 5_000 * (clears + resets);
        let gross = result.open_gas_spent + result.finalize_gas_spent;
        let measurement = Measurement {
            scenario,
            installed: a,
            admission: result.admission_gas,
            open: result.open_gas_spent,
            finalize: result.finalize_gas_spent,
            total: result.total_gas_spent,
            sets,
            clears,
            resets,
            rest_exact: gross.saturating_sub(exact_writes),
            allowance: g_rest(a),
        };
        assert!(
            result.total_gas_spent <= limit,
            "B={} {scenario}: gross {} exceeds the profile envelope {limit}",
            self.context.max_epochs,
            result.total_gas_spent
        );
        self.db = next;
        self.assigned = next_assignment;
        if a > 0 {
            self.tail = Tail { epoch, start: round };
        }
        self.last_round = round;
        self.results.push(measurement.clone());
        measurement
    }

    /// Runs the whole scenario ladder for this `B`.
    fn ladder(&mut self) {
        let mut round = 1;
        // The first usable origin at the genesis epoch: no history change, `originReady` flips.
        self.step("first origin, no import", round, 1);
        round += 1;
        self.step("repeated origin", round, 1);
        // One maximal entry: closes the predecessor and moves the origin onto the new tip.
        round += 1;
        let epoch = self.tail.epoch + 1;
        self.step("one epoch imported", round, epoch);
        if self.context.max_epochs >= 2 {
            // The widest import `B = 2` allows: a folded supersession installs two maximal entries.
            round += 2;
            let epoch = self.tail.epoch + 2;
            self.step("two epochs imported (supersession)", round, epoch);
            // A later single import over a registry that already holds three maximal entries.
            round += 1;
            let epoch = self.tail.epoch + 1;
            self.step("one epoch imported over a larger registry", round, epoch);
        }
    }
}

fn check(measurements: &[Measurement]) {
    for m in measurements {
        assert!(
            m.rest_exact <= m.allowance,
            "{}: measured G_rest {} exceeds the frozen allowance {}; raise the constants",
            m.scenario,
            m.rest_exact,
            m.allowance
        );
    }
}

#[test]
fn gross_gas_stays_within_the_profile_envelope_and_the_frozen_allowance() {
    let mut all = Vec::new();
    {
        let mut world = World::new(2);
        world.ladder();
        check(&world.results);
        let last = world.results.last().unwrap();
        assert_eq!(last.installed, 1);
        all.extend(world.results);
    }
    let manifest = serde_json::json!({
        "format": "unicity-b1-gas-profile",
        "client": "reth-unicity-execution on revm 42, Cancun, gross pre-refund",
        "frozenAllowance": "G_rest(B) = 1150000 + 250000*B",
        "exactWrites": "22100 per set, 5000 per clear or reset",
        "measurements": all,
    });
    let rendered = serde_json::to_string_pretty(&manifest).unwrap() + "\n";
    if let Some(path) = std::env::var_os("B1_PROFILE_MANIFEST") {
        std::fs::write(path, &rendered).unwrap();
    } else {
        // The checked-in manifest is the frozen measurement: any change in gas shows up here.
        assert!(
            rendered == include_str!("../testdata/b1-gas-profile.json"),
            "the gas profile changed; regenerate testdata/b1-gas-profile.json with \
             B1_PROFILE_MANIFEST=<path> and review the difference"
        );
    }
}
