//! The mandatory records hook (briefs/p85-pr1c-control-records.md section 6, step 1).
//!
//! After finalize and the stock EIP-4788 call, the block reads custody's record cursor and the
//! registry's record count and target, and when the registry holds more records than custody has
//! applied it makes exactly one `applyRootRecords(min(H, available))` call, then requires the
//! cursor to have advanced by exactly that amount. Every read and the call run under the EVM
//! meter from the system budget that import and finalize left; their gross gas is `G_hooks`, which
//! joins the system total and stays out of the outcome commitment. An unexpected revert, a cursor
//! that does not advance, an out-of-gas call or an inconsistent registry invalidates the block.
//!
//! Activation and election (steps 2 to 4) are not here: their contracts do not exist yet. The hook
//! never loops and never retries with a smaller batch.

use crate::{ExecutionError, SEAL_REGISTRY, SYSTEM_CALLER};
use alloy_primitives::{Address, Bytes, B256, U256};
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::{Block, ContextSetters, ContextTr, JournalTr},
    handler::{EvmTr, Handler, MainnetHandler, SystemCallTx},
    primitives::hardfork::SpecId,
    Context, Database, DatabaseCommit, MainBuilder, MainContext,
};

/// `recordCursor()` of custody.
pub const RECORD_CURSOR: [u8; 4] = [0xca, 0x01, 0xc9, 0x83];
/// `recordCount()` of the registry.
pub const RECORD_COUNT: [u8; 4] = [0x90, 0x04, 0x07, 0xbc];
/// `recordTargetCount()` of the registry.
pub const RECORD_TARGET_COUNT: [u8; 4] = [0x99, 0xa1, 0xd3, 0x76];
/// `applyRootRecords(uint32)` of custody.
pub const APPLY_ROOT_RECORDS: [u8; 4] = [0x1d, 0x2a, 0x00, 0x37];
/// `limits()` of custody: `(vMax, lMax, rMax, maxBatch)`.
pub const LIMITS: [u8; 4] = [0x86, 0x0a, 0xef, 0xcf];
/// `elect(bytes32)` of the election module (checked against the keccak of the signature in the
/// tests).
pub const ELECT: [u8; 4] = [0x45, 0xb7, 0xff, 0xa0];

/// The most records one hook call may apply: custody's own `maxBatch` ceiling.
pub const MAX_H_RECORDS: u32 = 32;
/// The gate reads' share of the system envelope (`b1state.HookReadsGas`).
pub const HOOK_READS_GAS: u64 = 150_000;

/// The environment the hook's calls run in: the executing block's, as the stock EIP-4788 call and
/// ordinary transactions see it. Custody reads `block.chainid` (the exposure identifiers hash it),
/// so a fresh default environment would key everything the hook creates under chain id 1.
#[derive(Clone, Debug)]
pub struct HookEnv {
    /// `block.chainid`.
    pub chain_id: u64,
    /// The block environment of the executing block.
    pub block: BlockEnv,
}

impl HookEnv {
    /// The environment of the block an EVM is executing.
    pub fn from_evm<E: alloy_evm::Evm>(evm: &E) -> Self {
        let b = evm.block();
        let block = BlockEnv {
            number: b.number(),
            beneficiary: b.beneficiary(),
            timestamp: b.timestamp(),
            gas_limit: b.gas_limit(),
            basefee: b.basefee(),
            difficulty: b.difficulty(),
            prevrandao: b.prevrandao(),
            blob_excess_gas_and_price: b.blob_excess_gas_and_price(),
            ..Default::default()
        };
        Self { chain_id: evm.chain_id(), block }
    }

    /// A block environment of the given chain, number and timestamp, for tests.
    pub fn at(chain_id: u64, number: u64, timestamp: u64) -> Self {
        Self {
            chain_id,
            block: BlockEnv {
                number: U256::from(number),
                timestamp: U256::from(timestamp),
                ..Default::default()
            },
        }
    }
}

/// The mandatory hooks a profile pins: the records hook (the custody contract, `H_records` and the
/// gross gas reserved for applying one record; zero custody means a chain without it) and the
/// election hook (the election module and the gross gas reserved for one `elect` call; zero
/// election means a chain without it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordsHook {
    /// The custody contract the records are applied to.
    pub custody: Address,
    /// Most records one block's hook applies.
    pub h_records: u32,
    /// Gross gas reserved for applying one record.
    pub record_gas: u64,
    /// The election module whose `elect(origin)` the block's hook calls after the records are
    /// applied.
    pub election: Address,
    /// Gross gas reserved for the `elect` call, sized for the profile's worst case on a threshold
    /// block.
    pub elect_gas: u64,
}

/// Why the hook invalidated the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookError {
    /// The pinned hook parameters are not a valid combination.
    Profile(&'static str),
    /// A call errored, reverted or halted.
    Call(&'static str, String),
    /// A call returned something other than one uint64 word.
    BadReturn(&'static str),
    /// `elect` returned an outcome the module does not define.
    BadOutcome(u64),
    /// `c <= r <= q` does not hold.
    Inconsistent {
        /// Custody's cursor.
        cursor: u64,
        /// The registry's record count.
        count: u64,
        /// The registry's target count.
        target: u64,
    },
    /// The cursor did not advance by exactly the applied amount.
    CursorMoved {
        /// Cursor before the call.
        before: u64,
        /// Records the call was asked to apply.
        applied: u64,
        /// Cursor after the call.
        after: u64,
    },
    /// The pinned `H_records` exceeds the deployed custody's `limits.maxBatch`: its
    /// `applyRootRecords(H)` would revert (`BatchTooLarge`) and the chain could never catch
    /// up.
    HExceedsMaxBatch {
        /// The pinned `H_records`.
        h_records: u32,
        /// Custody's `limits.maxBatch`.
        max_batch: u64,
    },
    /// The system budget cannot pay for the next call.
    Budget,
}

/// What the hook did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookOutcome {
    /// Gross gas of every read and the call.
    pub gas_spent: u64,
    /// Records applied (zero when custody was caught up).
    pub applied: u64,
    /// What the election call reported (`0` disabled, `1` not due, `2` reserved, `3` no candidate
    /// recorded), `None` on a chain without the election hook.
    pub elected: Option<u8>,
}

impl RecordsHook {
    /// Whether the profile carries the hook.
    pub fn enabled(&self) -> bool {
        self.custody != Address::ZERO
    }

    /// The gross gas the profile reserves: the gate reads and `H` applied records.
    pub fn envelope_gas(&self) -> Result<u64, HookError> {
        if !self.enabled() {
            return Ok(0);
        }
        self.validate()?;
        u64::from(self.h_records)
            .checked_mul(self.record_gas)
            .and_then(|records| records.checked_add(HOOK_READS_GAS))
            .and_then(|records| records.checked_add(self.elect_gas))
            .ok_or(HookError::Profile("hook envelope overflows"))
    }

    /// Whether the profile carries the election hook.
    pub fn election_enabled(&self) -> bool {
        self.election != Address::ZERO
    }

    /// Checks the combination: all three zero, or a custody with `1 <= H <= 32` and a price; the
    /// election hook, when pinned, needs the records hook and a price.
    pub fn validate(&self) -> Result<(), HookError> {
        if !self.election_enabled() && self.elect_gas != 0 {
            return Err(HookError::Profile("the elect gas without an election contract"));
        }
        if self.election_enabled() && (!self.enabled() || self.elect_gas == 0) {
            return Err(HookError::Profile(
                "the election hook needs the records hook and a positive elect gas",
            ));
        }
        if !self.enabled() {
            return if self.h_records == 0 && self.record_gas == 0 {
                Ok(())
            } else {
                Err(HookError::Profile("hook parameters without a custody contract"))
            };
        }
        if self.h_records == 0 || self.h_records > MAX_H_RECORDS {
            return Err(HookError::Profile("H_records must be within 1..=32"));
        }
        if self.record_gas == 0 {
            return Err(HookError::Profile("the per-record hook gas must be positive"));
        }
        Ok(())
    }
}

/// Runs the records hook alone (a profile without the election hook) within `budget` gross gas.
pub fn run_records_hook<DB>(
    db: &mut DB,
    hook: &RecordsHook,
    env: &HookEnv,
    budget: u64,
) -> Result<HookOutcome, ExecutionError>
where
    DB: Database + DatabaseCommit,
{
    if hook.election_enabled() {
        return Err(ExecutionError::Hook(HookError::Profile(
            "the election hook needs the block's origin: use run_hooks",
        )));
    }
    run_hooks(db, hook, env, B256::ZERO, budget)
}

/// Runs the mandatory hooks on `db` within `budget` gross gas (the system budget import and
/// finalize left), in the approved order: the records hook (step 1), then the election (step 4)
/// with the block's authenticated root origin identity. Activation (step 3) has no module until
/// governance exists: a profile without one makes no call.
pub fn run_hooks<DB>(
    db: &mut DB,
    hook: &RecordsHook,
    env: &HookEnv,
    origin: B256,
    budget: u64,
) -> Result<HookOutcome, ExecutionError>
where
    DB: Database + DatabaseCommit,
{
    let hook_err = ExecutionError::Hook;
    hook.validate().map_err(hook_err)?;
    if !hook.enabled() {
        return Ok(HookOutcome::default());
    }
    let mut evm = Context::mainnet()
        .with_block(env.block.clone())
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = env.chain_id;
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN)
        })
        .with_db(db)
        .build_mainnet();
    let mut spent = 0u64;
    // The gas the next call may use is what the budget has left, further capped for the election.
    let mut limit = budget;
    // One system call within what the budget has left; `commit` keeps its state (the apply call),
    // a read discards the journal.
    macro_rules! call {
        ($what:expr, $to:expr, $data:expr, $commit:expr) => {{
            let remaining = limit
                .checked_sub(spent)
                .filter(|r| *r > 0)
                .ok_or(ExecutionError::Hook(HookError::Budget))?;
            let mut tx =
                TxEnv::new_system_tx_with_caller(SYSTEM_CALLER, $to, Bytes::copy_from_slice($data));
            tx.gas_limit = remaining;
            evm.ctx_mut().set_tx(tx);
            let result = MainnetHandler::<
                _,
                revm::context_interface::result::EVMError<<DB as Database>::Error>,
                _,
            >::default()
            .run_system_call(&mut evm)
            .map_err(|e| ExecutionError::Hook(HookError::Call($what, format!("{e:?}"))))?;
            if !result.is_success() {
                return Err(ExecutionError::Hook(HookError::Call($what, format!("{result:?}"))));
            }
            spent = spent
                .checked_add(result.gas().total_gas_spent())
                .ok_or(ExecutionError::Hook(HookError::Budget))?;
            let state = evm.ctx_mut().journal_mut().finalize();
            if $commit {
                evm.ctx_mut().db_mut().commit(state);
            }
            result.output().cloned().unwrap_or_default()
        }};
    }
    let word = |what: &'static str, out: Bytes| -> Result<u64, HookError> {
        if out.len() != 32 || out[..24].iter().any(|b| *b != 0) {
            return Err(HookError::BadReturn(what));
        }
        Ok(u64::from_be_bytes(out[24..].try_into().expect("eight bytes")))
    };

    let applied = 'records: {
        let out = call!("recordCursor", hook.custody, &RECORD_CURSOR, false);
        let before = word("recordCursor", out).map_err(hook_err)?;
        let out = call!("recordCount", SEAL_REGISTRY, &RECORD_COUNT, false);
        let count = word("recordCount", out).map_err(hook_err)?;
        let out = call!("recordTargetCount", SEAL_REGISTRY, &RECORD_TARGET_COUNT, false);
        let target = word("recordTargetCount", out).map_err(hook_err)?;
        if before > count || count > target {
            return Err(hook_err(HookError::Inconsistent { cursor: before, count, target }));
        }
        let available = count - before;
        if available == 0 {
            break 'records 0;
        }
        // The pinned H must fit the deployed custody: checked against its own limits before every
        // call.
        let out = call!("limits", hook.custody, &LIMITS, false);
        if out.len() != 128 {
            return Err(hook_err(HookError::BadReturn("limits")));
        }
        let max_batch = word("limits", Bytes::copy_from_slice(&out[96..128])).map_err(hook_err)?;
        if u64::from(hook.h_records) > max_batch {
            return Err(hook_err(HookError::HExceedsMaxBatch {
                h_records: hook.h_records,
                max_batch,
            }));
        }
        let n = available.min(u64::from(hook.h_records));
        let mut data = APPLY_ROOT_RECORDS.to_vec();
        data.extend_from_slice(&[0u8; 28]);
        data.extend_from_slice(&(n as u32).to_be_bytes());
        let _ = call!("applyRootRecords", hook.custody, &data, true);
        let out = call!("recordCursor", hook.custody, &RECORD_CURSOR, false);
        let after = word("recordCursor", out).map_err(hook_err)?;
        if after != before + n {
            return Err(hook_err(HookError::CursorMoved { before, applied: n, after }));
        }
        n
    };

    // Step 4: the threshold election, with exactly the gas the profile reserved for it. The module
    // never reverts for a chain-state reason (a failed election is a stored NoCandidate); a call
    // that errors, reverts or runs out of the reserved gas invalidates the block, as for the
    // records.
    let mut elected = None;
    if hook.election_enabled() {
        limit = budget.min(spent.saturating_add(hook.elect_gas));
        let mut data = ELECT.to_vec();
        data.extend_from_slice(origin.as_slice());
        let out = call!("elect", hook.election, &data, true);
        let outcome = word("elect", out).map_err(hook_err)?;
        if outcome > 3 {
            return Err(hook_err(HookError::BadOutcome(outcome)));
        }
        elected = Some(outcome as u8);
    }
    Ok(HookOutcome { gas_spent: spent, applied, elected })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, custody_code, ADVANCE, ENV_PROBE, NOTHING, OVERSHOOT, REVERT};
    use alloy_primitives::{address, keccak256, B256, U256};
    use revm::{
        bytecode::Bytecode,
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
        DatabaseRef,
    };

    const CUSTODY: Address = address!("00000000000000000000000000000000c0570d17");

    fn slot(name: &str) -> U256 {
        U256::from_be_bytes(keccak256(format!("unicity.seal-registry/{name}")).0)
    }

    fn db(body: &[u8], cursor: U256, count: u64, target: u64) -> CacheDB<EmptyDB> {
        let mut db = testing::genesis_db();
        db.insert_account_info(
            CUSTODY,
            AccountInfo {
                code_hash: keccak256(custody_code(body)),
                code: Some(Bytecode::new_raw(custody_code(body))),
                ..Default::default()
            },
        );
        db.insert_account_storage(CUSTODY, U256::ZERO, cursor).unwrap();
        db.insert_account_storage(CUSTODY, U256::from(1), U256::from(32)).unwrap(); // limits.maxBatch
        db.insert_account_storage(SEAL_REGISTRY, slot("records.count"), U256::from(count)).unwrap();
        db.insert_account_storage(SEAL_REGISTRY, slot("records.targetCount"), U256::from(target))
            .unwrap();
        db
    }

    fn hook(h: u32) -> RecordsHook {
        RecordsHook { custody: CUSTODY, h_records: h, record_gas: 1_000_000, ..Default::default() }
    }

    fn env() -> HookEnv {
        HookEnv::at(1337, 7, 1_700_000_000)
    }

    fn cursor(db: &CacheDB<EmptyDB>) -> U256 {
        db.storage_ref(CUSTODY, U256::ZERO).unwrap()
    }

    fn refused(err: ExecutionError) -> HookError {
        match err {
            ExecutionError::Hook(e) => e,
            other => panic!("not a hook error: {other:?}"),
        }
    }

    #[test]
    fn the_selectors_are_the_abi_ones() {
        for (sig, sel) in [
            ("recordCursor()", RECORD_CURSOR),
            ("recordCount()", RECORD_COUNT),
            ("recordTargetCount()", RECORD_TARGET_COUNT),
            ("applyRootRecords(uint32)", APPLY_ROOT_RECORDS),
            ("limits()", LIMITS),
        ] {
            assert_eq!(keccak256(sig)[..4], sel, "{sig}");
        }
    }

    #[test]
    fn a_caught_up_custody_makes_no_call_and_pays_only_the_reads() {
        let mut db = db(ADVANCE, U256::from(7), 7, 9);
        let out = run_records_hook(&mut db, &hook(3), &env(), 10_000_000).unwrap();
        assert_eq!(out.applied, 0);
        assert!(out.gas_spent > 0 && out.gas_spent < HOOK_READS_GAS / 4, "{}", out.gas_spent);
        assert_eq!(cursor(&db), U256::from(7));
    }

    #[test]
    fn exactly_one_call_of_min_h_and_available_per_block() {
        let mut db = db(ADVANCE, U256::from(2), 12, 12);
        let h = hook(4);
        assert_eq!(run_records_hook(&mut db, &h, &env(), 20_000_000).unwrap().applied, 4);
        assert_eq!(cursor(&db), U256::from(6), "H bounds the call, it is never looped to catch up");
        assert_eq!(run_records_hook(&mut db, &h, &env(), 20_000_000).unwrap().applied, 4);
        assert_eq!(
            run_records_hook(&mut db, &h, &env(), 20_000_000).unwrap().applied,
            2,
            "available < H"
        );
        assert_eq!(cursor(&db), U256::from(12));
        assert_eq!(run_records_hook(&mut db, &h, &env(), 20_000_000).unwrap().applied, 0);
    }

    #[test]
    fn the_reads_leave_no_state_and_the_call_commits_its_own() {
        let mut db = db(ADVANCE, U256::from(1), 3, 3);
        run_records_hook(&mut db, &hook(1), &env(), 20_000_000).unwrap();
        assert_eq!(cursor(&db), U256::from(2));
        // the system caller is never created by a read
        assert!(db.basic_ref(SYSTEM_CALLER).unwrap().is_none_or(|a| a.nonce == 0));
    }

    #[test]
    fn a_cursor_that_does_not_advance_by_exactly_the_applied_amount_invalidates() {
        for (name, body) in [("frozen", NOTHING), ("overshoot", OVERSHOOT)] {
            let mut db = db(body, U256::from(1), 9, 9);
            let err = refused(run_records_hook(&mut db, &hook(3), &env(), 20_000_000).unwrap_err());
            assert!(
                matches!(err, HookError::CursorMoved { before: 1, applied: 3, .. }),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn an_unexpected_revert_is_not_swallowed() {
        let mut db = db(REVERT, U256::from(1), 9, 9);
        let err = refused(run_records_hook(&mut db, &hook(3), &env(), 20_000_000).unwrap_err());
        assert!(matches!(err, HookError::Call("applyRootRecords", _)), "{err:?}");
        assert_eq!(cursor(&db), U256::from(1));
    }

    #[test]
    fn the_registry_and_custody_must_be_consistent() {
        // c > r
        let mut a = db(ADVANCE, U256::from(5), 4, 9);
        assert!(matches!(
            refused(run_records_hook(&mut a, &hook(1), &env(), 20_000_000).unwrap_err()),
            HookError::Inconsistent { cursor: 5, count: 4, target: 9 }
        ));
        // r > q
        let mut b = db(ADVANCE, U256::from(1), 8, 7);
        assert!(matches!(
            refused(run_records_hook(&mut b, &hook(1), &env(), 20_000_000).unwrap_err()),
            HookError::Inconsistent { cursor: 1, count: 8, target: 7 }
        ));
        // a cursor that is not a uint64
        let mut c = db(ADVANCE, U256::from(1) << 64, 8, 8);
        assert!(matches!(
            refused(run_records_hook(&mut c, &hook(1), &env(), 20_000_000).unwrap_err()),
            HookError::BadReturn("recordCursor")
        ));
    }

    #[test]
    fn the_whole_hook_is_metered_from_the_budget_given() {
        let mut probe = db(ADVANCE, U256::from(0), 6, 6);
        let g = run_records_hook(&mut probe, &hook(6), &env(), 20_000_000).unwrap().gas_spent;
        assert!(g > HOOK_READS_GAS / 10, "{g}");
        let mut exact = db(ADVANCE, U256::from(0), 6, 6);
        assert_eq!(run_records_hook(&mut exact, &hook(6), &env(), g).unwrap().gas_spent, g);
        let mut short = db(ADVANCE, U256::from(0), 6, 6);
        assert!(
            run_records_hook(&mut short, &hook(6), &env(), g - 1).is_err(),
            "one gas short fails"
        );
        let mut none = db(ADVANCE, U256::from(0), 6, 6);
        assert!(matches!(
            refused(run_records_hook(&mut none, &hook(6), &env(), 0).unwrap_err()),
            HookError::Budget
        ));
    }

    #[test]
    fn a_chain_without_custody_runs_nothing_and_reserves_nothing() {
        let off = RecordsHook::default();
        let mut db = db(ADVANCE, U256::from(0), 6, 6);
        assert_eq!(run_records_hook(&mut db, &off, &env(), 0).unwrap(), HookOutcome::default());
        assert_eq!(off.envelope_gas().unwrap(), 0);
        assert_eq!(cursor(&db), U256::ZERO);
    }

    #[test]
    fn the_pinned_parameters_are_one_valid_combination() {
        assert!(RecordsHook::default().validate().is_ok());
        assert!(hook(1).validate().is_ok() && hook(MAX_H_RECORDS).validate().is_ok());
        for (name, h) in [
            ("H without custody", RecordsHook { h_records: 1, ..RecordsHook::default() }),
            ("price without custody", RecordsHook { record_gas: 1, ..RecordsHook::default() }),
            ("custody without H", RecordsHook { h_records: 0, ..hook(1) }),
            ("H above custody's ceiling", RecordsHook { h_records: MAX_H_RECORDS + 1, ..hook(1) }),
            ("no price", RecordsHook { record_gas: 0, ..hook(1) }),
        ] {
            assert!(matches!(h.validate(), Err(HookError::Profile(_))), "{name}");
        }
        // the envelope is Go's: the gate reads plus H records
        assert_eq!(hook(3).envelope_gas().unwrap(), HOOK_READS_GAS + 3_000_000);
        assert!(RecordsHook { record_gas: u64::MAX, ..hook(2) }.envelope_gas().is_err());
        let _ = B256::ZERO;
    }

    #[test]
    fn the_calls_run_in_the_executing_blocks_environment() {
        // the stand-in stores chainid * 1000 + number; the hook is applying one record of a custody
        // at cursor 0
        let mut db = db(ENV_PROBE, U256::ZERO, 1, 1);
        run_records_hook(&mut db, &hook(1), &HookEnv::at(1337, 7, 1_700_000_000), 20_000_000)
            .unwrap_err();
        // (the probe does not advance the cursor by one, so the hook refuses it; what matters is
        // what it stored)
        assert_eq!(
            cursor(&db),
            U256::from(1337 * 1000 + 7),
            "chain id and number of the block, not revm's defaults"
        );
        // revm's default environment would have stored 1 * 1000 + 0
        let mut default = self::db(ENV_PROBE, U256::ZERO, 1, 1);
        run_records_hook(&mut default, &hook(1), &HookEnv::at(1, 0, 0), 20_000_000).unwrap_err();
        assert_eq!(cursor(&default), U256::from(1000));
    }

    #[test]
    fn h_must_fit_the_deployed_custodys_max_batch() {
        let mut ok = db(ADVANCE, U256::ZERO, 5, 5);
        ok.insert_account_storage(CUSTODY, U256::from(1), U256::from(3)).unwrap();
        assert_eq!(run_records_hook(&mut ok, &hook(3), &env(), 20_000_000).unwrap().applied, 3);
        let mut small = db(ADVANCE, U256::ZERO, 5, 5);
        small.insert_account_storage(CUSTODY, U256::from(1), U256::from(2)).unwrap();
        assert!(matches!(
            refused(run_records_hook(&mut small, &hook(3), &env(), 20_000_000).unwrap_err()),
            HookError::HExceedsMaxBatch { h_records: 3, max_batch: 2 }
        ));
        // a custody that accepts no batch at all
        let mut zero = db(ADVANCE, U256::ZERO, 5, 5);
        zero.insert_account_storage(CUSTODY, U256::from(1), U256::ZERO).unwrap();
        assert!(matches!(
            refused(run_records_hook(&mut zero, &hook(1), &env(), 20_000_000).unwrap_err()),
            HookError::HExceedsMaxBatch { max_batch: 0, .. }
        ));
        // nothing to apply: the limit is not read, so a caught-up chain is not held to it
        let mut idle = db(ADVANCE, U256::from(5), 5, 5);
        idle.insert_account_storage(CUSTODY, U256::from(1), U256::ZERO).unwrap();
        assert_eq!(run_records_hook(&mut idle, &hook(1), &env(), 20_000_000).unwrap().applied, 0);
    }

    // --- the election hook -----------------------------------------------------------------------

    const ELECTION: Address = address!("00000000000000000000000000000000e1ec7100");
    const ORIGIN: B256 = B256::repeat_byte(0x5a);

    /// An election stand-in: reverts unless called with `elect(bytes32)`, then runs `body`.
    fn election_code(body: &[u8]) -> Bytes {
        let mut c = vec![0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c]; // selector
        c.extend([0x63, 0x45, 0xb7, 0xff, 0xa0, 0x14, 0x61, 0x00, 0x14, 0x57]); // == elect -> 0x14
        c.extend([0x60, 0x00, 0x80, 0xfd]); // otherwise revert
        assert_eq!(c.len(), 0x14);
        c.push(0x5b);
        c.extend(body);
        Bytes::from(c)
    }

    /// Stores the first argument in slot 0 and reports outcome `n`.
    fn elects(n: u8) -> Vec<u8> {
        vec![
            0x60, 0x04, 0x35, 0x60, 0x00, 0x55, 0x60, n, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
            0xf3,
        ]
    }

    fn with_election(mut db: CacheDB<EmptyDB>, body: &[u8]) -> CacheDB<EmptyDB> {
        db.insert_account_info(
            ELECTION,
            AccountInfo {
                code_hash: keccak256(election_code(body)),
                code: Some(Bytecode::new_raw(election_code(body))),
                ..Default::default()
            },
        );
        db
    }

    fn elected(h: u32, elect_gas: u64) -> RecordsHook {
        RecordsHook { election: ELECTION, elect_gas, ..hook(h) }
    }

    fn origin_stored(db: &CacheDB<EmptyDB>) -> U256 {
        db.storage_ref(ELECTION, U256::ZERO).unwrap()
    }

    #[test]
    fn the_election_hook_needs_the_records_hook_and_a_price() {
        assert!(elected(1, 5_000_000).validate().is_ok());
        for (name, h) in [
            ("election without a price", RecordsHook { elect_gas: 0, ..elected(1, 1) }),
            ("a price without an election", RecordsHook { elect_gas: 1, ..hook(1) }),
            (
                "election without custody",
                RecordsHook { election: ELECTION, elect_gas: 1, ..RecordsHook::default() },
            ),
        ] {
            assert!(matches!(h.validate(), Err(HookError::Profile(_))), "{name}");
        }
        // the election's price joins the envelope Go's profile reserves
        assert_eq!(
            elected(3, 7_000_000).envelope_gas().unwrap(),
            HOOK_READS_GAS + 3_000_000 + 7_000_000
        );
        assert!(RecordsHook { elect_gas: u64::MAX, ..elected(2, 1) }.envelope_gas().is_err());
    }

    #[test]
    fn the_records_hook_alone_refuses_a_profile_with_an_election() {
        let mut d = db(ADVANCE, U256::ZERO, 0, 0);
        assert!(matches!(
            refused(
                run_records_hook(&mut d, &elected(1, 5_000_000), &env(), 50_000_000).unwrap_err()
            ),
            HookError::Profile(_)
        ));
    }

    #[test]
    fn the_election_runs_after_the_records_with_the_blocks_origin() {
        let mut d = with_election(db(ADVANCE, U256::ZERO, 2, 2), &elects(2));
        let out = run_hooks(&mut d, &elected(2, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap();
        assert_eq!(out.applied, 2);
        assert_eq!(out.elected, Some(2));
        assert_eq!(cursor(&d), U256::from(2));
        assert_eq!(origin_stored(&d), U256::from_be_bytes(ORIGIN.0), "elect(origin)");
        assert!(out.gas_spent > 0 && out.gas_spent < elected(2, 5_000_000).envelope_gas().unwrap());
    }

    #[test]
    fn the_election_is_called_on_a_caught_up_chain_too() {
        let mut d = with_election(db(ADVANCE, U256::from(4), 4, 4), &elects(1));
        let out = run_hooks(&mut d, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap();
        assert_eq!((out.applied, out.elected), (0, Some(1)));
        assert_eq!(origin_stored(&d), U256::from_be_bytes(ORIGIN.0));
    }

    #[test]
    fn a_chain_without_the_election_hook_makes_no_call() {
        let mut d = with_election(db(ADVANCE, U256::from(4), 4, 4), &elects(2));
        let out = run_hooks(&mut d, &hook(1), &env(), ORIGIN, 50_000_000).unwrap();
        assert_eq!(out.elected, None);
        assert_eq!(origin_stored(&d), U256::ZERO, "the election was never called");
    }

    #[test]
    fn every_defined_outcome_is_accepted_and_no_other() {
        for n in 0..=3u8 {
            let mut d = with_election(db(ADVANCE, U256::ZERO, 0, 0), &elects(n));
            let out =
                run_hooks(&mut d, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap();
            assert_eq!(out.elected, Some(n));
        }
        let mut d = with_election(db(ADVANCE, U256::ZERO, 0, 0), &elects(4));
        assert!(matches!(
            refused(
                run_hooks(&mut d, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap_err()
            ),
            HookError::BadOutcome(4)
        ));
    }

    #[test]
    fn an_election_that_reverts_or_returns_the_wrong_shape_invalidates_the_block() {
        // reverts
        let mut d = with_election(db(ADVANCE, U256::ZERO, 0, 0), &[0x60, 0x00, 0x80, 0xfd]);
        assert!(matches!(
            refused(
                run_hooks(&mut d, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap_err()
            ),
            HookError::Call("elect", _)
        ));
        // returns nothing
        let mut none = with_election(db(ADVANCE, U256::ZERO, 0, 0), &[0x00]);
        assert!(matches!(
            refused(
                run_hooks(&mut none, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000)
                    .unwrap_err()
            ),
            HookError::BadReturn("elect")
        ));
        // a high byte set in the word
        let mut wide = with_election(
            db(ADVANCE, U256::ZERO, 0, 0),
            &[0x60, 0x01, 0x60, 0xf8, 0x1b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3],
        );
        assert!(matches!(
            refused(
                run_hooks(&mut wide, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000)
                    .unwrap_err()
            ),
            HookError::BadReturn("elect")
        ));
    }

    #[test]
    fn an_election_cannot_use_more_gas_than_its_reserved_price() {
        // an election that spins until it runs out of gas
        let spin = [0x5b, 0x60, 0x00, 0x56];
        let mut d = with_election(db(ADVANCE, U256::ZERO, 0, 0), &spin);
        // the whole budget is large, but the call gets only the price: it halts, the block is
        // invalid
        let err = run_hooks(&mut d, &elected(1, 200_000), &env(), ORIGIN, 50_000_000).unwrap_err();
        assert!(matches!(refused(err), HookError::Call("elect", _)));
        // and the budget bounds it when it is smaller than the price
        let mut small = with_election(db(ADVANCE, U256::ZERO, 0, 0), &spin);
        let err =
            run_hooks(&mut small, &elected(1, 40_000_000), &env(), ORIGIN, 1_000_000).unwrap_err();
        assert!(matches!(refused(err), HookError::Call("elect", _) | HookError::Budget));
    }

    #[test]
    fn a_failed_record_application_stops_before_the_election() {
        let mut d = with_election(db(REVERT, U256::ZERO, 3, 3), &elects(2));
        assert!(matches!(
            refused(
                run_hooks(&mut d, &elected(1, 5_000_000), &env(), ORIGIN, 50_000_000).unwrap_err()
            ),
            HookError::Call("applyRootRecords", _)
        ));
        assert_eq!(origin_stored(&d), U256::ZERO, "the election was not called");
    }

    #[test]
    fn the_selector_is_elect_bytes32() {
        assert_eq!(ELECT, keccak256("elect(bytes32)").0[..4]);
        assert_eq!(APPLY_ROOT_RECORDS, keccak256("applyRootRecords(uint32)").0[..4]);
    }
}
