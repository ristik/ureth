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
use alloy_primitives::{Address, Bytes};
use revm::{
    context::TxEnv,
    context_interface::{ContextSetters, ContextTr, JournalTr},
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

/// The most records one hook call may apply: custody's own `maxBatch` ceiling.
pub const MAX_H_RECORDS: u32 = 32;
/// The gate reads' share of the system envelope (`b1state.HookReadsGas`).
pub const HOOK_READS_GAS: u64 = 150_000;

/// The records hook a profile pins: the custody contract, `H_records` and the gross gas reserved
/// for applying one record. Zero custody means a chain without the hook.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordsHook {
    /// The custody contract the records are applied to.
    pub custody: Address,
    /// Most records one block's hook applies.
    pub h_records: u32,
    /// Gross gas reserved for applying one record.
    pub record_gas: u64,
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
            .ok_or(HookError::Profile("hook envelope overflows"))
    }

    /// Checks the combination: all three zero, or a custody with `1 <= H <= 32` and a price.
    pub fn validate(&self) -> Result<(), HookError> {
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

/// Runs the hook on `db` within `budget` gross gas (the system budget import and finalize left).
pub fn run_records_hook<DB>(
    db: &mut DB,
    hook: &RecordsHook,
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
        .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN))
        .with_db(db)
        .build_mainnet();
    let mut spent = 0u64;
    // One system call within what the budget has left; `commit` keeps its state (the apply call),
    // a read discards the journal.
    macro_rules! call {
        ($what:expr, $to:expr, $data:expr, $commit:expr) => {{
            let remaining = budget
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
        return Ok(HookOutcome { gas_spent: spent, applied: 0 });
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
    Ok(HookOutcome { gas_spent: spent, applied: n })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, custody_code, ADVANCE, NOTHING, OVERSHOOT, REVERT};
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
        db.insert_account_storage(SEAL_REGISTRY, slot("records.count"), U256::from(count)).unwrap();
        db.insert_account_storage(SEAL_REGISTRY, slot("records.targetCount"), U256::from(target))
            .unwrap();
        db
    }

    fn hook(h: u32) -> RecordsHook {
        RecordsHook { custody: CUSTODY, h_records: h, record_gas: 1_000_000 }
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
        ] {
            assert_eq!(keccak256(sig)[..4], sel, "{sig}");
        }
    }

    #[test]
    fn a_caught_up_custody_makes_no_call_and_pays_only_the_reads() {
        let mut db = db(ADVANCE, U256::from(7), 7, 9);
        let out = run_records_hook(&mut db, &hook(3), 10_000_000).unwrap();
        assert_eq!(out.applied, 0);
        assert!(out.gas_spent > 0 && out.gas_spent < HOOK_READS_GAS / 4, "{}", out.gas_spent);
        assert_eq!(cursor(&db), U256::from(7));
    }

    #[test]
    fn exactly_one_call_of_min_h_and_available_per_block() {
        let mut db = db(ADVANCE, U256::from(2), 12, 12);
        let h = hook(4);
        assert_eq!(run_records_hook(&mut db, &h, 20_000_000).unwrap().applied, 4);
        assert_eq!(cursor(&db), U256::from(6), "H bounds the call, it is never looped to catch up");
        assert_eq!(run_records_hook(&mut db, &h, 20_000_000).unwrap().applied, 4);
        assert_eq!(run_records_hook(&mut db, &h, 20_000_000).unwrap().applied, 2, "available < H");
        assert_eq!(cursor(&db), U256::from(12));
        assert_eq!(run_records_hook(&mut db, &h, 20_000_000).unwrap().applied, 0);
    }

    #[test]
    fn the_reads_leave_no_state_and_the_call_commits_its_own() {
        let mut db = db(ADVANCE, U256::from(1), 3, 3);
        run_records_hook(&mut db, &hook(1), 20_000_000).unwrap();
        assert_eq!(cursor(&db), U256::from(2));
        // the system caller is never created by a read
        assert!(db.basic_ref(SYSTEM_CALLER).unwrap().is_none_or(|a| a.nonce == 0));
    }

    #[test]
    fn a_cursor_that_does_not_advance_by_exactly_the_applied_amount_invalidates() {
        for (name, body) in [("frozen", NOTHING), ("overshoot", OVERSHOOT)] {
            let mut db = db(body, U256::from(1), 9, 9);
            let err = refused(run_records_hook(&mut db, &hook(3), 20_000_000).unwrap_err());
            assert!(
                matches!(err, HookError::CursorMoved { before: 1, applied: 3, .. }),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn an_unexpected_revert_is_not_swallowed() {
        let mut db = db(REVERT, U256::from(1), 9, 9);
        let err = refused(run_records_hook(&mut db, &hook(3), 20_000_000).unwrap_err());
        assert!(matches!(err, HookError::Call("applyRootRecords", _)), "{err:?}");
        assert_eq!(cursor(&db), U256::from(1));
    }

    #[test]
    fn the_registry_and_custody_must_be_consistent() {
        // c > r
        let mut a = db(ADVANCE, U256::from(5), 4, 9);
        assert!(matches!(
            refused(run_records_hook(&mut a, &hook(1), 20_000_000).unwrap_err()),
            HookError::Inconsistent { cursor: 5, count: 4, target: 9 }
        ));
        // r > q
        let mut b = db(ADVANCE, U256::from(1), 8, 7);
        assert!(matches!(
            refused(run_records_hook(&mut b, &hook(1), 20_000_000).unwrap_err()),
            HookError::Inconsistent { cursor: 1, count: 8, target: 7 }
        ));
        // a cursor that is not a uint64
        let mut c = db(ADVANCE, U256::from(1) << 64, 8, 8);
        assert!(matches!(
            refused(run_records_hook(&mut c, &hook(1), 20_000_000).unwrap_err()),
            HookError::BadReturn("recordCursor")
        ));
    }

    #[test]
    fn the_whole_hook_is_metered_from_the_budget_given() {
        let mut probe = db(ADVANCE, U256::from(0), 6, 6);
        let g = run_records_hook(&mut probe, &hook(6), 20_000_000).unwrap().gas_spent;
        assert!(g > HOOK_READS_GAS / 10, "{g}");
        let mut exact = db(ADVANCE, U256::from(0), 6, 6);
        assert_eq!(run_records_hook(&mut exact, &hook(6), g).unwrap().gas_spent, g);
        let mut short = db(ADVANCE, U256::from(0), 6, 6);
        assert!(run_records_hook(&mut short, &hook(6), g - 1).is_err(), "one gas short fails");
        let mut none = db(ADVANCE, U256::from(0), 6, 6);
        assert!(matches!(
            refused(run_records_hook(&mut none, &hook(6), 0).unwrap_err()),
            HookError::Budget
        ));
    }

    #[test]
    fn a_chain_without_custody_runs_nothing_and_reserves_nothing() {
        let off = RecordsHook::default();
        let mut db = db(ADVANCE, U256::from(0), 6, 6);
        assert_eq!(run_records_hook(&mut db, &off, 0).unwrap(), HookOutcome::default());
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
}
