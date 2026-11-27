//! Drives the activation-schedule operator view (gauge `unicity_upgrade_required`, the warning
//! log and `unicity_rulesV1`) from the canonical head only (VT-07b).
//!
//! Execution of other blocks (build, import, replay) resolves its own parent's schedule for its
//! own decision and never writes the view, so historical execution cannot clear the head's
//! pending-rule warning.
//!
//! The observer initializes from the current canonical tip when it starts, so the view is right
//! before the first new block, and it refreshes on every canonical-state notification. A pure
//! revert (a reorg whose replacement segment is empty) carries no new tip block; the canonical
//! tip is then whatever the provider's latest state says, so that is what is observed.

use alloy_primitives::B256;
use futures_util::{Stream, StreamExt};
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_unicity_execution::{rules::UnicityRules, VALIDATOR_REGISTRY};

/// Observes the schedule at the canonical tip now and at every canonical change until the stream
/// ends. A failed read is logged and leaves the previous view in place.
pub async fn run_rules_head_observer<P>(provider: P, rules: UnicityRules)
where
    P: StateProviderFactory + CanonStateSubscriptions + Send + 'static,
{
    // subscribe before the first read so no change between the two is missed
    let stream = provider.canonical_state_stream().map(|n| tip_of(&n));
    drive(stream, |tip| {
        if let Err(error) = observe_tip(&provider, &rules, tip) {
            tracing::error!(
                target: "unicity::rules",
                %error,
                ?tip,
                "could not read the activation schedule at the canonical head"
            );
        }
    })
    .await;
}

/// The new canonical tip a notification names; `None` for a pure revert, whose canonical tip is
/// the provider's latest state.
pub(crate) fn tip_of<N: reth_primitives_traits::NodePrimitives>(
    notification: &CanonStateNotification<N>,
) -> Option<B256> {
    notification.tip_checked().map(|tip| tip.hash())
}

/// Calls `observe(None)` once for the current tip, then once per stream item.
pub(crate) async fn drive<S>(stream: S, mut observe: impl FnMut(Option<B256>))
where
    S: Stream<Item = Option<B256>>,
{
    observe(None);
    futures_util::pin_mut!(stream);
    while let Some(tip) = stream.next().await {
        observe(tip);
    }
}

/// Publishes the schedule of the state at `tip`, or of the provider's latest (canonical) state.
pub(crate) fn observe_tip<P: StateProviderFactory>(
    provider: &P,
    rules: &UnicityRules,
    tip: Option<B256>,
) -> Result<(), String> {
    let state = match tip {
        Some(hash) => provider.state_by_block_hash(hash),
        None => provider.latest(),
    }
    .map_err(|e| e.to_string())?;
    let mut db = StateProviderDatabase::new(state);
    rules.observe_head(&mut db, VALIDATOR_REGISTRY).map_err(|e| e.to_string())
}

/// Resolves a freshly bound job's EVM spec from the state of its parent `parent_hash`
/// (bft-core#1230), so the job's `evm_env`, `next_evm_env` and the engine's `evm_env_for_payload`
/// run ordinary transactions under the spec the activation schedule selects. Build, import and
/// restart repair all bind through here. A resolution that fails leaves the job unresolved and its
/// executor refuses with the typed error; only a missing parent state is an error here.
pub(crate) fn with_parent_spec<P: StateProviderFactory>(
    provider: &P,
    parent_hash: B256,
    bound: reth_unicity_execution::block_executor::BoundExecutionInput,
) -> reth_provider::ProviderResult<reth_unicity_execution::block_executor::BoundExecutionInput> {
    let state = provider.state_by_block_hash(parent_hash)?;
    Ok(bound.with_parent_spec(&mut StateProviderDatabase::new(state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use futures_util::stream;
    use reth_ethereum_primitives::EthPrimitives;
    use reth_execution_types::Chain;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_unicity_execution::rules::{
        rule_id, schedule_storage, EntryState, KnownRule, ScheduleEntry, GENESIS_SPEC,
    };
    use std::sync::Arc;

    fn rules() -> UnicityRules {
        UnicityRules::with_known(vec![KnownRule {
            name: "known",
            id: rule_id("known"),
            spec: GENESIS_SPEC,
        }])
    }

    /// A provider whose registry holds `entries`.
    fn provider_with(entries: &[ScheduleEntry]) -> MockEthProvider {
        let provider = MockEthProvider::default();
        set_schedule(&provider, entries);
        provider
    }

    fn set_schedule(provider: &MockEthProvider, entries: &[ScheduleEntry]) {
        let storage = schedule_storage(entries)
            .into_iter()
            .map(|(k, v)| (B256::from(k.to_be_bytes::<32>()), v))
            .collect::<Vec<_>>();
        provider.add_account(
            VALIDATOR_REGISTRY,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
        );
    }

    fn pending() -> ScheduleEntry {
        ScheduleEntry {
            rule_id: rule_id("future"),
            release_digest: B256::repeat_byte(0xd1),
            root_epoch: 10,
            not_before_uc_time: 0,
            state: EntryState::Active,
            change_id: 1,
        }
    }

    #[tokio::test]
    async fn startup_initializes_the_view_from_the_current_tip() {
        let rules = rules();
        let provider = provider_with(&[pending()]);
        assert!(rules.head_view().is_none());
        // the stream has produced nothing yet: only the startup observation runs
        let calls = std::cell::RefCell::new(Vec::new());
        drive(stream::empty(), |tip| {
            calls.borrow_mut().push(tip);
            observe_tip(&provider, &rules, tip).unwrap();
        })
        .await;
        assert_eq!(*calls.borrow(), vec![None]);
        assert_eq!(rules.head_view().unwrap().lacking.len(), 1);
    }

    #[tokio::test]
    async fn a_pure_revert_reobserves_the_new_canonical_tip() {
        // a Reorg whose replacement segment is empty names no tip block
        let revert: CanonStateNotification<EthPrimitives> = CanonStateNotification::Reorg {
            old: Arc::new(Chain::default()),
            new: Arc::new(Chain::default()),
        };
        assert_eq!(tip_of(&revert), None);

        let rules = rules();
        let provider = provider_with(&[pending()]);
        let seen = std::cell::RefCell::new(Vec::new());
        drive(stream::iter([tip_of(&revert)]), |tip| {
            // before the revert notification is handled the chain moved back to a head that no
            // longer holds the entry
            if !seen.borrow().is_empty() {
                set_schedule(&provider, &[]);
            }
            seen.borrow_mut().push(tip);
            observe_tip(&provider, &rules, tip).unwrap();
        })
        .await;
        assert_eq!(*seen.borrow(), vec![None, None], "startup, then the revert");
        assert!(rules.head_view().unwrap().lacking.is_empty(), "the revert cleared the warning");
    }
}
