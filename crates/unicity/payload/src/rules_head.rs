//! Drives the activation-schedule operator view (gauge `unicity_upgrade_required`, the warning
//! log and `unicity_rulesV1`) from the canonical head only (VT-07b).
//!
//! Execution of other blocks (build, import, replay) resolves its own parent's schedule for its
//! own decision and never writes the view, so historical execution cannot clear the head's
//! pending-rule warning.

use futures_util::StreamExt;
use reth_provider::{CanonStateSubscriptions, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_unicity_execution::{rules::UnicityRules, VALIDATOR_REGISTRY};

/// Observes the schedule at every new canonical tip until the stream ends. A failed read is
/// logged and leaves the previous view in place.
pub async fn run_rules_head_observer<P>(provider: P, rules: UnicityRules)
where
    P: StateProviderFactory + CanonStateSubscriptions + Send + 'static,
{
    let mut stream = provider.canonical_state_stream();
    while let Some(notification) = stream.next().await {
        // a revert can commit an empty segment: no new tip, nothing to observe
        let Some(tip) = notification.tip_checked() else {
            continue;
        };
        let hash = tip.hash();
        let result =
            provider.state_by_block_hash(hash).map_err(|e| e.to_string()).and_then(|state| {
                let mut db = StateProviderDatabase::new(state);
                rules.observe_head(&mut db, VALIDATOR_REGISTRY).map_err(|e| e.to_string())
            });
        if let Err(error) = result {
            tracing::error!(
                target: "unicity::rules",
                %error,
                tip = %hash,
                "could not read the activation schedule at the canonical head"
            );
        }
    }
}
