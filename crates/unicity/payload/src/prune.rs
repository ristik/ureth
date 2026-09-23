//! Companion retention: evict non-canonical entries, then prune below the retention horizon.
//!
//! Retention has two independent halves and conflating them is a bug:
//!
//! - **Eviction** drops an entry whose block hash is not the canonical block at its number, once
//!   that number is at or below the finalized block. Below finality the chain cannot reorg, so the
//!   node will never serve that block again. It runs on every node, including one that retains
//!   indefinitely, and it never publishes a horizon.
//! - **Horizon pruning** drops entries below `tip - depth` and publishes that horizon. It runs only
//!   when a retention depth is configured.
//!
//! The store is told what to read and what to drop; the canonical comparison lives here, not in the
//! store.

use std::sync::Arc;

use alloy_consensus::BlockHeader;
use futures_util::StreamExt;
use reth_provider::CanonStateSubscriptions;
use reth_storage_api::BlockIdReader;
use reth_unicity_store::{CompanionStore, StoreError};

/// Error from one retention pass.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompanionPruneError {
    /// The companion store could not be read or written.
    Store(StoreError),
    /// The provider could not answer a canonical-chain question.
    Provider(String),
}

impl std::fmt::Display for CompanionPruneError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "companion store error: {error}"),
            Self::Provider(error) => write!(formatter, "companion chain read failed: {error}"),
        }
    }
}

impl std::error::Error for CompanionPruneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Provider(_) => None,
        }
    }
}

impl From<StoreError> for CompanionPruneError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// One node's retention policy over the shared companion store.
///
/// The eviction cursor is not held here; it lives in the store's metadata so a restart resumes
/// instead of rescanning the chain. A pass reads it, works forward, and writes it back.
#[derive(Debug)]
pub struct CompanionPruner<P> {
    provider: P,
    store: Arc<CompanionStore>,
    depth: Option<u64>,
    repair_limit: u64,
}

impl<P> CompanionPruner<P>
where
    P: BlockIdReader,
{
    /// Creates a pruner over `store`. `depth` is the number of blocks to retain; `None` retains
    /// every companion indefinitely.
    pub const fn new(provider: P, store: Arc<CompanionStore>, depth: Option<u64>) -> Self {
        Self { provider, store, depth, repair_limit: crate::recovery::DEFAULT_REPAIR_LIMIT }
    }

    /// Sets the replay window whose durable predecessor tokens retention must protect.
    pub const fn with_repair_limit(mut self, limit: u64) -> Self {
        self.repair_limit = limit;
        self
    }

    /// Runs one retention pass at `tip`: evict non-canonical entries at or below finalized, then
    /// prune below `tip - depth` when a depth is configured.
    ///
    /// Eviction never raises the horizon, so a node that retains indefinitely still answers
    /// `horizon: null` after dropping a reorged entry.
    pub fn prune_once(&self, tip: u64) -> Result<(), CompanionPruneError> {
        let companion_result = self.evict_non_canonical().and_then(|()| self.prune_to_depth(tip));
        let accounting_result = self.prune_accounting();
        companion_result?;
        accounting_result
    }

    fn prune_accounting(&self) -> Result<(), CompanionPruneError> {
        // The sidecar may be far ahead of the main database when a process dies. Anchor token
        // retention to the persisted DB frontier so a rollback still has a usable token window.
        let persisted = self
            .provider
            .last_block_number()
            .map_err(|error| CompanionPruneError::Provider(error.to_string()))?;
        self.store.prune_accounting_below(persisted.saturating_sub(
            crate::recovery::ACCOUNTING_WINDOW.saturating_add(self.repair_limit),
        ))?;
        Ok(())
    }

    /// Drops every entry whose hash is not the canonical block at its number, once that number is
    /// at or below the finalized block.
    ///
    /// The finalized block is the bound rather than a reorg-window constant because the chain
    /// cannot reorg below finality: an entry at or below it that is not the canonical block is one
    /// this node will never be asked to serve. Above finality either branch could still win, so the
    /// entry is left alone.
    fn evict_non_canonical(&self) -> Result<(), CompanionPruneError> {
        let Some(finalized) = self
            .provider
            .finalized_block_number()
            .map_err(|error| CompanionPruneError::Provider(error.to_string()))?
        else {
            // Without a finalized block there is no settled chain to evict against yet.
            return Ok(());
        };
        let end = finalized.saturating_add(1);
        // The cursor is durable, so a restart resumes where the last pass stopped instead of
        // rescanning the chain. Below it, finality means nothing can have changed.
        let start = self.store.eviction_cursor()?.unwrap_or(0);
        if start >= end {
            return Ok(());
        }

        // The provider returning `None` means it has no hash for that number, not that the number
        // holds a different block. Deleting a companion is unrecoverable while keeping one only
        // wastes disk, so only an affirmative mismatch evicts. The pass cannot advance past the
        // lowest unresolved number, so that number is re-read on the next pass.
        let mut unresolved = None;
        for (hash, number) in self.store.entries_in_range(start, end)? {
            let canonical = self
                .provider
                .block_hash(number)
                .map_err(|error| CompanionPruneError::Provider(error.to_string()))?;
            match canonical {
                Some(canonical) if canonical != hash => self.store.remove(hash)?,
                Some(_) => {}
                None => {
                    if unresolved.is_none() {
                        unresolved = Some(number);
                    }
                }
            }
        }

        let next = unresolved.unwrap_or(end);
        if next != start {
            self.store.set_eviction_cursor(next)?;
        }
        Ok(())
    }

    /// Drops the entries below `tip - depth` and publishes that horizon.
    ///
    /// [`CompanionStore::prune_below`] removes the entries first and then raises the horizon, and
    /// it never lowers an already published horizon, so a tip that moves backwards in a reorg
    /// cannot move the published horizon backwards with it.
    fn prune_to_depth(&self, tip: u64) -> Result<(), CompanionPruneError> {
        let Some(depth) = self.depth else {
            return Ok(());
        };
        self.store.prune_below(tip.saturating_sub(depth))?;
        Ok(())
    }
}

/// Runs the retention loop until the canonical-state stream ends.
///
/// The stream notifies on every canonical chain change, including reorgs, so the task needs no
/// timer: the block cadence is the rate limit. The caller spawns this on the node's own executor
/// and logs each failed pass, because a node that cannot prune is still a correct node that retains
/// more than configured.
pub async fn run_companion_pruner<P>(
    provider: P,
    store: Arc<CompanionStore>,
    depth: Option<u64>,
    repair_limit: u64,
) where
    P: BlockIdReader + CanonStateSubscriptions + Send + 'static,
{
    let mut stream = provider.canonical_state_stream();
    let pruner = CompanionPruner::new(provider, store, depth).with_repair_limit(repair_limit);
    while let Some(notification) = stream.next().await {
        // A revert can commit an empty segment, so there may be no new tip to prune against.
        let Some(tip) = notification.tip_checked() else {
            continue;
        };
        let tip = tip.number();
        if let Err(error) = pruner.prune_once(tip) {
            tracing::error!(
                target: "reth::unicity",
                %error,
                tip,
                "companion retention pass failed; the node retains more than configured"
            );
        }
    }
}
