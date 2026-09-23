//! Bounded in-process handoff for seal build jobs.
//!
//! The registry is the attachment point the `engine_*WithSealV1` methods will use. A future
//! authenticated caller inserts one [`ResolvedPayloadJob`] per build request, and the node's
//! [`UnicityExecutionPayloadBuilder`](crate::UnicityExecutionPayloadBuilder) resolves that exact
//! job through [`ExecutionPayloadJobResolver`] when the payload service starts the build.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadId;
use reth_basic_payload_builder::PayloadConfig;
use reth_chainspec::ChainSpec;
use reth_primitives_traits::SealedHeader;
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{CompletedParent, UnicityEvmConfig},
    RootInputV2,
};

use crate::{
    ExecutionPayloadJobResolver, PayloadJobResolutionError, ResolvedPayloadJob,
    UnicityPayloadAttributes,
};

/// Floor for [`SealJobRegistry`] capacity.
///
/// The node does not use this number directly. When it constructs the payload builder it raises the
/// registry capacity to `max(DEFAULT_SEAL_JOB_CAPACITY, max_payload_tasks * 4)`, where
/// `max_payload_tasks` is the configured `--builder.max-payload-tasks`. Upstream
/// [`BasicPayloadJobGenerator`](reth_basic_payload_builder::BasicPayloadJobGenerator) admits at
/// most that many builds to execute at once, so the four-times multiplier keeps the registry above
/// the number of builds that can be in flight and leaves headroom for jobs that are alive but not
/// yet executing. Sixteen is the floor for a node that leaves the default configuration in place.
pub const DEFAULT_SEAL_JOB_CAPACITY: usize = 16;

#[derive(Debug)]
struct SealJobRegistryInner {
    jobs: VecDeque<ResolvedPayloadJob>,
    capacity: usize,
}

/// Bounded, shareable registry of seal build jobs waiting to be resolved.
///
/// A future authenticated caller (the U3c to U3f methods) inserts one [`ResolvedPayloadJob`] per
/// request. The payload service clones the resolved [`UnicityEvmConfig`] on every `try_build`,
/// `build_empty_payload` and missing-payload path, so the registry only has to keep a job until its
/// build has started.
///
/// The capacity is at least [`DEFAULT_SEAL_JOB_CAPACITY`] and tracks the node's
/// `max_payload_tasks` through [`SealJobRegistry::grow_capacity`]. It evicts in insertion order:
/// the oldest job is dropped when a new one would exceed the capacity. An identical retry reuses
/// its existing job; a payload id collision with different input is refused. All clones share the
/// same entries, so the payload service and
/// the method that inserts jobs see one registry.
#[derive(Clone, Debug)]
pub struct SealJobRegistry {
    inner: Arc<Mutex<SealJobRegistryInner>>,
}

impl SealJobRegistry {
    /// Creates an empty registry with [`DEFAULT_SEAL_JOB_CAPACITY`] entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SEAL_JOB_CAPACITY)
    }

    /// Creates an empty registry bounded to `capacity` entries.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero, because a zero-capacity registry could never hold the job for
    /// a build it just started.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "seal job registry capacity must be greater than zero");
        Self {
            inner: Arc::new(Mutex::new(SealJobRegistryInner { jobs: VecDeque::new(), capacity })),
        }
    }

    /// Returns the current capacity.
    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Raises the capacity to `capacity` if that is larger.
    ///
    /// The node calls this once when it constructs the payload builder, so the registry tracks
    /// `--builder.max-payload-tasks`. Capacity never shrinks, so a job already held cannot be
    /// evicted by a later, smaller configuration.
    pub fn grow_capacity(&self, capacity: usize) {
        let mut inner = self.lock();
        inner.capacity = inner.capacity.max(capacity);
    }

    /// Returns the number of jobs currently held.
    pub fn len(&self) -> usize {
        self.lock().jobs.len()
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().jobs.is_empty()
    }

    /// Returns the structured input the job with `payload_id` was bound to, if it is still held.
    ///
    /// The build path does not retain the caller's raw `rootInput` bytes. The job holds the decoded
    /// [`RootInputV2`], and the companion re-encodes it with the canonical codec; the decoder is
    /// the exact inverse of that encoder, so the re-encoded bytes equal what the caller
    /// supplied.
    pub fn root_input(&self, payload_id: &PayloadId) -> Option<RootInputV2> {
        self.lock()
            .jobs
            .iter()
            .find(|job| job.payload_id == *payload_id)
            .map(|job| job.evm_config.root_input().clone())
    }

    /// Installs `job`, accepting an identical retry without replacing the existing job.
    ///
    /// If the registry is full, the oldest insertion is evicted first. Eviction happens only when
    /// the incoming job is new, so a retry or collision does not displace the held job.
    pub fn insert(&self, job: ResolvedPayloadJob) -> Result<(), PayloadJobResolutionError> {
        let mut inner = self.lock();
        if let Some(existing) =
            inner.jobs.iter().find(|existing| existing.payload_id == job.payload_id)
        {
            return if existing.same_build_input(&job) {
                Ok(())
            } else {
                Err(PayloadJobResolutionError("duplicate payload job with different input"))
            };
        }
        if inner.jobs.len() >= inner.capacity {
            inner.jobs.pop_front();
        }
        inner.jobs.push_back(job);
        Ok(())
    }

    /// Drops every held job. Used when a caller knows no build is outstanding.
    pub fn clear(&self) {
        self.lock().jobs.clear();
    }

    fn lock(&self) -> MutexGuard<'_, SealJobRegistryInner> {
        // A poisoned registry means an earlier insert or resolve panicked. The `VecDeque` is still
        // readable and the worst case is one missing or stale entry, which resolves as "absent"
        // rather than taking the payload service down with the panic.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for SealJobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionPayloadJobResolver for SealJobRegistry {
    fn resolve(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<UnicityEvmConfig, PayloadJobResolutionError> {
        let inner = self.lock();
        let job = inner
            .jobs
            .iter()
            .find(|job| job.payload_id == config.payload_id)
            .ok_or(PayloadJobResolutionError("payload job is absent"))?;
        job.check_binding(config)?;
        Ok(job.evm_config.clone())
    }
}

/// Capacity of [`UnicityParentAccountings`].
///
/// Only recent heads can be the parent of the next build, and the payload service keeps at most a
/// few builds alive at once, so a small window is enough. The oldest published token is evicted
/// first, so the store cannot grow without limit as the node builds blocks.
pub const DEFAULT_PARENT_ACCOUNTING_CAPACITY: usize = 16;

#[derive(Debug)]
struct ParentAccountingInner {
    tokens: VecDeque<ParentAccountingEntry>,
    capacity: usize,
}

#[derive(Debug)]
struct ParentAccountingEntry {
    hash: B256,
    token: CompletedParent,
    identity: Option<(u64, B256)>,
    pins: usize,
}

/// A token lookup that can become available after a local build, import, or restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("parent accounting unavailable for {0}")]
pub struct ParentAccountingUnavailable(pub B256);

/// Shared checked lookup contract for build, replay, and parent-header consensus.
pub trait ParentAccountingResolver: Send + Sync {
    /// Resolves the exact header under the configured chain and profile, pinning the entry until
    /// the caller drops the lease.
    fn resolve(
        &self,
        parent: &SealedHeader<Header>,
        chain_spec: &ChainSpec,
        profile: BlockProfile,
    ) -> Result<ParentAccountingLease, ParentAccountingUnavailable>;
}

/// Keeps a parent token available while an Engine import validates its child.
#[derive(Debug)]
pub struct ParentAccountingLease {
    hash: B256,
    token: CompletedParent,
    next_fee: u64,
    inner: Arc<Mutex<ParentAccountingInner>>,
}

impl ParentAccountingLease {
    /// The checked token for binding an exact child execution input.
    pub const fn token(&self) -> CompletedParent {
        self.token
    }

    /// The checked next fee from the shared ordinary-gas rule.
    pub const fn next_fee(&self) -> u64 {
        self.next_fee
    }
}

impl Drop for ParentAccountingLease {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = inner.tokens.iter_mut().find(|entry| entry.hash == self.hash) {
            entry.pins -= 1;
        }
        while inner.tokens.len() > inner.capacity {
            if let Some(index) = inner.tokens.iter().position(|entry| entry.pins == 0) {
                inner.tokens.remove(index);
            } else {
                break;
            }
        }
    }
}

/// Bounded store of completed parent-accounting tokens published by the build path.
///
/// The next build needs the accounting token for the block it builds on. The token is opaque and
/// can only be minted by a completed build or replay, so it must be retained between calls. This
/// store is that retention point: the payload builder inserts the token for a block it produced,
/// and the seal build path reads it for the parent.
///
/// This is why the token is not derived from the parent header: the header carries the gross gas
/// but not the system/ordinary split, and deriving that split from a header alone would let a
/// caller invent the parent's base-fee input rather than inherit it from the build that produced
/// it.
///
/// Completed builds and replay-validated imports both publish tokens for their children.
#[derive(Clone, Debug)]
pub struct UnicityParentAccountings {
    inner: Arc<Mutex<ParentAccountingInner>>,
    durable: Arc<std::sync::OnceLock<Arc<reth_unicity_store::CompanionStore>>>,
    durability_required: bool,
}

impl UnicityParentAccountings {
    /// Creates an empty store with [`DEFAULT_PARENT_ACCOUNTING_CAPACITY`] entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_PARENT_ACCOUNTING_CAPACITY)
    }

    /// Creates an empty store bounded to `capacity` entries.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "parent accounting capacity must be greater than zero");
        Self {
            inner: Arc::new(Mutex::new(ParentAccountingInner {
                tokens: VecDeque::new(),
                capacity,
            })),
            durable: Arc::new(std::sync::OnceLock::new()),
            durability_required: false,
        }
    }

    /// Requires a durable write before publishing a token; used by the launched node.
    pub const fn require_durability(mut self) -> Self {
        self.durability_required = true;
        self
    }

    /// Attaches the shared sidecar once the chain data directory is available.
    pub fn attach_store(&self, store: Arc<reth_unicity_store::CompanionStore>) {
        let _ = self.durable.set(store);
    }

    /// Returns the node's local accounting store when it has been opened.
    pub fn durable_store(&self) -> Option<&Arc<reth_unicity_store::CompanionStore>> {
        self.durable.get()
    }

    /// Durably publishes a completed build or checked replay before it can be delivered.
    pub fn publish(
        &self,
        block_hash: B256,
        block_number: u64,
        chain_id: u64,
        genesis_hash: B256,
        token: CompletedParent,
    ) -> Result<(), reth_unicity_store::StoreError> {
        if token.for_local_storage().block_hash != block_hash {
            return Err(reth_unicity_store::StoreError::Corrupt("token/hash mismatch"));
        }
        if let Some(store) = self.durable.get() {
            store.put_accounting(reth_unicity_store::StoredAccounting {
                chain_id,
                genesis_hash,
                block_number,
                accounting: token.for_local_storage(),
            })?;
        } else if self.durability_required {
            return Err(reth_unicity_store::StoreError::Corrupt("accounting store unavailable"));
        }
        self.insert_for_chain(block_hash, token, chain_id, genesis_hash);
        Ok(())
    }

    /// Restores a record by exact hash after checking chain identity, header, profile, and gas.
    /// Canonical startup selection is the caller's separate responsibility.
    pub fn restore_exact(
        &self,
        header: &reth_primitives_traits::SealedHeader<alloy_consensus::Header>,
        chain_id: u64,
        genesis_hash: B256,
        profile: reth_unicity_execution::block::BlockProfile,
    ) -> Result<Option<CompletedParent>, reth_unicity_store::StoreError> {
        if let Some(entry) = self.lock().tokens.iter().find(|entry| entry.hash == header.hash()) {
            if entry.identity != Some((chain_id, genesis_hash)) ||
                entry.token.checked_next_base_fee(header, profile).is_err()
            {
                return Err(reth_unicity_store::StoreError::Corrupt("cached accounting mismatch"));
            }
            return Ok(Some(entry.token));
        }
        let Some(store) = self.durable.get() else {
            if self.durability_required {
                return Err(reth_unicity_store::StoreError::Corrupt("accounting store unavailable"));
            }
            return Ok(None);
        };
        let Some(record) = store.get_accounting(header.hash())? else {
            return Ok(None);
        };
        if record.chain_id != chain_id ||
            record.genesis_hash != genesis_hash ||
            record.block_number != header.number
        {
            return Err(reth_unicity_store::StoreError::Corrupt("accounting chain identity"));
        }
        let token = CompletedParent::from_local_storage(record.accounting, header, profile)
            .map_err(|_| reth_unicity_store::StoreError::Corrupt("accounting/header mismatch"))?;
        token
            .checked_next_base_fee(header, profile)
            .map_err(|_| reth_unicity_store::StoreError::Corrupt("accounting fee mismatch"))?;
        self.insert_for_chain(header.hash(), token, chain_id, genesis_hash);
        Ok(Some(token))
    }

    /// Publishes the token for the block whose hash is `block_hash`.
    ///
    /// A repeated hash replaces the existing entry rather than adding a second one. If the store is
    /// full, the oldest insertion is evicted first.
    pub fn insert(&self, block_hash: B256, token: CompletedParent) {
        self.insert_inner(block_hash, token, None);
    }

    /// Publishes a token bound to the node's chain identity.
    pub fn insert_for_chain(
        &self,
        block_hash: B256,
        token: CompletedParent,
        chain_id: u64,
        genesis_hash: B256,
    ) {
        self.insert_inner(block_hash, token, Some((chain_id, genesis_hash)));
    }

    fn insert_inner(
        &self,
        block_hash: B256,
        token: CompletedParent,
        identity: Option<(u64, B256)>,
    ) {
        let mut inner = self.lock();
        if let Some(entry) = inner.tokens.iter_mut().find(|entry| entry.hash == block_hash) {
            // A validator already holds this exact token. Keep the published fact stable until
            // its lease is dropped; a later publication can then replace it if needed.
            if entry.pins > 0 {
                return;
            }
            entry.token = token;
            entry.identity = identity;
            return;
        }
        if inner.tokens.len() >= inner.capacity &&
            let Some(index) = inner.tokens.iter().position(|entry| entry.pins == 0)
        {
            inner.tokens.remove(index);
        }
        inner.tokens.push_back(ParentAccountingEntry {
            hash: block_hash,
            token,
            identity,
            pins: 0,
        });
    }

    /// Returns the token for `block_hash`, if a build or replay published one.
    pub fn get(&self, block_hash: &B256) -> Option<CompletedParent> {
        self.lock().tokens.iter().find(|entry| entry.hash == *block_hash).map(|entry| entry.token)
    }

    /// Returns the number of tokens currently held.
    pub fn len(&self) -> usize {
        self.lock().tokens.len()
    }

    /// Returns whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().tokens.is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, ParentAccountingInner> {
        // A poisoned store means an earlier insert panicked. The deque is still readable, and the
        // worst case is a missing token, which refuses a build rather than taking the payload
        // service down with the panic.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ParentAccountingResolver for UnicityParentAccountings {
    fn resolve(
        &self,
        parent: &SealedHeader<Header>,
        chain_spec: &ChainSpec,
        profile: BlockProfile,
    ) -> Result<ParentAccountingLease, ParentAccountingUnavailable> {
        let exists = self.lock().tokens.iter().any(|entry| entry.hash == parent.hash());
        if !exists {
            self.restore_exact(parent, chain_spec.chain().id(), chain_spec.genesis_hash(), profile)
                .map_err(|_| ParentAccountingUnavailable(parent.hash()))?;
        }
        let mut inner = self.lock();
        let entry = inner
            .tokens
            .iter_mut()
            .find(|entry| entry.hash == parent.hash())
            .ok_or_else(|| ParentAccountingUnavailable(parent.hash()))?;
        if entry.identity != Some((chain_spec.chain().id(), chain_spec.genesis_hash())) {
            return Err(ParentAccountingUnavailable(parent.hash()));
        }
        let next_fee = entry
            .token
            .checked_next_base_fee(parent, profile)
            .map_err(|_| ParentAccountingUnavailable(parent.hash()))?;
        entry.pins += 1;
        Ok(ParentAccountingLease {
            hash: parent.hash(),
            token: entry.token,
            next_fee,
            inner: self.inner.clone(),
        })
    }
}

impl Default for UnicityParentAccountings {
    fn default() -> Self {
        Self::new()
    }
}
