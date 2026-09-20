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

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadId;
use reth_basic_payload_builder::PayloadConfig;
use reth_unicity_execution::{
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
/// request. The payload service clones the resolved
/// [`UnicityEvmConfig`](reth_unicity_execution::block_executor::UnicityEvmConfig) on every
/// `try_build`, `build_empty_payload` and missing-payload path, so the registry only has to keep a
/// job until its build has started.
///
/// The capacity is at least [`DEFAULT_SEAL_JOB_CAPACITY`] and tracks the node's
/// `max_payload_tasks` through [`SealJobRegistry::grow_capacity`]. It evicts in insertion order:
/// the oldest job is dropped when a new one would exceed the capacity. A duplicate payload id is
/// refused instead of replacing the existing job, matching
/// [`FixedPayloadJobResolver`](crate::FixedPayloadJobResolver) and the fact that a payload id
/// identifies one exhaustive job. All clones share the same entries, so the payload service and
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

    /// Installs `job` and refuses a payload id that is already present.
    ///
    /// If the registry is full, the oldest insertion is evicted first. Eviction happens only when
    /// the incoming job is accepted, so a duplicate does not displace the job it collides with.
    pub fn insert(&self, job: ResolvedPayloadJob) -> Result<(), PayloadJobResolutionError> {
        let mut inner = self.lock();
        if inner.jobs.iter().any(|existing| existing.payload_id == job.payload_id) {
            return Err(PayloadJobResolutionError("duplicate payload job"));
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
    tokens: VecDeque<(B256, CompletedParent)>,
    capacity: usize,
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
/// Only blocks this node built are recorded. A follower that imported the parent block through
/// `engine_newPayloadWithSealV1` has no token for it, so a node cannot currently build on an
/// imported parent and the build path refuses it as an internal error. The import path executes
/// imported blocks through the same executor and must record the token there too; that is what
/// lets a follower lead in a rotating-leader shard. The token is not and must not be derived from
/// the parent header.
#[derive(Clone, Debug)]
pub struct UnicityParentAccountings {
    inner: Arc<Mutex<ParentAccountingInner>>,
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
        }
    }

    /// Publishes the token for the block whose hash is `block_hash`.
    ///
    /// A repeated hash replaces the existing entry rather than adding a second one. If the store is
    /// full, the oldest insertion is evicted first.
    pub fn insert(&self, block_hash: B256, token: CompletedParent) {
        let mut inner = self.lock();
        if let Some(index) = inner.tokens.iter().position(|(hash, _)| *hash == block_hash) {
            inner.tokens.remove(index);
        }
        if inner.tokens.len() >= inner.capacity {
            inner.tokens.pop_front();
        }
        inner.tokens.push_back((block_hash, token));
    }

    /// Returns the token for `block_hash`, if a build or replay published one.
    pub fn get(&self, block_hash: &B256) -> Option<CompletedParent> {
        self.lock().tokens.iter().find(|(hash, _)| hash == block_hash).map(|(_, token)| *token)
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

impl Default for UnicityParentAccountings {
    fn default() -> Self {
        Self::new()
    }
}
