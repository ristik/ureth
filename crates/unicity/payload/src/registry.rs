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

use reth_basic_payload_builder::PayloadConfig;
use reth_unicity_execution::block_executor::UnicityEvmConfig;

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
