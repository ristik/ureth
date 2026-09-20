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

/// Number of seal build jobs [`SealJobRegistry`] holds when it is not given an explicit capacity.
///
/// The upstream payload service deduplicates by payload id and keeps a job alive while it builds,
/// and [`BasicPayloadJobGenerator`](reth_basic_payload_builder::BasicPayloadJobGenerator) admits at
/// most `max_payload_tasks` builds to execute at once. That value is
/// `--builder.max-payload-tasks`, three by default. Sixteen exceeds that default by more than five
/// times, so with the default configuration every in-flight job stays resident and is never
/// evicted while its build still needs it.
///
/// If an operator raises `max_payload_tasks` above the registry capacity, a build can outlive its
/// own entry. That is fail-safe rather than a wrong result: the oldest insertion is evicted first,
/// so the evicted job can no longer resolve and the build fails with "payload job is absent". A
/// job that has been evicted is never silently replaced by a different one.
pub const DEFAULT_SEAL_JOB_CAPACITY: usize = 16;

#[derive(Debug)]
struct SealJobRegistryInner {
    jobs: VecDeque<ResolvedPayloadJob>,
}

/// Bounded, shareable registry of seal build jobs waiting to be resolved.
///
/// A future authenticated caller (the U3c to U3f methods) inserts one [`ResolvedPayloadJob`] per
/// request. The payload service clones the resolved
/// [`UnicityEvmConfig`](reth_unicity_execution::block_executor::UnicityEvmConfig) on every
/// `try_build`, `build_empty_payload` and missing-payload path, so the registry only has to keep a
/// job until its build has started.
///
/// The registry is bounded to [`DEFAULT_SEAL_JOB_CAPACITY`] entries and evicts in insertion order:
/// the oldest job is dropped when a new one would exceed the capacity. A duplicate payload id is
/// refused instead of replacing the existing job, matching
/// [`FixedPayloadJobResolver`](crate::FixedPayloadJobResolver) and the fact that a payload id
/// identifies one exhaustive job. All clones share the same entries, so the payload service and
/// the method that inserts jobs see one registry.
#[derive(Clone, Debug)]
pub struct SealJobRegistry {
    capacity: usize,
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
            capacity,
            inner: Arc::new(Mutex::new(SealJobRegistryInner { jobs: VecDeque::new() })),
        }
    }

    /// Returns the configured capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
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
        if inner.jobs.len() == self.capacity {
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
