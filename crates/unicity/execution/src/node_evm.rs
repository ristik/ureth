//! Node-level execution dispatch for imported seal blocks.
//!
//! The payload-builder job path carries its own `UnicityEvmConfig`. The engine tree does not: it
//! executes a block through the node's [`ConfigureEvm`] component, and the stock EVM rejects a seal
//! block's privileged system prefix by design. This module supplies that component, a
//! [`UnicityNodeEvmConfig`] that resolves the block's bound execution input from its 32-byte
//! `extraData` commitment before the engine tree executes it.
//!
//! The commitment is the binding. `extraData` is `SHA-256(CBOR(rootInput))`, so the header names
//! the exact authenticated input the block must run against. A block whose commitment is not
//! registered fails execution with [`crate::block_executor::MISSING_EXECUTION_INPUT_ERROR`] rather
//! than falling back to stock execution, because a seal block cannot be validated without its root
//! input.

use std::{
    collections::VecDeque,
    convert::Infallible,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use alloy_consensus::{Header, Transaction, TransactionEnvelope, TxReceipt};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{BlockExecutorFactory, StateDB},
    eth::{
        receipt_builder::ReceiptBuilder, spec::EthExecutorSpec, EthBlockExecutionCtx,
        EthBlockExecutorFactory, EthTxResult,
    },
    EvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Log, B256};
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use revm::{primitives::hardfork::SpecId, Inspector};

use crate::block_executor::{BoundExecutionInput, UnicityBlockExecutor, UnicityEvmConfig};

/// Floor capacity for [`UnicityBlockExecutionRegistry`].
///
/// One entry is needed per imported seal block, and only until the engine tree has executed it. The
/// engine forwards one payload at a time and executes it promptly, so the live window is tiny. The
/// number is a memory bound rather than a concurrency guarantee: eviction only affects a block
/// whose execution has not yet run, and that block then fails closed with
/// [`crate::block_executor::MISSING_EXECUTION_INPUT_ERROR`] instead of executing unauthenticated.
/// Sixteen leaves headroom
/// for a few queued payloads while keeping the store small.
pub const DEFAULT_BLOCK_EXECUTION_CAPACITY: usize = 16;

#[derive(Debug)]
struct BlockExecutionInner {
    entries: VecDeque<(B256, Arc<BoundExecutionInput>)>,
    capacity: usize,
}

/// Shareable, bounded store of bound execution inputs keyed by header commitment.
///
/// The import path inserts the input before forwarding the block to the engine, and the node's
/// [`UnicityNodeEvmConfig`] reads it when the engine tree executes that block. The same block may
/// be offered more than once, so inserting an identical input under an existing commitment is
/// idempotent. A different input under an existing commitment is refused rather than replacing it,
/// because that would let a later caller change what an already-seen commitment executes.
#[derive(Clone, Debug)]
pub struct UnicityBlockExecutionRegistry {
    inner: Arc<Mutex<BlockExecutionInner>>,
}

impl UnicityBlockExecutionRegistry {
    /// Creates an empty registry with [`DEFAULT_BLOCK_EXECUTION_CAPACITY`] entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BLOCK_EXECUTION_CAPACITY)
    }

    /// Creates an empty registry bounded to `capacity` entries.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "block execution registry capacity must be greater than zero");
        Self {
            inner: Arc::new(Mutex::new(BlockExecutionInner { entries: VecDeque::new(), capacity })),
        }
    }

    /// Returns the capacity.
    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Returns the number of entries currently held.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// Registers `input` under `commitment`.
    ///
    /// The input's own root-input commitment must equal `commitment`. An identical entry is
    /// idempotent; a different input under an existing commitment is refused. If the registry is
    /// full, the oldest insertion is evicted first.
    pub fn insert(
        &self,
        commitment: B256,
        input: Arc<BoundExecutionInput>,
    ) -> Result<(), BlockExecutionRegistryError> {
        let actual = input
            .root_input()
            .input_commitment()
            .map_err(|_| BlockExecutionRegistryError::InvalidInput)?;
        if actual != commitment {
            return Err(BlockExecutionRegistryError::CommitmentMismatch {
                declared: commitment,
                actual,
            });
        }

        let mut inner = self.lock();
        if let Some(position) =
            inner.entries.iter().position(|(existing, _)| *existing == commitment)
        {
            if inner.entries[position].1.root_input() == input.root_input() {
                return Ok(());
            }
            return Err(BlockExecutionRegistryError::ConflictingInput(commitment));
        }
        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back((commitment, input));
        Ok(())
    }

    /// Returns the input registered under `commitment`, if any.
    pub fn get(&self, commitment: &B256) -> Option<Arc<BoundExecutionInput>> {
        self.lock()
            .entries
            .iter()
            .find(|(existing, _)| existing == commitment)
            .map(|(_, input)| input.clone())
    }

    fn lock(&self) -> MutexGuard<'_, BlockExecutionInner> {
        // A poisoned registry means an earlier insert panicked. The deque is still readable and the
        // worst case is a missing entry, which fails execution closed rather than falling back.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for UnicityBlockExecutionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure to register a bound execution input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockExecutionRegistryError {
    /// The declared commitment does not match the input's own commitment.
    CommitmentMismatch {
        /// The commitment the caller supplied.
        declared: B256,
        /// The commitment derived from the input.
        actual: B256,
    },
    /// A different input is already registered under this commitment.
    ConflictingInput(B256),
    /// The input's root input could not be re-encoded to derive its commitment.
    InvalidInput,
}

impl fmt::Display for BlockExecutionRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitmentMismatch { declared, actual } => write!(
                formatter,
                "declared commitment {declared} does not match the input commitment {actual}"
            ),
            Self::ConflictingInput(commitment) => write!(
                formatter,
                "a different execution input is already registered under commitment {commitment}"
            ),
            Self::InvalidInput => formatter.write_str("execution input has no valid commitment"),
        }
    }
}

impl Error for BlockExecutionRegistryError {}

/// Failure to resolve or validate a block against its bound execution input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnicityNodeEvmError {
    /// The block's `extraData` is not a 32-byte commitment.
    MalformedCommitment {
        /// Length of the `extraData` field.
        found: usize,
    },
    /// No bound execution input is registered for the block's commitment.
    MissingInput(B256),
    /// The EVM environment is not the fixed Cancun profile.
    UnsupportedSpec,
    /// The bound input rejected the block or the next-block attributes.
    Binding(crate::block_executor::BindingError),
}

impl fmt::Display for UnicityNodeEvmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedCommitment { found } => {
                write!(formatter, "block extraData is {found} bytes, not a 32-byte commitment")
            }
            Self::MissingInput(commitment) => {
                write!(
                    formatter,
                    "{}: {commitment}",
                    crate::block_executor::MISSING_EXECUTION_INPUT_ERROR
                )
            }
            Self::UnsupportedSpec => {
                formatter.write_str("only the fixed Cancun profile is supported")
            }
            Self::Binding(error) => {
                write!(formatter, "bound execution input rejected the block: {error}")
            }
        }
    }
}

impl Error for UnicityNodeEvmError {}

/// Block executor factory that resolves each block's bound input from its context commitment.
///
/// `BlockExecutorFactory::create_executor` cannot fail, so it records an absent input as `None` in
/// the executor and lets `apply_pre_execution_changes` return the named error. That keeps the
/// failure at execution time, where a seal block without its root input must be refused, and avoids
/// a second failure point before the engine tree owns the block.
#[derive(Clone, Debug)]
pub struct UnicityNodeBlockExecutorFactory<R, Spec, EvmF> {
    inner: EthBlockExecutorFactory<R, Spec, EvmF>,
    registry: UnicityBlockExecutionRegistry,
}

impl<R, Spec, EvmF> UnicityNodeBlockExecutorFactory<R, Spec, EvmF> {
    /// Wraps the stock Ethereum factory and shares the execution-input registry.
    pub const fn new(
        inner: EthBlockExecutorFactory<R, Spec, EvmF>,
        registry: UnicityBlockExecutionRegistry,
    ) -> Self {
        Self { inner, registry }
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for UnicityNodeBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: EthExecutorSpec,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>>,
    <R::Transaction as TransactionEnvelope>::TxType: Send + 'static,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type TxExecutionResult = EthTxResult<
        <EvmF as EvmFactory>::HaltReason,
        <R::Transaction as TransactionEnvelope>::TxType,
    >;
    type Executor<'a, DB: StateDB, I: Inspector<EvmF::Context<DB>>> =
        UnicityBlockExecutor<'a, EvmF::Evm<DB, I>, &'a Spec, &'a R>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<EvmF::Context<DB>>,
    {
        let bound = commitment_from_extra_data(&ctx.extra_data)
            .and_then(|commitment| self.registry.get(&commitment));
        UnicityBlockExecutor::new(self.inner.create_executor(evm, ctx), bound)
    }
}

/// Returns the commitment a block's `extraData` names, or `None` when it is not 32 bytes.
fn commitment_from_extra_data(extra_data: &[u8]) -> Option<B256> {
    (extra_data.len() == 32).then(|| B256::from_slice(extra_data))
}

/// Node-level EVM configuration that dispatches each seal block to its bound execution input.
///
/// The build path uses a per-job `UnicityEvmConfig` supplied by the job resolver. This type is the
/// node component the engine tree uses, so an imported seal block executes through the same bounded
/// executor as a locally built one. If a block's commitment is not registered, the executor returns
/// [`MISSING_EXECUTION_INPUT_ERROR`]. There is deliberately no fallback to stock execution.
///
/// [`MISSING_EXECUTION_INPUT_ERROR`]: crate::block_executor::MISSING_EXECUTION_INPUT_ERROR
#[derive(Clone, Debug)]
pub struct UnicityNodeEvmConfig {
    inner: EthEvmConfig,
    registry: UnicityBlockExecutionRegistry,
    executor_factory: UnicityNodeBlockExecutorFactory<
        RethReceiptBuilder,
        Arc<ChainSpec>,
        alloy_evm::EthEvmFactory,
    >,
}

impl UnicityNodeEvmConfig {
    /// Creates the node EVM config over the stock Ethereum config and the execution-input registry.
    pub fn new(inner: EthEvmConfig, registry: UnicityBlockExecutionRegistry) -> Self {
        let executor_factory =
            UnicityNodeBlockExecutorFactory::new(inner.executor_factory.clone(), registry.clone());
        Self { inner, registry, executor_factory }
    }

    /// Returns the execution-input registry shared with the import path.
    pub const fn registry(&self) -> &UnicityBlockExecutionRegistry {
        &self.registry
    }

    fn bound_from_bytes(
        &self,
        extra_data: &[u8],
    ) -> Result<Arc<BoundExecutionInput>, UnicityNodeEvmError> {
        let commitment = commitment_from_extra_data(extra_data)
            .ok_or(UnicityNodeEvmError::MalformedCommitment { found: extra_data.len() })?;
        self.registry.get(&commitment).ok_or(UnicityNodeEvmError::MissingInput(commitment))
    }

    fn per_block(&self, bound: Arc<BoundExecutionInput>) -> UnicityEvmConfig {
        UnicityEvmConfig::new(self.inner.clone(), bound)
    }
}

impl ConfigureEvm for UnicityNodeEvmConfig {
    type Primitives = EthPrimitives;
    type Error = UnicityNodeEvmError;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = UnicityNodeBlockExecutorFactory<
        RethReceiptBuilder,
        Arc<ChainSpec>,
        alloy_evm::EthEvmFactory,
    >;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.inner.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv, Self::Error> {
        let env = self.inner.evm_env(header).map_err(|never: Infallible| match never {})?;
        if env.cfg_env.spec != SpecId::CANCUN {
            return Err(UnicityNodeEvmError::UnsupportedSpec);
        }
        Ok(env)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        // The build path resolves its own per-job config. This still validates the bound input for
        // the attributes' commitment so a node-configured build cannot silently diverge.
        let bound = self.bound_from_bytes(&attributes.extra_data)?;
        self.per_block(bound).next_evm_env(parent, attributes).map_err(UnicityNodeEvmError::Binding)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        let bound = self.bound_from_bytes(&block.header().extra_data)?;
        // The per-block config validates the header against the bound input and builds the stock
        // context. The returned context borrows `block`, not the temporary config.
        self.per_block(bound).context_for_block(block).map_err(UnicityNodeEvmError::Binding)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        // Only the bound-input lookup is needed here. The stock context borrows from `self.inner`,
        // and the build path (which uses a per-job config) is the only consumer of the full
        // next-block validation.
        self.bound_from_bytes(&attributes.extra_data)?;
        self.inner
            .context_for_next_block(parent, attributes)
            .map_err(|never: Infallible| match never {})
    }
}

impl ConfigureEngineEvm<ExecutionData> for UnicityNodeEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload).map_err(|never: Infallible| match never {})
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        // The engine builds the executor from this context, so validate here that the payload's
        // commitment resolves. The factory resolves the input itself when it creates the executor.
        self.bound_from_bytes(payload.payload.as_v1().extra_data.as_ref())?;
        self.inner.context_for_payload(payload).map_err(|never: Infallible| match never {})
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload).map_err(|never: Infallible| match never {})
    }
}
