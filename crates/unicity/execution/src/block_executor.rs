//! Shared Ethereum block executor with the bounded Unicity system prefix.

use crate::{
    block::{next_base_fee, BlockGasAccounting, BlockProfile, ParentExecutionOutcome},
    derive_beacon_root, derive_prev_randao, derive_timestamp, execute_registry_transition_on_db,
    ExecutionConfig, RootInputV2, SYSTEM_CALLER,
};
use alloy_consensus::{
    transaction::Recovered, Header, Transaction, TransactionEnvelope, TxReceipt,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockValidationError, ExecutableTx, GasOutput, StateDB, TxResult,
    },
    eth::{
        receipt_builder::ReceiptBuilder, spec::EthExecutorSpec, EthBlockExecutionCtx,
        EthBlockExecutor, EthBlockExecutorFactory, EthTxResult,
    },
    Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded, InvalidTxError, RecoveredTx,
};
use alloy_primitives::{keccak256, Address, Log};
use reth_chainspec::ChainSpec;
use reth_consensus::HeaderValidator;
use reth_consensus_common::validation::validate_block_pre_execution;
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_ethereum_primitives::{Block, EthPrimitives, Receipt, TransactionSigned};
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome, BlockExecutionOutput, Executor},
    ConfigureEvm, EvmEnv, NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_storage_api::StateProvider;
use revm::{database::State, DatabaseCommit, Inspector};
use std::{convert::Infallible, error::Error, fmt, sync::Arc};

/// Immutable data bound to one build or replay job.
#[derive(Clone, Debug)]
pub struct BoundExecutionInput {
    /// Authenticated structured input. Authentication remains the caller's prerequisite.
    input: Arc<RootInputV2>,
    /// Fixed gas and fee profile for this job.
    profile: BlockProfile,
    parent_hash: alloy_primitives::B256,
    parent_number: u64,
    parent_timestamp: u64,
    parent_execution: ParentExecutionOutcome,
    fee_collector: Address,
}

impl BoundExecutionInput {
    /// Binds the first post-genesis job to a genesis header already validated against the
    /// configured standard JSON. This is the sole numeric parent-accounting bootstrap.
    pub fn from_validated_genesis(
        input: Arc<RootInputV2>,
        profile: BlockProfile,
        parent: &SealedHeader<Header>,
        configured_genesis_hash: alloy_primitives::B256,
        fee_collector: Address,
    ) -> Result<Self, crate::block::BlockAccountingError> {
        let parent_hash = parent.hash();
        if parent_hash != parent.header().hash_slow() ||
            parent_hash != configured_genesis_hash ||
            parent.number != 0 ||
            parent.gas_used != 0 ||
            input.parent_hash != parent_hash
        {
            return Err(crate::block::BlockAccountingError::ParentGasMismatch);
        }
        let parent_execution = ParentExecutionOutcome::reconcile(
            profile,
            parent_hash,
            parent.gas_used,
            0,
            parent
                .base_fee_per_gas
                .ok_or(crate::block::BlockAccountingError::InvalidParentBaseFee)?,
        )?;
        Ok(Self {
            input,
            profile,
            parent_hash,
            parent_number: parent.number,
            parent_timestamp: parent.timestamp,
            parent_execution,
            fee_collector,
        })
    }

    /// Binds a job to a parent completed by [`build_complete`] or checked replay.
    pub fn from_completed_parent(
        input: Arc<RootInputV2>,
        profile: BlockProfile,
        parent: &SealedHeader<Header>,
        completed: CompletedParent,
        fee_collector: Address,
    ) -> Result<Self, crate::block::BlockAccountingError> {
        if parent.header().hash_slow() != parent.hash() ||
            input.parent_hash != parent.hash() ||
            completed.0.parent_hash() != parent.hash() ||
            completed.0.profile() != profile
        {
            return Err(crate::block::BlockAccountingError::ParentGasMismatch);
        }
        Ok(Self {
            input,
            profile,
            parent_hash: parent.hash(),
            parent_number: parent.number,
            parent_timestamp: parent.timestamp,
            parent_execution: completed.0,
            fee_collector,
        })
    }
}

/// Opaque accounting and identity proof minted only by a completed shared build or replay.
#[derive(Clone, Copy, Debug)]
pub struct CompletedParent(ParentExecutionOutcome);

/// Fully assembled block plus the opaque token required to configure its child.
#[derive(Debug)]
pub struct CompletedBuild {
    /// Stock Reth block-builder output with real state and receipt roots.
    pub outcome: BlockBuilderOutcome<EthPrimitives>,
    /// Opaque parent accounting for the next immutable block job.
    pub parent: CompletedParent,
}

/// Locally validated replay output plus the opaque token required by its child.
#[derive(Debug)]
pub struct CompletedReplay {
    /// Standard execution result and post-state bundle.
    pub output: BlockExecutionOutput<Receipt>,
    /// Opaque parent accounting for the next immutable block job.
    pub parent: CompletedParent,
}

/// Builds and fully assembles one block through the shared Unicity configuration.
///
/// `state` and `state_provider` must be consistent views of the immutable exact parent bound by
/// `config`. Every [`Recovered`] transaction must carry a sender independently verified by the
/// caller; this boundary does not perform sender recovery.
pub fn build_complete<DB, P>(
    config: &UnicityEvmConfig,
    parent: &SealedHeader<Header>,
    attributes: NextBlockEnvAttributes,
    state: &mut State<DB>,
    state_provider: P,
    transactions: Vec<Recovered<TransactionSigned>>,
) -> Result<CompletedBuild, BlockExecutionError>
where
    DB: Database,
    P: StateProvider,
{
    let mut builder = config
        .builder_for_next_block(state, parent, attributes)
        .map_err(BlockExecutionError::other)?;
    builder.apply_pre_execution_changes()?;
    for transaction in transactions {
        builder.execute_transaction(transaction)?;
    }
    let outcome = builder.finish(state_provider, None)?;
    validate_fixed_block(config, &outcome.block)?;
    let sealed = outcome.block.clone().into_sealed_block();
    let ordinary =
        outcome.execution_result.receipts.last().map(TxReceipt::cumulative_gas_used).unwrap_or(0);
    let system = outcome
        .execution_result
        .gas_used
        .checked_sub(ordinary)
        .ok_or_else(|| BlockExecutionError::msg("gross gas below ordinary receipt gas"))?;
    let accounting = ParentExecutionOutcome::reconcile(
        config.bound.profile,
        sealed.hash(),
        outcome.execution_result.gas_used,
        system,
        sealed.base_fee_per_gas.ok_or_else(|| BlockExecutionError::msg("base fee missing"))?,
    )
    .map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?;
    Ok(CompletedBuild { outcome, parent: CompletedParent(accounting) })
}

/// Replays one block, verifies the listed header/body fields, gas, receipts, bloom and real
/// post-state root, then mints the same opaque child token as [`build_complete`].
///
/// `db` and `state_provider` must be consistent views of the immutable exact parent bound by
/// `config`. The recovered senders attached to `block` must be independently verified by the
/// caller; this boundary does not perform sender recovery or certificate authentication.
pub fn replay_complete<DB, P>(
    config: &UnicityEvmConfig,
    db: DB,
    state_provider: &P,
    block: &RecoveredBlock<Block>,
) -> Result<CompletedReplay, BlockExecutionError>
where
    DB: Database,
    P: StateProvider,
{
    validate_fixed_block(config, block)?;
    let output = config.executor(db).execute(block)?;
    validate_block_post_execution(block, config.inner.chain_spec(), &output.result, None, None)
        .map_err(BlockExecutionError::other)?;
    let hashed =
        state_provider.hashed_post_state(&output.state).map_err(BlockExecutionError::other)?;
    let (state_root, _) =
        state_provider.state_root_with_updates(hashed).map_err(BlockExecutionError::other)?;
    if state_root != block.header().state_root {
        return Err(BlockExecutionError::msg("post-state root mismatch"));
    }
    let ordinary = output.result.receipts.last().map(TxReceipt::cumulative_gas_used).unwrap_or(0);
    let system = output
        .result
        .gas_used
        .checked_sub(ordinary)
        .ok_or_else(|| BlockExecutionError::msg("gross gas below ordinary receipt gas"))?;
    let accounting = ParentExecutionOutcome::reconcile(
        config.bound.profile,
        block.hash(),
        output.result.gas_used,
        system,
        block
            .header()
            .base_fee_per_gas
            .ok_or_else(|| BlockExecutionError::msg("base fee missing"))?,
    )
    .map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?;
    Ok(CompletedReplay { output, parent: CompletedParent(accounting) })
}

fn validate_fixed_block(
    config: &UnicityEvmConfig,
    block: &RecoveredBlock<Block>,
) -> Result<(), BlockExecutionError> {
    if block.header().hash_slow() != block.hash() {
        return Err(BlockExecutionError::msg("sealed block hash mismatch"));
    }
    let sealed_header = SealedHeader::new(block.header().clone(), block.hash());
    EthBeaconConsensus::new(config.inner.chain_spec().clone())
        .validate_header(&sealed_header)
        .map_err(BlockExecutionError::other)?;
    if block.header().blob_gas_used != Some(0) ||
        block.header().excess_blob_gas != Some(0) ||
        block.header().requests_hash.is_some() ||
        block.header().block_access_list_hash.is_some() ||
        block.header().slot_number.is_some()
    {
        return Err(BlockExecutionError::msg("header is outside the fixed Cancun profile"));
    }
    validate_block_pre_execution(block.sealed_block(), config.inner.chain_spec())
        .map_err(BlockExecutionError::other)
}

/// Structural binding failure for one immutable build or replay job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingError(&'static str);

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl Error for BindingError {}

#[derive(Debug)]
struct UnsupportedPoolTransaction(&'static str);

impl fmt::Display for UnsupportedPoolTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for UnsupportedPoolTransaction {}

impl InvalidTxError for UnsupportedPoolTransaction {
    fn as_invalid_tx_err(&self) -> Option<&revm::context_interface::result::InvalidTransaction> {
        None
    }
}

/// Concrete Ethereum EVM configuration bound to one authenticated companion.
#[derive(Clone, Debug)]
pub struct UnicityEvmConfig {
    inner: EthEvmConfig,
    executor_factory:
        UnicityBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, alloy_evm::EthEvmFactory>,
    bound: Arc<BoundExecutionInput>,
}

impl UnicityEvmConfig {
    /// Creates one immutable block-job configuration for both build and replay.
    pub fn new(inner: EthEvmConfig, bound: Arc<BoundExecutionInput>) -> Self {
        let executor_factory =
            UnicityBlockExecutorFactory::new(inner.executor_factory.clone(), bound.clone());
        Self { inner, executor_factory, bound }
    }

    /// Checks that payload-builder inputs select this configuration's exact immutable job.
    ///
    /// This is a structural check only. Authentication of the root input and consistency of the
    /// supplied parent state remain prerequisites of the caller that created this configuration.
    pub fn validate_payload_job(
        &self,
        parent: &SealedHeader<Header>,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<(), BindingError> {
        self.validate_parent(parent)?;
        self.validate_next_attributes(attributes)
    }

    /// Checks that a previously validated candidate belongs to this exact job.
    ///
    /// This checks structural job fields only; it does not validate the block body or execution.
    pub fn validate_payload_candidate(
        &self,
        block: &SealedBlock<Block>,
    ) -> Result<(), BindingError> {
        self.context_for_block(block).map(|_| ())
    }

    fn validate_parent(&self, parent: &SealedHeader<Header>) -> Result<(), BindingError> {
        if parent.header().hash_slow() != parent.hash() ||
            parent.hash() != self.bound.parent_hash ||
            self.bound.input.parent_hash != parent.hash()
        {
            return Err(BindingError("bound parent hash mismatch"));
        }
        if self.bound.parent_execution.parent_hash() != parent.hash() {
            return Err(BindingError("parent execution identity mismatch"));
        }
        Ok(())
    }
}

/// Factory that gives build and replay the same immutable Unicity input.
#[derive(Clone, Debug)]
pub struct UnicityBlockExecutorFactory<R, Spec, EvmF> {
    inner: EthBlockExecutorFactory<R, Spec, EvmF>,
    bound: Arc<BoundExecutionInput>,
}

impl<R, Spec, EvmF> UnicityBlockExecutorFactory<R, Spec, EvmF> {
    /// Wraps the stock Ethereum factory for one block job.
    pub const fn new(
        inner: EthBlockExecutorFactory<R, Spec, EvmF>,
        bound: Arc<BoundExecutionInput>,
    ) -> Self {
        Self { inner, bound }
    }
}

/// Executor that runs the registry pair before stock Cancun pre-execution calls.
pub struct UnicityBlockExecutor<'a, E, Spec, R: ReceiptBuilder> {
    inner: EthBlockExecutor<'a, E, Spec, R>,
    bound: Arc<BoundExecutionInput>,
    prefix: PrefixState,
}

#[derive(Clone, Copy, Debug)]
enum PrefixState {
    Pending,
    Ready(u64),
    Poisoned,
}

impl<E, Spec, R: ReceiptBuilder> fmt::Debug for UnicityBlockExecutor<'_, E, Spec, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnicityBlockExecutor")
            .field("bound", &self.bound)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for UnicityBlockExecutorFactory<R, Spec, EvmF>
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
        UnicityBlockExecutor {
            inner: self.inner.create_executor(evm, ctx),
            bound: self.bound.clone(),
            prefix: PrefixState::Pending,
        }
    }
}

impl<E, Spec, R> BlockExecutor for UnicityBlockExecutor<'_, E, Spec, R>
where
    E: Evm<
        DB: StateDB + DatabaseCommit,
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    >,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    <R::Transaction as TransactionEnvelope>::TxType: Send + 'static,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;
    type Result = EthTxResult<E::HaltReason, <R::Transaction as TransactionEnvelope>::TxType>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        if self.inner.ctx.withdrawals.as_deref().is_some_and(|w| !w.is_empty()) {
            return Err(BlockExecutionError::msg("withdrawals are unsupported"));
        }
        if !matches!(self.prefix, PrefixState::Pending) {
            self.prefix = PrefixState::Poisoned;
            return Err(BlockExecutionError::msg("pre-execution changes already applied"));
        }
        self.prefix = PrefixState::Poisoned;
        self.bound.profile.validate().map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?;
        let result = execute_registry_transition_on_db(
            &self.bound.input,
            self.inner.evm.db_mut(),
            ExecutionConfig { system_gas_limit: self.bound.profile.system_gas },
        )
        .map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?;

        // Approved ordering: the stock Cancun EIP-4788 call follows finalize. Its gas is excluded
        // from both system and ordinary accounting. EIP-2935 is inactive in the bounded profile.
        self.inner.apply_pre_execution_changes()?;
        self.prefix = PrefixState::Ready(result.total_gas_spent);
        Ok(())
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (env, recovered) = tx.into_parts();
        if !matches!(self.prefix, PrefixState::Ready(_)) {
            return Err(BlockExecutionError::msg("ordinary transaction before system prefix"));
        }
        if *recovered.signer() == SYSTEM_CALLER {
            return Err(BlockValidationError::InvalidTx {
                hash: keccak256(recovered.tx().encoded_2718()),
                error: Box::new(UnsupportedPoolTransaction("reserved sender")),
            }
            .into());
        }
        if recovered.tx().blob_gas_used().unwrap_or_default() != 0 {
            return Err(BlockValidationError::InvalidTx {
                hash: keccak256(recovered.tx().encoded_2718()),
                error: Box::new(UnsupportedPoolTransaction("blob transactions are unsupported")),
            }
            .into());
        }
        let available = self
            .bound
            .profile
            .ordinary_capacity()
            .map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?
            .checked_sub(self.inner.cumulative_tx_gas_used)
            .ok_or_else(|| BlockExecutionError::msg("ordinary gas capacity exceeded"))?;
        if recovered.tx().gas_limit() > available {
            return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                transaction_gas_limit: recovered.tx().gas_limit(),
                block_available_gas: available,
            }
            .into());
        }
        let result = self.inner.execute_transaction_without_commit((env, recovered))?;
        if result.result().result.gas().tx_gas_used() > available {
            return Err(BlockExecutionError::msg("ordinary gas capacity exceeded"));
        }
        Ok(result)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        let PrefixState::Ready(system) = self.prefix else {
            return Err(BlockExecutionError::msg("pre-execution changes not applied"));
        };
        let profile = self.bound.profile;
        let (evm, mut result) = self.inner.finish()?;
        if result.blob_gas_used != 0 {
            return Err(BlockExecutionError::msg("blob gas is unsupported"));
        }
        result.gas_used = BlockGasAccounting::derive(profile, system, result.gas_used)
            .map_err(|e| BlockExecutionError::msg(format!("{e:?}")))?
            .header;
        Ok((evm, result))
    }

    fn receipts(&self) -> &[Self::Receipt] {
        &self.inner.receipts
    }
    fn evm(&self) -> &Self::Evm {
        &self.inner.evm
    }
    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.inner.evm
    }
}

impl ConfigureEvm for UnicityEvmConfig {
    type Primitives = EthPrimitives;
    type Error = BindingError;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        UnicityBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, alloy_evm::EthEvmFactory>;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }
    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.inner.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv, Self::Error> {
        let env = self.inner.evm_env(header).map_err(|never: Infallible| match never {})?;
        if env.cfg_env.spec != revm::primitives::hardfork::SpecId::CANCUN {
            return Err(BindingError("only the fixed Cancun profile is supported"));
        }
        Ok(env)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        let parent = SealedHeader::new(parent.clone(), parent.hash_slow());
        self.validate_parent(&parent)?;
        self.validate_next_attributes(attributes)?;
        let mut env = self
            .inner
            .next_evm_env(parent.header(), attributes)
            .map_err(|never: Infallible| match never {})?;
        if env.cfg_env.spec != revm::primitives::hardfork::SpecId::CANCUN {
            return Err(BindingError("only the fixed Cancun profile is supported"));
        }
        env.block_env.basefee = next_base_fee(self.bound.parent_execution)
            .map_err(|_| BindingError("next base fee derivation failed"))?;
        env.block_env.gas_limit = self.bound.profile.max_gas;
        Ok(env)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        let header = block.header();
        let expected_commitment = self
            .bound
            .input
            .input_commitment()
            .map_err(|_| BindingError("invalid bound root input"))?;
        let expected_timestamp =
            derive_timestamp(self.bound.input.origin.reference_time, self.bound.parent_timestamp)
                .ok_or(BindingError("timestamp overflow"))?;
        if self.bound.input.parent_hash != self.bound.parent_hash ||
            header.parent_hash != self.bound.parent_hash ||
            header.number !=
                self.bound
                    .parent_number
                    .checked_add(1)
                    .ok_or(BindingError("parent block number overflow"))? ||
            header.extra_data.as_ref() != expected_commitment.as_slice() ||
            header.timestamp != expected_timestamp ||
            header.mix_hash !=
                derive_prev_randao(
                    self.bound.input.origin.root_round,
                    self.bound.input.authorized_round,
                ) ||
            header.parent_beacon_block_root !=
                Some(derive_beacon_root(
                    self.bound.input.origin.root_round,
                    self.bound.input.authorized_round,
                )) ||
            header.base_fee_per_gas !=
                Some(
                    next_base_fee(self.bound.parent_execution)
                        .map_err(|_| BindingError("next base fee derivation failed"))?,
                ) ||
            header.gas_limit != self.bound.profile.max_gas ||
            header.beneficiary != self.bound.fee_collector
        {
            return Err(BindingError("block header diverges from bound execution input"));
        }
        self.inner.context_for_block(block).map_err(|never: Infallible| match never {})
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        self.validate_parent(parent)?;
        self.validate_next_attributes(&attributes)?;
        self.inner
            .context_for_next_block(parent, attributes)
            .map_err(|never: Infallible| match never {})
    }
}

impl UnicityEvmConfig {
    fn validate_next_attributes(
        &self,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<(), BindingError> {
        let timestamp =
            derive_timestamp(self.bound.input.origin.reference_time, self.bound.parent_timestamp)
                .ok_or(BindingError("timestamp overflow"))?;
        if attributes.timestamp != timestamp ||
            attributes.prev_randao !=
                derive_prev_randao(
                    self.bound.input.origin.root_round,
                    self.bound.input.authorized_round,
                ) ||
            attributes.parent_beacon_block_root !=
                Some(derive_beacon_root(
                    self.bound.input.origin.root_round,
                    self.bound.input.authorized_round,
                )) ||
            attributes.gas_limit != self.bound.profile.max_gas ||
            attributes.suggested_fee_recipient != self.bound.fee_collector ||
            attributes.withdrawals.as_ref().is_some_and(|w| !w.is_empty()) ||
            attributes.slot_number.is_some() ||
            attributes.extra_data.as_ref() !=
                self.bound
                    .input
                    .input_commitment()
                    .map_err(|_| BindingError("invalid bound root input"))?
                    .as_slice()
        {
            return Err(BindingError("next-block attributes diverge from bound execution input"));
        }
        Ok(())
    }
}
