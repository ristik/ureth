//! The `engine_forkchoiceUpdatedWithSealV1` sibling method.
//!
//! This is a jsonrpsee trait in the `engine` namespace, separate from reth's own
//! [`reth_rpc_api::EngineApi`], so the fork adds one method without editing an upstream file. It is
//! shaped after `EngineApiInner` in `reth_rpc_engine_api`: the same provider, consensus handle and
//! shared node state.
//!
//! The method is reachable but never advertised. `engine_exchangeCapabilities` is the stock list,
//! because U3f advertises all three seal methods together or none.
//!
//! # Order
//!
//! The handler runs the D2 build flow in this order:
//!
//! 1. decode `sealBuildInput.rootInput` through the single canonical [`RootInputV2`] codec;
//! 2. resolve `forkchoiceState.headBlockHash` from the provider, where absence is SYNCING;
//! 3. bind the decoded input to that parent through the U3a entry points;
//! 4. build the [`UnicityEvmConfig`] and [`ResolvedPayloadJob`] with the node's published
//!    [`EthereumBuilderConfig`];
//! 5. insert the job before forwarding, because the payload service can start as soon as the update
//!    is accepted;
//! 6. forward to the consensus handle and return its [`ForkchoiceUpdated`].
//!
//! # The system operation is not run here
//!
//! "Runs the system operation as step 0" in D2 describes where the privileged `open` and `finalize`
//! pair sits in the built block, which the bounded kernel already implements. This method does not
//! trial-execute it. A system-operation failure therefore surfaces as a failed payload build, not
//! as an INVALID from this call.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use alloy_consensus::Header;
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadStatusEnum};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, RpcModule};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_engine_primitives::{ConsensusEngineHandle, EngineApiValidator};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm_ethereum::EthEvmConfig;
use reth_node_builder::{
    rpc::{BasicEngineApiBuilder, EngineApiBuilder},
    AddOnsContext, FullNodeComponents,
};
use reth_payload_primitives::EngineApiMessageVersion;
use reth_rpc_api::IntoEngineApiRpcModule;
use reth_rpc_engine_api::EngineApiError;
use reth_storage_api::HeaderProvider;
use reth_unicity_execution::{
    block::BlockAccountingError,
    block_executor::UnicityEvmConfig,
    wire::{bind_completed_parent, bind_validated_genesis, CanonicalCborError, SealBuildInput},
};

use crate::{
    node::{UnicityEngineValidator, UnicityEngineValidatorBuilder, UnicityNode, UnicitySealConfig},
    registry::{SealJobRegistry, UnicityParentAccountings},
    PayloadJobResolutionError, ResolvedPayloadJob, UnicityEngineTypes, UnicityPayloadAttributes,
};

/// The `engine` namespace sibling that carries the seal build input.
#[rpc(server, namespace = "engine")]
pub trait UnicityEngineApi {
    /// `engine_forkchoiceUpdatedWithSealV1`.
    ///
    /// `payloadAttributes` is required: a seal build input without attributes describes nothing,
    /// and D2 lists the V3 attributes unconditionally.
    #[method(name = "forkchoiceUpdatedWithSealV1")]
    async fn fork_choice_updated_with_seal_v1(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<UnicityPayloadAttributes>,
        seal_build_input: SealBuildInput,
    ) -> RpcResult<ForkchoiceUpdated>;
}

/// A refusal from the seal build flow.
///
/// Variants that describe caller input map to an INVALID [`PayloadStatusEnum`] with this error's
/// display text in `validationError`. [`Self::UnknownParent`] maps to SYNCING. The two
/// `Unavailable` variants are internal node state, not caller input, and map to an RPC error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealBuildError {
    /// The required `payloadAttributes` parameter was absent.
    AttributesMissing,
    /// The validator refused the payload attributes.
    Attributes(String),
    /// `sealBuildInput.rootInput` is not a canonical root input.
    RootInput(CanonicalCborError),
    /// The provider failed to read the parent header.
    Provider(String),
    /// The forkchoice head is not known locally.
    UnknownParent,
    /// A non-genesis parent has no published accounting token yet.
    ParentAccountingUnavailable,
    /// The decoded input does not bind to the resolved parent.
    Binding(BlockAccountingError),
    /// The node has not published its payload builder configuration yet.
    BuilderConfigUnavailable,
    /// The job was rejected by its own immutable binding checks.
    Job(PayloadJobResolutionError),
    /// A job with this payload id is already installed.
    DuplicatePayloadId,
}

impl fmt::Display for SealBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttributesMissing => formatter.write_str("payload attributes are required"),
            Self::Attributes(message) => formatter.write_str(message),
            Self::RootInput(error) => {
                write!(formatter, "rootInput is not a canonical root input: {error}")
            }
            Self::Provider(error) => write!(formatter, "parent header lookup failed: {error}"),
            Self::UnknownParent => formatter.write_str("parent is unknown"),
            Self::ParentAccountingUnavailable => {
                formatter.write_str("parent accounting token is not available")
            }
            Self::Binding(error) => write!(formatter, "parent binding failed: {error:?}"),
            Self::BuilderConfigUnavailable => {
                formatter.write_str("payload builder configuration is not published")
            }
            Self::Job(error) => write!(formatter, "payload job rejected: {error}"),
            Self::DuplicatePayloadId => formatter.write_str("duplicate payload id"),
        }
    }
}

impl std::error::Error for SealBuildError {}

/// Resolves and installs the seal job for one build request.
///
/// This is the ordered flow the RPC handler runs, factored out so it can be exercised without a
/// running engine. The caller forwards the returned attributes to the consensus handle after this
/// succeeds.
///
/// `context.builder_config` must be the node's published [`EthereumBuilderConfig`], not a freshly
/// derived copy. The job carries it, and the payload service re-derives the next-block attributes
/// from the configuration it was handed, so a second derivation would drift and fail resolution at
/// runtime.
pub fn prepare_seal_build<P>(
    provider: &P,
    context: &SealBuildContext,
    validator: &UnicityEngineValidator,
    state: &ForkchoiceState,
    attributes: Option<&UnicityPayloadAttributes>,
    seal_build_input: &SealBuildInput,
) -> Result<UnicityPayloadAttributes, SealBuildError>
where
    P: HeaderProvider<Header = Header> + ChainSpecProvider<ChainSpec = ChainSpec>,
{
    let attributes = attributes.cloned().ok_or(SealBuildError::AttributesMissing)?;
    // Match the stock `fork_choice_updated_v3` path: reject malformed attributes before any state
    // change, so a refusal cannot leave a registry entry behind for input that should never have
    // been accepted. The refusal stays INVALID with the validator's message.
    validator
        .ensure_well_formed_attributes(EngineApiMessageVersion::V3, &attributes)
        .map_err(|error| SealBuildError::Attributes(error.to_string()))?;
    let root = seal_build_input.decode_root_input().map_err(SealBuildError::RootInput)?;
    let parent = provider
        .sealed_header_by_hash(state.head_block_hash)
        .map_err(|error| SealBuildError::Provider(error.to_string()))?
        .ok_or(SealBuildError::UnknownParent)?;

    let chain_spec = provider.chain_spec();
    let genesis_hash = chain_spec.genesis_hash();
    let bound = if parent.number == 0 && parent.hash() == genesis_hash {
        bind_validated_genesis(
            root,
            context.seal.profile,
            &parent,
            genesis_hash,
            context.seal.fee_collector,
        )
        .map_err(SealBuildError::Binding)?
    } else {
        let token = context
            .parent_accounting
            .get(&parent.hash())
            .ok_or(SealBuildError::ParentAccountingUnavailable)?;
        bind_completed_parent(
            root,
            context.seal.profile,
            &parent,
            token,
            context.seal.fee_collector,
        )
        .map_err(SealBuildError::Binding)?
    };

    let builder_config =
        context.builder_config.get().ok_or(SealBuildError::BuilderConfigUnavailable)?;
    let evm_config = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec), Arc::new(bound));
    let job =
        ResolvedPayloadJob::new(Arc::new(parent), attributes.clone(), evm_config, builder_config)
            .map_err(SealBuildError::Job)?;
    context.registry.insert(job).map_err(|_| SealBuildError::DuplicatePayloadId)?;
    Ok(attributes)
}

/// Node-owned state the seal build flow resolves against.
///
/// The payload service and the handler share every field, so the job the handler installs is
/// resolved by the builder with the same configuration, registry and parent accounting.
#[derive(Clone, Debug)]
pub struct SealBuildContext {
    /// Registry the resolved job is installed into.
    pub registry: SealJobRegistry,
    /// Exact payload builder configuration the node resolved, once the payload service is built.
    pub builder_config: Arc<OnceLock<EthereumBuilderConfig>>,
    /// Pinned execution profile and fee collector.
    pub seal: UnicitySealConfig,
    /// Completed parent-accounting tokens published by the build path.
    pub parent_accounting: UnicityParentAccountings,
}

/// Maps a preparation refusal to the handler's response.
///
/// An unknown parent is a sync condition, not a bad input, so it returns SYNCING. A parent whose
/// accounting token is missing is internal node state, not caller input, so it returns an RPC
/// error. Every other refusal describes the caller's input and returns INVALID with the refusal's
/// display text in `validationError`.
pub fn refusal_response(error: SealBuildError) -> Result<ForkchoiceUpdated, EngineApiError> {
    match error {
        SealBuildError::UnknownParent => {
            Ok(ForkchoiceUpdated::from_status(PayloadStatusEnum::Syncing))
        }
        error @ SealBuildError::ParentAccountingUnavailable => {
            Err(EngineApiError::Internal(Box::new(error)))
        }
        error => Ok(ForkchoiceUpdated::from_status(PayloadStatusEnum::Invalid {
            validation_error: error.to_string(),
        })),
    }
}

/// Runtime state of the seal build handler.
pub struct UnicityEngineApiImpl<Provider> {
    provider: Provider,
    beacon_consensus: ConsensusEngineHandle<UnicityEngineTypes>,
    context: SealBuildContext,
    validator: UnicityEngineValidator,
}

impl<Provider> UnicityEngineApiImpl<Provider> {
    /// Creates the handler over the node's provider, consensus handle, shared build state and
    /// attribute validator.
    pub const fn new(
        provider: Provider,
        beacon_consensus: ConsensusEngineHandle<UnicityEngineTypes>,
        context: SealBuildContext,
        validator: UnicityEngineValidator,
    ) -> Self {
        Self { provider, beacon_consensus, context, validator }
    }
}

impl<Provider> fmt::Debug for UnicityEngineApiImpl<Provider> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The provider is deliberately not printed: it is a database handle, not state.
        formatter
            .debug_struct("UnicityEngineApiImpl")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<Provider> UnicityEngineApiServer for UnicityEngineApiImpl<Provider>
where
    Provider: HeaderProvider<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + Send
        + Sync
        + 'static,
{
    async fn fork_choice_updated_with_seal_v1(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<UnicityPayloadAttributes>,
        seal_build_input: SealBuildInput,
    ) -> RpcResult<ForkchoiceUpdated> {
        let attributes = match prepare_seal_build(
            &self.provider,
            &self.context,
            &self.validator,
            &fork_choice_state,
            payload_attributes.as_ref(),
            &seal_build_input,
        ) {
            Ok(attributes) => attributes,
            Err(error) => return refusal_response(error).map_err(Into::into),
        };

        // The job is already installed, so a payload service that starts on acceptance resolves it.
        let updated = self
            .beacon_consensus
            .fork_choice_updated(fork_choice_state, Some(attributes))
            .await
            .map_err(EngineApiError::ForkChoiceUpdate)?;
        Ok(updated)
    }
}

/// The authenticated engine module: the stock Engine API plus the seal sibling.
pub struct UnicityEngineApiModule<Inner, Sibling> {
    inner: Inner,
    sibling: Sibling,
}

impl<Inner, Sibling> UnicityEngineApiModule<Inner, Sibling> {
    /// Wraps the stock Engine API module and the seal sibling.
    pub const fn new(inner: Inner, sibling: Sibling) -> Self {
        Self { inner, sibling }
    }
}

impl<Inner, Sibling> fmt::Debug for UnicityEngineApiModule<Inner, Sibling> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("UnicityEngineApiModule").finish_non_exhaustive()
    }
}

impl<Inner, Sibling> IntoEngineApiRpcModule for UnicityEngineApiModule<Inner, Sibling>
where
    Inner: IntoEngineApiRpcModule,
    Sibling: UnicityEngineApiServer + Send + Sync + 'static,
{
    fn into_rpc_module(self) -> RpcModule<()> {
        let mut module = self.inner.into_rpc_module();
        module
            .merge(UnicityEngineApiServer::into_rpc(self.sibling).remove_context())
            .expect("forkchoiceUpdatedWithSealV1 is additive and cannot conflict");
        module
    }
}

/// Builds the stock Engine API plus the seal sibling, sharing the node's build state.
#[derive(Clone, Debug)]
pub struct UnicityEngineApiBuilder {
    context: SealBuildContext,
}

impl UnicityEngineApiBuilder {
    /// Creates the builder from the state [`UnicityNode`] shares with the payload service.
    pub const fn new(context: SealBuildContext) -> Self {
        Self { context }
    }
}

impl<N> EngineApiBuilder<N> for UnicityEngineApiBuilder
where
    N: FullNodeComponents<Types = UnicityNode>,
    N::Provider: HeaderProvider<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type EngineApi = UnicityEngineApiModule<
        <BasicEngineApiBuilder<UnicityEngineValidatorBuilder> as EngineApiBuilder<N>>::EngineApi,
        UnicityEngineApiImpl<N::Provider>,
    >;

    async fn build_engine_api(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::EngineApi> {
        let validator = UnicityEngineValidator::new(ctx.config.chain.clone());
        let inner = BasicEngineApiBuilder::<UnicityEngineValidatorBuilder>::default()
            .build_engine_api(ctx)
            .await?;
        let sibling = UnicityEngineApiImpl::new(
            ctx.node.provider().clone(),
            ctx.beacon_engine_handle.clone(),
            self.context,
            validator,
        );
        Ok(UnicityEngineApiModule::new(inner, sibling))
    }
}
