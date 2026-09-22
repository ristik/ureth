//! Unicity node wiring.
//!
//! [`UnicityNode`] implements [`NodeTypes`] with [`UnicityEngineTypes`] and replaces the stock
//! payload builder with [`UnicityExecutionPayloadBuilder`] resolving through a shared
//! [`SealJobRegistry`]. The node's add-ons register the `engine_forkchoiceUpdatedWithSealV1`
//! sibling through [`UnicityEngineApiBuilder`], so a future method can insert a
//! [`ResolvedPayloadJob`](crate::ResolvedPayloadJob) into the registry and then start an ordinary
//! build, which resolves that exact job.
//!
//! The sibling is reachable and advertised: a Unicity node's `engine_exchangeCapabilities` is the
//! stock list plus all three seal methods together. The stock `engine_*` surface is otherwise
//! assembled from upstream components exactly as the plain Ethereum node assembles it.
//!
//! The add-ons also mount the `unicity_getSealCompanionV1` and `unicity_sealCompanionHorizonV1`
//! read methods on the standard transports, over the same companion store the seal paths write.

use std::sync::{Arc, OnceLock};

use alloy_primitives::Address;
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::ChainSpec;
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::{EthereumBuilderConfig, EthereumExecutionPayloadValidator};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_evm_ethereum::EthEvmConfig;
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder, PayloadBuilderBuilder,
    },
    rpc::{BasicEngineValidatorBuilder, Identity, PayloadValidatorBuilder, RpcAddOns, RpcContext},
    AddOnsContext, BuilderContext, FullNodeComponents, FullNodeTypes, Node, NodeAdapter, NodeTypes,
    PayloadBuilderConfig,
};
use reth_node_ethereum::{
    EthereumConsensusBuilder, EthereumEthApiBuilder, EthereumNetworkBuilder, EthereumPoolBuilder,
};
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_primitives_traits::SealedBlock;
use reth_provider::{CanonStateSubscriptions, EthStorage};
use reth_rpc_eth_api::helpers::config::{EthConfigApiServer, EthConfigHandler};
use reth_rpc_server_types::RethRpcModule;
use reth_storage_api::BlockIdReader;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_unicity_execution::{
    block::BlockProfile,
    node_evm::{UnicityBlockExecutionRegistry, UnicityNodeEvmConfig},
};
use reth_unicity_store::CompanionStore;

use crate::{
    prune::run_companion_pruner,
    registry::UnicityParentAccountings,
    rpc::{companion_store, unicity_rpc_module, SealBuildState, UnicityEngineApiBuilder},
    SealJobRegistry, UnicityEngineTypes, UnicityExecutionPayloadBuilder, UnicityPayloadAttributes,
    DEFAULT_SEAL_JOB_CAPACITY,
};

/// Pinned profile and fee collector the seal build path uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicitySealConfig {
    /// Gas and fee profile the build path pins.
    pub profile: BlockProfile,
    /// Beneficiary the payload attributes must name.
    pub fee_collector: Address,
}

/// Retention policy for the node's companion store.
///
/// The default is D2's full-node behaviour: retain every companion indefinitely and publish no
/// retention horizon. A pruned node opts in by naming a retention **depth**: the number of blocks
/// to keep behind the tip. It is not an absolute block number, because a running node moves and an
/// operator should not have to reconfigure the value every block. The published horizon stays
/// absolute and is computed as `tip - depth` by the pruning path.
///
/// The horizon read surface reports only what the node has actually dropped, so a node configured
/// with a depth that has not yet pruned still answers `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnicityRetentionConfig {
    depth: Option<u64>,
}

impl UnicityRetentionConfig {
    /// Retains every companion indefinitely and publishes no horizon. This is the default.
    pub const fn retain_indefinitely() -> Self {
        Self { depth: None }
    }

    /// Retains the last `depth` blocks behind the tip and prunes below the published horizon.
    pub const fn retain_last(depth: u64) -> Self {
        Self { depth: Some(depth) }
    }

    /// The configured retention depth, or `None` when the node retains indefinitely.
    pub const fn depth(&self) -> Option<u64> {
        self.depth
    }
}

/// A Unicity execution node.
///
/// This is the plain Ethereum node with two changes: [`NodeTypes::Payload`] is
/// [`UnicityEngineTypes`], and the payload component builds through
/// [`UnicityExecutionPayloadBuilder`] with the registry this node holds. Everything else, including
/// the network, pool, executor, consensus and the standard Engine API, is the stock Ethereum
/// component plus the seal sibling method.
///
/// A caller that needs to insert seal jobs shares the registry with the node by constructing it
/// with [`UnicityNode::new`]; all clones observe the same entries. The node also publishes the
/// exact [`EthereumBuilderConfig`] it hands to the payload builder, because a seal job is
/// constructed outside the node and must reproduce that configuration for resolution to succeed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnicityNode {
    registry: SealJobRegistry,
    builder_config: Arc<OnceLock<EthereumBuilderConfig>>,
    seal: UnicitySealConfig,
    parent_accounting: UnicityParentAccountings,
    execution_inputs: UnicityBlockExecutionRegistry,
    retention: UnicityRetentionConfig,
    companion_store: Arc<OnceLock<Arc<CompanionStore>>>,
}

impl UnicityNode {
    /// Creates a node whose payload builder resolves through `registry`.
    pub fn new(registry: SealJobRegistry, seal: UnicitySealConfig) -> Self {
        Self {
            registry,
            builder_config: Arc::new(OnceLock::new()),
            seal,
            parent_accounting: UnicityParentAccountings::default(),
            execution_inputs: UnicityBlockExecutionRegistry::default(),
            retention: UnicityRetentionConfig::default(),
            companion_store: Arc::new(OnceLock::new()),
        }
    }

    /// Sets the companion retention policy.
    ///
    /// The default retains every companion indefinitely and publishes no horizon. A pruned node
    /// opts in with [`UnicityRetentionConfig::retain_last`].
    pub const fn with_retention(mut self, retention: UnicityRetentionConfig) -> Self {
        self.retention = retention;
        self
    }

    /// Returns the companion retention policy.
    pub const fn retention(&self) -> UnicityRetentionConfig {
        self.retention
    }

    /// Returns the shared companion store cell.
    ///
    /// The engine API add-on and the standard RPC read surface resolve this one cell, so the store
    /// is opened once and both see the same entries and horizon.
    pub const fn companion_store(&self) -> &Arc<OnceLock<Arc<CompanionStore>>> {
        &self.companion_store
    }

    /// Returns the seal job registry shared with the payload builder.
    pub const fn registry(&self) -> &SealJobRegistry {
        &self.registry
    }

    /// Returns the pinned execution profile and fee collector.
    pub const fn seal(&self) -> UnicitySealConfig {
        self.seal
    }

    /// Returns the parent-accounting store shared with the payload builder and the seal method.
    pub const fn parent_accounting(&self) -> &UnicityParentAccountings {
        &self.parent_accounting
    }

    /// Returns the execution-input registry shared with the node EVM config.
    pub const fn execution_inputs(&self) -> &UnicityBlockExecutionRegistry {
        &self.execution_inputs
    }

    /// Returns the exact payload builder configuration the node resolved, once the payload builder
    /// has been constructed.
    ///
    /// A seal method constructs [`ResolvedPayloadJob`](crate::ResolvedPayloadJob) outside the node
    /// and must pass this value as its builder configuration. The builder re-derives the next-block
    /// attributes from the configuration it was handed and refuses a job that does not match, so a
    /// caller that derived its own copy would drift and fail resolution at runtime. This returns
    /// `None` before the payload service has been built.
    pub fn builder_config(&self) -> Option<&EthereumBuilderConfig> {
        self.builder_config.get()
    }
}

impl NodeTypes for UnicityNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = UnicityEngineTypes;
}

impl<N> Node<N> for UnicityNode
where
    N: FullNodeTypes<Types = Self>,
    N::Provider: BlockIdReader + CanonStateSubscriptions,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<UnicityPayloadBuilderBuilder>,
        EthereumNetworkBuilder,
        UnicityExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = UnicityNodeAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(UnicityExecutorBuilder::new(self.execution_inputs.clone()))
            .payload(BasicPayloadServiceBuilder::new(UnicityPayloadBuilderBuilder::new(
                self.registry.clone(),
                self.builder_config.clone(),
                self.parent_accounting.clone(),
            )))
            .network(EthereumNetworkBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        // The engine API add-on, the RPC read surface and the pruning task share this one store
        // cell. `build_engine_api` runs first inside `RpcAddOns`, but the hook resolves the same
        // cell rather than a second environment, so the order is not load-bearing.
        let store = self.companion_store.clone();
        let depth = self.retention.depth();
        RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            UnicityEngineValidatorBuilder,
            UnicityEngineApiBuilder::new(
                SealBuildState {
                    registry: self.registry.clone(),
                    builder_config: self.builder_config.clone(),
                    seal: self.seal,
                    parent_accounting: self.parent_accounting.clone(),
                    execution_inputs: self.execution_inputs.clone(),
                    retention: self.retention,
                },
                self.companion_store.clone(),
            ),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Identity::new(),
        )
        .extend_rpc_modules(
            move |ctx: RpcContext<'_, NodeAdapter<N>, _>| -> eyre::Result<()> {
                // The context's eth-api type is concrete here, so `config` and `provider` are
                // reachable without naming the eth-api trait. The store cell is the same one the
                // engine API add-on resolved.
                let provider = ctx.provider().clone();
                let store = companion_store(&store, ctx.config().datadir().data_dir())?;
                ctx.modules
                    .merge_configured(unicity_rpc_module(provider.clone(), store.clone()))?;

                // eth_config (EIP-7910), which the stock node registers in EthereumNode's
                // launch_add_ons (crates/ethereum/node/src/node.rs) and this node otherwise loses
                // by assembling its own add-ons. It is not optional here: a
                // consensus client reads it to refuse an execution client whose
                // loaded chain spec is not the one it expects, so a Unicity node
                // without it is a node nothing will pair with. Same handler, same
                // module guard, and the value is derived from this node's own provider and EVM
                // config rather than restated, because the point of the check is to report the real
                // loaded fork schedule.
                ctx.modules.merge_if_module_configured(
                    RethRpcModule::Eth,
                    EthConfigHandler::new(provider.clone(), ctx.node().evm_config().clone())
                        .into_rpc(),
                )?;
                // The same stock function also registers the Flashbots `ValidationApi` and the
                // hidden `TestingApi`, and this node deliberately keeps neither. Both are
                // block-production surfaces built on stock Ethereum rules: the first validates a
                // builder submission with an `EthereumEngineValidator`, the second builds a block
                // straight through the engine handle. On this node a block is valid only when it
                // carries the root input it is bound to, so either handler would answer
                // confidently under rules this node does not execute — worse than not answering.
                // Their absence costs nothing by default, since both sit behind opt-in modules.
                // Retention is driven by the canonical-state stream on the node's own executor.
                // The stream fires on every canonical change, including reorgs, so the block
                // cadence is the rate limit and no timer is needed. A failed pass is logged inside
                // the task and never takes the node down.
                ctx.node().task_executor().spawn_task(run_companion_pruner(provider, store, depth));
                Ok(())
            },
        )
    }
}

/// Builds [`UnicityNodeEvmConfig`], so the engine tree executes seal blocks with their bound input.
///
/// This replaces the stock Ethereum executor component. Without it the engine tree would execute an
/// imported seal block with the stock EVM, whose pre-execution rules reject the privileged system
/// prefix, so a valid seal block would be rejected after the import path already accepted it.
#[derive(Clone, Debug)]
pub struct UnicityExecutorBuilder {
    execution_inputs: UnicityBlockExecutionRegistry,
}

impl UnicityExecutorBuilder {
    /// Creates the builder from the registry shared with the import path.
    pub const fn new(execution_inputs: UnicityBlockExecutionRegistry) -> Self {
        Self { execution_inputs }
    }
}

impl<Types, Node> ExecutorBuilder<Node> for UnicityExecutorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = UnicityNodeEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(UnicityNodeEvmConfig::new(EthEvmConfig::new(ctx.chain_spec()), self.execution_inputs))
    }
}

/// Builds [`UnicityExecutionPayloadBuilder`] for the payload service.
///
/// The builder owns a clone of the node's [`SealJobRegistry`] and a clone of the node's shared
/// builder-configuration slot. On construction it derives the configuration once, publishes it in
/// that slot, and hands the same value to the payload builder, so a seal method and the payload
/// service can never resolve against different configurations.
#[derive(Clone, Debug)]
pub struct UnicityPayloadBuilderBuilder {
    registry: SealJobRegistry,
    builder_config: Arc<OnceLock<EthereumBuilderConfig>>,
    parent_accounting: UnicityParentAccountings,
}

impl UnicityPayloadBuilderBuilder {
    /// Creates a payload builder builder that resolves through `registry` and publishes the
    /// resolved configuration into `builder_config`.
    pub const fn new(
        registry: SealJobRegistry,
        builder_config: Arc<OnceLock<EthereumBuilderConfig>>,
        parent_accounting: UnicityParentAccountings,
    ) -> Self {
        Self { registry, builder_config, parent_accounting }
    }

    /// Returns the registry shared with the resulting payload builder.
    pub const fn registry(&self) -> &SealJobRegistry {
        &self.registry
    }
}

impl<Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for UnicityPayloadBuilderBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            Payload = UnicityEngineTypes,
            ChainSpec = ChainSpec,
            Primitives = EthPrimitives,
        >,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
{
    type PayloadBuilder = UnicityExecutionPayloadBuilder<Pool, Node::Provider, SealJobRegistry>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        _evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);
        let skip_state_root = ctx.config().tree_config().skip_state_root();

        // The commitment in each job overrides `extra_data` inside the builder, so this base value
        // is only the node's configured default for paths that never enter a Unicity job. The
        // remaining fields are the stock Ethereum payload builder configuration.
        let base_config = EthereumBuilderConfig::new()
            .with_gas_limit(gas_limit)
            .with_max_blobs_per_block(conf.max_blobs_per_block())
            .with_extra_data(conf.extra_data())
            .with_skip_state_root(skip_state_root);

        // Publish the exact value handed to the builder. A seal job is constructed outside the
        // node, so it must read this slot rather than derive its own copy. `get_or_init` keeps the
        // first value, so even a second construction of the payload service hands out the same
        // configuration that was published.
        let base_config = self.builder_config.get_or_init(|| base_config).clone();

        // Track `max_payload_tasks` so the registry stays above the number of builds that can be in
        // flight. `grow_capacity` only raises the floor, so an already-held job is never evicted.
        self.registry.grow_capacity(registry_capacity(conf.max_payload_tasks()));

        Ok(UnicityExecutionPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            self.registry,
            base_config,
        )
        .with_parent_accounting(self.parent_accounting))
    }
}

/// Capacity a Unicity node gives its [`SealJobRegistry`].
///
/// The upstream payload service admits at most `max_payload_tasks` builds to execute at once, so
/// four times that leaves headroom for jobs that are alive but not yet executing. The floor covers
/// a node that leaves the default in place.
fn registry_capacity(max_payload_tasks: usize) -> usize {
    DEFAULT_SEAL_JOB_CAPACITY.max(max_payload_tasks.saturating_mul(4))
}

/// Engine API validator for [`UnicityEngineTypes`].
///
/// This is the stock Ethereum payload structure validator plus the standard version-specific field
/// checks. It deliberately adds no Unicity-specific verdict: certificate authentication, the
/// registry state and the body outcomes are not available at this layer, and U3c to U3e own any
/// additional rejection rules on the methods that carry the companion.
#[derive(Debug, Clone)]
pub struct UnicityEngineValidator {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl UnicityEngineValidator {
    /// Instantiates a validator over the given chain spec.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthereumExecutionPayloadValidator::new(chain_spec) }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl PayloadValidator<UnicityEngineTypes> for UnicityEngineValidator {
    type Block = reth_ethereum_primitives::Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        self.inner.ensure_well_formed_payload(payload).map_err(Into::into)
    }
}

impl EngineApiValidator<UnicityEngineTypes> for UnicityEngineValidator {
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, UnicityPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        // Mirrors `EthereumEngineValidator`: the same execution-requests check and the same
        // version-specific field checks as a plain Ethereum node. No Unicity-specific verdict is
        // added here.
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;
        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &UnicityPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<ExecutionData, UnicityPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// Builds [`UnicityEngineValidator`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct UnicityEngineValidatorBuilder;

impl<N> PayloadValidatorBuilder<N> for UnicityEngineValidatorBuilder
where
    N: FullNodeComponents<Types = UnicityNode>,
{
    type Validator = UnicityEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(UnicityEngineValidator::new(ctx.config.chain.clone()))
    }
}

/// Standard RPC add-ons for a Unicity node.
///
/// The engine API builder registers the seal siblings and advertises the three seal capabilities
/// together with the stock list. The `extend_rpc_modules` hook adds the `unicity` read methods on
/// the standard transports, sharing the same companion store. No stock method changes.
pub type UnicityNodeAddOns<N> =
    RpcAddOns<N, EthereumEthApiBuilder, UnicityEngineValidatorBuilder, UnicityEngineApiBuilder>;

#[cfg(test)]
mod tests {
    use super::registry_capacity;
    use crate::DEFAULT_SEAL_JOB_CAPACITY;

    #[test]
    fn registry_capacity_tracks_max_payload_tasks_with_a_floor() {
        assert_eq!(registry_capacity(0), DEFAULT_SEAL_JOB_CAPACITY);
        assert_eq!(registry_capacity(1), DEFAULT_SEAL_JOB_CAPACITY);
        assert_eq!(registry_capacity(4), DEFAULT_SEAL_JOB_CAPACITY);
        assert_eq!(registry_capacity(5), 20);
        assert_eq!(registry_capacity(usize::MAX), usize::MAX);
    }
}
