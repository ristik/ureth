//! Unicity node wiring.
//!
//! [`UnicityNode`] implements [`NodeTypes`] with [`UnicityEngineTypes`] and replaces the stock
//! payload builder with [`UnicityExecutionPayloadBuilder`](crate::UnicityExecutionPayloadBuilder)
//! resolving through a shared [`SealJobRegistry`]. The node is the attachment point for the
//! `engine_*WithSealV1` methods: a future method inserts a
//! [`ResolvedPayloadJob`](crate::ResolvedPayloadJob) into the registry and then starts an ordinary
//! build, which resolves that exact job.
//!
//! Nothing here registers an RPC method or a capability string. The stock `engine_*` surface is
//! assembled from upstream components exactly as the plain Ethereum node assembles it, and this
//! file contains no method registration, capability list or seal parameter type.

use std::sync::Arc;

use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::ChainSpec;
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::{EthereumBuilderConfig, EthereumExecutionPayloadValidator};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_node_builder::{
    components::{BasicPayloadServiceBuilder, ComponentsBuilder, PayloadBuilderBuilder},
    rpc::{
        BasicEngineApiBuilder, BasicEngineValidatorBuilder, Identity, PayloadValidatorBuilder,
        RpcAddOns,
    },
    AddOnsContext, BuilderContext, FullNodeComponents, FullNodeTypes, Node, NodeAdapter, NodeTypes,
    PayloadBuilderConfig,
};
use reth_node_ethereum::{
    EthereumConsensusBuilder, EthereumEthApiBuilder, EthereumExecutorBuilder,
    EthereumNetworkBuilder, EthereumPoolBuilder,
};
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_primitives_traits::SealedBlock;
use reth_provider::EthStorage;
use reth_transaction_pool::{PoolTransaction, TransactionPool};

use crate::{
    SealJobRegistry, UnicityEngineTypes, UnicityExecutionPayloadBuilder, UnicityPayloadAttributes,
};

/// A Unicity execution node.
///
/// This is the plain Ethereum node with two changes: [`NodeTypes::Payload`] is
/// [`UnicityEngineTypes`], and the payload component builds through
/// [`UnicityExecutionPayloadBuilder`](crate::UnicityExecutionPayloadBuilder) with the registry this
/// node holds. Everything else, including the network, pool, executor, consensus and the standard
/// Engine API, is the stock Ethereum component.
///
/// A caller that needs to insert seal jobs shares the registry with the node by constructing it
/// with [`UnicityNode::new`]; all clones observe the same entries.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UnicityNode {
    registry: SealJobRegistry,
}

impl UnicityNode {
    /// Creates a node whose payload builder resolves through `registry`.
    pub const fn new(registry: SealJobRegistry) -> Self {
        Self { registry }
    }

    /// Returns the seal job registry shared with the payload builder.
    pub const fn registry(&self) -> &SealJobRegistry {
        &self.registry
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
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<UnicityPayloadBuilderBuilder>,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = UnicityNodeAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(UnicityPayloadBuilderBuilder::new(
                self.registry.clone(),
            )))
            .network(EthereumNetworkBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            UnicityEngineValidatorBuilder,
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Identity::new(),
        )
    }
}

/// Builds [`UnicityExecutionPayloadBuilder`](crate::UnicityExecutionPayloadBuilder) for the
/// payload service.
///
/// The builder owns a clone of the node's [`SealJobRegistry`], so the registry the payload service
/// resolves through is the same one a seal method will insert into.
#[derive(Clone, Debug)]
pub struct UnicityPayloadBuilderBuilder {
    registry: SealJobRegistry,
}

impl UnicityPayloadBuilderBuilder {
    /// Creates a payload builder builder that resolves through `registry`.
    pub const fn new(registry: SealJobRegistry) -> Self {
        Self { registry }
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
        Ok(UnicityExecutionPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            self.registry,
            EthereumBuilderConfig::new()
                .with_gas_limit(gas_limit)
                .with_max_blobs_per_block(conf.max_blobs_per_block())
                .with_extra_data(conf.extra_data())
                .with_skip_state_root(skip_state_root),
        ))
    }
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
/// The engine API builder is the stock [`BasicEngineApiBuilder`], so no seal method is registered
/// and no capability is advertised. U3c will extend this type to register the sibling methods and
/// to carry the node's [`SealJobRegistry`] into them.
pub type UnicityNodeAddOns<N> = RpcAddOns<N, EthereumEthApiBuilder, UnicityEngineValidatorBuilder>;
