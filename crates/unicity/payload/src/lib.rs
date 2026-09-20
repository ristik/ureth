//! Unicity per-payload `extraData` commitment provision (U2, bft-core #11).
//!
//! The stock Ethereum payload builder copies one per-process value,
//! `EthereumBuilderConfig::extra_data`, into every block it builds, and the stock payload id hashes
//! only the standard attribute fields. This crate adds, without editing any upstream crate:
//!
//! - [`UnicityPayloadAttributes`]: the standard attributes plus the 32-byte D1 commitment the
//!   block's header `extraData` must carry. The commitment has no default and is refused unless it
//!   is exactly 32 bytes.
//! - A payload id that also covers the commitment, so two build jobs that differ only in their
//!   commitment are different jobs.
//! - [`UnicityPayloadBuilder`]: the U2 commitment-only stock builder wrapper.
//! - [`UnicityExecutionPayloadBuilder`]: an execution-aware wrapper which resolves every build,
//!   empty-build and missing-payload path to an immutable [`UnicityEvmConfig`].
//! - [`SealJobRegistry`]: a bounded, shareable handoff between a future seal method and the payload
//!   builder.
//! - [`UnicityEngineTypes`] and [`UnicityNode`]: the Engine API types and the node wiring that
//!   carry the Unicity attributes end to end and use [`UnicityExecutionPayloadBuilder`] with that
//!   registry.
//! - [`prepare_seal_build`] and the `engine_forkchoiceUpdatedWithSealV1`,
//!   `engine_getPayloadWithSealV1` and `engine_newPayloadWithSealV1` siblings: the build path that
//!   decodes the canonical input, binds the parent, installs the job and forwards the forkchoice
//!   update; the response that returns the built payload, its block value and the companion; and
//!   the import path that re-executes the payload, records its accounting token, registers its
//!   bound input and forwards it to the engine.
//!
//! THE SEAL METHODS ARE ADVERTISED. A Unicity node's `engine_exchangeCapabilities` is the stock
//! Ethereum list plus the three seal methods, added together as one set. The siblings are
//! registered on the authenticated engine module and reachable. The execution-aware path remains
//! structurally bound only: its resolver performs structural binding, while certificate/JWT
//! authentication and exact-parent state provenance remain caller prerequisites. The import path
//! does not verify witnesses, and the build-path companion carries no witnesses because
//! `sealBuildInput` supplies none; bft-core holds the authenticated certificate and must populate
//! them before dissemination. See the crate README.

pub mod engine;
pub mod node;
pub mod registry;
pub mod rpc;

pub use engine::UnicityEngineTypes;
pub use node::{
    UnicityEngineValidator, UnicityEngineValidatorBuilder, UnicityExecutorBuilder, UnicityNode,
    UnicityNodeAddOns, UnicityPayloadBuilderBuilder, UnicitySealConfig,
};
pub use registry::{
    SealJobRegistry, UnicityParentAccountings, DEFAULT_PARENT_ACCOUNTING_CAPACITY,
    DEFAULT_SEAL_JOB_CAPACITY,
};
pub use rpc::{
    build_seal_companion, companion_not_retained_error, import_response, prepare_seal_build,
    refusal_response, unicity_engine_capabilities, GetPayloadWithSealV1Response, SealBuildContext,
    SealBuildError, SealCompanionError, SealImportError, UnicityEngineApiBuilder,
    UnicityEngineApiImpl, UnicityEngineApiModule, BUILD_PROVENANCE, COMPANION_NOT_RETAINED_CODE,
    SEAL_CAPABILITIES,
};

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadId};
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_ethereum_payload_builder::{EthereumBuilderConfig, EthereumPayloadBuilder};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_payload_builder::EthBuiltPayload;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadAttributes;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_unicity_execution::block_executor::UnicityEvmConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, sync::Arc};

/// Domain separation for the payload id. The stock id and the commitment are hashed under this tag,
/// so the derivation is distinct from the stock one and a job cannot alias another merely because
/// the commitment was left out. It does not make collisions impossible: like the stock id, the
/// result is a hash truncated to eight bytes, and payload ids are job handles, not cryptographic
/// bindings.
pub const PAYLOAD_ID_DOMAIN: &[u8] = b"UNICITY_PAYLOAD_ID_EXTRADATA_COMMITMENT_V1";

/// Payload attributes with the per-payload header commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicityPayloadAttributes {
    /// The standard Engine API V3 attributes, unchanged.
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// The 32-byte value the built block's header `extraData` must carry. Required:
    /// deserialization refuses a missing field and any value that is not exactly 32 bytes of
    /// hex.
    pub commitment: B256,
}

impl UnicityPayloadAttributes {
    /// The payload id for these attributes on `parent`: the stock id, bound to the commitment.
    pub fn unicity_payload_id(&self, parent: &B256) -> PayloadId {
        let stock = PayloadAttributes::payload_id(&self.inner, parent);
        let mut hasher = Sha256::new();
        hasher.update(PAYLOAD_ID_DOMAIN);
        hasher.update(stock.0.as_slice());
        hasher.update(self.commitment.as_slice());
        let out = hasher.finalize();
        let mut id = [0u8; 8];
        id.copy_from_slice(&out[..8]);
        PayloadId::new(id)
    }
}

impl PayloadAttributes for UnicityPayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        self.unicity_payload_id(parent_hash)
    }

    fn timestamp(&self) -> u64 {
        PayloadAttributes::timestamp(&self.inner)
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        PayloadAttributes::withdrawals(&self.inner)
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        PayloadAttributes::parent_beacon_block_root(&self.inner)
    }

    fn slot_number(&self) -> Option<u64> {
        PayloadAttributes::slot_number(&self.inner)
    }

    fn target_gas_limit(&self) -> Option<u64> {
        PayloadAttributes::target_gas_limit(&self.inner)
    }
}

/// A payload builder that writes each job's commitment into its block's header `extraData`.
///
/// It holds the parts of a stock `EthereumPayloadBuilder` and constructs one per job, with that
/// job's commitment as `extra_data`. `base_config.extra_data` is therefore never used: every block
/// built here carries the commitment of the job that built it.
#[derive(Debug, Clone)]
pub struct UnicityPayloadBuilder<Pool, Client, EvmConfig> {
    client: Client,
    pool: Pool,
    evm_config: EvmConfig,
    base_config: EthereumBuilderConfig,
}

impl<Pool, Client, EvmConfig> UnicityPayloadBuilder<Pool, Client, EvmConfig> {
    /// `UnicityPayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        base_config: EthereumBuilderConfig,
    ) -> Self {
        Self { client, pool, evm_config, base_config }
    }
}

impl<Pool, Client, EvmConfig> UnicityPayloadBuilder<Pool, Client, EvmConfig>
where
    Pool: Clone,
    Client: Clone,
    EvmConfig: Clone,
{
    /// The stock builder for one job: the base configuration with this job's commitment as
    /// extraData.
    fn for_job(&self, commitment: B256) -> EthereumPayloadBuilder<Pool, Client, EvmConfig> {
        EthereumPayloadBuilder::new(
            self.client.clone(),
            self.pool.clone(),
            self.evm_config.clone(),
            self.base_config.clone().with_extra_data(commitment.0.to_vec().into()),
        )
    }
}

/// Splits Unicity build arguments into the job's commitment and stock build arguments.
fn split_args(
    args: BuildArguments<UnicityPayloadAttributes, EthBuiltPayload>,
) -> (B256, BuildArguments<EthPayloadAttributes, EthBuiltPayload>) {
    let BuildArguments {
        cached_reads,
        execution_cache,
        state_root_handle,
        config,
        cancel,
        best_payload,
    } = args;
    let (commitment, config) = split_config(config);
    (
        commitment,
        BuildArguments {
            cached_reads,
            execution_cache,
            state_root_handle,
            config,
            cancel,
            best_payload,
        },
    )
}

/// Splits a Unicity payload config into the job's commitment and a stock config. The payload id is
/// kept as computed from the Unicity attributes.
fn split_config(
    config: PayloadConfig<UnicityPayloadAttributes>,
) -> (B256, PayloadConfig<EthPayloadAttributes>) {
    let PayloadConfig { parent_header, parent_block_info, attributes, payload_id } = config;
    (
        attributes.commitment,
        PayloadConfig {
            parent_header,
            parent_block_info,
            attributes: attributes.inner,
            payload_id,
        },
    )
}

impl<Pool, Client, EvmConfig> PayloadBuilder for UnicityPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = UnicityPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let (commitment, args) = split_args(args);
        self.for_job(commitment).try_build(args)
    }

    fn on_missing_payload(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        let (commitment, args) = split_args(args);
        self.for_job(commitment).on_missing_payload(args)
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let (commitment, config) = split_config(config);
        self.for_job(commitment).build_empty_payload(config)
    }
}

/// A resolver that selects one immutable execution configuration for an exact payload job.
///
/// Resolution is structural. The party populating the resolver must authenticate the Unicity
/// certificate and bind the supplied state snapshot to the exact parent; this crate does not
/// deserialize or verify that authentication verdict.
pub trait ExecutionPayloadJobResolver: Clone + Send + Sync {
    /// Resolves `config`, refusing absent jobs or any changed parent/attributes.
    fn resolve(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<UnicityEvmConfig, PayloadJobResolutionError>;
}

/// One immutable payload-job binding installed by the external authenticated-input path.
#[derive(Clone, Debug)]
pub struct ResolvedPayloadJob {
    parent: Arc<reth_primitives_traits::SealedHeader>,
    attributes: UnicityPayloadAttributes,
    payload_id: PayloadId,
    evm_config: UnicityEvmConfig,
}

impl ResolvedPayloadJob {
    /// Creates and checks an exact job binding before it can be installed in a resolver.
    pub fn new(
        parent: Arc<reth_primitives_traits::SealedHeader>,
        attributes: UnicityPayloadAttributes,
        evm_config: UnicityEvmConfig,
        builder_config: &EthereumBuilderConfig,
    ) -> Result<Self, PayloadJobResolutionError> {
        if builder_config.skip_state_root {
            return Err(PayloadJobResolutionError(
                "Unicity payload jobs require state-root computation",
            ));
        }
        let payload_id = attributes.payload_id(&parent.hash());
        evm_config
            .validate_payload_job(
                &parent,
                &next_block_attributes(&parent, &attributes, builder_config),
            )
            .map_err(|_| PayloadJobResolutionError("execution configuration does not match job"))?;
        Ok(Self { parent, attributes, payload_id, evm_config })
    }

    /// Checks that `config` still selects this exact immutable job.
    ///
    /// The eight-byte payload id is only a lookup handle. This compares the full parent and
    /// attributes again, so a resolver cannot select a job whose id collided or whose caller
    /// changed the parent or attributes after the id was computed.
    pub(crate) fn check_binding(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<(), PayloadJobResolutionError> {
        let parent_mismatch = self.parent.as_ref() != config.parent_header.as_ref();
        let attributes_mismatch = self.attributes != config.attributes;
        let id_mismatch =
            config.attributes.payload_id(&config.parent_header.hash()) != config.payload_id;
        if parent_mismatch || attributes_mismatch || id_mismatch {
            return Err(PayloadJobResolutionError("payload job binding mismatch"));
        }
        Ok(())
    }
}

/// A fixed set of independently prepared payload jobs. It has no mutable current-job state.
#[derive(Clone, Debug, Default)]
pub struct FixedPayloadJobResolver {
    jobs: Arc<[ResolvedPayloadJob]>,
}

impl FixedPayloadJobResolver {
    /// Installs immutable jobs and refuses duplicate payload ids.
    pub fn new(jobs: Vec<ResolvedPayloadJob>) -> Result<Self, PayloadJobResolutionError> {
        for (index, job) in jobs.iter().enumerate() {
            if jobs[index + 1..].iter().any(|other| other.payload_id == job.payload_id) {
                return Err(PayloadJobResolutionError("duplicate payload job"));
            }
        }
        Ok(Self { jobs: jobs.into() })
    }
}

impl ExecutionPayloadJobResolver for FixedPayloadJobResolver {
    fn resolve(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<UnicityEvmConfig, PayloadJobResolutionError> {
        let job = self
            .jobs
            .iter()
            .find(|job| job.payload_id == config.payload_id)
            .ok_or(PayloadJobResolutionError("payload job is absent"))?;
        job.check_binding(config)?;
        Ok(job.evm_config.clone())
    }
}

/// Failure to select the exact immutable execution companion for a payload job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadJobResolutionError(&'static str);

impl PayloadJobResolutionError {
    /// Creates a resolver failure with a stable static description.
    pub const fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for PayloadJobResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for PayloadJobResolutionError {}

/// Payload builder that resolves every job to the shared Unicity block executor.
#[derive(Clone, Debug)]
pub struct UnicityExecutionPayloadBuilder<Pool, Client, Resolver> {
    client: Client,
    pool: Pool,
    resolver: Resolver,
    base_config: EthereumBuilderConfig,
    parent_accounting: UnicityParentAccountings,
}

impl<Pool, Client, Resolver> UnicityExecutionPayloadBuilder<Pool, Client, Resolver> {
    /// Creates an execution-aware payload builder. No stock EVM fallback is retained.
    pub fn new(
        client: Client,
        pool: Pool,
        resolver: Resolver,
        base_config: EthereumBuilderConfig,
    ) -> Self {
        Self { client, pool, resolver, base_config, parent_accounting: Default::default() }
    }

    /// Shares the store where completed builds publish their parent-accounting tokens.
    ///
    /// A build on top of a block this node produced needs that block's token. The token is minted
    /// here after a successful build and read back by a later build; the store is what carries it
    /// across the two calls.
    pub fn with_parent_accounting(mut self, parent_accounting: UnicityParentAccountings) -> Self {
        self.parent_accounting = parent_accounting;
        self
    }
}

impl<Pool, Client, Resolver> UnicityExecutionPayloadBuilder<Pool, Client, Resolver>
where
    Pool: Clone,
    Client: Clone,
    Resolver: ExecutionPayloadJobResolver,
{
    fn resolve_job(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<UnicityEvmConfig, PayloadBuilderError> {
        let evm_config = self.resolver.resolve(config).map_err(PayloadBuilderError::other)?;
        evm_config
            .validate_payload_job(
                &config.parent_header,
                &next_block_attributes(
                    &config.parent_header,
                    &config.attributes,
                    &self.base_config,
                ),
            )
            .map_err(PayloadBuilderError::other)?;
        if self.base_config.skip_state_root {
            return Err(PayloadBuilderError::other(PayloadJobResolutionError(
                "Unicity payload jobs require state-root computation",
            )));
        }
        Ok(evm_config)
    }

    fn for_resolved_job(
        &self,
        config: &PayloadConfig<UnicityPayloadAttributes>,
        evm_config: UnicityEvmConfig,
    ) -> EthereumPayloadBuilder<Pool, Client, UnicityEvmConfig> {
        EthereumPayloadBuilder::new(
            self.client.clone(),
            self.pool.clone(),
            evm_config,
            self.base_config
                .clone()
                .with_extra_data(config.attributes.commitment.0.to_vec().into()),
        )
    }

    /// Publishes the parent-accounting token for a payload this job just produced.
    ///
    /// The token is only minted from a block the executor actually finished, so a later build can
    /// inherit the parent's ordinary/system gas split instead of inventing it from the header.
    ///
    /// Only built blocks are recorded here. A parent this node imported through
    /// `engine_newPayloadWithSealV1` has no token until the import path records one, so a follower
    /// cannot yet lead on it. That import path runs the same executor and must publish the token
    /// there too.
    fn remember_parent(&self, evm_config: &UnicityEvmConfig, payload: &EthBuiltPayload) {
        if let Ok(token) = evm_config.completed_parent_for(payload.block()) {
            self.parent_accounting.insert(payload.block().hash(), token);
        }
    }
}

impl<Pool, Client, Resolver> PayloadBuilder
    for UnicityExecutionPayloadBuilder<Pool, Client, Resolver>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    Resolver: ExecutionPayloadJobResolver,
{
    type Attributes = UnicityPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let evm_config = self.resolve_job(&args.config)?;
        if let Some(best) = &args.best_payload {
            evm_config
                .validate_payload_candidate(best.block())
                .map_err(PayloadBuilderError::other)?;
        }
        let builder = self.for_resolved_job(&args.config, evm_config.clone());
        let (_, args) = split_args(args);
        let outcome = builder.try_build(args)?;
        if let BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) = &outcome {
            self.remember_parent(&evm_config, payload);
        }
        Ok(outcome)
    }

    fn on_missing_payload(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        let evm_config = match self.resolve_job(&args.config) {
            Ok(config) => config,
            Err(error) => return MissingPayloadBehaviour::RacePayload(Box::new(|| Err(error))),
        };
        let builder = self.for_resolved_job(&args.config, evm_config);
        let (_, args) = split_args(args);
        builder.on_missing_payload(args)
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let evm_config = self.resolve_job(&config)?;
        let builder = self.for_resolved_job(&config, evm_config.clone());
        let (_, config) = split_config(config);
        let payload = builder.build_empty_payload(config)?;
        self.remember_parent(&evm_config, &payload);
        Ok(payload)
    }
}

fn next_block_attributes(
    parent: &reth_primitives_traits::SealedHeader,
    attributes: &UnicityPayloadAttributes,
    builder_config: &EthereumBuilderConfig,
) -> NextBlockEnvAttributes {
    NextBlockEnvAttributes {
        timestamp: attributes.inner.timestamp,
        suggested_fee_recipient: attributes.inner.suggested_fee_recipient,
        prev_randao: attributes.inner.prev_randao,
        gas_limit: builder_config
            .gas_limit_with_target(parent.gas_limit, attributes.inner.target_gas_limit),
        parent_beacon_block_root: attributes.inner.parent_beacon_block_root,
        withdrawals: attributes.inner.withdrawals.clone().map(Into::into),
        extra_data: attributes.commitment.0.to_vec().into(),
        slot_number: attributes.inner.slot_number,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header};
    use alloy_primitives::{Address, Bytes};
    use reth_basic_payload_builder::BuildOutcome;
    use reth_chainspec::{ChainSpec, ChainSpecBuilder};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_primitives_traits::SealedHeader;
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::test_utils::{testing_pool, TestPool};
    use std::sync::Arc;

    type Provider = MockEthProvider<EthPrimitives, ChainSpec>;

    struct Fixture {
        provider: Provider,
        pool: TestPool,
        evm: EthEvmConfig,
        parent: Arc<SealedHeader>,
    }

    /// A post-Shanghai, pre-Cancun chain with one parent header, an empty pool and mock state.
    /// Cancun is left inactive so the test needs no parent beacon root or blob fields:
    /// extraData is all it checks.
    fn fixture() -> Fixture {
        let spec = ChainSpecBuilder::mainnet()
            .london_activated()
            .paris_activated()
            .shanghai_activated()
            .build();
        let provider = MockEthProvider::default().with_chain_spec(spec.clone());
        let header = Header {
            number: 1,
            gas_limit: 30_000_000,
            timestamp: 1_000,
            base_fee_per_gas: Some(1_000_000_000),
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(header.clone());
        provider.add_header(parent.hash(), header);
        Fixture {
            provider,
            pool: testing_pool(),
            evm: EthEvmConfig::new(Arc::new(spec)),
            parent: Arc::new(parent),
        }
    }

    fn inner() -> EthPayloadAttributes {
        EthPayloadAttributes {
            timestamp: 1_012,
            prev_randao: B256::repeat_byte(0x11),
            suggested_fee_recipient: Address::repeat_byte(0x22),
            withdrawals: Some(vec![]),
            parent_beacon_block_root: None,
            slot_number: None,
            target_gas_limit: None,
        }
    }

    fn attrs(commitment: B256) -> UnicityPayloadAttributes {
        UnicityPayloadAttributes { inner: inner(), commitment }
    }

    fn builder(f: &Fixture) -> UnicityPayloadBuilder<TestPool, Provider, EthEvmConfig> {
        UnicityPayloadBuilder::new(
            f.provider.clone(),
            f.pool.clone(),
            f.evm.clone(),
            // A base extraData that must never appear in a block this builder builds.
            EthereumBuilderConfig::new()
                .with_extra_data(Bytes::from_static(b"base-must-not-appear")),
        )
    }

    fn config(f: &Fixture, a: UnicityPayloadAttributes) -> PayloadConfig<UnicityPayloadAttributes> {
        let payload_id = a.payload_id(&f.parent.hash());
        PayloadConfig {
            parent_header: f.parent.clone(),
            parent_block_info: None,
            attributes: a,
            payload_id,
        }
    }

    fn extra_data_of(p: &EthBuiltPayload) -> Bytes {
        p.block().header().extra_data().clone()
    }

    fn build_full(
        b: &UnicityPayloadBuilder<TestPool, Provider, EthEvmConfig>,
        cfg: PayloadConfig<UnicityPayloadAttributes>,
    ) -> EthBuiltPayload {
        let args =
            BuildArguments::new(Default::default(), None, None, cfg, Default::default(), None);
        match b.try_build(args).expect("build") {
            BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) => payload,
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn different_commitments_are_different_jobs_and_reach_their_own_extra_data() {
        let f = fixture();
        let b = builder(&f);
        let (ca, cb) = (B256::repeat_byte(0xaa), B256::repeat_byte(0xbb));
        let (a, bb) = (attrs(ca), attrs(cb));

        let (ida, idb) = (a.payload_id(&f.parent.hash()), bb.payload_id(&f.parent.hash()));
        assert_ne!(ida, idb, "a commitment difference alone must change the payload id");

        // Interleaved: A empty, B full, A full, B empty. Each block carries its own job's
        // commitment.
        let a_empty = b.build_empty_payload(config(&f, a.clone())).expect("a empty");
        let b_full = build_full(&b, config(&f, bb.clone()));
        let a_full = build_full(&b, config(&f, a));
        let b_empty = b.build_empty_payload(config(&f, bb)).expect("b empty");

        assert_eq!(extra_data_of(&a_empty).as_ref(), ca.as_slice());
        assert_eq!(extra_data_of(&a_full).as_ref(), ca.as_slice());
        assert_eq!(extra_data_of(&b_full).as_ref(), cb.as_slice());
        assert_eq!(extra_data_of(&b_empty).as_ref(), cb.as_slice());
    }

    #[test]
    fn the_same_commitment_is_the_same_job() {
        let f = fixture();
        let c = B256::repeat_byte(0x33);
        assert_eq!(attrs(c).payload_id(&f.parent.hash()), attrs(c).payload_id(&f.parent.hash()));
    }

    #[test]
    fn the_unicity_id_is_domain_separated_from_the_stock_id() {
        let f = fixture();
        let a = attrs(B256::ZERO);
        assert_ne!(
            a.payload_id(&f.parent.hash()),
            PayloadAttributes::payload_id(&a.inner, &f.parent.hash()),
            "for this input the derivation differs from the stock id; an eight-byte collision is not excluded in general"
        );
    }

    #[test]
    fn the_payload_id_is_the_documented_derivation() {
        let f = fixture();
        let c = B256::repeat_byte(0x5a);
        let a = attrs(c);
        let stock = PayloadAttributes::payload_id(&a.inner, &f.parent.hash());
        // The domain tag is written out rather than taken from the constant, so changing either
        // fails here.
        let mut h = Sha256::new();
        h.update(b"UNICITY_PAYLOAD_ID_EXTRADATA_COMMITMENT_V1");
        h.update(stock.0.as_slice());
        h.update(c.as_slice());
        let out = h.finalize();
        let mut want = [0u8; 8];
        want.copy_from_slice(&out[..8]);
        assert_eq!(a.payload_id(&f.parent.hash()), PayloadId::new(want));
    }

    #[test]
    fn missing_or_malformed_commitments_are_refused() {
        let base = serde_json::json!({
            "timestamp": "0x3f4",
            "prevRandao": format!("{:#x}", B256::repeat_byte(0x11)),
            "suggestedFeeRecipient": format!("{:#x}", Address::repeat_byte(0x22)),
            "withdrawals": []
        });

        let mut good = base.clone();
        good["commitment"] = serde_json::json!(format!("{:#x}", B256::repeat_byte(0x44)));
        let parsed: UnicityPayloadAttributes =
            serde_json::from_value(good).expect("premise: well-formed");
        assert_eq!(parsed.commitment, B256::repeat_byte(0x44));
        assert_eq!(parsed.inner.timestamp, 0x3f4);

        let cases = [
            ("missing", None),
            ("31 bytes", Some(format!("0x{}", "44".repeat(31)))),
            ("33 bytes", Some(format!("0x{}", "44".repeat(33)))),
            ("not hex", Some(format!("0x{}", "zz".repeat(32)))),
            ("empty", Some("0x".to_string())),
        ];
        for (name, value) in cases {
            let mut v = base.clone();
            if let Some(value) = value {
                v["commitment"] = serde_json::json!(value);
            }
            assert!(
                serde_json::from_value::<UnicityPayloadAttributes>(v).is_err(),
                "{name} commitment must be refused"
            );
        }
    }

    #[test]
    fn the_stock_builder_and_stock_id_are_unchanged() {
        let f = fixture();
        let stock = EthereumPayloadBuilder::new(
            f.provider.clone(),
            f.pool.clone(),
            f.evm.clone(),
            EthereumBuilderConfig::new().with_extra_data(Bytes::from_static(b"stock-extra")),
        );
        let a = inner();
        let payload_id = PayloadAttributes::payload_id(&a, &f.parent.hash());
        assert_eq!(
            payload_id,
            reth_payload_primitives::payload_id(&f.parent.hash(), &a),
            "the stock id is still the stock function"
        );
        let cfg = PayloadConfig {
            parent_header: f.parent,
            parent_block_info: None,
            attributes: a,
            payload_id,
        };
        let p = stock.build_empty_payload(cfg).expect("stock empty");
        assert_eq!(extra_data_of(&p).as_ref(), b"stock-extra");
    }
}
