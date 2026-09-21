//! The `engine_forkchoiceUpdatedWithSealV1`, `engine_getPayloadWithSealV1` and
//! `engine_newPayloadWithSealV1` siblings.
//!
//! This is a jsonrpsee trait in the `engine` namespace, separate from reth's own
//! [`reth_rpc_api::EngineApiServer`], so the fork adds methods without editing an upstream file. It
//! is shaped after `EngineApiInner` in `reth_rpc_engine_api`: the same provider, consensus handle
//! and shared node state.
//!
//! The methods are reachable and advertised. A Unicity node's `engine_exchangeCapabilities` adds
//! all three seal methods together; the stock Ethereum set is unchanged and the three are never
//! advertised as a subset.
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
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use alloy_consensus::Header;
use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ClientVersionV1, ExecutionData, ExecutionPayload,
    ExecutionPayloadEnvelopeV3, ExecutionPayloadSidecar, ExecutionPayloadV3, ForkchoiceState,
    ForkchoiceUpdated, PayloadId, PayloadStatus, PayloadStatusEnum,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject, RpcModule};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_engine_primitives::{ConsensusEngineHandle, EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm_ethereum::EthEvmConfig;
use reth_node_builder::{
    rpc::{EngineApiBuilder, PayloadValidatorBuilder},
    AddOnsContext, FullNodeComponents,
};
use reth_node_core::version::{version_metadata, CLIENT_CODE};
use reth_payload_builder::PayloadStore;
use reth_payload_primitives::{
    validate_payload_timestamp, EngineApiMessageVersion, MessageValidationKind, PayloadOrAttributes,
};
use reth_revm::database::StateProviderDatabase;
use reth_rpc_api::IntoEngineApiRpcModule;
use reth_rpc_engine_api::{
    capabilities::{EngineCapabilities, CAPABILITIES},
    EngineApi, EngineApiError,
};
use reth_storage_api::{HeaderProvider, StateProviderFactory};
use reth_unicity_execution::{
    block::BlockAccountingError,
    block_executor::{replay_complete, BoundExecutionInput, UnicityEvmConfig},
    node_evm::UnicityBlockExecutionRegistry,
    wire::{
        bind_completed_parent, bind_validated_genesis, CanonicalCborError, SealBuildInput,
        SealCompanion,
    },
    RootInputV2,
};
use reth_unicity_store::{open as open_companion_store, CompanionStore, StoreError};
use serde::{Deserialize, Serialize};

use crate::{
    node::{
        UnicityEngineValidator, UnicityEngineValidatorBuilder, UnicityNode, UnicityRetentionConfig,
        UnicitySealConfig,
    },
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

    /// `engine_getPayloadWithSealV1`.
    ///
    /// Returns the built payload, its block value and the companion the leader disseminates. The
    /// companion's `rootInput` is re-encoded from the job's decoded input, and its `witnesses` list
    /// is empty by design.
    ///
    /// Witnesses are verifier-owned. D2 §2 keeps `VerifiedCert` and `ExpectedTransitions` outside
    /// the header commitment and out of the execution client: the shard node holds the verified
    /// certificate on the build path and supplies them, and the execution client is not the
    /// verifier on any path. This method therefore returns the fields the node owns.
    #[method(name = "getPayloadWithSealV1")]
    async fn get_payload_with_seal_v1(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<GetPayloadWithSealV1Response>;

    /// `engine_newPayloadWithSealV1`.
    ///
    /// Validates and records one imported seal block. This is the follower and re-execution path,
    /// and it is what lets a node that followed round N lead round N+1 by recording the imported
    /// block's accounting token. It does not verify witnesses: the shard-node adapter runs
    /// `VerifyCompanionWitnesses` before calling this method and reth accepts that verdict over the
    /// JWT-authenticated channel. `sealCompanion.rootInput` is taken as the structured input to
    /// execute against, nothing more.
    #[method(name = "newPayloadWithSealV1")]
    async fn new_payload_with_seal_v1(
        &self,
        payload: ExecutionPayloadV3,
        expected_blob_versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        seal_companion: SealCompanion,
    ) -> RpcResult<PayloadStatus>;
}

/// The `engine_getPayloadWithSealV1` response.
///
/// D2 fixes the shape as `{ executionPayload, blockValue, sealCompanion }`. This is the V3
/// execution payload and block value with the companion added, not the full stock
/// [`ExecutionPayloadEnvelopeV3`], which also carries `blobsBundle` and `shouldOverrideBuilder`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadWithSealV1Response {
    /// The built execution payload.
    pub execution_payload: ExecutionPayloadV3,
    /// The total fees the built block collected.
    pub block_value: U256,
    /// The companion the leader disseminates alongside the payload.
    pub seal_companion: SealCompanion,
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

/// A refusal from the seal import flow.
///
/// Every variant maps to a [`PayloadStatus`]: [`Self::UnknownParent`] and
/// [`Self::ParentAccountingMissing`] are SYNCING, [`Self::Provider`] is an internal RPC error, and
/// the rest are INVALID with this error's display text in `validationError`. `ACCEPTED` is never
/// produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealImportError {
    /// `sealCompanion.rootInput` is not a canonical root input.
    RootInput(CanonicalCborError),
    /// The caller supplied blob versioned hashes, which the bounded Cancun profile forbids.
    UnexpectedBlobHashes {
        /// Number of hashes the caller supplied.
        count: usize,
    },
    /// The payload could not be converted into a block with recovered senders.
    Payload(String),
    /// The version-specific Engine API fields did not match the V3 shape.
    VersionFields(String),
    /// The payload parent header is not local.
    UnknownParent,
    /// The parent is local but no accounting token is recorded for it.
    ParentAccountingMissing,
    /// The decoded input does not bind to the resolved parent.
    Binding(BlockAccountingError),
    /// Local execution rejected the block.
    Replay(String),
    /// A provider read failed; this is internal state, not caller input.
    Provider(String),
}

impl fmt::Display for SealImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootInput(error) => {
                write!(formatter, "rootInput is not a canonical root input: {error}")
            }
            Self::UnexpectedBlobHashes { count } => {
                write!(formatter, "blob versioned hashes are unsupported ({count} supplied)")
            }
            Self::Payload(error) => write!(formatter, "payload is not well formed: {error}"),
            Self::VersionFields(error) => {
                write!(formatter, "payload version fields are invalid: {error}")
            }
            Self::UnknownParent => formatter.write_str("payload parent is unknown"),
            Self::ParentAccountingMissing => {
                formatter.write_str("parent accounting token is not retained")
            }
            Self::Binding(error) => write!(formatter, "parent binding failed: {error:?}"),
            Self::Replay(error) => write!(formatter, "local execution rejected the block: {error}"),
            Self::Provider(error) => write!(formatter, "provider read failed: {error}"),
        }
    }
}

impl std::error::Error for SealImportError {}

/// A validated import ready to be registered and forwarded to the consensus engine.
struct PreparedSealImport {
    /// The payload to forward, unchanged from the caller.
    execution_data: ExecutionData,
    /// The header commitment the bound input resolves under.
    commitment: B256,
    /// The bound execution input the engine tree will resolve when it executes the block.
    input: Arc<BoundExecutionInput>,
    /// Hash of the imported block, captured before `execution_data` is moved to the engine.
    block_hash: B256,
    /// Number of the imported block, captured before `execution_data` is moved to the engine.
    block_number: u64,
}

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

/// Provenance label for a companion produced by the local build path, matching D2.
pub const BUILD_PROVENANCE: &str = "build";

/// Failure to re-encode a job's root input while building its companion.
///
/// The job's input was accepted by the canonical decoder, so the decoder's inverse should always
/// accept it. This exists so a failure is reported rather than silently producing a companion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCompanionError(String);

impl fmt::Display for SealCompanionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SealCompanionError {}

/// JSON-RPC error code for a payload whose build job was evicted before its companion was served.
///
/// This is a fork-specific diagnostic outside the standard Engine API error range, so an operator
/// can tell "the payload exists but its companion is no longer retained" apart from "the payload id
/// is unknown".
pub const COMPANION_NOT_RETAINED_CODE: i32 = -39001;

/// The distinct error for a payload that resolved but whose build job is no longer retained.
///
/// The payload store may still hold the payload after the bounded job registry evicts the job that
/// carried its root input. Reporting the stock unknown-payload error in that case would point an
/// operator at the payload store rather than at companion retention.
pub fn companion_not_retained_error(payload_id: PayloadId) -> EngineApiError {
    EngineApiError::other(ErrorObject::owned(
        COMPANION_NOT_RETAINED_CODE,
        format!("seal companion is no longer retained for payload {payload_id}"),
        None::<()>,
    ))
}

/// Builds the companion the leader disseminates for a payload this node built.
///
/// `root_input` is re-encoded with the canonical codec rather than retaining the caller's raw
/// bytes. That is provably byte-identical: [`RootInputV2::from_canonical_cbor`] accepts only
/// canonical encodings, and the round-trip invariant `from_canonical_cbor(canonical_cbor(v)) == v`
/// together with `canonical_cbor(from_canonical_cbor(b)) == b` is asserted in both directions, so
/// re-encoding cannot differ from what the caller supplied. Retaining a second copy would only add
/// a way for the two to disagree.
///
/// The witness list is empty because the build input carries no witnesses. Witnesses are the
/// authentication material a follower needs, bft-core holds the authenticated certificate, and it
/// is the party that can populate them before dissemination. See the crate README.
pub fn build_seal_companion(root_input: &RootInputV2) -> Result<SealCompanion, SealCompanionError> {
    let root_input =
        root_input.canonical_cbor().map_err(|error| SealCompanionError(format!("{error:?}")))?;
    Ok(SealCompanion {
        root_input: root_input.into(),
        witnesses: Vec::new(),
        provenance: BUILD_PROVENANCE.to_owned(),
    })
}

/// The write surface the seal handlers use to record a companion.
///
/// This is deliberately one method: this unit only writes. The read lookup, pruning and horizon
/// surfaces stay on [`CompanionStore`] and are wired by the later unit. The trait exists so a test
/// can substitute a sink whose write fails and prove that a store failure cannot change a verdict.
pub trait CompanionSink: fmt::Debug + Send + Sync {
    /// Records `companion` under `block_hash`, durable on return.
    fn put(
        &self,
        block_hash: B256,
        block_number: u64,
        companion: &SealCompanion,
    ) -> Result<(), StoreError>;
}

impl CompanionSink for CompanionStore {
    fn put(
        &self,
        block_hash: B256,
        block_number: u64,
        companion: &SealCompanion,
    ) -> Result<(), StoreError> {
        Self::put(self, block_hash, block_number, companion)
    }
}

/// Node-owned build state the seal build flow resolves against, before the store is opened.
///
/// The payload service and the handler share every field, so the job the handler installs is
/// resolved by the builder with the same configuration, registry and parent accounting. This is
/// [`SealBuildContext`] without the companion store: it can be built by `UnicityNode::add_ons`,
/// which has no datadir. Keeping it as one named value avoids a positional constructor that is
/// easy to transpose at the call site.
#[derive(Clone, Debug)]
pub struct SealBuildState {
    /// Registry the resolved job is installed into.
    pub registry: SealJobRegistry,
    /// Exact payload builder configuration the node resolved, once the payload service is built.
    pub builder_config: Arc<OnceLock<EthereumBuilderConfig>>,
    /// Pinned execution profile and fee collector.
    pub seal: UnicitySealConfig,
    /// Completed parent-accounting tokens published by the build path.
    pub parent_accounting: UnicityParentAccountings,
    /// Bound execution inputs the node's EVM config resolves when the engine executes a seal
    /// block.
    pub execution_inputs: UnicityBlockExecutionRegistry,
    /// Retention policy carried for the pruning path. This unit only carries it.
    pub retention: UnicityRetentionConfig,
}

/// Node-owned state the seal build flow resolves against, including the durable companion store.
///
/// The store-independent fields live in [`SealBuildState`] and are reachable by deref, so callers
/// read `context.registry` and the rest exactly as before while the store stays a distinct field.
#[derive(Clone, Debug)]
pub struct SealBuildContext {
    /// Store-independent build state shared with the payload service.
    pub state: SealBuildState,
    /// Durable companion store both seal paths write to.
    pub store: Arc<dyn CompanionSink>,
}

impl std::ops::Deref for SealBuildContext {
    type Target = SealBuildState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
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

/// Maps an import refusal to the handler's [`PayloadStatus`].
///
/// A missing parent token is SYNCING rather than INVALID. This is an interpretation of D2: the
/// block is not invalid, the node simply cannot establish the parent accounting until the parent
/// has been seal-executed locally through this same path. Treating a never-seal-executed parent as
/// not yet local is what makes the seal chain import contiguous. A provider read failure is
/// internal state and returns an RPC error. Nothing here ever produces `ACCEPTED`.
pub fn import_response(error: SealImportError) -> Result<PayloadStatus, EngineApiError> {
    match error {
        SealImportError::UnknownParent | SealImportError::ParentAccountingMissing => {
            Ok(PayloadStatus::from_status(PayloadStatusEnum::Syncing))
        }
        error @ SealImportError::Provider(_) => Err(EngineApiError::Internal(Box::new(error))),
        error => Ok(PayloadStatus::from_status(PayloadStatusEnum::Invalid {
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
    payload_store: PayloadStore<UnicityEngineTypes>,
}

impl<Provider> UnicityEngineApiImpl<Provider> {
    /// Creates the handler over the node's provider, consensus handle, shared build state,
    /// attribute validator and payload store.
    pub const fn new(
        provider: Provider,
        beacon_consensus: ConsensusEngineHandle<UnicityEngineTypes>,
        context: SealBuildContext,
        validator: UnicityEngineValidator,
        payload_store: PayloadStore<UnicityEngineTypes>,
    ) -> Self {
        Self { provider, beacon_consensus, context, validator, payload_store }
    }

    /// Records `companion` for `block_hash`, logging a failure instead of returning it.
    ///
    /// D2 part 3 says an unproducible companion does not un-certify a block, so a store failure
    /// must not change a verdict. Returning a `Result` here would invite a `?` at the call sites,
    /// which is the bug this method exists to prevent.
    fn record_companion(&self, block_hash: B256, block_number: u64, companion: &SealCompanion) {
        if let Err(error) = self.context.store.put(block_hash, block_number, companion) {
            tracing::error!(
                target: "reth::unicity",
                %block_hash,
                block_number,
                %error,
                "failed to retain the seal companion; the verdict is unchanged"
            );
        }
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

impl<Provider> UnicityEngineApiImpl<Provider>
where
    Provider: ChainSpecProvider<ChainSpec = ChainSpec>,
{
    /// Resolves the built payload and companion, mirroring the stock `getPayloadV3` path.
    ///
    /// An unknown payload id returns the stock [`EngineApiError::UnknownPayload`]. A payload that
    /// resolves while its build job has been evicted from the bounded registry returns
    /// [`COMPANION_NOT_RETAINED_CODE`] instead, because the payload exists but its companion is
    /// gone.
    pub async fn get_payload_with_seal(
        &self,
        payload_id: PayloadId,
    ) -> Result<GetPayloadWithSealV1Response, EngineApiError> {
        // Validate the payload timestamp before resolving, as the stock `get_payload_inner` does.
        let timestamp = self
            .payload_store
            .payload_timestamp(payload_id)
            .await
            .ok_or(EngineApiError::UnknownPayload)?
            .map_err(|_| EngineApiError::UnknownPayload)?;
        let chain_spec = self.provider.chain_spec();
        validate_payload_timestamp(
            &chain_spec,
            EngineApiMessageVersion::V3,
            timestamp,
            MessageValidationKind::GetPayload,
        )?;

        let payload = self
            .payload_store
            .resolve(payload_id)
            .await
            .ok_or(EngineApiError::UnknownPayload)?
            .map_err(|_| EngineApiError::UnknownPayload)?;

        // The companion needs the job's decoded input. The job is still in the registry while its
        // payload is being served. A bounded registry can evict it before getPayload, and the
        // payload store may still resolve the payload; that is its own verdict, not an unknown id.
        let root_input = self
            .context
            .registry
            .root_input(&payload_id)
            .ok_or_else(|| companion_not_retained_error(payload_id))?;
        let seal_companion = build_seal_companion(&root_input)
            .map_err(|error| EngineApiError::Internal(Box::new(error)))?;

        // Capture the key before the payload is consumed by the conversion. The store key is the
        // same block hash the import path will compute for this block.
        let block_hash = payload.block().hash();
        let block_number = payload.block().header().number;

        let envelope: ExecutionPayloadEnvelopeV3 =
            payload.try_into().map_err(|_| EngineApiError::UnknownPayload)?;

        // Write the companion this method is about to return. A store failure is logged and does
        // not change the response: D2 part 3 says an unproducible companion does not un-certify a
        // block, so this must not become a `?`.
        self.record_companion(block_hash, block_number, &seal_companion);

        Ok(GetPayloadWithSealV1Response {
            execution_payload: envelope.execution_payload,
            block_value: envelope.block_value,
            seal_companion,
        })
    }
}

impl<Provider> UnicityEngineApiImpl<Provider>
where
    Provider: HeaderProvider<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + StateProviderFactory
        + Send
        + Sync
        + 'static,
{
    /// Validates and records one imported seal block, registers its bound input and forwards the
    /// payload to the consensus engine.
    ///
    /// The pre-checks run before the forward and keep their verdicts: VALID is not assumed, an
    /// unknown parent or a parent without a token is SYNCING, and a malformed or unbound payload is
    /// INVALID with the refusal in `validationError`. A provider read failure is an internal error.
    /// The method does not verify witnesses; the shard-node adapter has already authenticated the
    /// companion over the JWT channel. It never constructs `ACCEPTED`.
    pub async fn new_payload_with_seal(
        &self,
        payload: ExecutionPayloadV3,
        expected_blob_versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        seal_companion: &SealCompanion,
    ) -> Result<PayloadStatus, EngineApiError> {
        let prepared = match self.try_import_seal_payload(
            payload,
            expected_blob_versioned_hashes,
            parent_beacon_block_root,
            seal_companion,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return import_response(error),
        };

        // Capture the key before `execution_data` is moved into the forward.
        let block_hash = prepared.block_hash;
        let block_number = prepared.block_number;

        // The engine tree resolves this input when it executes the forwarded block. Register it
        // before the forward, because the engine can begin executing as soon as the message is
        // sent.
        self.context
            .execution_inputs
            .insert(prepared.commitment, prepared.input)
            .map_err(|error| EngineApiError::Internal(Box::new(error)))?;

        // Forward to the engine as the stock `newPayloadV3` path does and return its verdict.
        let status = self
            .beacon_consensus
            .new_payload(prepared.execution_data)
            .await
            .map_err(EngineApiError::NewPayload)?;

        // Retain only a block the engine accepted. An INVALID or SYNCING verdict leaves no entry,
        // and a store failure is logged rather than allowed to change the verdict.
        if status.is_valid() {
            self.record_companion(block_hash, block_number, seal_companion);
        }

        Ok(status)
    }

    /// Runs the ordered import flow and returns the pieces the forward needs on success.
    ///
    /// Sender recovery is this path's responsibility: `replay_complete` documents that it does not
    /// recover senders and requires the caller to have verified them, so the payload validator's
    /// `ensure_well_formed_payload` recovers them here before the block reaches the executor.
    fn try_import_seal_payload(
        &self,
        payload: ExecutionPayloadV3,
        expected_blob_versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        seal_companion: &SealCompanion,
    ) -> Result<PreparedSealImport, SealImportError> {
        // 1. Decode the canonical root input.
        let root = seal_companion.decode_root_input().map_err(SealImportError::RootInput)?;
        // 2. The bounded profile disables blobs, so any expected hash is a refusal rather than
        //    something to ignore.
        if !expected_blob_versioned_hashes.is_empty() {
            return Err(SealImportError::UnexpectedBlobHashes {
                count: expected_blob_versioned_hashes.len(),
            });
        }
        // 3. Convert the payload and recover senders. Validate the version-specific fields first,
        //    exactly as the stock `newPayloadV3` path does, because this data arrives from outside
        //    the process. The bounded-profile checks in `replay_complete` cover the Cancun fields,
        //    but matching the stock order removes a difference a reviewer would have to reason
        //    about.
        let execution_data = ExecutionData {
            payload: ExecutionPayload::V3(payload),
            sidecar: ExecutionPayloadSidecar::v3(CancunPayloadFields {
                parent_beacon_block_root,
                versioned_hashes: expected_blob_versioned_hashes,
            }),
        };
        self.validator
            .validate_version_specific_fields(
                EngineApiMessageVersion::V3,
                PayloadOrAttributes::from_execution_payload(&execution_data),
            )
            .map_err(|error| SealImportError::VersionFields(error.to_string()))?;
        let block = self
            .validator
            .ensure_well_formed_payload(execution_data.clone())
            .map_err(|error| SealImportError::Payload(error.to_string()))?;

        // 4. Resolve the payload parent. Absence is a sync condition, not a bad block.
        let parent_hash = block.header().parent_hash;
        let parent = self
            .provider
            .sealed_header_by_hash(parent_hash)
            .map_err(|error| SealImportError::Provider(error.to_string()))?
            .ok_or(SealImportError::UnknownParent)?;

        // 5. Bind through the U3a entry points. The token is the genesis bootstrap or the token the
        //    build path or a previous import published, never a value derived from the header.
        let chain_spec = self.provider.chain_spec();
        let genesis_hash = chain_spec.genesis_hash();
        let bound = if parent.number == 0 && parent.hash() == genesis_hash {
            bind_validated_genesis(
                root,
                self.context.seal.profile,
                &parent,
                genesis_hash,
                self.context.seal.fee_collector,
            )
            .map_err(SealImportError::Binding)?
        } else {
            let token = self
                .context
                .parent_accounting
                .get(&parent.hash())
                .ok_or(SealImportError::ParentAccountingMissing)?;
            bind_completed_parent(
                root,
                self.context.seal.profile,
                &parent,
                token,
                self.context.seal.fee_collector,
            )
            .map_err(SealImportError::Binding)?
        };
        let input = Arc::new(bound);
        let config = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec), input.clone());

        // 6. Re-use the shared replay rather than a second execution or comparison path.
        let state_provider = self
            .provider
            .state_by_block_hash(parent_hash)
            .map_err(|error| SealImportError::Provider(error.to_string()))?;
        let replay = replay_complete(
            &config,
            StateProviderDatabase::new(state_provider.as_ref()),
            &state_provider,
            &block,
        )
        .map_err(|error| SealImportError::Replay(error.to_string()))?;

        // 7. Record the imported block's accounting so a node that followed it can lead on it next.
        let block_hash = block.hash();
        let block_number = block.header().number;
        self.context.parent_accounting.insert(block_hash, replay.parent);

        // 8. The engine executes the forwarded block and its EVM config resolves this input by the
        //    commitment in the header's extraData. Derive that key from the input itself.
        let commitment = input
            .root_input()
            .input_commitment()
            .map_err(|_| SealImportError::Payload("bound input has no commitment".to_owned()))?;
        Ok(PreparedSealImport { execution_data, commitment, input, block_hash, block_number })
    }
}

#[async_trait::async_trait]
impl<Provider> UnicityEngineApiServer for UnicityEngineApiImpl<Provider>
where
    Provider: HeaderProvider<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + StateProviderFactory
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

    async fn get_payload_with_seal_v1(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<GetPayloadWithSealV1Response> {
        Ok(self.get_payload_with_seal(payload_id).await?)
    }

    async fn new_payload_with_seal_v1(
        &self,
        payload: ExecutionPayloadV3,
        expected_blob_versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        seal_companion: SealCompanion,
    ) -> RpcResult<PayloadStatus> {
        Ok(self
            .new_payload_with_seal(
                payload,
                expected_blob_versioned_hashes,
                parent_beacon_block_root,
                &seal_companion,
            )
            .await?)
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
            .expect("the seal methods are additive and cannot conflict");
        module
    }
}

/// Builds the stock Engine API plus the seal sibling, sharing the node's build state.
///
/// The companion store is deliberately not held here. Its path comes from the node's datadir,
/// which is only reachable from the add-ons context, so the builder carries the store-independent
/// state and opens the store in [`EngineApiBuilder::build_engine_api`].
#[derive(Clone, Debug)]
pub struct UnicityEngineApiBuilder {
    state: SealBuildState,
}

impl UnicityEngineApiBuilder {
    /// Creates the builder from the store-independent state [`UnicityNode`] shares with the
    /// payload service.
    pub const fn new(state: SealBuildState) -> Self {
        Self { state }
    }
}

/// The three `engine_*WithSealV1` capability strings this node serves.
///
/// D2 requires all three to be advertised together or not at all, so this is one list and the
/// capability set is built from it in one step. A client that saw a subset would believe it could
/// complete a flow the node cannot.
pub const SEAL_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedWithSealV1",
    "engine_newPayloadWithSealV1",
    "engine_getPayloadWithSealV1",
];

/// Builds the node's capability set: the stock Ethereum list plus the three seal methods.
///
/// This is the only place a Unicity node changes the advertised set.
/// [`EngineCapabilities::default`] is left untouched, so `EthereumNode` still reports exactly the
/// stock list.
pub fn unicity_engine_capabilities() -> EngineCapabilities {
    EngineCapabilities::new(CAPABILITIES.iter().copied().chain(SEAL_CAPABILITIES.iter().copied()))
}

impl<N> EngineApiBuilder<N> for UnicityEngineApiBuilder
where
    N: FullNodeComponents<Types = UnicityNode>,
    N::Provider: HeaderProvider<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    type EngineApi = UnicityEngineApiModule<
        EngineApi<N::Provider, UnicityEngineTypes, N::Pool, UnicityEngineValidator, ChainSpec>,
        UnicityEngineApiImpl<N::Provider>,
    >;

    async fn build_engine_api(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::EngineApi> {
        // The node's datadir is only reachable from the add-ons context, so the companion store is
        // opened here rather than in `UnicityNode::add_ons`. It lives under a Unicity-specific
        // subdirectory of the chain datadir, never inside reth's own database directory, so the
        // fork never shares an MDBX environment with reth's consistency checks and migrations.
        let store_path = companion_store_path(ctx.config.datadir().data_dir());
        let store: Arc<dyn CompanionSink> = Arc::new(open_companion_store(store_path)?);
        let context = SealBuildContext { state: self.state, store };

        // Build the validator once and share it between the stock Engine API and the seal sibling.
        let validator = UnicityEngineValidatorBuilder.build(ctx).await?;
        let client = ClientVersionV1 {
            code: CLIENT_CODE,
            name: version_metadata().name_client.to_string(),
            version: version_metadata().cargo_pkg_version.to_string(),
            commit: version_metadata().vergen_git_sha.to_string(),
        };
        // `BasicEngineApiBuilder` hardcodes `EngineCapabilities::default()`. This fork builds the
        // same `EngineApi` with the three seal methods added, so the extension stays in
        // `crates/unicity` and the stock node's advertised set is untouched. The three are added in
        // one step, never incrementally.
        let inner = EngineApi::new(
            ctx.node.provider().clone(),
            ctx.config.chain.clone(),
            ctx.beacon_engine_handle.clone(),
            PayloadStore::new(ctx.node.payload_builder_handle().clone()),
            ctx.node.pool().clone(),
            ctx.node.task_executor().clone(),
            client,
            unicity_engine_capabilities(),
            validator.clone(),
            ctx.config.engine.accept_execution_requests_hash,
            ctx.node.network().clone(),
        );
        let sibling = UnicityEngineApiImpl::new(
            ctx.node.provider().clone(),
            ctx.beacon_engine_handle.clone(),
            context,
            validator,
            PayloadStore::new(ctx.node.payload_builder_handle().clone()),
        );
        Ok(UnicityEngineApiModule::new(inner, sibling))
    }
}

/// Path of the companion store under the chain's data directory.
///
/// The store is a sibling of reth's own `db` and `static_files` directories, never inside `db`, so
/// the fork never shares an MDBX environment with reth's consistency checks and migrations.
fn companion_store_path(chain_data_dir: &Path) -> PathBuf {
    chain_data_dir.join("unicity").join("companions")
}

#[cfg(test)]
mod tests {
    use super::companion_store_path;
    use std::path::Path;

    #[test]
    fn companion_store_path_is_a_unicity_subdirectory_of_the_chain_datadir() {
        assert_eq!(
            companion_store_path(Path::new("/data/mainnet")),
            Path::new("/data/mainnet/unicity/companions")
        );
    }
}
