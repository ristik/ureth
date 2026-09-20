//! Real payload-builder integration over the signed test-only genesis.

mod support;

use alloy_consensus::{Header, SignableTransaction, TxLegacy};
use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_genesis::Genesis;
use alloy_primitives::{b256, Address, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ForkchoiceState, PayloadAttributes as EthPayloadAttributes, PayloadId,
};
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecProvider};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_evm_ethereum::EthEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadStore};
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_rpc_engine_api::EngineApiError;
use reth_storage_api::{
    BlockHashReader, BlockIdReader, BlockNumReader, HeaderProvider, StateProviderBox,
    StateProviderFactory,
};
use reth_storage_errors::provider::ProviderResult;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, test_utils::OkValidator, CoinbaseTipOrdering,
    EthPooledTransaction, Pool, TransactionOrigin, TransactionPool,
};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{replay_complete, BoundExecutionInput, UnicityEvmConfig},
    derive_beacon_root, derive_prev_randao, derive_timestamp, technical_record_hash,
    wire::SealBuildInput,
    InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2, SEAL_REGISTRY,
};
use reth_unicity_payload::{
    build_seal_companion, prepare_seal_build, refusal_response, ExecutionPayloadJobResolver,
    FixedPayloadJobResolver, PayloadJobResolutionError, ResolvedPayloadJob, SealBuildContext,
    SealBuildError, SealJobRegistry, UnicityEngineApiImpl, UnicityEngineValidator,
    UnicityExecutionPayloadBuilder, UnicityParentAccountings, UnicityPayloadAttributes,
    UnicitySealConfig, DEFAULT_SEAL_JOB_CAPACITY,
};
use std::{
    ops::RangeBounds,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use support::provider::FixtureProvider;

const GENESIS_HASH: B256 =
    b256!("82430ee9e534f0e454399cdaa06042c5dcc52b0378f48609e9c45c3cc1ae01f0");
const FEE_COLLECTOR: Address = Address::new([0x77; 20]);
const PROFILE: BlockProfile = BlockProfile {
    max_gas: 30_000_001,
    system_gas: 500_001,
    base_fee_floor: 7,
    elasticity: 2,
    change_denominator: 8,
};

fn next_base_fee(parent: u64, ordinary_used: u64) -> u64 {
    let target = (PROFILE.max_gas - PROFILE.system_gas) / PROFILE.elasticity;
    let delta = u128::from(parent) * u128::from(ordinary_used.abs_diff(target)) /
        u128::from(target) /
        u128::from(PROFILE.change_denominator);
    if ordinary_used > target {
        parent + u64::try_from(delta).unwrap().max(1)
    } else {
        parent.saturating_sub(u64::try_from(delta).unwrap()).max(PROFILE.base_fee_floor)
    }
}

#[derive(Clone, Debug)]
struct Client {
    chain_spec: Arc<ChainSpec>,
    parent_hash: B256,
    state: FixtureProvider,
}

#[derive(Clone)]
struct AlwaysResolver {
    config: UnicityEvmConfig,
    calls: Arc<AtomicUsize>,
}

impl ExecutionPayloadJobResolver for AlwaysResolver {
    fn resolve(
        &self,
        _: &PayloadConfig<UnicityPayloadAttributes>,
    ) -> Result<UnicityEvmConfig, PayloadJobResolutionError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.config.clone())
    }
}

impl ChainSpecProvider for Client {
    type ChainSpec = ChainSpec;
    fn chain_spec(&self) -> Arc<ChainSpec> {
        self.chain_spec.clone()
    }
}

impl BlockHashReader for Client {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        Ok((number == 0).then_some(self.parent_hash))
    }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        Ok((start..end).filter_map(|n| (n == 0).then_some(self.parent_hash)).collect())
    }
}

impl BlockNumReader for Client {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        Ok(ChainInfo { best_hash: self.parent_hash, best_number: 0 })
    }
    fn best_block_number(&self) -> ProviderResult<u64> {
        Ok(0)
    }
    fn last_block_number(&self) -> ProviderResult<u64> {
        Ok(0)
    }
    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        Ok((hash == self.parent_hash).then_some(0))
    }
}

impl HeaderProvider for Client {
    type Header = Header;

    fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> {
        Ok((block_hash == self.chain_spec.genesis_hash())
            .then(|| self.chain_spec.genesis_header().clone()))
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        Ok((number == 0).then(|| self.chain_spec.genesis_header().clone()))
    }

    fn headers_range(&self, _: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Header>> {
        Ok(Vec::new())
    }

    fn sealed_header(&self, number: u64) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        Ok((number == 0).then(|| {
            SealedHeader::new(
                self.chain_spec.genesis_header().clone(),
                self.chain_spec.genesis_hash(),
            )
        }))
    }

    fn sealed_headers_while(
        &self,
        _: impl RangeBounds<u64>,
        _: impl FnMut(&SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        Ok(Vec::new())
    }
}

impl BlockIdReader for Client {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash { number: 0, hash: self.parent_hash }))
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash { number: 0, hash: self.parent_hash }))
    }
}

impl StateProviderFactory for Client {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        Ok(Box::new(self.state.clone()))
    }
    fn state_by_block_number_or_tag(
        &self,
        _: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.latest()
    }
    fn history_by_block_number(&self, _: u64) -> ProviderResult<StateProviderBox> {
        self.latest()
    }
    fn history_by_block_hash(&self, _: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }
    fn state_by_block_hash(&self, hash: B256) -> ProviderResult<StateProviderBox> {
        assert_eq!(hash, self.parent_hash);
        self.latest()
    }
    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.latest()
    }
    fn pending_state_by_hash(&self, _: B256) -> ProviderResult<Option<StateProviderBox>> {
        Ok(None)
    }
    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        Ok(None)
    }
}

fn input(round: u64, root_round: u64, parent_hash: B256) -> RootInputV2 {
    let technical = TechnicalRecordV2 {
        round,
        epoch: 0,
        leader: "evm-node".into(),
        stat_hash: B256::repeat_byte(0xe0),
        fee_hash: B256::repeat_byte(0xf0),
    };
    RootInputV2 {
        version: 2,
        network_id: 3,
        partition_id: 8,
        shard_id: vec![],
        authorized_round: round,
        certified_epoch: 0,
        authorized_epoch: 0,
        parent_hash,
        origin: RootOriginV2 {
            network_id: 3,
            root_round,
            root_epoch: 1,
            reference_time: 1,
            tree_root: B256::repeat_byte(0xc0),
            input_record_version: 1,
            input_record: InputRecordV2 {
                round: round.saturating_sub(1),
                epoch: 0,
                previous_hash: (round > 1).then(|| B256::repeat_byte(0x31)),
                state_hash: (round > 1).then(|| B256::repeat_byte(0x31)),
                timestamp: u64::from(round > 1),
                block_hash: None,
            },
            tr_hash: technical_record_hash(&technical),
            shard_conf_hash: b256!(
                "4ba6ed4d7f56b668f781eb698b9ad1101d823050c677c8bc03b88b3b3b92a6ba"
            ),
        },
        technical,
        transitions: vec![],
    }
}

fn attributes(input: &RootInputV2, parent_timestamp: u64) -> UnicityPayloadAttributes {
    UnicityPayloadAttributes {
        inner: EthPayloadAttributes {
            timestamp: derive_timestamp(input.origin.reference_time, parent_timestamp).unwrap(),
            prev_randao: derive_prev_randao(input.origin.root_round, input.authorized_round),
            suggested_fee_recipient: FEE_COLLECTOR,
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(derive_beacon_root(
                input.origin.root_round,
                input.authorized_round,
            )),
            slot_number: None,
            target_gas_limit: Some(PROFILE.max_gas),
        },
        commitment: input.input_commitment().unwrap(),
    }
}

/// Builds one valid job and the attributes whose payload id selects it. Used to exercise the seal
/// job registry without a running payload service.
fn resolved_job(
    chain_spec: &Arc<ChainSpec>,
    parent: &Arc<SealedHeader>,
    root: &Arc<RootInputV2>,
    base: &EthereumBuilderConfig,
) -> (ResolvedPayloadJob, UnicityPayloadAttributes) {
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root.clone(),
            PROFILE,
            parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let evm = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), bound);
    let attrs = attributes(root, parent.timestamp);
    let job = ResolvedPayloadJob::new(parent.clone(), attrs.clone(), evm, base).unwrap();
    (job, attrs)
}

fn signed_call(
    nonce: u64,
    gas_price: u128,
    to: Address,
    value: U256,
    gas_limit: u64,
) -> TransactionSigned {
    let transaction = Transaction::Legacy(TxLegacy {
        chain_id: Some(1337),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: Default::default(),
    });
    let signature = sign_message(B256::with_last_byte(1), transaction.signature_hash()).unwrap();
    TransactionSigned::new_unhashed(transaction, signature)
}

type TestPool = Pool<
    OkValidator<EthPooledTransaction>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    InMemoryBlobStore,
>;

fn test_pool() -> TestPool {
    Pool::new(
        OkValidator::default(),
        CoinbaseTipOrdering::default(),
        InMemoryBlobStore::default(),
        Default::default(),
    )
}

async fn add(pool: &TestPool, tx: TransactionSigned) {
    let recovered = tx.try_into_recovered().unwrap();
    pool.add_transaction(TransactionOrigin::External, EthPooledTransaction::new(recovered, 200))
        .await
        .unwrap();
}

#[tokio::test]
async fn real_pool_payload_resolves_prefix_skips_oversized_and_replays() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), GENESIS_HASH));
    let mut state = FixtureProvider::signed_genesis();
    state.set_block_hash(0, GENESIS_HASH);
    let client =
        Client { chain_spec: chain_spec.clone(), parent_hash: GENESIS_HASH, state: state.clone() };
    let root = Arc::new(input(1, 1, GENESIS_HASH));
    let attrs = attributes(&root, parent.timestamp);
    let base = EthereumBuilderConfig::new()
        .with_gas_limit(PROFILE.max_gas)
        .with_await_payload_on_missing(false);
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root,
            PROFILE,
            &parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let evm = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), bound);
    let job = ResolvedPayloadJob::new(parent.clone(), attrs.clone(), evm.clone(), &base).unwrap();
    let resolver = FixedPayloadJobResolver::new(vec![job]).unwrap();
    let pool = test_pool();
    let price = u128::from(parent.base_fee_per_gas.unwrap()) + 100;
    add(&pool, signed_call(0, price, Address::repeat_byte(0x42), U256::from(1), 21_000)).await;
    add(&pool, signed_call(1, price, SEAL_REGISTRY, U256::ZERO, 100_000)).await;
    add(
        &pool,
        signed_call(
            2,
            price,
            Address::repeat_byte(0x43),
            U256::ZERO,
            PROFILE.ordinary_capacity().unwrap() + 1,
        ),
    )
    .await;
    let builder = UnicityExecutionPayloadBuilder::new(client.clone(), pool, resolver, base.clone());
    let config = PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&GENESIS_HASH));
    let args = BuildArguments::new(
        Default::default(),
        None,
        None,
        config.clone(),
        Default::default(),
        None,
    );
    let payload = match builder.try_build(args).unwrap() {
        BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) => payload,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(payload.block().body().transactions.len(), 2);
    assert_eq!(
        payload.block().header().base_fee_per_gas,
        Some(next_base_fee(parent.base_fee_per_gas.unwrap(), 0)),
    );
    let recovered = RecoveredBlock::try_new(
        payload.block().clone().into_block(),
        vec![],
        payload.block().hash(),
    )
    .unwrap();
    let replay = replay_complete(&evm, state.clone(), &state, &recovered).unwrap();
    assert_eq!(payload.block().header().gas_used, replay.output.result.gas_used);
    assert_eq!(replay.output.result.receipts.len(), 2);
    assert!(replay.output.result.receipts[0].success);
    assert!(!replay.output.result.receipts[1].success);

    let first_header = recovered.into_sealed_block().into_sealed_header();
    state.apply_bundle(&replay.output.state);
    state.set_block_hash(1, first_header.hash());
    assert_eq!(state.root(), first_header.state_root);
    let second_input = Arc::new(input(2, 2, first_header.hash()));
    let second_attrs = attributes(&second_input, first_header.timestamp);
    let second_bound = Arc::new(
        BoundExecutionInput::from_completed_parent(
            second_input,
            PROFILE,
            &first_header,
            replay.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let second_evm = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), second_bound);
    let second_job = ResolvedPayloadJob::new(
        Arc::new(first_header.clone()),
        second_attrs.clone(),
        second_evm,
        &base,
    )
    .unwrap();
    let second_client =
        Client { chain_spec, parent_hash: first_header.hash(), state: state.clone() };
    let second_builder = UnicityExecutionPayloadBuilder::new(
        second_client,
        test_pool(),
        FixedPayloadJobResolver::new(vec![second_job]).unwrap(),
        base.clone(),
    );
    let second_parent = Arc::new(first_header);
    let second_config = PayloadConfig::new(
        second_parent.clone(),
        second_attrs.clone(),
        second_attrs.payload_id(&second_parent.hash()),
    );
    let second = second_builder.build_empty_payload(second_config).unwrap();
    assert!(second.block().body().transactions.is_empty());
    assert_eq!(second.block().header().extra_data.as_ref(), second_attrs.commitment.as_slice());
    let first_ordinary = replay.output.result.receipts.last().unwrap().cumulative_gas_used;
    assert_eq!(
        second.block().header().base_fee_per_gas,
        Some(next_base_fee(second_parent.base_fee_per_gas.unwrap(), first_ordinary)),
    );

    let empty = builder.build_empty_payload(config).unwrap();
    assert!(empty.block().body().transactions.is_empty());
    assert_eq!(empty.block().header().extra_data.as_ref(), attrs.commitment.as_slice());
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let counting = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        AlwaysResolver { config: evm.clone(), calls: resolve_calls.clone() },
        base.clone(),
    );
    let counting_args = BuildArguments::new(
        Default::default(),
        None,
        None,
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash())),
        Default::default(),
        Some(empty),
    );
    counting.try_build(counting_args).unwrap();
    assert_eq!(resolve_calls.load(Ordering::Relaxed), 1, "one immutable config per attempt");
    let valid_missing_args = BuildArguments::new(
        Default::default(),
        None,
        None,
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash())),
        Default::default(),
        None,
    );
    assert!(matches!(
        builder.on_missing_payload(valid_missing_args),
        MissingPayloadBehaviour::RaceEmptyPayload
    ));

    let mut bad_attrs = attrs.clone();
    bad_attrs.commitment = B256::repeat_byte(0x99);
    let bad_config =
        PayloadConfig::new(parent.clone(), bad_attrs.clone(), bad_attrs.payload_id(&parent.hash()));
    assert!(builder.build_empty_payload(bad_config.clone()).is_err());
    let bad_args =
        BuildArguments::new(Default::default(), None, None, bad_config, Default::default(), None);
    assert!(builder.try_build(bad_args).is_err());
    let same_id_mismatch =
        PayloadConfig::new(parent.clone(), bad_attrs.clone(), attrs.payload_id(&parent.hash()));
    assert!(builder.build_empty_payload(same_id_mismatch).is_err());
    let bad_args = BuildArguments::new(
        Default::default(),
        None,
        None,
        PayloadConfig::new(parent.clone(), bad_attrs.clone(), bad_attrs.payload_id(&parent.hash())),
        Default::default(),
        None,
    );
    match builder.on_missing_payload(bad_args) {
        MissingPayloadBehaviour::RacePayload(fallback) => assert!(fallback().is_err()),
        other => panic!("unresolved fallback did not refuse: {other:?}"),
    }

    let best_args = BuildArguments::new(
        Default::default(),
        None,
        None,
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash())),
        Default::default(),
        Some(second),
    );
    assert!(builder.try_build(best_args).is_err());

    let mut forged_header = parent.header().clone();
    forged_header.state_root = B256::repeat_byte(0xee);
    let forged_parent = Arc::new(SealedHeader::new(forged_header, parent.hash()));
    let forged_config =
        PayloadConfig::new(forged_parent, attrs.clone(), attrs.payload_id(&parent.hash()));
    let custom = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        AlwaysResolver { config: evm.clone(), calls: Arc::new(AtomicUsize::new(0)) },
        base.clone(),
    );
    assert!(custom.build_empty_payload(forged_config).is_err());

    let mut alternate_input = input(1, 1, GENESIS_HASH);
    alternate_input.origin.tree_root = B256::repeat_byte(0xab);
    let alternate_input = Arc::new(alternate_input);
    let alternate_attrs = attributes(&alternate_input, parent.timestamp);
    let alternate_bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            alternate_input,
            PROFILE,
            &parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let alternate_evm =
        UnicityEvmConfig::new(EthEvmConfig::new(client.chain_spec.clone()), alternate_bound);
    assert!(ResolvedPayloadJob::new(
        parent.clone(),
        attrs.clone(),
        evm.clone(),
        &base.clone().with_skip_state_root(true),
    )
    .is_err());
    let first_job = ResolvedPayloadJob::new(parent.clone(), attrs.clone(), evm, &base).unwrap();
    let alternate_job =
        ResolvedPayloadJob::new(parent.clone(), alternate_attrs.clone(), alternate_evm, &base)
            .unwrap();
    let interleaved = UnicityExecutionPayloadBuilder::new(
        client,
        test_pool(),
        FixedPayloadJobResolver::new(vec![first_job, alternate_job]).unwrap(),
        base,
    );
    let alternate_config = PayloadConfig::new(
        parent.clone(),
        alternate_attrs.clone(),
        alternate_attrs.payload_id(&parent.hash()),
    );
    let first_config =
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash()));
    let alt_a = interleaved.build_empty_payload(alternate_config.clone()).unwrap();
    let first = interleaved.build_empty_payload(first_config).unwrap();
    let alt_b = interleaved.build_empty_payload(alternate_config).unwrap();
    assert_eq!(alt_a.block().hash(), alt_b.block().hash());
    assert_ne!(alt_a.block().header().extra_data, first.block().header().extra_data);
}

/// The production registry is the bounded replacement for [`FixedPayloadJobResolver`]: it refuses
/// a duplicate payload id, evicts the oldest insertion at capacity, and shares its entries between
/// clones so the payload service and a future seal method see the same jobs.
#[test]
fn seal_job_registry_is_bounded_shared_and_refuses_duplicates() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), GENESIS_HASH));
    let base = EthereumBuilderConfig::new()
        .with_gas_limit(PROFILE.max_gas)
        .with_await_payload_on_missing(false);

    // Three jobs on the same parent that differ only in the committed tree root, so each has a
    // distinct payload id and a matching execution configuration.
    let root_a = Arc::new(input(1, 1, GENESIS_HASH));
    let mut root_b = input(1, 1, GENESIS_HASH);
    root_b.origin.tree_root = B256::repeat_byte(0xab);
    let root_b = Arc::new(root_b);
    let mut root_c = input(1, 1, GENESIS_HASH);
    root_c.origin.tree_root = B256::repeat_byte(0xcd);
    let root_c = Arc::new(root_c);

    let (job_a, attrs_a) = resolved_job(&chain_spec, &parent, &root_a, &base);
    let (job_a_duplicate, _) = resolved_job(&chain_spec, &parent, &root_a, &base);
    let (job_b, attrs_b) = resolved_job(&chain_spec, &parent, &root_b, &base);
    let (job_c, attrs_c) = resolved_job(&chain_spec, &parent, &root_c, &base);

    let config = |attrs: &UnicityPayloadAttributes| {
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash()))
    };

    assert_eq!(SealJobRegistry::new().capacity(), DEFAULT_SEAL_JOB_CAPACITY);

    // Capacity only grows, so a later smaller configuration cannot evict a held job.
    let grown = SealJobRegistry::with_capacity(2);
    grown.grow_capacity(5);
    assert_eq!(grown.capacity(), 5);
    grown.grow_capacity(3);
    assert_eq!(grown.capacity(), 5, "capacity never shrinks");

    let registry = SealJobRegistry::with_capacity(2);
    assert!(registry.is_empty());
    registry.insert(job_a).unwrap();
    assert_eq!(registry.len(), 1);
    assert!(registry.insert(job_a_duplicate).is_err(), "duplicate payload id must be refused");
    assert_eq!(registry.len(), 1, "a refused duplicate must not displace the held job");
    assert!(registry.resolve(&config(&attrs_a)).is_ok());

    registry.insert(job_b).unwrap();
    assert_eq!(registry.len(), 2);
    assert!(registry.resolve(&config(&attrs_b)).is_ok());

    // The registry is full, so inserting a third job evicts the oldest insertion.
    registry.insert(job_c).unwrap();
    assert_eq!(registry.len(), 2, "the registry stays bounded");
    assert!(registry.resolve(&config(&attrs_a)).is_err(), "the oldest job was evicted");
    assert!(registry.resolve(&config(&attrs_b)).is_ok());
    assert!(registry.resolve(&config(&attrs_c)).is_ok());

    // All clones share one registry, which is what lets the payload service and the method that
    // inserts a job observe the same entries.
    let shared = registry.clone();
    shared.clear();
    assert!(registry.is_empty());
    let (job_d, attrs_d) = resolved_job(&chain_spec, &parent, &root_a, &base);
    registry.insert(job_d).unwrap();
    assert!(shared.resolve(&config(&attrs_d)).is_ok());
}
/// A genesis-parent fixture for the seal build handler.
///
/// The provider serves only the genesis header, and the state is the signed real genesis so a job
/// inserted by the handler can be resolved and built.
fn seal_fixture() -> (
    Client,
    Arc<SealedHeader>,
    RootInputV2,
    UnicityPayloadAttributes,
    SealBuildContext,
    UnicityEngineValidator,
) {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let validator = UnicityEngineValidator::new(chain_spec.clone());
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), GENESIS_HASH));
    let mut state = FixtureProvider::signed_genesis();
    state.set_block_hash(0, GENESIS_HASH);
    let client = Client { chain_spec, parent_hash: GENESIS_HASH, state };
    let root = input(1, 1, GENESIS_HASH);
    let attrs = attributes(&root, parent.timestamp);
    let builder_config = Arc::new(OnceLock::new());
    builder_config
        .set(
            EthereumBuilderConfig::new()
                .with_gas_limit(PROFILE.max_gas)
                .with_await_payload_on_missing(false),
        )
        .unwrap();
    let context = SealBuildContext {
        registry: SealJobRegistry::new(),
        builder_config,
        seal: UnicitySealConfig { profile: PROFILE, fee_collector: FEE_COLLECTOR },
        parent_accounting: UnicityParentAccountings::default(),
    };
    (client, parent, root, attrs, context, validator)
}

fn seal_input(root: &RootInputV2) -> SealBuildInput {
    SealBuildInput { root_input: root.canonical_cbor().unwrap().into(), transitions: vec![] }
}

#[test]
fn seal_build_rejects_non_canonical_root_input_as_invalid() {
    let (client, _parent, _root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(GENESIS_HASH);
    let bad = SealBuildInput { root_input: vec![0x80].into(), transitions: vec![] };

    let error =
        prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &bad).unwrap_err();
    assert!(matches!(error, SealBuildError::RootInput(_)));

    let response = refusal_response(error).unwrap();
    assert!(response.payload_status.is_invalid());
    assert!(response
        .payload_status
        .status
        .validation_error()
        .unwrap()
        .contains("canonical root input"));
    assert!(context.registry.is_empty());
}

#[test]
fn seal_build_rejects_malformed_attributes_as_invalid_before_inserting() {
    let (client, _parent, root, mut attrs, context, validator) = seal_fixture();
    // Cancun requires withdrawals in the attributes; ResolvedPayloadJob alone would tolerate a
    // missing list, so this exercises the validator parity.
    attrs.inner.withdrawals = None;
    let state = ForkchoiceState::same_hash(GENESIS_HASH);

    let error =
        prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &seal_input(&root))
            .unwrap_err();
    assert!(matches!(error, SealBuildError::Attributes(_)));
    assert!(context.registry.is_empty(), "the refusal must happen before any job is inserted");

    let response = refusal_response(error).unwrap();
    assert!(response.payload_status.is_invalid());
    assert!(response.payload_status.status.validation_error().is_some());
}

#[test]
fn seal_build_reports_an_unknown_parent_as_syncing() {
    let (client, _parent, root, attrs, context, validator) = seal_fixture();
    let unknown = ForkchoiceState::same_hash(B256::repeat_byte(0x99));

    let error = prepare_seal_build(
        &client,
        &context,
        &validator,
        &unknown,
        Some(&attrs),
        &seal_input(&root),
    )
    .unwrap_err();
    assert_eq!(error, SealBuildError::UnknownParent);
    assert!(refusal_response(error).unwrap().is_syncing());
    assert!(context.registry.is_empty());
}

#[test]
fn seal_build_requires_payload_attributes() {
    let (client, _parent, root, _attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(GENESIS_HASH);

    let error = prepare_seal_build(&client, &context, &validator, &state, None, &seal_input(&root))
        .unwrap_err();
    assert_eq!(error, SealBuildError::AttributesMissing);

    let response = refusal_response(error).unwrap();
    assert_eq!(
        response.payload_status.status.validation_error(),
        Some("payload attributes are required")
    );
    assert!(context.registry.is_empty());
}

#[test]
fn seal_build_refuses_a_duplicate_payload_id() {
    let (client, _parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(GENESIS_HASH);
    let input = seal_input(&root);

    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &input).unwrap();
    let error = prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &input)
        .unwrap_err();
    assert_eq!(error, SealBuildError::DuplicatePayloadId);
    assert_eq!(
        refusal_response(error).unwrap().payload_status.status.validation_error(),
        Some("duplicate payload id")
    );
    assert_eq!(context.registry.len(), 1);
}

#[test]
fn seal_build_job_resolves_with_the_published_builder_config() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(GENESIS_HASH);

    let returned =
        prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &seal_input(&root))
            .unwrap();
    assert_eq!(returned, attrs);
    assert_eq!(context.registry.len(), 1);

    // The payload service resolves the job through the exact configuration the handler published
    // into the job, and the built block carries the commitment the attributes named.
    let base = context.builder_config.get().unwrap().clone();
    let accounting = context.parent_accounting.clone();
    let builder = UnicityExecutionPayloadBuilder::new(client, test_pool(), context.registry, base)
        .with_parent_accounting(accounting.clone());
    let config =
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash()));
    let payload = builder.build_empty_payload(config).unwrap();
    assert_eq!(payload.block().header().extra_data.as_ref(), attrs.commitment.as_slice());
    assert!(
        accounting.get(&payload.block().hash()).is_some(),
        "the build must publish its parent token for the next block"
    );

    // The token store is bounded and evicts the oldest insertion.
    let bounded = UnicityParentAccountings::with_capacity(1);
    let token = accounting.get(&payload.block().hash()).unwrap();
    bounded.insert(B256::repeat_byte(0x01), token);
    bounded.insert(B256::repeat_byte(0x02), token);
    assert!(bounded.get(&B256::repeat_byte(0x01)).is_none());
    assert!(bounded.get(&B256::repeat_byte(0x02)).is_some());
}

#[test]
fn get_payload_companion_reencodes_exactly_the_caller_bytes() {
    let (_client, _parent, root, _attrs, _context, _validator) = seal_fixture();
    let input = seal_input(&root);
    // The decoder accepts only canonical encodings, so re-encoding the decoded value must equal the
    // bytes the caller supplied to forkchoiceUpdatedWithSealV1.
    let decoded = input.decode_root_input().unwrap();
    let companion = build_seal_companion(&decoded).unwrap();
    assert_eq!(companion.root_input, input.root_input);
    assert_eq!(companion.provenance, "build");
    assert!(companion.witnesses.is_empty(), "the build input carries no witnesses");
}

#[tokio::test]
async fn get_payload_with_seal_refuses_an_unknown_payload_id() {
    let (client, _parent, _root, _attrs, context, validator) = seal_fixture();
    // The store's service receiver is dropped, so every request resolves as absent, which is the
    // same shape as an unknown payload id.
    let (beacon_tx, _beacon_rx) = tokio::sync::mpsc::unbounded_channel();
    let (store_tx, store_rx) = tokio::sync::mpsc::unbounded_channel();
    drop(store_rx);
    let handler = UnicityEngineApiImpl::new(
        client,
        ConsensusEngineHandle::new(beacon_tx),
        context,
        validator,
        PayloadStore::new(PayloadBuilderHandle::new(store_tx)),
    );
    let error = handler.get_payload_with_seal(PayloadId::new([0x11; 8])).await.unwrap_err();
    assert!(matches!(error, EngineApiError::UnknownPayload));
}
