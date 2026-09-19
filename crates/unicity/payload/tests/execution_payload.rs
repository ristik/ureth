//! Real payload-builder integration over the signed test-only genesis.

mod support;

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_genesis::Genesis;
use alloy_primitives::{b256, Address, TxKind, B256, U256};
use alloy_rpc_types_engine::PayloadAttributes as EthPayloadAttributes;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecProvider};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_evm_ethereum::EthEvmConfig;
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_storage_api::{
    BlockHashReader, BlockIdReader, BlockNumReader, StateProviderBox, StateProviderFactory,
};
use reth_storage_errors::provider::ProviderResult;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, test_utils::OkValidator, CoinbaseTipOrdering,
    EthPooledTransaction, Pool, TransactionOrigin, TransactionPool,
};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{replay_complete, BoundExecutionInput, UnicityEvmConfig},
    derive_beacon_root, derive_prev_randao, derive_timestamp, technical_record_hash, InputRecordV2,
    RootInputV2, RootOriginV2, TechnicalRecordV2, SEAL_REGISTRY,
};
use reth_unicity_payload::{
    ExecutionPayloadJobResolver, FixedPayloadJobResolver, PayloadJobResolutionError,
    ResolvedPayloadJob, UnicityExecutionPayloadBuilder, UnicityPayloadAttributes,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
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
