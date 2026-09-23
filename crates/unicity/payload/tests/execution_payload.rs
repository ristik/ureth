//! Real payload-builder integration over the signed test-only genesis.

mod support;

use alloy_consensus::{Header, SignableTransaction, TxLegacy};
use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_genesis::Genesis;
use alloy_primitives::{b256, Address, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayloadV3, ForkchoiceState, PayloadAttributes as EthPayloadAttributes,
    PayloadId, PayloadStatus, PayloadStatusEnum,
};
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecProvider};
use reth_consensus::{Consensus, ConsensusError, HeaderValidator};
use reth_consensus_common::validation::validate_against_parent_eip1559_base_fee;
use reth_engine_primitives::{BeaconEngineMessage, ConsensusEngineHandle};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_payload_builder::{
    EthBuiltPayload, PayloadBuilderHandle, PayloadServiceCommand, PayloadStore,
};
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_rpc_engine_api::{capabilities::EngineCapabilities, EngineApiError};
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
    block_executor::{
        replay_complete, BoundExecutionInput, UnicityEvmConfig, MISSING_EXECUTION_INPUT_ERROR,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    node_evm::{
        BlockExecutionRegistryError, UnicityBlockExecutionRegistry, UnicityNodeEvmConfig,
        UnicityNodeEvmError,
    },
    technical_record_hash,
    wire::{SealBuildInput, SealCompanion},
    InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2, SEAL_REGISTRY,
};
use reth_unicity_payload::{
    build_seal_companion, prepare_seal_build, refusal_response, unicity_engine_capabilities,
    CompanionPruner, CompanionSink, ExecutionPayloadJobResolver, FixedPayloadJobResolver,
    PayloadJobResolutionError, ResolvedPayloadJob, SealBuildContext, SealBuildError,
    SealBuildState, SealCompanionLookup, SealJobRegistry, UnicityConsensus, UnicityEngineApiImpl,
    UnicityEngineTypes, UnicityEngineValidator, UnicityExecutionPayloadBuilder, UnicityNode,
    UnicityParentAccountings, UnicityPayloadAttributes, UnicityRetentionConfig,
    UnicityRpcModuleImpl, UnicityRpcServer, UnicitySealConfig, COMPANION_NOT_RETAINED_CODE,
    DEFAULT_SEAL_JOB_CAPACITY, SEAL_CAPABILITIES,
};
use reth_unicity_store::{open as open_companion_store, CompanionStore, Lookup, StoreError};
use std::{
    ops::RangeBounds,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use support::provider::FixtureProvider;
use tempfile::tempdir;

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
    extra_headers: Vec<Header>,
    finalized: u64,
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
        if number == 0 {
            return Ok(Some(self.parent_hash));
        }
        // The pruner compares an entry's hash to the canonical hash at its number, so the mock
        // serves every header it was given by number.
        Ok(self
            .extra_headers
            .iter()
            .find(|header| header.number == number)
            .map(|header| header.hash_slow()))
    }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        let mut hashes = Vec::new();
        for number in start..end {
            if let Some(hash) = self.block_hash(number)? {
                hashes.push(hash);
            }
        }
        Ok(hashes)
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
        if hash == self.parent_hash {
            return Ok(Some(0));
        }
        // The read-surface tests serve canonical headers above genesis through `extra_headers`,
        // so a hash in that set resolves to the number it carries.
        Ok(self
            .extra_headers
            .iter()
            .find(|header| header.hash_slow() == hash)
            .map(|header| header.number))
    }
}

impl HeaderProvider for Client {
    type Header = Header;

    fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> {
        if block_hash == self.chain_spec.genesis_hash() {
            return Ok(Some(self.chain_spec.genesis_header().clone()))
        }
        Ok(self.extra_headers.iter().find(|header| header.hash_slow() == block_hash).cloned())
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        if number == 0 {
            return Ok(Some(self.chain_spec.genesis_header().clone()))
        }
        Ok(self.extra_headers.iter().find(|header| header.number == number).cloned())
    }

    fn headers_range(&self, _: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Header>> {
        Ok(Vec::new())
    }

    fn sealed_header(&self, number: u64) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        Ok(self.header_by_number(number)?.map(|header| {
            let hash = header.hash_slow();
            SealedHeader::new(header, hash)
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
        // A real chain always has a finalized block once finality exists. The hash is the canonical
        // one when the mock was given a header at that number; the pruner only reads the number.
        let hash = self.block_hash(self.finalized)?.unwrap_or_default();
        Ok(Some(BlockNumHash { number: self.finalized, hash }))
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
    let client = Client {
        chain_spec: chain_spec.clone(),
        parent_hash: GENESIS_HASH,
        state: state.clone(),
        extra_headers: Vec::new(),
        finalized: 0,
    };
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
    let second_client = Client {
        chain_spec: chain_spec.clone(),
        parent_hash: first_header.hash(),
        state: state.clone(),
        extra_headers: Vec::new(),
        finalized: 0,
    };
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

    let accounting = UnicityParentAccountings::with_capacity(1);
    let consensus = UnicityConsensus::new(chain_spec.clone(), PROFILE, accounting.clone());
    let child = second.block().clone().into_sealed_header();
    let unavailable = consensus.validate_header_against_parent(&child, &second_parent).unwrap_err();
    assert!(consensus.is_validation_unavailable(&unavailable));
    accounting.insert_for_chain(
        second_parent.hash(),
        replay.parent,
        chain_spec.chain().id(),
        chain_spec.genesis_hash(),
    );
    assert!(consensus.validate_header_against_parent(&child, &second_parent).is_ok());
    let stock_fee = match validate_against_parent_eip1559_base_fee(
        child.header(),
        second_parent.header(),
        &chain_spec,
    ) {
        Err(ConsensusError::BaseFeeDiff(diff)) => diff.expected,
        other => panic!("stock parent fee must disagree with ordinary-only fee: {other:?}"),
    };
    let lease = reth_unicity_payload::ParentAccountingResolver::resolve(
        &accounting,
        &second_parent,
        &chain_spec,
        PROFILE,
    )
    .unwrap();
    assert_eq!(lease.next_fee(), child.base_fee_per_gas.unwrap());
    accounting.insert_for_chain(
        B256::repeat_byte(0xfa),
        replay.parent,
        chain_spec.chain().id(),
        chain_spec.genesis_hash(),
    );
    assert!(
        reth_unicity_payload::ParentAccountingResolver::resolve(
            &accounting,
            &second_parent,
            &chain_spec,
            PROFILE,
        )
        .is_ok(),
        "an active parent must survive capacity eviction"
    );
    drop(lease);
    accounting.insert_for_chain(
        B256::repeat_byte(0xfb),
        replay.parent,
        chain_spec.chain().id(),
        chain_spec.genesis_hash(),
    );
    assert!(reth_unicity_payload::ParentAccountingResolver::resolve(
        &accounting,
        &second_parent,
        &chain_spec,
        PROFILE,
    )
    .is_err());
    accounting.insert_for_chain(
        second_parent.hash(),
        replay.parent,
        chain_spec.chain().id(),
        chain_spec.genesis_hash(),
    );
    let expected_fee = child.base_fee_per_gas.unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let accounting = accounting.clone();
            let chain_spec = chain_spec.clone();
            let second_parent = second_parent.clone();
            scope.spawn(move || {
                let lease = reth_unicity_payload::ParentAccountingResolver::resolve(
                    &accounting,
                    &second_parent,
                    &chain_spec,
                    PROFILE,
                )
                .unwrap();
                assert_eq!(lease.next_fee(), expected_fee);
            });
        }
    });
    let mut forged_parent = second_parent.header().clone();
    forged_parent.state_root = B256::repeat_byte(0xed);
    let forged_parent = SealedHeader::new(forged_parent, second_parent.hash());
    assert!(reth_unicity_payload::ParentAccountingResolver::resolve(
        &accounting,
        &forged_parent,
        &chain_spec,
        PROFILE,
    )
    .is_err());
    assert!(reth_unicity_payload::ParentAccountingResolver::resolve(
        &accounting,
        &second_parent,
        &chain_spec,
        BlockProfile { base_fee_floor: PROFILE.base_fee_floor + 1, ..PROFILE },
    )
    .is_err());

    let mut wrong_fee = child.header().clone();
    wrong_fee.base_fee_per_gas = Some(stock_fee);
    let wrong_fee = SealedHeader::new(wrong_fee.clone(), wrong_fee.hash_slow());
    assert!(matches!(
        consensus.validate_header_against_parent(&wrong_fee, &second_parent),
        Err(ConsensusError::BaseFeeDiff(_))
    ));
    for change in 0..5 {
        let mut invalid = child.header().clone();
        match change {
            0 => invalid.parent_hash = B256::repeat_byte(0xee),
            1 => invalid.number += 1,
            2 => invalid.timestamp = second_parent.timestamp,
            3 => invalid.gas_limit = second_parent.gas_limit / 2,
            4 => invalid.excess_blob_gas = invalid.excess_blob_gas.map(|gas| gas + 1),
            _ => unreachable!(),
        }
        let invalid = SealedHeader::new(invalid.clone(), invalid.hash_slow());
        assert!(
            consensus.validate_header_against_parent(&invalid, &second_parent).is_err(),
            "non-fee check {change}"
        );
    }

    let empty = builder.build_empty_payload(config).unwrap();
    assert!(empty.block().body().transactions.is_empty());
    assert_eq!(empty.block().header().extra_data.as_ref(), attrs.commitment.as_slice());
    let alternate_parent = empty.block().clone().into_sealed_header();
    assert_eq!(alternate_parent.number, second_parent.number);
    assert_ne!(alternate_parent.hash(), second_parent.hash());
    let alternate_token = evm.completed_parent_for(empty.block()).unwrap();
    let branch_accounting = UnicityParentAccountings::with_capacity(2);
    for (header, token) in [(&*second_parent, replay.parent), (&alternate_parent, alternate_token)]
    {
        branch_accounting.insert_for_chain(
            header.hash(),
            token,
            chain_spec.chain().id(),
            chain_spec.genesis_hash(),
        );
        let lease = reth_unicity_payload::ParentAccountingResolver::resolve(
            &branch_accounting,
            header,
            &chain_spec,
            PROFILE,
        )
        .unwrap();
        assert_eq!(lease.next_fee(), token.checked_next_base_fee(header, PROFILE).unwrap(),);
    }
    assert!(branch_accounting.get(&second_parent.hash()).is_some());
    assert!(branch_accounting.get(&alternate_parent.hash()).is_some());
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
    let client = Client {
        chain_spec,
        parent_hash: GENESIS_HASH,
        state,
        extra_headers: Vec::new(),
        finalized: 0,
    };
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
        state: SealBuildState {
            registry: SealJobRegistry::new(),
            builder_config,
            seal: UnicitySealConfig { profile: PROFILE, fee_collector: FEE_COLLECTOR },
            parent_accounting: UnicityParentAccountings::default(),
            execution_inputs: UnicityBlockExecutionRegistry::default(),
            retention: UnicityRetentionConfig::default(),
        },
        store: Arc::new(NoopCompanionSink),
    };
    (client, parent, root, attrs, context, validator)
}

/// A sink that accepts every write and stores nothing.
///
/// The shared fixture uses it so tests that do not exercise retention stay uniform and do not each
/// have to own a temporary store. Tests that do assert retention replace `context.store` with a
/// real [`CompanionStore`] or a [`FailingCompanionSink`].
#[derive(Debug)]
struct NoopCompanionSink;

impl CompanionSink for NoopCompanionSink {
    fn put(
        &self,
        _block_hash: B256,
        _block_number: u64,
        _companion: &SealCompanion,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

/// A sink whose every write fails.
///
/// This is the seam the write-failure test needs: a real store cannot be made to fail a single
/// write deterministically. It is one trait method, added for the test rather than for production.
#[derive(Debug)]
struct FailingCompanionSink;

impl CompanionSink for FailingCompanionSink {
    fn put(
        &self,
        _block_hash: B256,
        _block_number: u64,
        _companion: &SealCompanion,
    ) -> Result<(), StoreError> {
        Err(StoreError::Io(std::io::Error::other("forced store failure")))
    }
}

/// Opens a fresh, empty companion store in a temporary directory.
///
/// The returned [`tempfile::TempDir`] must be kept alive: dropping it removes the directory the
/// environment lives in.
fn temp_store() -> (tempfile::TempDir, Arc<CompanionStore>) {
    let dir = tempdir().unwrap();
    let store = Arc::new(open_companion_store(dir.path()).unwrap());
    (dir, store)
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
    assert!(refusal_response(SealBuildError::ParentAccountingUnavailable).unwrap().is_syncing());
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
    let builder =
        UnicityExecutionPayloadBuilder::new(client, test_pool(), context.registry.clone(), base)
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

/// Serves one already-built payload from a payload store, so the getPayload path can be exercised
/// without a running payload service.
async fn serve_resolved_payload(
    mut commands: tokio::sync::mpsc::UnboundedReceiver<PayloadServiceCommand<UnicityEngineTypes>>,
    payload: EthBuiltPayload,
) {
    while let Some(command) = commands.recv().await {
        match command {
            PayloadServiceCommand::PayloadTimestamp(_, tx) => {
                let _ = tx.send(Some(Ok(payload.block().header().timestamp)));
            }
            PayloadServiceCommand::Resolve(_, _, tx) => {
                let payload = payload.clone();
                let _ = tx.send(Some(Box::pin(async move { Ok(payload) })));
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn get_payload_with_seal_names_an_evicted_companion() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(GENESIS_HASH);
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &seal_input(&root))
        .unwrap();

    // Build the payload, then drop its job from the registry so the payload exists but its
    // companion input is gone.
    let base = context.builder_config.get().unwrap().clone();
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        base,
    );
    let payload =
        builder.build_empty_payload(PayloadConfig::new(parent, attrs, payload_id)).unwrap();
    context.registry.clear();
    assert!(context.registry.root_input(&payload_id).is_none());

    let (store_tx, store_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_resolved_payload(store_rx, payload));
    let (beacon_tx, _beacon_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = UnicityEngineApiImpl::new(
        client,
        ConsensusEngineHandle::new(beacon_tx),
        context,
        validator,
        PayloadStore::new(PayloadBuilderHandle::new(store_tx)),
    );
    let error = handler.get_payload_with_seal(payload_id).await.unwrap_err();
    match error {
        EngineApiError::Other(error) => {
            assert_eq!(error.code(), COMPANION_NOT_RETAINED_CODE);
            assert!(error.message().contains("no longer retained"));
        }
        other => panic!("expected the evicted-companion error, got {other:?}"),
    }
}

/// Builds the first post-genesis block through the payload service path, so the import tests have a
/// real block whose state root and gas accounting are correct.
fn build_genesis_seal_payload(
    client: &Client,
    parent: &Arc<SealedHeader>,
    root: &RootInputV2,
    attrs: &UnicityPayloadAttributes,
    context: &SealBuildContext,
    validator: &UnicityEngineValidator,
) -> EthBuiltPayload {
    prepare_seal_build(
        client,
        context,
        validator,
        &ForkchoiceState::same_hash(GENESIS_HASH),
        Some(attrs),
        &seal_input(root),
    )
    .unwrap();
    let base = context.builder_config.get().unwrap().clone();
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        base,
    );
    builder
        .build_empty_payload(PayloadConfig::new(
            parent.clone(),
            attrs.clone(),
            attrs.payload_id(&parent.hash()),
        ))
        .unwrap()
}

/// Converts a built block into the `ExecutionPayloadV3` the import method accepts, plus the
/// companion for `root` and the block's parent beacon root.
///
/// `mutate` runs on the block before conversion, so a test can tamper with one header field and
/// keep the payload's `blockHash` consistent with the tampered block.
fn payload_for_import(
    payload: &EthBuiltPayload,
    root: &RootInputV2,
    mutate: impl FnOnce(&mut Header),
) -> (ExecutionPayloadV3, SealCompanion, B256) {
    let mut block = payload.block().clone().into_block();
    mutate(&mut block.header);
    let block_hash = block.header.hash_slow();
    let execution_payload = ExecutionPayloadV3::from_block_unchecked(block_hash, &block);
    let beacon_root = block.header.parent_beacon_block_root.unwrap();
    let companion = build_seal_companion(root).unwrap();
    (execution_payload, companion, beacon_root)
}

/// The block hash an `ExecutionPayloadV3` declares to the caller.
///
/// This is the key a client knows and would look a companion up by. The retention tests use it
/// rather than the pre-conversion built block, so a divergence between the hash the method reports
/// and the hash it stores under cannot pass unnoticed.
const fn declared_block_hash(payload: &ExecutionPayloadV3) -> B256 {
    payload.payload_inner.payload_inner.block_hash
}

/// Builds the import handler over a consensus handle and a closed payload store. The import path
/// does not use the payload store; only the forward uses the consensus handle.
fn seal_import_handler(
    client: Client,
    context: SealBuildContext,
    validator: UnicityEngineValidator,
    beacon_consensus: ConsensusEngineHandle<UnicityEngineTypes>,
) -> UnicityEngineApiImpl<Client> {
    let (store_tx, _store_rx) = tokio::sync::mpsc::unbounded_channel();
    UnicityEngineApiImpl::new(
        client,
        beacon_consensus,
        context,
        validator,
        PayloadStore::new(PayloadBuilderHandle::new(store_tx)),
    )
}

/// A consensus handle whose receiver is dropped, for refusals that never reach the forward.
fn closed_engine() -> ConsensusEngineHandle<UnicityEngineTypes> {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    ConsensusEngineHandle::new(tx)
}

/// A fake consensus engine that replies to every `NewPayload` with `status` and reports the first
/// payload it saw on the returned receiver.
///
/// This exercises the forward without booting a node. It is not a real engine and does not execute
/// or persist anything.
async fn fake_engine(
    status: PayloadStatus,
) -> (ConsensusEngineHandle<UnicityEngineTypes>, tokio::sync::oneshot::Receiver<ExecutionData>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut seen_tx = Some(seen_tx);
        while let Some(message) = rx.recv().await {
            if let BeaconEngineMessage::NewPayload { payload, tx: reply } = message {
                if let Some(seen_tx) = seen_tx.take() {
                    let _ = seen_tx.send(payload);
                }
                let _ = reply.send(Ok(status.clone()));
            }
        }
    });
    (ConsensusEngineHandle::new(tx), seen_rx)
}

/// Builds the genesis-bound execution input for `root`.
fn bound_input(root: &RootInputV2, parent: &Arc<SealedHeader>) -> Arc<BoundExecutionInput> {
    Arc::new(
        BoundExecutionInput::from_validated_genesis(
            Arc::new(root.clone()),
            PROFILE,
            parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    )
}

/// Returns a copy of `root` with a different tree root, so it has a different commitment.
fn root_with_tree_root(root: &RootInputV2, tree_root: B256) -> RootInputV2 {
    let mut next = root.clone();
    next.origin.tree_root = tree_root;
    next
}

#[tokio::test]
async fn new_payload_with_seal_imports_a_built_block_and_records_its_token() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let commitment = B256::from_slice(&payload.block().header().extra_data);
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});

    let (engine, seen) =
        fake_engine(PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash))).await;
    let handler = seal_import_handler(client, context.clone(), validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_valid());
    assert_eq!(status.latest_valid_hash, Some(block_hash));
    assert!(!matches!(status.status, PayloadStatusEnum::Accepted));
    assert!(
        context.parent_accounting.get(&block_hash).is_some(),
        "the import must record the accounting token for the imported block"
    );
    assert!(
        context.execution_inputs.get(&commitment).is_some(),
        "the import must register the bound input for the engine to resolve"
    );
    // The forward actually reached the engine with this block.
    assert_eq!(seen.await.unwrap().block_hash(), block_hash);
}

#[tokio::test]
async fn new_payload_with_seal_stores_the_companion_of_an_accepted_import() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (_dir, store) = temp_store();
    context.store = store.clone();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});
    // The key a client knows, taken from the payload it sends rather than the pre-conversion block.
    let client_hash = declared_block_hash(&execution_payload);

    let (engine, _seen) =
        fake_engine(PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash))).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_valid());

    match store.get(client_hash).unwrap() {
        Lookup::Found(found) => assert_eq!(found, companion),
        other => panic!("expected the accepted companion to be stored, got {other:?}"),
    }
}

#[tokio::test]
async fn new_payload_with_seal_leaves_no_entry_for_a_rejected_import() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (_dir, store) = temp_store();
    context.store = store.clone();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});
    let client_hash = declared_block_hash(&execution_payload);

    // The handler resolves and forwards the block, and the engine rejects it. This is the case
    // where the write-on-VALID-only rule matters, because the forward did happen.
    let rejected = PayloadStatus::from_status(PayloadStatusEnum::Invalid {
        validation_error: "engine verdict".into(),
    });
    let (engine, _seen) = fake_engine(rejected.clone()).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert_eq!(status, rejected);
    assert!(status.is_invalid());

    // No horizon is set, so an absent hash is exactly Unknown rather than Unavailable.
    match store.get(client_hash).unwrap() {
        Lookup::Unknown => {}
        other => panic!("a rejected import must leave no entry, got {other:?}"),
    }
}

#[tokio::test]
async fn new_payload_with_seal_leaves_no_entry_for_a_syncing_import() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (_dir, store) = temp_store();
    context.store = store.clone();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});
    let client_hash = declared_block_hash(&execution_payload);

    // The handler forwards the block and the engine answers SYNCING. SYNCING is not VALID, so the
    // write-on-VALID-only rule must skip it. This is the case a reader of the comment would ask
    // about, because the import was not rejected and might look like something to retain.
    let syncing = PayloadStatus::from_status(PayloadStatusEnum::Syncing);
    let (engine, _seen) = fake_engine(syncing.clone()).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert_eq!(status, syncing);
    assert!(status.is_syncing());

    match store.get(client_hash).unwrap() {
        Lookup::Unknown => {}
        other => panic!("a syncing import must leave no entry, got {other:?}"),
    }
}

#[tokio::test]
async fn a_failing_store_write_does_not_change_a_valid_verdict() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    context.store = Arc::new(FailingCompanionSink);
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});

    let (engine, _seen) =
        fake_engine(PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash))).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_valid(), "a store failure must not change the engine's VALID verdict");
    assert_eq!(status.latest_valid_hash, Some(block_hash));
}

#[tokio::test]
async fn get_payload_with_seal_stores_the_companion_it_returns() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (_dir, store) = temp_store();
    context.store = store.clone();

    let state = ForkchoiceState::same_hash(GENESIS_HASH);
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &seal_input(&root))
        .unwrap();
    let base = context.builder_config.get().unwrap().clone();
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        base,
    );
    let payload =
        builder.build_empty_payload(PayloadConfig::new(parent, attrs, payload_id)).unwrap();
    let expected = build_seal_companion(&root).unwrap();

    let (store_tx, store_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_resolved_payload(store_rx, payload));
    let (beacon_tx, _beacon_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = UnicityEngineApiImpl::new(
        client,
        ConsensusEngineHandle::new(beacon_tx),
        context,
        validator,
        PayloadStore::new(PayloadBuilderHandle::new(store_tx)),
    );

    let response = handler.get_payload_with_seal(payload_id).await.unwrap();
    assert_eq!(response.seal_companion, expected);
    // Look up by the hash in the response, not the pre-conversion block. If the method reported a
    // different hash than it keyed the store with, this must fail.
    match store.get(declared_block_hash(&response.execution_payload)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, response.seal_companion),
        other => panic!("expected the returned companion to be stored, got {other:?}"),
    }
}

#[tokio::test]
async fn a_failing_store_write_does_not_change_the_get_payload_response() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    context.store = Arc::new(FailingCompanionSink);

    let state = ForkchoiceState::same_hash(GENESIS_HASH);
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &seal_input(&root))
        .unwrap();
    let base = context.builder_config.get().unwrap().clone();
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        base,
    );
    let payload =
        builder.build_empty_payload(PayloadConfig::new(parent, attrs, payload_id)).unwrap();

    let (store_tx, store_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_resolved_payload(store_rx, payload));
    let (beacon_tx, _beacon_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = UnicityEngineApiImpl::new(
        client,
        ConsensusEngineHandle::new(beacon_tx),
        context,
        validator,
        PayloadStore::new(PayloadBuilderHandle::new(store_tx)),
    );

    let response = handler.get_payload_with_seal(payload_id).await.unwrap();
    assert_eq!(response.seal_companion, build_seal_companion(&root).unwrap());
}

#[tokio::test]
async fn new_payload_with_seal_returns_the_engine_verdict() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});

    let engine_status = PayloadStatus::from_status(PayloadStatusEnum::Invalid {
        validation_error: "engine verdict".into(),
    });
    let (engine, _seen) = fake_engine(engine_status.clone()).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert_eq!(status, engine_status, "the handler must return the engine's verdict");
}

#[tokio::test]
async fn new_payload_with_seal_rejects_a_state_root_mismatch() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &root, |header| {
            header.state_root = B256::repeat_byte(0x99);
        });

    let handler = seal_import_handler(client, context.clone(), validator, closed_engine());
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_invalid());
    assert!(status.status.validation_error().unwrap().contains("state root"));
    assert!(!matches!(status.status, PayloadStatusEnum::Accepted));
    assert!(context.parent_accounting.is_empty(), "a rejected import records nothing");
    assert!(context.execution_inputs.is_empty(), "a rejected import registers nothing");
}

#[tokio::test]
async fn new_payload_with_seal_reports_a_missing_parent_as_syncing() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &root, |header| {
            header.parent_hash = B256::repeat_byte(0x99);
        });

    let handler = seal_import_handler(client, context.clone(), validator, closed_engine());
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_syncing());
    assert!(!matches!(status.status, PayloadStatusEnum::Accepted));
    assert!(context.parent_accounting.is_empty());
}

#[tokio::test]
async fn new_payload_with_seal_reports_a_parent_without_a_token_as_syncing() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    // A local non-genesis parent that this node has never seal-executed.
    let mut orphan_header = payload.block().header().clone();
    orphan_header.number = 7;
    let orphan_hash = orphan_header.hash_slow();
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &root, |header| {
            header.parent_hash = orphan_hash;
        });

    let client = Client { extra_headers: vec![orphan_header], ..client };
    let handler = seal_import_handler(client, context.clone(), validator, closed_engine());
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_syncing(), "a local parent without a token is a sync condition");
    assert!(!matches!(status.status, PayloadStatusEnum::Accepted));
    assert!(context.parent_accounting.is_empty());
}

#[tokio::test]
async fn new_payload_with_seal_rejects_blob_versioned_hashes() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});

    let handler = seal_import_handler(client, context.clone(), validator, closed_engine());
    let status = handler
        .new_payload_with_seal(
            execution_payload,
            vec![B256::repeat_byte(0x01)],
            beacon_root,
            &companion,
        )
        .await
        .unwrap();
    assert!(status.is_invalid());
    assert!(status.status.validation_error().unwrap().contains("blob versioned hashes"));
    assert!(context.parent_accounting.is_empty());
}

#[tokio::test]
async fn new_payload_with_seal_rejects_a_malformed_root_input() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, _companion, beacon_root) = payload_for_import(&payload, &root, |_| {});
    let malformed = SealCompanion {
        root_input: vec![0x80].into(),
        witnesses: vec![],
        provenance: "newPayload".into(),
    };

    let handler = seal_import_handler(client, context.clone(), validator, closed_engine());
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &malformed)
        .await
        .unwrap();
    assert!(status.is_invalid());
    assert!(status.status.validation_error().unwrap().contains("canonical root input"));
    assert!(context.parent_accounting.is_empty());
}

#[tokio::test]
async fn new_payload_with_seal_never_returns_accepted() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (good_payload, good_companion, beacon_root) = payload_for_import(&payload, &root, |_| {});
    let (bad_payload, bad_companion, _) = payload_for_import(&payload, &root, |header| {
        header.state_root = B256::repeat_byte(0x99);
    });

    let (good_engine, _seen) =
        fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let good_handler =
        seal_import_handler(client.clone(), context.clone(), validator.clone(), good_engine);
    let valid = good_handler
        .new_payload_with_seal(good_payload, vec![], beacon_root, &good_companion)
        .await
        .unwrap();

    let bad_handler = seal_import_handler(client, context, validator, closed_engine());
    let invalid = bad_handler
        .new_payload_with_seal(bad_payload, vec![], beacon_root, &bad_companion)
        .await
        .unwrap();

    assert!(valid.is_valid());
    assert!(invalid.is_invalid());
    for status in [valid, invalid] {
        assert!(!matches!(status.status, PayloadStatusEnum::Accepted));
    }
}

#[test]
fn block_execution_registry_is_idempotent_and_refuses_conflicts() {
    let (_client, parent, root, _attrs, _context, _validator) = seal_fixture();
    let input = bound_input(&root, &parent);
    let commitment = input.root_input().input_commitment().unwrap();

    let registry = UnicityBlockExecutionRegistry::with_capacity(2);
    registry.insert(commitment, input.clone()).unwrap();
    // The same input under the same commitment is idempotent, because a block may be offered twice.
    registry.insert(commitment, input).unwrap();
    assert_eq!(registry.len(), 1);

    // A different input declared under the existing commitment is refused, because its own
    // commitment differs and replacing the entry would change what the commitment executes.
    let conflicting = bound_input(&root_with_tree_root(&root, B256::repeat_byte(0xab)), &parent);
    let error = registry.insert(commitment, conflicting).unwrap_err();
    assert!(matches!(error, BlockExecutionRegistryError::CommitmentMismatch { .. }));
    assert_eq!(registry.get(&commitment).unwrap().root_input(), &root);

    // Eviction is oldest-first.
    let second = bound_input(&root_with_tree_root(&root, B256::repeat_byte(0xcd)), &parent);
    let second_commitment = second.root_input().input_commitment().unwrap();
    registry.insert(second_commitment, second).unwrap();
    assert_eq!(registry.len(), 2);
    let third = bound_input(&root_with_tree_root(&root, B256::repeat_byte(0xef)), &parent);
    let third_commitment = third.root_input().input_commitment().unwrap();
    registry.insert(third_commitment, third).unwrap();
    assert_eq!(registry.len(), 2);
    assert!(registry.get(&commitment).is_none(), "the oldest commitment was evicted");
    assert!(registry.get(&second_commitment).is_some());
    assert!(registry.get(&third_commitment).is_some());
}

#[test]
fn node_evm_resolves_each_block_to_its_own_bound_input() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block = payload.block().clone();
    let commitment = B256::from_slice(&block.header().extra_data);

    let registry = UnicityBlockExecutionRegistry::default();
    registry.insert(commitment, bound_input(&root, &parent)).unwrap();
    // A second, unrelated commitment must not be selected for this block. If the dispatch were
    // wrong, the header validation against the other input would fail.
    let other = bound_input(&root_with_tree_root(&root, B256::repeat_byte(0xab)), &parent);
    let other_commitment = other.root_input().input_commitment().unwrap();
    registry.insert(other_commitment, other).unwrap();

    let node_config = UnicityNodeEvmConfig::new(EthEvmConfig::new(client.chain_spec()), registry);
    let ctx = node_config.context_for_block(&block).unwrap();
    assert_eq!(ctx.extra_data, block.header().extra_data);

    // An unregistered commitment fails with the named error instead of falling back.
    let mut orphan = block.clone().into_block();
    orphan.header.extra_data = B256::repeat_byte(0x99).to_vec().into();
    let orphan = reth_primitives_traits::SealedBlock::seal_slow(orphan);
    let error = node_config.context_for_block(&orphan).unwrap_err();
    assert!(matches!(error, UnicityNodeEvmError::MissingInput(_)));
}

#[test]
fn node_evm_executes_a_registered_block_and_fails_closed_without_an_input() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block = payload.block().clone();
    let commitment = B256::from_slice(&block.header().extra_data);
    let recovered =
        RecoveredBlock::try_new(block.clone().into_block(), vec![], block.hash()).unwrap();

    let registry = UnicityBlockExecutionRegistry::default();
    registry.insert(commitment, bound_input(&root, &parent)).unwrap();
    let registered = UnicityNodeEvmConfig::new(EthEvmConfig::new(client.chain_spec()), registry);
    let output = registered.executor(client.state.clone()).execute(&recovered).unwrap();
    assert_eq!(output.result.gas_used, block.header().gas_used);

    // Without the input the executor fails closed with the named error, not stock execution.
    let bare = UnicityNodeEvmConfig::new(
        EthEvmConfig::new(client.chain_spec()),
        UnicityBlockExecutionRegistry::default(),
    );
    let error = bare.executor(client.state).execute(&recovered).unwrap_err();
    assert!(error.to_string().contains(MISSING_EXECUTION_INPUT_ERROR));
}

#[tokio::test]
async fn the_parent_token_recorded_by_an_import_is_usable_by_a_later_build() {
    // This test proves only the token mechanism: an import records the parent accounting token and
    // a later `prepare_seal_build` can bind a child job with it. It does NOT demonstrate the
    // production follower-becomes-leader path on its own, because the test installs the imported
    // header in the test provider. U3f now supplies the node executor that lets the engine persist
    // and re-execute an imported block, so the production gap is closing, but this test does not
    // exercise a real engine.
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let imported_header = payload.block().header().clone();
    let imported_hash = payload.block().hash();
    let (execution_payload, companion, beacon_root) = payload_for_import(&payload, &root, |_| {});

    let (engine, _seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler = seal_import_handler(client.clone(), context.clone(), validator.clone(), engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_valid());
    assert!(context.parent_accounting.get(&imported_hash).is_some());

    // The build binds the child to the imported parent using the token the import just recorded.
    // Without that recording this call would be SYNCING with a missing parent accounting token.
    // The provider's `extra_headers` above isolates this mechanism from the block-persistence path.
    let leader_client = Client {
        parent_hash: imported_hash,
        extra_headers: vec![imported_header.clone()],
        ..client
    };
    let child_root = input(2, 2, imported_hash);
    let child_attrs = attributes(&child_root, imported_header.timestamp);
    let returned = prepare_seal_build(
        &leader_client,
        &context,
        &validator,
        &ForkchoiceState::same_hash(imported_hash),
        Some(&child_attrs),
        &seal_input(&child_root),
    )
    .unwrap();
    assert_eq!(returned, child_attrs);

    // The inserted child job resolves through the registry, which is what the payload service does.
    let child_id = child_attrs.payload_id(&imported_hash);
    let child_config = PayloadConfig::new(
        Arc::new(SealedHeader::new(imported_header, imported_hash)),
        child_attrs,
        child_id,
    );
    assert!(context.registry.resolve(&child_config).is_ok());
}

/// The M1 node advertises the three seal methods and withholds stock newPayload admission.
#[test]
fn unicity_capabilities_withhold_stock_new_payload() {
    let stock = EngineCapabilities::default();
    let unicity = unicity_engine_capabilities();

    let mut expected: Vec<_> = stock
        .list()
        .into_iter()
        .filter(|capability| {
            !reth_unicity_payload::rpc::DEFERRED_NEW_PAYLOAD_METHODS.contains(&capability.as_str())
        })
        .collect();
    expected.extend(SEAL_CAPABILITIES.iter().map(|capability| (*capability).to_owned()));
    expected.sort_unstable();
    let mut actual = unicity.list();
    actual.sort_unstable();
    assert_eq!(actual, expected);

    // The only additions are those three, so a client never sees a partial seal contract.
    let mut added: Vec<String> = unicity
        .list()
        .into_iter()
        .filter(|capability| !stock.as_set().contains(capability))
        .collect();
    added.sort_unstable();
    let mut expected_added: Vec<String> =
        SEAL_CAPABILITIES.iter().map(|capability| (*capability).to_owned()).collect();
    expected_added.sort_unstable();
    assert_eq!(added, expected_added, "the only additions must be the three seal strings");

    // A stock Ethereum capability set contains none of them.
    for capability in SEAL_CAPABILITIES {
        assert!(!stock.as_set().contains(*capability), "stock must not advertise {capability}");
    }
    for capability in reth_unicity_payload::rpc::DEFERRED_NEW_PAYLOAD_METHODS {
        assert!(!unicity.as_set().contains(*capability));
    }
}

#[tokio::test]
async fn get_seal_companion_returns_a_stored_companion() {
    let (client, _parent, root, _attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    let companion = build_seal_companion(&root).unwrap();
    store.put(GENESIS_HASH, 0, &companion).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    let lookup = rpc.get_seal_companion_v1(GENESIS_HASH).await.unwrap();
    assert_eq!(lookup, SealCompanionLookup::Found { companion });
}

#[tokio::test]
async fn get_seal_companion_reports_unavailable_below_the_horizon() {
    let (client, _parent, root, _attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    let companion = build_seal_companion(&root).unwrap();
    // A genuine prune: `prune_below` drops block 0 and raises the horizon to 5.
    store.put(GENESIS_HASH, 0, &companion).unwrap();
    store.prune_below(5).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.get_seal_companion_v1(GENESIS_HASH).await.unwrap(),
        SealCompanionLookup::Unavailable { horizon: 5 },
        "a pruned block below the horizon is unavailable"
    );
}

#[tokio::test]
async fn get_seal_companion_reports_unknown_for_a_canonical_block_at_the_horizon() {
    let (client, _parent, _root, _attrs, _context, _validator) = seal_fixture();
    // A canonical header exactly at the horizon. Pruning drops only numbers below the horizon, so
    // this block was never dropped; an absent entry means the node never saw it, not that it was
    // pruned.
    let mut at_horizon = client.chain_spec.genesis_header().clone();
    at_horizon.number = 5;
    let at_hash = at_horizon.hash_slow();
    let client = Client { extra_headers: vec![at_horizon], ..client };

    let (_dir, store) = temp_store();
    store.set_horizon(5).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.get_seal_companion_v1(at_hash).await.unwrap(),
        SealCompanionLookup::Unknown,
        "a block at the horizon was never pruned, so its absence is unknown"
    );
}

#[tokio::test]
async fn get_seal_companion_reports_unknown_for_a_hash_the_node_never_saw_with_a_horizon() {
    let (client, _parent, _root, _attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    store.set_horizon(5).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.get_seal_companion_v1(B256::repeat_byte(0x99)).await.unwrap(),
        SealCompanionLookup::Unknown,
        "a horizon does not make a hash the chain does not know unavailable"
    );
}

#[tokio::test]
async fn get_seal_companion_reports_unknown_for_a_canonical_hash_above_the_horizon() {
    let (client, _parent, _root, _attrs, _context, _validator) = seal_fixture();
    let mut above = client.chain_spec.genesis_header().clone();
    above.number = 7;
    let above_hash = above.hash_slow();
    let client = Client { extra_headers: vec![above], ..client };

    let (_dir, store) = temp_store();
    store.set_horizon(5).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.get_seal_companion_v1(above_hash).await.unwrap(),
        SealCompanionLookup::Unknown,
        "a canonical block above the horizon is unknown, not unavailable"
    );
}

#[tokio::test]
async fn seal_companion_horizon_is_null_before_pruning_even_with_a_retention_configured() {
    let (client, _parent, _root, _attrs, _context, _validator) = seal_fixture();
    let node = UnicityNode::new(
        SealJobRegistry::new(),
        UnicitySealConfig { profile: PROFILE, fee_collector: FEE_COLLECTOR },
    )
    .with_retention(UnicityRetentionConfig::retain_last(5));
    assert_eq!(node.retention().depth(), Some(5), "the retention policy is carried");

    let (_dir, store) = temp_store();
    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.seal_companion_horizon_v1().await.unwrap(),
        None,
        "a configured retention is not a published horizon until pruning runs"
    );
}

#[tokio::test]
async fn seal_companion_horizon_reports_a_published_horizon() {
    let (client, _parent, _root, _attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    store.set_horizon(7).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(rpc.seal_companion_horizon_v1().await.unwrap(), Some(7));
}

/// Builds a pruning fixture: a client whose canonical chain is genesis at 0 plus a header at each
/// number in `numbers`, the finalized number set to `finalized`, a fresh store, and a companion.
///
/// The `TempDir` is returned so the caller keeps the store's directory alive.
fn pruner_fixture(
    finalized: u64,
    numbers: &[u64],
) -> (Client, Arc<CompanionStore>, tempfile::TempDir, SealCompanion) {
    let (client, _parent, root, _attrs, _context, _validator) = seal_fixture();
    let companion = build_seal_companion(&root).unwrap();
    let extra_headers = numbers
        .iter()
        .map(|number| {
            let mut header = client.chain_spec.genesis_header().clone();
            header.number = *number;
            header
        })
        .collect();
    let client = Client { extra_headers, finalized, ..client };
    let (dir, store) = temp_store();
    (client, store, dir, companion)
}

#[test]
fn a_non_canonical_entry_at_or_below_finalized_is_evicted() {
    // A canonical header at 3 so the provider can answer affirmatively: the entry's hash is not the
    // canonical one, which is what eviction requires.
    let (client, store, _dir, companion) = pruner_fixture(5, &[3]);
    let orphan = B256::repeat_byte(0x11);
    store.put(orphan, 3, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), None);
    pruner.prune_once(10).unwrap();

    // Block 3 is canonical as a different hash and 3 <= finalized 5, so the entry is dropped. No
    // horizon was published, so the absent hash is Unknown.
    assert!(matches!(store.get(orphan).unwrap(), Lookup::Unknown));
}

#[test]
fn an_entry_the_provider_cannot_resolve_is_kept_and_rechecked() {
    let (client, store, _dir, companion) = pruner_fixture(5, &[]);
    let unresolved = B256::repeat_byte(0x33);
    store.put(unresolved, 3, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), None);
    pruner.prune_once(10).unwrap();

    // The provider has no hash at 3. That is not an affirmative mismatch, so the companion is kept
    // and the cursor does not advance past the number, which is re-read next pass.
    assert!(matches!(store.get(unresolved).unwrap(), Lookup::Found(_)));
    assert_eq!(store.eviction_cursor().unwrap(), Some(3));
}

#[test]
fn a_non_canonical_entry_above_finalized_is_kept() {
    let (client, store, _dir, companion) = pruner_fixture(0, &[]);
    let orphan = B256::repeat_byte(0x11);
    store.put(orphan, 3, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), None);
    pruner.prune_once(10).unwrap();

    // 3 is above finalized 0, so either branch could still win; the entry stays.
    assert!(matches!(store.get(orphan).unwrap(), Lookup::Found(_)));
}

#[test]
fn eviction_without_a_retention_leaves_the_horizon_unset() {
    let (client, store, _dir, companion) = pruner_fixture(5, &[3]);
    let orphan = B256::repeat_byte(0x11);
    store.put(orphan, 3, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), None);
    pruner.prune_once(10).unwrap();

    assert!(matches!(store.get(orphan).unwrap(), Lookup::Unknown), "the entry was evicted");
    assert_eq!(store.horizon().unwrap(), None, "eviction must not publish a horizon");
}

#[test]
fn a_retention_depth_prunes_below_the_horizon_and_publishes_it() {
    let (client, store, _dir, companion) = pruner_fixture(0, &[95]);
    let below = B256::repeat_byte(0x22);
    let inside = client.block_hash(95).unwrap().unwrap();
    store.put(below, 80, &companion).unwrap();
    store.put(inside, 95, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), Some(10));
    pruner.prune_once(100).unwrap();

    // tip 100 - depth 10 = horizon 90. Block 80 is below it and dropped; block 95 is retained.
    assert_eq!(store.horizon().unwrap(), Some(90));
    assert!(matches!(store.get(below).unwrap(), Lookup::Unavailable { horizon: 90 }));
    assert!(matches!(store.get(inside).unwrap(), Lookup::Found(_)));
}

#[test]
fn the_published_horizon_does_not_move_backwards_when_the_tip_does() {
    let (client, store, _dir, _companion) = pruner_fixture(0, &[]);
    let pruner = CompanionPruner::new(client, store.clone(), Some(10));

    pruner.prune_once(100).unwrap();
    assert_eq!(store.horizon().unwrap(), Some(90));

    // A reorg lowers the tip. The horizon is monotonic, so it stays where pruning already put it.
    pruner.prune_once(80).unwrap();
    assert_eq!(store.horizon().unwrap(), Some(90));
}

#[test]
fn a_canonical_entry_above_the_horizon_and_below_finalized_survives_both_paths() {
    let (client, store, _dir, companion) = pruner_fixture(95, &[95]);
    let inside = client.block_hash(95).unwrap().unwrap();
    store.put(inside, 95, &companion).unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), Some(10));
    // Eviction scans [0, 96) and finds block 95 canonical; the horizon is 90, below 95.
    pruner.prune_once(100).unwrap();

    assert!(matches!(store.get(inside).unwrap(), Lookup::Found(_)));
}
