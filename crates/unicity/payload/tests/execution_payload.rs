//! Real payload-builder integration over the signed test-only genesis.

mod support;

use alloy_consensus::{transaction::TransactionMeta, Header, SignableTransaction, TxLegacy};
use alloy_eips::{BlockHashOrNumber, BlockNumHash, BlockNumberOrTag};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, BlockNumber, TxHash, TxKind, TxNumber, B256, U256};
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
use reth_db_api::models::StoredBlockBodyIndices;
use reth_engine_primitives::{BeaconEngineMessage, ConsensusEngineHandle};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{Block, Receipt, Transaction, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_payload_builder::{
    EthBuiltPayload, PayloadBuilderHandle, PayloadServiceCommand, PayloadStore,
};
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_revm::database::StateProviderDatabase;
use reth_rpc_engine_api::{capabilities::EngineCapabilities, EngineApiError};
use reth_storage_api::{
    BlockBodyIndicesProvider, BlockHashReader, BlockIdReader, BlockNumReader, BlockReader,
    BlockSource, HeaderProvider, ReceiptProvider, StateProviderBox, StateProviderFactory,
    TransactionVariant, TransactionsProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, test_utils::OkValidator, CoinbaseTipOrdering,
    EthPooledTransaction, Pool, TransactionOrigin, TransactionPool,
};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{
        replay_complete, BoundExecutionInput, CompletedParent, UnicityEvmConfig,
        MISSING_EXECUTION_INPUT_ERROR,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    evm_factory::unicity_eth_config,
    node_evm::{
        BlockExecutionRegistryError, UnicityBlockExecutionRegistry, UnicityNodeEvmConfig,
        UnicityNodeEvmError,
    },
    pairing::{
        attributes_digest, reference_binding, ExpectedSubject, PairBinding, PairBindingError,
        PairContext, PairPins, PairSubject, SUBJECT_BUILD, SUBJECT_IMPORT,
    },
    technical_record_hash,
    wire::{SealBuildInput, SealCompanion},
    InputRecordV2, RootInputV2, SEAL_REGISTRY,
};
use reth_unicity_payload::{
    build_seal_companion, prepare_seal_build, recovery::RecoveryError, refusal_response,
    unicity_engine_capabilities, CompanionPruner, CompanionSink, ExecutionPayloadJobResolver,
    FixedPayloadJobResolver, GetPayloadWithSealV1Response, ParentAccountingResolver,
    PayloadJobResolutionError, ResolvedPayloadJob, SealBuildContext, SealBuildError,
    SealBuildState, SealCompanionLookup, SealImportError, SealJobRegistry, UnicityConsensus,
    UnicityEngineApiImpl, UnicityEngineTypes, UnicityEngineValidator,
    UnicityExecutionPayloadBuilder, UnicityNode, UnicityParentAccountings,
    UnicityPayloadAttributes, UnicityRetentionConfig, UnicityRpcModuleImpl, UnicityRpcServer,
    UnicitySealConfig, COMPANION_NOT_RETAINED_CODE, DEFAULT_SEAL_JOB_CAPACITY, SEAL_CAPABILITIES,
};
use reth_unicity_store::{open as open_companion_store, CompanionStore, Lookup, StoreError};
use std::{
    collections::BTreeMap,
    ops::{RangeBounds, RangeInclusive},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use support::{b1, provider::FixtureProvider};
use tempfile::tempdir;

fn genesis_hash() -> B256 {
    b1::genesis_hash()
}
fn profile() -> BlockProfile {
    b1::profile()
}
const FEE_COLLECTOR: Address = Address::new([0x77; 20]);

fn next_base_fee(parent: u64, ordinary_used: u64) -> u64 {
    let target = (profile().max_gas - profile().system_gas) / profile().elasticity;
    let delta = u128::from(parent) * u128::from(ordinary_used.abs_diff(target)) /
        u128::from(target) /
        u128::from(profile().change_denominator);
    if ordinary_used > target {
        parent + u64::try_from(delta).unwrap().max(1)
    } else {
        parent.saturating_sub(u64::try_from(delta).unwrap()).max(profile().base_fee_floor)
    }
}

#[derive(Clone, Debug)]
struct Client {
    chain_spec: Arc<ChainSpec>,
    parent_hash: B256,
    state: FixtureProvider,
    extra_headers: Vec<Header>,
    finalized: u64,
    best_number: u64,
    persisted_number: u64,
    fail_finalized: bool,
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
        Ok(ChainInfo {
            best_hash: self.block_hash(self.best_number)?.unwrap_or_default(),
            best_number: self.best_number,
        })
    }
    fn best_block_number(&self) -> ProviderResult<u64> {
        Ok(self.best_number)
    }
    fn last_block_number(&self) -> ProviderResult<u64> {
        Ok(self.persisted_number)
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
            return Ok(Some(self.chain_spec.genesis_header().clone()));
        }
        Ok(self.extra_headers.iter().find(|header| header.hash_slow() == block_hash).cloned())
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        if number == 0 {
            return Ok(Some(self.chain_spec.genesis_header().clone()));
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
        if self.fail_finalized {
            return Err(reth_storage_errors::provider::ProviderError::BestBlockNotFound);
        }
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
    let mut root = b1::input(round, root_round, parent_hash);
    b1::reseal(&mut root);
    root
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
            target_gas_limit: Some(profile().max_gas),
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
            b1::job(root),
            profile(),
            parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let evm = UnicityEvmConfig::new(unicity_eth_config(chain_spec.clone()), bound);
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
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash()));
    let mut state = FixtureProvider::signed_genesis();
    state.set_block_hash(0, genesis_hash());
    let client = Client {
        chain_spec: chain_spec.clone(),
        parent_hash: genesis_hash(),
        state: state.clone(),
        extra_headers: Vec::new(),
        finalized: 0,
        best_number: 0,
        persisted_number: 0,
        fail_finalized: false,
    };
    let root = Arc::new(input(1, 1, genesis_hash()));
    let attrs = attributes(&root, parent.timestamp);
    let base = EthereumBuilderConfig::new()
        .with_gas_limit(profile().max_gas)
        .with_await_payload_on_missing(false);
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root.clone(),
            b1::job(&root),
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let evm = UnicityEvmConfig::new(unicity_eth_config(chain_spec.clone()), bound);
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
            profile().ordinary_capacity().unwrap() + 1,
        ),
    )
    .await;
    let builder = UnicityExecutionPayloadBuilder::new(client.clone(), pool, resolver, base.clone());
    let config =
        PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&genesis_hash()));
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
            second_input.clone(),
            b1::job(&second_input),
            profile(),
            &first_header,
            replay.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let second_evm = UnicityEvmConfig::new(unicity_eth_config(chain_spec.clone()), second_bound);
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
        best_number: 0,
        persisted_number: 0,
        fail_finalized: false,
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
    let consensus = UnicityConsensus::new(chain_spec.clone(), profile(), accounting.clone());
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
        profile(),
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
            profile(),
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
        profile(),
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
                    profile(),
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
        profile(),
    )
    .is_err());
    assert!(reth_unicity_payload::ParentAccountingResolver::resolve(
        &accounting,
        &second_parent,
        &chain_spec,
        BlockProfile { base_fee_floor: profile().base_fee_floor + 1, ..profile() },
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
            profile(),
        )
        .unwrap();
        assert_eq!(lease.next_fee(), token.checked_next_base_fee(header, profile()).unwrap(),);
    }
    assert!(branch_accounting.get(&second_parent.hash()).is_some());
    assert!(branch_accounting.get(&alternate_parent.hash()).is_some());
    let (_dir, store) = temp_store();
    let durable = UnicityParentAccountings::with_capacity(2).require_durability();
    durable.attach_store(store.clone());
    for (header, token) in [(&*second_parent, replay.parent), (&alternate_parent, alternate_token)]
    {
        durable
            .publish(
                header.hash(),
                header.number,
                chain_spec.chain().id(),
                chain_spec.genesis_hash(),
                token,
            )
            .unwrap();
    }
    let cold = UnicityParentAccountings::with_capacity(2).require_durability();
    cold.attach_store(store);
    for header in [&*second_parent, &alternate_parent] {
        // Cold accounting is found by exact hash, checked against chain, genesis and profile,
        // and held back: it resolves only after recovery admission.
        assert!(
            cold.restore_exact(
                header,
                chain_spec.chain().id(),
                chain_spec.genesis_hash(),
                profile()
            )
            .unwrap()
            .is_some(),
            "cold exact-hash branch accounting"
        );
        assert!(
            reth_unicity_payload::ParentAccountingResolver::resolve(
                &cold,
                header,
                &chain_spec,
                profile(),
            )
            .is_err(),
            "an unadmitted cold token must not resolve"
        );
    }
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

    let mut alternate_input = input(1, 1, genesis_hash());
    alternate_input.origin.tree_root = B256::repeat_byte(0xab);
    b1::reseal(&mut alternate_input);
    let alternate_input = Arc::new(alternate_input);
    let alternate_attrs = attributes(&alternate_input, parent.timestamp);
    let alternate_bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            alternate_input.clone(),
            b1::job(&alternate_input),
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let alternate_evm =
        UnicityEvmConfig::new(unicity_eth_config(client.chain_spec.clone()), alternate_bound);
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

#[test]
fn consensus_rejects_a_block_level_base_fee_mutation_with_a_typed_error() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let consensus =
        UnicityConsensus::new(client.chain_spec, profile(), UnicityParentAccountings::default());
    let header = payload.block().header().clone();
    let unmutated = SealedHeader::new(header.clone(), header.hash_slow());
    consensus.validate_header_against_parent(&unmutated, &parent).unwrap();
    let mut header = header;
    header.base_fee_per_gas = Some(header.base_fee_per_gas.unwrap() + 1);
    let child = SealedHeader::new(header.clone(), header.hash_slow());

    let error = consensus.validate_header_against_parent(&child, &parent).unwrap_err();

    assert!(
        matches!(error, ConsensusError::BaseFeeDiff(_)),
        "unexpected consensus error: {error:?}"
    );
}

#[test]
fn consensus_rejects_a_block_level_gas_limit_mutation_with_a_typed_error() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let consensus =
        UnicityConsensus::new(client.chain_spec, profile(), UnicityParentAccountings::default());
    let header = payload.block().header().clone();
    let unmutated = SealedHeader::new(header.clone(), header.hash_slow());
    consensus.validate_header_against_parent(&unmutated, &parent).unwrap();
    let mut header = header;
    header.gas_limit = parent.gas_limit / 2;
    let child = SealedHeader::new(header.clone(), header.hash_slow());

    let error = consensus.validate_header_against_parent(&child, &parent).unwrap_err();

    assert!(
        matches!(error, ConsensusError::GasLimitInvalidDecrease { .. }),
        "unexpected consensus error: {error:?}"
    );
}

#[test]
fn consensus_rejects_a_block_level_timestamp_mutation_with_a_typed_error() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let consensus =
        UnicityConsensus::new(client.chain_spec, profile(), UnicityParentAccountings::default());
    let header = payload.block().header().clone();
    let unmutated = SealedHeader::new(header.clone(), header.hash_slow());
    consensus.validate_header_against_parent(&unmutated, &parent).unwrap();
    let mut header = header;
    header.timestamp = parent.timestamp;
    let child = SealedHeader::new(header.clone(), header.hash_slow());

    let error = consensus.validate_header_against_parent(&child, &parent).unwrap_err();

    assert!(
        matches!(error, ConsensusError::TimestampIsInPast { .. }),
        "unexpected consensus error: {error:?}"
    );
}

/// The production registry is the bounded replacement for [`FixedPayloadJobResolver`]: it reuses
/// identical payload ids, rejects ids with different build input, evicts the oldest insertion at
/// capacity, and shares entries between clones so the payload service and seal methods see the same
/// jobs.
#[test]
fn seal_job_registry_is_bounded_shared_and_reuses_identical_jobs() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash()));
    let base = EthereumBuilderConfig::new()
        .with_gas_limit(profile().max_gas)
        .with_await_payload_on_missing(false);

    // Three jobs on the same parent that differ only in the committed tree root, so each has a
    // distinct payload id and a matching execution configuration.
    let root_a = Arc::new(input(1, 1, genesis_hash()));
    let mut root_b = input(1, 1, genesis_hash());
    root_b.origin.tree_root = B256::repeat_byte(0xab);
    b1::reseal(&mut root_b);
    let root_b = Arc::new(root_b);
    let mut root_c = input(1, 1, genesis_hash());
    root_c.origin.tree_root = B256::repeat_byte(0xcd);
    b1::reseal(&mut root_c);
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
    registry.insert(job_a_duplicate).unwrap();
    assert_eq!(registry.len(), 1, "an identical retry must reuse the held job");
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
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash()));
    let mut state = FixtureProvider::signed_genesis();
    state.set_block_hash(0, genesis_hash());
    let client = Client {
        chain_spec,
        parent_hash: genesis_hash(),
        state,
        extra_headers: Vec::new(),
        finalized: 0,
        best_number: 0,
        persisted_number: 0,
        fail_finalized: false,
    };
    let root = input(1, 1, genesis_hash());
    let attrs = attributes(&root, parent.timestamp);
    let builder_config = Arc::new(OnceLock::new());
    builder_config
        .set(
            EthereumBuilderConfig::new()
                .with_gas_limit(profile().max_gas)
                .with_await_payload_on_missing(false),
        )
        .unwrap();
    let context = SealBuildContext {
        state: SealBuildState {
            registry: SealJobRegistry::new(),
            builder_config,
            seal: UnicitySealConfig {
                profile: profile(),
                fee_collector: FEE_COLLECTOR,
                pins: pair_pins(),
                b1: b1::context(),
            },
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

    fn remove(&self, _block_hash: B256) -> Result<(), StoreError> {
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

    fn remove(&self, _block_hash: B256) -> Result<(), StoreError> {
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

fn pair_pins() -> PairPins {
    PairPins {
        network_id: u64::from(b1::world().network),
        root_genesis_id: b1::world().root_genesis_id,
    }
}
const TEST_ACTIVATION: B256 = B256::repeat_byte(0xac);

/// The binding the local pair's Go verification would hand over for `subject`.
fn pair_binding(
    parent: &SealedHeader,
    root: &RootInputV2,
    subject: ExpectedSubject,
) -> PairBinding {
    pair_binding_on(genesis_hash(), parent, root, subject)
}

/// [`pair_binding`] for a chain whose execution genesis is `genesis_hash`.
fn pair_binding_on(
    genesis_hash: B256,
    parent: &SealedHeader,
    root: &RootInputV2,
    subject: ExpectedSubject,
) -> PairBinding {
    reference_binding(
        &PairContext {
            pins: pair_pins(),
            execution_genesis_hash: genesis_hash,
            parent,
            root,
            subject,
        },
        TEST_ACTIVATION,
    )
    .unwrap()
}

/// The build subject the handler derives from `attrs`.
fn build_subject(attrs: &UnicityPayloadAttributes) -> ExpectedSubject {
    ExpectedSubject::Build {
        attributes_digest: attributes_digest(
            attrs.inner.timestamp,
            attrs.inner.prev_randao,
            attrs.inner.suggested_fee_recipient,
            attrs.inner.parent_beacon_block_root.unwrap(),
        ),
    }
}

fn seal_input(
    parent: &SealedHeader,
    root: &RootInputV2,
    attrs: &UnicityPayloadAttributes,
) -> SealBuildInput {
    SealBuildInput {
        root_input: root.canonical_cbor().unwrap().into(),
        transitions: root.transitions.iter().cloned().map(Into::into).collect(),
        b1_update: b1::job(root).update,
        records: b1::job(root).records,
        pair_binding: pair_binding(parent, root, build_subject(attrs)).canonical_cbor().into(),
    }
}

/// The companion a follower's pair presents for the block `block_hash` built on `parent`.
fn import_companion(parent: &SealedHeader, root: &RootInputV2, block_hash: B256) -> SealCompanion {
    let binding = pair_binding(parent, root, ExpectedSubject::Import { block_hash });
    SealCompanion {
        root_input: root.canonical_cbor().unwrap().into(),
        b1_update: b1::job(root).update,
        records: b1::job(root).records,
        pair_binding: binding.canonical_cbor().into(),
        witnesses: Vec::new(),
        provenance: "newPayload".to_owned(),
    }
}

#[test]
fn seal_build_rejects_non_canonical_root_input_as_invalid() {
    let (client, _parent, _root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(genesis_hash());
    let bad = SealBuildInput {
        root_input: vec![0x80].into(),
        transitions: vec![],
        b1_update: Default::default(),
        records: Default::default(),
        pair_binding: Default::default(),
    };

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
    let (client, parent, root, mut attrs, context, validator) = seal_fixture();
    // Cancun requires withdrawals in the attributes; ResolvedPayloadJob alone would tolerate a
    // missing list, so this exercises the validator parity.
    attrs.inner.withdrawals = None;
    let state = ForkchoiceState::same_hash(genesis_hash());

    let error = prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
    .unwrap_err();
    assert!(matches!(error, SealBuildError::Attributes(_)));
    assert!(context.registry.is_empty(), "the refusal must happen before any job is inserted");

    let response = refusal_response(error).unwrap();
    assert!(response.payload_status.is_invalid());
    assert!(response.payload_status.status.validation_error().is_some());
}

#[test]
fn seal_build_reports_an_unknown_parent_as_syncing() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let unknown = ForkchoiceState::same_hash(B256::repeat_byte(0x99));

    let error = prepare_seal_build(
        &client,
        &context,
        &validator,
        &unknown,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
    .unwrap_err();
    assert_eq!(error, SealBuildError::UnknownParent);
    assert!(refusal_response(error).unwrap().is_syncing());
    assert!(refusal_response(SealBuildError::ParentAccountingUnavailable).unwrap().is_syncing());
    assert!(context.registry.is_empty());
}

#[test]
fn seal_build_requires_payload_attributes() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(genesis_hash());

    let error = prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        None,
        &seal_input(&parent, &root, &attrs),
    )
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
fn seal_build_reuses_an_identical_payload_id() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(genesis_hash());
    let input = seal_input(&parent, &root, &attrs);

    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &input).unwrap();
    let repeated =
        prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &input).unwrap();
    assert_eq!(repeated, attrs);
    assert_eq!(context.registry.len(), 1);
}

#[test]
fn seal_build_job_resolves_with_the_published_builder_config() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(genesis_hash());

    let returned = prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
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
    let (_client, parent, root, attrs, _context, _validator) = seal_fixture();
    let input = seal_input(&parent, &root, &attrs);
    // The decoder accepts only canonical encodings, so re-encoding the decoded value must equal the
    // bytes the caller supplied to forkchoiceUpdatedWithSealV1.
    let decoded = input.decode_root_input().unwrap();
    let companion = build_seal_companion(
        &decoded,
        &b1::job(&decoded).update,
        &b1::job(&decoded).records,
        &pair_binding(&parent, &decoded, build_subject(&attrs)),
    )
    .unwrap();
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
    let state = ForkchoiceState::same_hash(genesis_hash());
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
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
        &ForkchoiceState::same_hash(genesis_hash()),
        Some(attrs),
        &seal_input(parent, root, attrs),
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
    parent: &SealedHeader,
    root: &RootInputV2,
    mutate: impl FnOnce(&mut Header),
) -> (ExecutionPayloadV3, SealCompanion, B256) {
    let mut block = payload.block().clone().into_block();
    mutate(&mut block.header);
    let block_hash = block.header.hash_slow();
    let execution_payload = ExecutionPayloadV3::from_block_unchecked(block_hash, &block);
    let beacon_root = block.header.parent_beacon_block_root.unwrap();
    let companion = import_companion(parent, root, block_hash);
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

struct CapturedRouteBlock {
    client: Client,
    parent: Arc<SealedHeader>,
    post_state: FixtureProvider,
    root: RootInputV2,
    payload: EthBuiltPayload,
    execution_payload: ExecutionPayloadV3,
    companion: SealCompanion,
    import_companion: SealCompanion,
    beacon_root: B256,
    completed: CompletedParent,
}

struct CapturedRouteHistory {
    chain_spec: Arc<ChainSpec>,
    genesis_state: FixtureProvider,
    blocks: Vec<CapturedRouteBlock>,
    store: Arc<CompanionStore>,
    _dir: tempfile::TempDir,
}

/// Captures one deterministic paid, idle and root-origin-epoch-boundary chain through the real
/// builder and getPayload-with-seal response path. The third block is an ack-only EVM assignment
/// transition on the frozen parent; follower import and restore replay consume the same bytes.
async fn capture_paid_idle_transition_fixture() -> CapturedRouteHistory {
    capture_route_history(&[(1, 1, true), (2, 1, false), (3, 2, false)]).await
}

/// The same capture for an arbitrary schedule of `(round, root epoch, paid)` blocks.
async fn capture_route_history(schedule: &[(u64, u64, bool)]) -> CapturedRouteHistory {
    let (genesis_client, mut parent, _, _, mut context, validator) = seal_fixture();
    let chain_spec = genesis_client.chain_spec.clone();
    let genesis_state = genesis_client.state.clone();
    let (dir, store) = temp_store();
    context.store = store.clone();

    let mut state = genesis_state.clone();
    let mut prior_headers = Vec::new();
    let mut blocks = Vec::new();
    for &(round, root_epoch, paid) in schedule {
        let parent_for_block = parent.clone();
        let mut root = input(round, round, parent.hash());
        root.origin.root_epoch = root_epoch;
        root.origin.reference_time = parent.timestamp + 1;
        if round == 1 {
            root.origin.input_record = InputRecordV2 {
                round: 1,
                epoch: 0,
                previous_hash: None,
                state_hash: Some(B256::repeat_byte(0x31)),
                timestamp: 1,
                block_hash: Some(B256::repeat_byte(0x32)),
            };
        }
        if root_epoch == 2 {
            let old_conf = root.origin.shard_conf_hash;
            let new_conf = B256::repeat_byte(0x56);
            root.certified_epoch = 0;
            root.authorized_epoch = 1;
            root.technical.epoch = 1;
            root.origin.input_record.epoch = 0;
            root.origin.shard_conf_hash = new_conf;
            root.origin.tr_hash = technical_record_hash(&root.technical);
            root.transitions = vec![epoch_ack_transition(EpochAck {
                old_root_epoch: 1,
                new_root_epoch: 2,
                old_shard_epoch: 0,
                new_shard_epoch: 1,
                old_active_conf_hash: old_conf,
                new_active_conf_hash: new_conf,
                span: 0,
                span_commitment: B256::ZERO,
                round,
                parent: parent.hash(),
            })];
        }
        b1::reseal(&mut root);
        let attrs = attributes(&root, parent.timestamp);
        let client = Client {
            chain_spec: chain_spec.clone(),
            parent_hash: parent.hash(),
            state: state.clone(),
            extra_headers: prior_headers.clone(),
            finalized: parent.number,
            best_number: parent.number,
            persisted_number: parent.number,
            fail_finalized: false,
        };
        let forkchoice = ForkchoiceState::same_hash(parent.hash());
        prepare_seal_build(
            &client,
            &context,
            &validator,
            &forkchoice,
            Some(&attrs),
            &seal_input(&parent, &root, &attrs),
        )
        .unwrap();

        let pool = test_pool();
        if paid {
            let gas_price = u128::from(parent.base_fee_per_gas.unwrap()) + 100;
            add(
                &pool,
                signed_call(0, gas_price, Address::repeat_byte(0x42), U256::from(1), 21_000),
            )
            .await;
        }
        let config =
            PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&parent.hash()));
        let builder = UnicityExecutionPayloadBuilder::new(
            client.clone(),
            pool,
            context.registry.clone(),
            context.builder_config.get().unwrap().clone(),
        )
        .with_parent_accounting(context.parent_accounting.clone());
        let payload = if paid {
            let args = BuildArguments::new(
                Default::default(),
                None,
                None,
                config.clone(),
                Default::default(),
                None,
            );
            match builder.try_build(args).unwrap() {
                BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) => payload,
                other => panic!("unexpected paid fixture build result: {other:?}"),
            }
        } else {
            builder.build_empty_payload(config.clone()).unwrap()
        };

        let evm = context.registry.resolve(&config).unwrap();
        let parent_state = state.clone();
        let recovered = RecoveredBlock::try_new(
            payload.block().clone().into_block(),
            vec![],
            payload.block().hash(),
        )
        .unwrap();
        let replay = replay_complete(
            &evm,
            StateProviderDatabase::new(&parent_state),
            &parent_state,
            &recovered,
        )
        .unwrap();
        state.apply_bundle(&replay.output.state);
        state.set_block_hash(payload.block().header().number, payload.block().hash());
        assert_eq!(state.root(), payload.block().header().state_root);

        let response = get_payload_with_seal_response(
            client.clone(),
            context.clone(),
            validator.clone(),
            attrs.payload_id(&parent.hash()),
            payload.clone(),
        )
        .await;
        let companion = build_seal_companion(
            &root,
            &b1::job(&root).update,
            &b1::job(&root).records,
            &pair_binding(&parent_for_block, &root, build_subject(&attrs)),
        )
        .unwrap();
        let import_companion = import_companion(&parent_for_block, &root, payload.block().hash());
        assert_eq!(response.seal_companion, companion);
        assert_eq!(declared_block_hash(&response.execution_payload), payload.block().hash());
        match store.get(payload.block().hash()).unwrap() {
            Lookup::Found(found) => assert_eq!(found, companion),
            other => panic!("build route did not retain its returned companion: {other:?}"),
        }

        let beacon_root = payload.block().header().parent_beacon_block_root.unwrap();
        let completed = replay.parent;
        prior_headers.push(payload.block().header().clone());
        parent = Arc::new(payload.block().clone().into_sealed_header());
        blocks.push(CapturedRouteBlock {
            client,
            parent: parent_for_block,
            post_state: state.clone(),
            root,
            payload,
            execution_payload: response.execution_payload,
            companion,
            import_companion,
            beacon_root,
            completed,
        });
    }

    CapturedRouteHistory { chain_spec, genesis_state, blocks, store, _dir: dir }
}

/// Creates the canonical local epoch-ack body consumed by the pinned registry EVM. Its IDs are
/// deterministic test values; the upstream BFT verifier remains the certificate-authentication
/// boundary and is not exercised by this Ureth route test.
struct EpochAck {
    old_root_epoch: u64,
    new_root_epoch: u64,
    old_shard_epoch: u64,
    new_shard_epoch: u64,
    old_active_conf_hash: B256,
    new_active_conf_hash: B256,
    span: u64,
    span_commitment: B256,
    round: u64,
    parent: B256,
}

fn epoch_ack_transition(ack: EpochAck) -> Vec<u8> {
    let EpochAck {
        old_root_epoch,
        new_root_epoch,
        old_shard_epoch,
        new_shard_epoch,
        old_active_conf_hash,
        new_active_conf_hash,
        span,
        span_commitment,
        round,
        parent,
    } = ack;
    fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
        let prefix = major << 5;
        if value < 24 {
            out.push(prefix | value as u8);
        } else if value <= u8::MAX as u64 {
            out.extend([prefix | 24, value as u8]);
        } else if value <= u16::MAX as u64 {
            out.push(prefix | 25);
            out.extend((value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            out.push(prefix | 26);
            out.extend((value as u32).to_be_bytes());
        } else {
            out.push(prefix | 27);
            out.extend(value.to_be_bytes());
        }
    }

    fn uint(out: &mut Vec<u8>, value: u64) {
        cbor_head(out, 0, value);
    }

    fn array(out: &mut Vec<u8>, len: u64) {
        cbor_head(out, 4, len);
    }

    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        cbor_head(out, 2, value.len() as u64);
        out.extend(value);
    }

    fn text(out: &mut Vec<u8>, value: &str) {
        cbor_head(out, 3, value.len() as u64);
        out.extend(value.as_bytes());
    }

    let mut ack = Vec::new();
    array(&mut ack, 8);
    text(&mut ack, "UNICITY_HANDOFF_ACK");
    uint(&mut ack, 2);
    for word in
        [B256::repeat_byte(0x41), B256::repeat_byte(0x42), parent, parent, B256::repeat_byte(0x43)]
    {
        bytes(&mut ack, word.as_slice());
    }
    uint(&mut ack, round);

    let mut transition = Vec::new();
    array(&mut transition, 13);
    text(&mut transition, "UNICITY_HANDOFF_EVM_TRANSITION");
    uint(&mut transition, 3);
    uint(&mut transition, old_root_epoch);
    uint(&mut transition, new_root_epoch);
    uint(&mut transition, old_shard_epoch);
    uint(&mut transition, new_shard_epoch);
    bytes(&mut transition, old_active_conf_hash.as_slice());
    bytes(&mut transition, new_active_conf_hash.as_slice());
    uint(&mut transition, span);
    bytes(&mut transition, span_commitment.as_slice());
    bytes(&mut transition, B256::repeat_byte(0x44).as_slice());
    bytes(&mut transition, B256::repeat_byte(0x45).as_slice());
    bytes(&mut transition, &ack);
    transition
}

async fn get_payload_with_seal_response(
    client: Client,
    context: SealBuildContext,
    validator: UnicityEngineValidator,
    payload_id: PayloadId,
    payload: EthBuiltPayload,
) -> GetPayloadWithSealV1Response {
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
    handler.get_payload_with_seal(payload_id).await.unwrap()
}

/// Block/state reader used only by the restore route test. The captured source blocks are the
/// canonical DB contents; each state lookup returns the exact pre-block snapshot replay needs.
#[derive(Debug)]
struct ReplayProvider {
    client: Client,
    blocks: BTreeMap<B256, Block>,
    states: BTreeMap<B256, FixtureProvider>,
}

impl ChainSpecProvider for ReplayProvider {
    type ChainSpec = ChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        self.client.chain_spec()
    }
}

impl BlockHashReader for ReplayProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.client.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.client.canonical_hashes_range(start, end)
    }
}

impl BlockNumReader for ReplayProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.client.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<BlockNumber> {
        self.client.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<BlockNumber> {
        self.client.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<BlockNumber>> {
        self.client.block_number(hash)
    }
}

impl BlockIdReader for ReplayProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.client.pending_block_num_hash()
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.client.safe_block_num_hash()
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        self.client.finalized_block_num_hash()
    }
}

impl HeaderProvider for ReplayProvider {
    type Header = Header;

    fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> {
        self.client.header(block_hash)
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        self.client.header_by_number(number)
    }

    fn headers_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Header>> {
        self.client.headers_range(range)
    }

    fn sealed_header(&self, number: u64) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        self.client.sealed_header(number)
    }

    fn sealed_headers_while(
        &self,
        range: impl RangeBounds<u64>,
        predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        self.client.sealed_headers_while(range, predicate)
    }
}

impl BlockBodyIndicesProvider for ReplayProvider {
    fn block_body_indices(&self, _number: u64) -> ProviderResult<Option<StoredBlockBodyIndices>> {
        Ok(None)
    }

    fn block_body_indices_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<StoredBlockBodyIndices>> {
        Ok(Vec::new())
    }
}

impl TransactionsProvider for ReplayProvider {
    type Transaction = TransactionSigned;

    fn transaction_id(&self, _hash: TxHash) -> ProviderResult<Option<TxNumber>> {
        Ok(None)
    }

    fn transaction_by_id(&self, _id: TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_id_unhashed(
        &self,
        _id: TxNumber,
    ) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Transaction>> {
        Ok(None)
    }

    fn transaction_by_hash_with_meta(
        &self,
        _hash: TxHash,
    ) -> ProviderResult<Option<(Self::Transaction, TransactionMeta)>> {
        Ok(None)
    }

    fn transactions_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Transaction>>> {
        Ok(None)
    }

    fn transactions_by_block_range(
        &self,
        _range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Transaction>>> {
        Ok(Vec::new())
    }

    fn transactions_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Transaction>> {
        Ok(Vec::new())
    }

    fn senders_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        Ok(Vec::new())
    }

    fn transaction_sender(&self, _id: TxNumber) -> ProviderResult<Option<Address>> {
        Ok(None)
    }
}

impl ReceiptProvider for ReplayProvider {
    type Receipt = Receipt;

    fn receipt(&self, _id: TxNumber) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipt_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipts_by_block(
        &self,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        Ok(None)
    }

    fn receipts_by_tx_range(
        &self,
        _range: impl RangeBounds<TxNumber>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        Ok(Vec::new())
    }

    fn receipts_by_block_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Receipt>>> {
        Ok(Vec::new())
    }
}

impl BlockReader for ReplayProvider {
    type Block = Block;

    fn find_block_by_hash(
        &self,
        hash: B256,
        _source: BlockSource,
    ) -> ProviderResult<Option<Self::Block>> {
        Ok(self.blocks.get(&hash).cloned())
    }

    fn block(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> {
        Ok(match id {
            BlockHashOrNumber::Hash(hash) => self.blocks.get(&hash).cloned(),
            BlockHashOrNumber::Number(number) => {
                self.blocks.values().find(|block| block.header.number == number).cloned()
            }
        })
    }

    fn pending_block(&self) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn pending_block_and_receipts(
        &self,
    ) -> ProviderResult<Option<(RecoveredBlock<Self::Block>, Vec<Self::Receipt>)>> {
        Ok(None)
    }

    fn recovered_block(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn sealed_block_with_senders(
        &self,
        _id: BlockHashOrNumber,
        _transaction_kind: TransactionVariant,
    ) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> {
        Ok(None)
    }

    fn block_range(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<Vec<Self::Block>> {
        let mut blocks: Vec<_> = self
            .blocks
            .values()
            .filter(|block| range.contains(&block.header.number))
            .cloned()
            .collect();
        blocks.sort_by_key(|block| block.header.number);
        Ok(blocks)
    }

    fn block_with_senders_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        Ok(Vec::new())
    }

    fn recovered_block_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> {
        Ok(Vec::new())
    }

    fn block_by_transaction_id(&self, _id: TxNumber) -> ProviderResult<Option<BlockNumber>> {
        Ok(None)
    }
}

impl StateProviderFactory for ReplayProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        let hash = self.client.block_hash(self.client.best_number)?.unwrap_or_else(genesis_hash);
        self.state_by_block_hash(hash)
    }

    fn state_by_block_number_or_tag(
        &self,
        number: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        let number = match number {
            BlockNumberOrTag::Latest | BlockNumberOrTag::Pending => self.client.best_number,
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => self.client.finalized,
            BlockNumberOrTag::Earliest => 0,
            BlockNumberOrTag::Number(number) => number,
        };
        let hash = self.client.block_hash(number)?.unwrap_or_else(genesis_hash);
        self.state_by_block_hash(hash)
    }

    fn history_by_block_number(&self, number: u64) -> ProviderResult<StateProviderBox> {
        let hash = self.client.block_hash(number)?.unwrap_or_else(genesis_hash);
        self.state_by_block_hash(hash)
    }

    fn history_by_block_hash(&self, hash: B256) -> ProviderResult<StateProviderBox> {
        self.state_by_block_hash(hash)
    }

    fn state_by_block_hash(&self, hash: B256) -> ProviderResult<StateProviderBox> {
        Ok(Box::new(self.states.get(&hash).expect("captured parent state").clone()))
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending_state_by_hash(&self, _hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        Ok(None)
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        Ok(None)
    }
}

impl CapturedRouteHistory {
    fn recovery_provider(&self, count: usize) -> ReplayProvider {
        let selected = &self.blocks[..count];
        let mut blocks = BTreeMap::new();
        let mut states = BTreeMap::new();
        let mut headers = Vec::new();
        states.insert(genesis_hash(), self.genesis_state.clone());
        for captured in selected {
            let hash = captured.payload.block().hash();
            blocks.insert(hash, captured.payload.block().clone().into_block());
            states.insert(hash, captured.post_state.clone());
            headers.push(captured.payload.block().header().clone());
        }
        let best_number = selected.last().map_or(0, |block| block.payload.block().header().number);
        ReplayProvider {
            client: Client {
                chain_spec: self.chain_spec.clone(),
                parent_hash: genesis_hash(),
                state: selected
                    .last()
                    .map_or_else(|| self.genesis_state.clone(), |block| block.post_state.clone()),
                extra_headers: headers,
                finalized: best_number,
                best_number,
                persisted_number: best_number,
                fail_finalized: false,
            },
            blocks,
            states,
        }
    }

    fn reorg_above_first_certified_block(&self) -> (ReplayProvider, B256) {
        let mut provider = self.recovery_provider(2);
        let old_hash = self.blocks[1].payload.block().hash();
        let mut alternate = provider.blocks.remove(&old_hash).unwrap();
        alternate.header.extra_data = vec![0x99].into();
        let alternate_hash = alternate.header.hash_slow();
        provider.blocks.insert(alternate_hash, alternate.clone());
        provider.client.extra_headers[1] = alternate.header;
        provider.client.finalized = 1;
        (provider, alternate_hash)
    }

    fn reorg_at_first_certified_block(&self) -> (ReplayProvider, B256) {
        let mut provider = self.recovery_provider(1);
        let certified_hash = self.blocks[0].payload.block().hash();
        let mut alternate = provider.blocks.remove(&certified_hash).unwrap();
        alternate.header.extra_data = vec![0x98].into();
        let alternate_hash = alternate.header.hash_slow();
        provider.blocks.insert(alternate_hash, alternate.clone());
        provider.states.insert(alternate_hash, self.blocks[0].post_state.clone());
        provider.client.extra_headers[0] = alternate.header;
        // The alternate canonical hash is at the height the test treats as certified.
        provider.client.finalized = 1;
        (provider, alternate_hash)
    }
}

#[tokio::test]
async fn captured_paid_idle_transition_fixture_covers_enabled_routes_and_mutations() {
    let history = capture_paid_idle_transition_fixture().await;
    assert_eq!(history.blocks.len(), 3);
    assert_eq!(history.blocks[0].payload.block().body().transactions.len(), 1);
    assert!(history.blocks[1..].iter().all(|block| block
        .payload
        .block()
        .body()
        .transactions
        .is_empty()));
    assert_eq!(
        history.blocks[0].root.origin.input_record.block_hash,
        Some(B256::repeat_byte(0x32)),
        "the reorg fixture must anchor above a first-certified block"
    );
    assert_eq!(history.blocks[0].root.origin.root_epoch, 1);
    assert_eq!(history.blocks[2].root.origin.root_epoch, 2);

    // Follower import consumes the same captured payload/companion pairs in canonical order.
    let (_, _, _, _, mut follower_context, validator) = seal_fixture();
    let (_follower_dir, follower_store) = temp_store();
    follower_context.store = follower_store.clone();
    for captured in &history.blocks {
        let (engine, seen) = fake_engine(PayloadStatus::new(
            PayloadStatusEnum::Valid,
            Some(declared_block_hash(&captured.execution_payload)),
        ))
        .await;
        let handler = seal_import_handler(
            captured.client.clone(),
            follower_context.clone(),
            validator.clone(),
            engine,
        );
        let status = handler
            .new_payload_with_seal(
                captured.execution_payload.clone(),
                vec![],
                captured.beacon_root,
                &captured.import_companion,
            )
            .await
            .unwrap();
        assert!(
            status.is_valid(),
            "follower route rejected round {}: {status:?}",
            captured.root.authorized_round
        );
        assert_eq!(
            seen.await.unwrap().block_hash(),
            declared_block_hash(&captured.execution_payload)
        );
        assert!(follower_context
            .parent_accounting
            .get(&declared_block_hash(&captured.execution_payload))
            .is_some());
        match follower_store.get(declared_block_hash(&captured.execution_payload)).unwrap() {
            Lookup::Found(found) => assert_eq!(found, captured.import_companion),
            other => panic!(
                "follower route did not retain round {}: {other:?}",
                captured.root.authorized_round
            ),
        }
    }

    // Wrong root context is rejected before build-job insertion and before follower forwarding.
    let first = &history.blocks[0];
    let mut wrong_root = first.root.clone();
    wrong_root.network_id = 99;
    wrong_root.origin.network_id = 99;
    b1::reseal(&mut wrong_root);
    let attrs = attributes(&first.root, first.parent.timestamp);
    // The binding names the original root input, so the substituted one cannot ride under it.
    let wrong_input = SealBuildInput {
        root_input: wrong_root.canonical_cbor().unwrap().into(),
        transitions: vec![],
        b1_update: b1::job(&wrong_root).update,
        records: b1::job(&wrong_root).records,
        pair_binding: seal_input(&first.parent, &first.root, &attrs).pair_binding,
    };
    let (_, _, _, _, build_context, build_validator) = seal_fixture();
    let build_error = prepare_seal_build(
        &first.client,
        &build_context,
        &build_validator,
        &ForkchoiceState::same_hash(first.parent.hash()),
        Some(&attrs),
        &wrong_input,
    )
    .unwrap_err();
    assert!(refusal_response(build_error).unwrap().payload_status.is_invalid());
    assert!(build_context.registry.is_empty());

    let second = &history.blocks[1];
    let (_, _, _, _, missing_parent_build, missing_parent_validator) = seal_fixture();
    let missing_parent_error = prepare_seal_build(
        &second.client,
        &missing_parent_build,
        &missing_parent_validator,
        &ForkchoiceState::same_hash(second.parent.hash()),
        Some(&attributes(&second.root, second.parent.timestamp)),
        &seal_input(
            &second.parent,
            &second.root,
            &attributes(&second.root, second.parent.timestamp),
        ),
    )
    .unwrap_err();
    assert!(matches!(missing_parent_error, SealBuildError::ParentAccountingUnavailable));
    assert!(missing_parent_build.registry.is_empty());

    let wrong_context_companion = SealCompanion {
        root_input: wrong_root.canonical_cbor().unwrap().into(),
        b1_update: b1::job(&wrong_root).update,
        records: b1::job(&wrong_root).records,
        ..first.import_companion.clone()
    };
    let (_, _, _, _, wrong_context, wrong_context_validator) = seal_fixture();
    let (engine, seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler =
        seal_import_handler(first.client.clone(), wrong_context, wrong_context_validator, engine);
    let status = handler
        .new_payload_with_seal(
            first.execution_payload.clone(),
            vec![],
            first.beacon_root,
            &wrong_context_companion,
        )
        .await
        .unwrap();
    assert!(status.is_invalid());
    drop(handler);
    assert!(seen.await.is_err(), "wrong-context input must be refused before Engine forwarding");

    // An out-of-order follower has the parent header and body but lacks the parent's checked token.
    let (_, _, _, _, no_parent_token, no_parent_token_validator) = seal_fixture();
    let (engine, seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler = seal_import_handler(
        second.client.clone(),
        no_parent_token,
        no_parent_token_validator,
        engine,
    );
    let status = handler
        .new_payload_with_seal(
            second.execution_payload.clone(),
            vec![],
            second.beacon_root,
            &second.import_companion,
        )
        .await
        .unwrap();
    assert!(status.is_syncing(), "wrong-order import must remain unavailable, not VALID");
    drop(handler);
    assert!(seen.await.is_err(), "wrong-order import must not reach Engine forwarding");

    // Restore replays this exact captured chain from the configured genesis anchor.
    let provider = history.recovery_provider(history.blocks.len());
    let restored = UnicityParentAccountings::default();
    reth_unicity_payload::recovery::admit_recovered_head(
        &provider,
        &history.store,
        &restored,
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &history.blocks[2].import_companion.pair_binding,
        3,
    )
    .unwrap();
    for captured in &history.blocks {
        let hash = captured.payload.block().hash();
        assert!(restored.get(&hash).is_some(), "restore replay omitted block {hash}");
    }

    // A root input that points to the wrong parent/order cannot be used by restore replay.
    let (_wrong_order_dir, wrong_order_store) = temp_store();
    wrong_order_store.put(first.payload.block().hash(), 1, &first.companion).unwrap();
    let mut wrong_order_root = second.root.clone();
    wrong_order_root.parent_hash = genesis_hash();
    b1::reseal(&mut wrong_order_root);
    let wrong_order_companion = build_seal_companion(
        &wrong_order_root,
        &b1::job(&wrong_order_root).update,
        &b1::job(&wrong_order_root).records,
        &pair_binding(
            &second.parent,
            &wrong_order_root,
            build_subject(&attributes(&second.root, second.parent.timestamp)),
        ),
    )
    .unwrap();
    wrong_order_store.put(second.payload.block().hash(), 2, &wrong_order_companion).unwrap();
    let boundary_tokens = UnicityParentAccountings::default();
    boundary_tokens.insert_for_chain(
        first.payload.block().hash(),
        first.completed,
        history.chain_spec.chain().id(),
        history.chain_spec.genesis_hash(),
    );
    let wrong_order_provider = history.recovery_provider(2);
    // Presenting the tampered retained binding itself reaches the replay's own bind check.
    let wrong_order_error = reth_unicity_payload::recovery::admit_recovered_head(
        &wrong_order_provider,
        &wrong_order_store,
        &boundary_tokens,
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &wrong_order_companion.pair_binding,
        2,
    )
    .unwrap_err();
    assert!(wrong_order_error.to_string().contains("parent accounting binding failed at 2"));
    // The honest binding Go would present names the real root input, so it is refused first.
    let honest_presented = reth_unicity_payload::recovery::admit_recovered_head(
        &wrong_order_provider,
        &wrong_order_store,
        &boundary_tokens,
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &second.import_companion.pair_binding,
        2,
    )
    .unwrap_err();
    assert!(matches!(
        honest_presented.downcast_ref::<RecoveryError>(),
        Some(RecoveryError::PresentedRefused {
            number: 2,
            source: PairBindingError::RootInputMismatch
        })
    ));

    // A reorg above the certified boundary cannot reuse the old height-2 companion or drop the
    // boundary token. The canonical hash is changed while height 1 remains certified.
    let (reorg_provider, alternate_hash) = history.reorg_above_first_certified_block();
    let reorg_tokens = UnicityParentAccountings::default();
    reorg_tokens.insert_for_chain(
        first.payload.block().hash(),
        first.completed,
        history.chain_spec.chain().id(),
        history.chain_spec.genesis_hash(),
    );
    let reorg_error = reth_unicity_payload::recovery::admit_recovered_head(
        &reorg_provider,
        &history.store,
        &reorg_tokens,
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &second.import_companion.pair_binding,
        2,
    )
    .unwrap_err();
    assert!(matches!(
        reorg_error.downcast_ref::<RecoveryError>(),
        Some(RecoveryError::CompanionMissing(2))
    ));
    assert!(reorg_tokens.get(&first.payload.block().hash()).is_some());
    assert!(reorg_tokens.get(&alternate_hash).is_none());

    // A canonical reorg at the certified block itself is outside the accepted history. Restore
    // must refuse the alternate height-1 block instead of replacing the boundary token.
    let (boundary_reorg_provider, boundary_alternate_hash) =
        history.reorg_at_first_certified_block();
    assert!(boundary_reorg_provider.client.finalized >= 1);
    assert_ne!(boundary_alternate_hash, first.payload.block().hash());
    let boundary_reorg_error = reth_unicity_payload::recovery::admit_recovered_head(
        &boundary_reorg_provider,
        &history.store,
        &boundary_tokens,
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &first.import_companion.pair_binding,
        1,
    )
    .unwrap_err();
    assert!(matches!(
        boundary_reorg_error.downcast_ref::<RecoveryError>(),
        Some(RecoveryError::CompanionMissing(1))
    ));
    assert!(boundary_tokens.get(&first.payload.block().hash()).is_some());
    assert!(boundary_tokens.get(&boundary_alternate_hash).is_none());

    // Crash boundary A: accounting reached disk, but Engine did not accept the block. On restart
    // the main DB still ends at genesis, so canonical-only hydration ignores the orphan token.
    let (_precommit_dir, precommit_store) = temp_store();
    let precommit_tokens = UnicityParentAccountings::new().require_durability();
    precommit_tokens.attach_store(precommit_store.clone());
    let (_, _, _, _, mut precommit_context, precommit_validator) = seal_fixture();
    precommit_context.state.parent_accounting = precommit_tokens.clone();
    precommit_context.store = precommit_store.clone();
    let (engine, seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Invalid {
        validation_error: "injected interrupted import".into(),
    }))
    .await;
    let handler =
        seal_import_handler(first.client.clone(), precommit_context, precommit_validator, engine);
    let status = handler
        .new_payload_with_seal(
            first.execution_payload.clone(),
            vec![],
            first.beacon_root,
            &first.import_companion,
        )
        .await
        .unwrap();
    assert!(status.is_invalid());
    seen.await.unwrap();
    assert!(precommit_store.get_accounting(first.payload.block().hash()).unwrap().is_some());
    assert!(matches!(precommit_store.get(first.payload.block().hash()).unwrap(), Lookup::Unknown));
    let restarted_precommit = UnicityParentAccountings::new().require_durability();
    restarted_precommit.attach_store(precommit_store);
    let genesis_only = history.recovery_provider(0);
    reth_unicity_payload::recovery::hydrate_accounting(
        &genesis_only,
        &restarted_precommit,
        profile(),
    )
    .unwrap();
    assert!(restarted_precommit.get(&first.payload.block().hash()).is_none());

    // Crash boundary B: the companion write failed. The block is refused before the Engine sees
    // it, so no canonical block can exist without the companion that replays it. The durable
    // accounting record for the refused block is an orphan: nothing canonical names it.
    let (_postcommit_dir, postcommit_store) = temp_store();
    let postcommit_tokens = UnicityParentAccountings::new().require_durability();
    postcommit_tokens.attach_store(postcommit_store.clone());
    let (_, _, _, _, mut postcommit_context, postcommit_validator) = seal_fixture();
    postcommit_context.state.parent_accounting = postcommit_tokens;
    postcommit_context.store = Arc::new(FailingCompanionSink);
    let (engine, seen) = fake_engine(PayloadStatus::new(
        PayloadStatusEnum::Valid,
        Some(first.payload.block().hash()),
    ))
    .await;
    let handler =
        seal_import_handler(first.client.clone(), postcommit_context, postcommit_validator, engine);
    let refusal = handler
        .new_payload_with_seal(
            first.execution_payload.clone(),
            vec![],
            first.beacon_root,
            &first.import_companion,
        )
        .await
        .unwrap_err();
    assert!(refusal.to_string().contains("companion is not durable"), "{refusal}");
    drop(handler);
    assert!(seen.await.is_err(), "a block without a durable companion must not reach the Engine");
    assert!(matches!(postcommit_store.get(first.payload.block().hash()).unwrap(), Lookup::Unknown));
    let restarted_postcommit = UnicityParentAccountings::new().require_durability();
    let postcommit_store_for_replay = postcommit_store.clone();
    restarted_postcommit.attach_store(postcommit_store);
    let canonical_first = history.recovery_provider(1);
    reth_unicity_payload::recovery::hydrate_accounting(
        &canonical_first,
        &restarted_postcommit,
        profile(),
    )
    .unwrap();
    assert!(restarted_postcommit.get(&first.payload.block().hash()).is_some());
    let missing_companion_replay = reth_unicity_payload::recovery::admit_recovered_head(
        &canonical_first,
        &postcommit_store_for_replay,
        &UnicityParentAccountings::default(),
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
        &first.import_companion.pair_binding,
        1,
    )
    .unwrap_err();
    assert!(matches!(
        missing_companion_replay.downcast_ref::<RecoveryError>(),
        Some(RecoveryError::CompanionMissing(1))
    ));
}

/// Builds the genesis-bound execution input for `root`.
fn bound_input(root: &RootInputV2, parent: &Arc<SealedHeader>) -> Arc<BoundExecutionInput> {
    Arc::new(
        BoundExecutionInput::from_validated_genesis(
            Arc::new(root.clone()),
            b1::job(root),
            profile(),
            parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    )
}

/// Returns a copy of `root` with a different tree root, so it has a different commitment.
fn root_with_tree_root(root: &RootInputV2, tree_root: B256) -> RootInputV2 {
    let mut next = root.clone();
    next.origin.tree_root = tree_root;
    b1::reseal(&mut next);
    next
}

#[tokio::test]
async fn new_payload_with_seal_imports_a_built_block_and_records_its_token() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let commitment = B256::from_slice(&payload.block().header().extra_data);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});

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
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
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
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
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
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
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
async fn a_failing_store_write_refuses_the_import_before_the_engine_sees_the_block() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    context.store = Arc::new(FailingCompanionSink);
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});

    let (engine, seen) =
        fake_engine(PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash))).await;
    let handler = seal_import_handler(client, context, validator, engine);
    let error = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap_err();
    assert!(matches!(error, EngineApiError::Internal(_)), "{error:?}");
    assert!(error.to_string().contains("companion is not durable"), "{error}");
    drop(handler);
    assert!(seen.await.is_err(), "the block must not be forwarded without a durable companion");
}

#[tokio::test]
async fn get_payload_with_seal_stores_the_companion_it_returns() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (_dir, store) = temp_store();
    context.store = store.clone();

    let state = ForkchoiceState::same_hash(genesis_hash());
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
    .unwrap();
    let base = context.builder_config.get().unwrap().clone();
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        base,
    );
    let payload = builder
        .build_empty_payload(PayloadConfig::new(parent.clone(), attrs.clone(), payload_id))
        .unwrap();
    let expected = build_seal_companion(
        &root,
        &b1::job(&root).update,
        &b1::job(&root).records,
        &pair_binding(&parent, &root, build_subject(&attrs)),
    )
    .unwrap();

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
async fn a_failing_store_write_fails_get_payload_instead_of_serving_an_unretained_companion() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    context.store = Arc::new(FailingCompanionSink);

    let state = ForkchoiceState::same_hash(genesis_hash());
    let payload_id = attrs.payload_id(&parent.hash());
    prepare_seal_build(
        &client,
        &context,
        &validator,
        &state,
        Some(&attrs),
        &seal_input(&parent, &root, &attrs),
    )
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

    let error = handler.get_payload_with_seal(payload_id).await.unwrap_err();
    assert!(matches!(error, EngineApiError::Internal(_)), "{error:?}");
    assert!(error.to_string().contains("forced store failure"), "{error}");
}

#[tokio::test]
async fn new_payload_with_seal_returns_the_engine_verdict() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});

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
        payload_for_import(&payload, &parent, &root, |header| {
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
        payload_for_import(&payload, &parent, &root, |header| {
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
    let orphan = SealedHeader::new(orphan_header.clone(), orphan_hash);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &orphan, &root, |header| {
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
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});

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
    let (execution_payload, _companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    let malformed = SealCompanion {
        root_input: vec![0x80].into(),
        b1_update: Default::default(),
        records: Default::default(),
        pair_binding: Default::default(),
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
    let (good_payload, good_companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    let (bad_payload, bad_companion, _) = payload_for_import(&payload, &parent, &root, |header| {
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

    let node_config = UnicityNodeEvmConfig::new(unicity_eth_config(client.chain_spec()), registry);
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
    let registered = UnicityNodeEvmConfig::new(unicity_eth_config(client.chain_spec()), registry);
    let output = registered.executor(client.state.clone()).execute(&recovered).unwrap();
    assert_eq!(output.result.gas_used, block.header().gas_used);

    // Without the input the executor fails closed with the named error, not stock execution.
    let bare = UnicityNodeEvmConfig::new(
        unicity_eth_config(client.chain_spec()),
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
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});

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
        &seal_input(
            &SealedHeader::new(imported_header.clone(), imported_hash),
            &child_root,
            &child_attrs,
        ),
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

#[tokio::test]
async fn a_reopened_canonical_token_supports_the_next_build() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let header = payload.block().header().clone();
    let hash = payload.block().hash();
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    let (engine, _seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler = seal_import_handler(client.clone(), context.clone(), validator.clone(), engine);
    assert!(handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap()
        .is_valid());
    let token = context.parent_accounting.get(&hash).unwrap();

    let dir = tempdir().unwrap();
    {
        let store = Arc::new(open_companion_store(dir.path()).unwrap());
        let durable = UnicityParentAccountings::default().require_durability();
        durable.attach_store(store);
        durable.publish(hash, 1, 1337, genesis_hash(), token).unwrap();
    }
    let restored = UnicityParentAccountings::default().require_durability();
    restored.attach_store(Arc::new(open_companion_store(dir.path()).unwrap()));
    let sealed = SealedHeader::new(header.clone(), hash);
    assert!(restored.restore_exact(&sealed, 1338, genesis_hash(), profile()).is_err());
    assert!(restored.restore_exact(&sealed, 1337, B256::ZERO, profile()).is_err());
    assert!(restored
        .restore_exact(
            &sealed,
            1337,
            genesis_hash(),
            BlockProfile { base_fee_floor: 8, ..profile() }
        )
        .is_err());
    assert!(restored.restore_exact(&sealed, 1337, genesis_hash(), profile()).unwrap().is_some());
    context.state.parent_accounting = restored;
    let leader_client = Client { parent_hash: hash, extra_headers: vec![header.clone()], ..client };
    let child_root = input(2, 2, hash);
    let child_attrs = attributes(&child_root, header.timestamp);
    // A token read back from the sidecar is a cached projection: it supports no build until
    // recovery admission (see `restored_accounting_resolves_only_after_recovery_admission`).
    assert!(matches!(
        prepare_seal_build(
            &leader_client,
            &context,
            &validator,
            &ForkchoiceState::same_hash(hash),
            Some(&child_attrs),
            &seal_input(&SealedHeader::new(header.clone(), hash), &child_root, &child_attrs),
        ),
        Err(SealBuildError::ParentAccountingUnavailable)
    ));
}

#[tokio::test]
async fn hydration_restores_persisted_head_when_memory_tip_is_ahead() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let header = payload.block().header().clone();
    let hash = payload.block().hash();
    let token = context
        .registry
        .resolve(&PayloadConfig::new(
            parent.clone(),
            attrs.clone(),
            attrs.payload_id(&parent.hash()),
        ))
        .unwrap()
        .completed_parent_for(payload.block())
        .unwrap();
    let (_dir, store) = temp_store();
    let durable = UnicityParentAccountings::new().require_durability();
    durable.attach_store(store.clone());
    durable.publish(hash, 1, 1337, genesis_hash(), token).unwrap();

    let mut memory_tip = header.clone();
    memory_tip.number = 2;
    memory_tip.parent_hash = hash;
    let memory_hash = memory_tip.hash_slow();
    let provider = Client {
        extra_headers: vec![header, memory_tip],
        best_number: 2,
        persisted_number: 1,
        ..client
    };
    let restored = UnicityParentAccountings::new().require_durability();
    restored.attach_store(store);
    reth_unicity_payload::recovery::hydrate_accounting(&provider, &restored, profile()).unwrap();
    assert!(restored.get(&hash).is_some(), "the persisted DB head must be hydrated");
    assert!(restored.get(&memory_hash).is_none(), "the memory tip has no durable token");
}

#[tokio::test]
async fn accounting_persistence_failure_refuses_import_before_engine_forward() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    context.state.parent_accounting = UnicityParentAccountings::default().require_durability();
    let (engine, seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler = seal_import_handler(client, context.clone(), validator, engine);
    let error = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("accounting persistence failed"));
    assert!(context.parent_accounting.is_empty());
    drop(handler);
    assert!(seen.await.is_err(), "the engine must not see the unpersisted payload");
}

#[tokio::test]
async fn conflicting_durable_write_refuses_import_before_engine_forward() {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let token = context
        .registry
        .resolve(&PayloadConfig::new(
            parent.clone(),
            attrs.clone(),
            attrs.payload_id(&parent.hash()),
        ))
        .unwrap()
        .completed_parent_for(payload.block())
        .unwrap();
    let (execution_payload, companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    let (_dir, store) = temp_store();
    store
        .put_accounting(reth_unicity_store::StoredAccounting {
            chain_id: 42,
            genesis_hash: genesis_hash(),
            block_number: 1,
            accounting: token.for_local_storage(),
        })
        .unwrap();
    let durable = UnicityParentAccountings::new().require_durability();
    durable.attach_store(store);
    context.state.parent_accounting = durable;

    let (engine, seen) = fake_engine(PayloadStatus::from_status(PayloadStatusEnum::Valid)).await;
    let handler = seal_import_handler(client, context.clone(), validator, engine);
    let error = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("accounting persistence failed"));
    assert!(context.parent_accounting.is_empty());
    drop(handler);
    assert!(seen.await.is_err(), "the engine must not see a block whose durable write failed");
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
    let (client, parent, root, attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    let companion = build_seal_companion(
        &root,
        &b1::job(&root).update,
        &b1::job(&root).records,
        &pair_binding(&parent, &root, build_subject(&attrs)),
    )
    .unwrap();
    store.put(genesis_hash(), 0, &companion).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    let lookup = rpc.get_seal_companion_v1(genesis_hash()).await.unwrap();
    assert_eq!(lookup, SealCompanionLookup::Found { companion });
}

#[tokio::test]
async fn get_seal_companion_reports_unavailable_below_the_horizon() {
    let (client, parent, root, attrs, _context, _validator) = seal_fixture();
    let (_dir, store) = temp_store();
    let companion = build_seal_companion(
        &root,
        &b1::job(&root).update,
        &b1::job(&root).records,
        &pair_binding(&parent, &root, build_subject(&attrs)),
    )
    .unwrap();
    // A genuine prune: `prune_below` drops block 0 and raises the horizon to 5.
    store.put(genesis_hash(), 0, &companion).unwrap();
    store.prune_below(5).unwrap();

    let rpc = UnicityRpcModuleImpl::new(client, store);
    assert_eq!(
        rpc.get_seal_companion_v1(genesis_hash()).await.unwrap(),
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
        UnicitySealConfig {
            profile: profile(),
            fee_collector: FEE_COLLECTOR,
            pins: pair_pins(),
            b1: b1::context(),
        },
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
    let (client, parent, root, attrs, _context, _validator) = seal_fixture();
    let companion = build_seal_companion(
        &root,
        &b1::job(&root).update,
        &b1::job(&root).records,
        &pair_binding(&parent, &root, build_subject(&attrs)),
    )
    .unwrap();
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

#[test]
fn concurrent_accounting_publication_and_retention_keep_recent_block() {
    let (client, store, _dir, companion) = pruner_fixture(0, &[]);
    let client = Client { persisted_number: 100, ..client };
    let mut header = client.chain_spec.genesis_header().clone();
    header.number = 95;
    header.gas_limit = profile().max_gas;
    header.gas_used = 0;
    header.base_fee_per_gas = Some(profile().base_fee_floor);
    let hash = header.hash_slow();
    let token = reth_unicity_execution::block_executor::CompletedParent::from_local_storage(
        reth_unicity_execution::block_executor::LocalParentAccounting {
            block_hash: hash,
            profile: profile(),
            header_gas: 0,
            system_gas: 0,
            ordinary_gas: 0,
            base_fee: profile().base_fee_floor,
        },
        &SealedHeader::new(header, hash),
        profile(),
    )
    .unwrap();
    let tokens = UnicityParentAccountings::new().require_durability();
    tokens.attach_store(store.clone());
    let pruner = CompanionPruner::new(client, store.clone(), Some(18)).with_repair_limit(2);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..10 {
                tokens.publish(hash, 95, 1337, genesis_hash(), token).unwrap();
                store.put(hash, 95, &companion).unwrap();
            }
        });
        scope.spawn(|| {
            for _ in 0..10 {
                pruner.prune_once(100).unwrap();
            }
        });
    });
    assert!(store.get_accounting(hash).unwrap().is_some());
    assert!(matches!(store.get(hash).unwrap(), Lookup::Found(_)));
}

#[test]
fn companion_pruning_failure_does_not_skip_accounting_pruning() {
    let (client, store, _dir, _companion) = pruner_fixture(0, &[]);
    let client = Client { persisted_number: 100, fail_finalized: true, ..client };
    let hash = B256::repeat_byte(0x45);
    store
        .put_accounting(reth_unicity_store::StoredAccounting {
            chain_id: 1337,
            genesis_hash: genesis_hash(),
            block_number: 1,
            accounting: reth_unicity_execution::block_executor::LocalParentAccounting {
                block_hash: hash,
                profile: profile(),
                header_gas: 0,
                system_gas: 0,
                ordinary_gas: 0,
                base_fee: profile().base_fee_floor,
            },
        })
        .unwrap();

    let pruner = CompanionPruner::new(client, store.clone(), Some(18)).with_repair_limit(2);
    assert!(pruner.prune_once(100).is_err());
    assert!(store.get_accounting(hash).unwrap().is_none());
}

// ---- H3 #20 criterion X2: signer-subset determinism through the payload routes
// ----------------------------------------------
//
// One nonempty assignment acknowledgement, certified by two distinct valid signer subsets of the
// old root quorum: the root input, transition body, committed update and commitment are the same
// bytes for each, and the companion witnesses are the only subset-dependent bytes. The
// acknowledgement rotates root epoch 1 to 2, so its block also carries the update that closes the
// genesis interval and inserts epoch 2. The genesis is the B1 genesis whose block 0 is the
// acknowledgement's frozen parent.

const GO_X2_GENESIS: &str = include_str!("../testdata/signed-beacon-genesis.json");

/// The acknowledgement vector this pair would be handed, built from the B1 world.
fn go_x2_vector() -> serde_json::Value {
    let mut root = b1::ack_input(genesis_hash());
    b1::reseal(&mut root);
    let hex = |bytes: &[u8]| format!("0x{}", alloy_primitives::hex::encode(bytes));
    serde_json::json!({
        "parent_hash": hex(genesis_hash().as_slice()),
        "root_input": hex(&root.canonical_cbor().unwrap()),
        "b1_update": hex(&b1::job(&root).update),
        "records": hex(&b1::job(&root).records),
        "transition": hex(&root.transitions[0]),
        "commitment": hex(root.input_commitment().unwrap().as_slice()),
        "parent_beacon_block_root": hex(
            derive_beacon_root(root.origin.root_round, root.authorized_round).as_slice()
        ),
        "authorized_round": root.authorized_round,
        "new_root_epoch": 2,
        "subsets": [
            { "witnesses": [hex(&[1; 65]), hex(&[2; 65]), hex(&[3; 65])] },
            { "witnesses": [hex(&[1; 65]), hex(&[2; 65]), hex(&[4; 65])] },
        ],
    })
}

fn go_hex(value: &serde_json::Value) -> Vec<u8> {
    alloy_primitives::hex::decode(value.as_str().unwrap()).unwrap()
}

fn go_registry_slot(name: &str) -> U256 {
    U256::from_be_bytes(alloy_primitives::keccak256(format!("unicity.seal-registry/{name}")).0)
}

fn go_genesis_fixture(
    genesis_hash: B256,
) -> (Client, Arc<SealedHeader>, SealBuildContext, UnicityEngineValidator) {
    let genesis: Genesis = serde_json::from_str(GO_X2_GENESIS).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let validator = UnicityEngineValidator::new(chain_spec.clone());
    let parent = Arc::new(SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash));
    assert_eq!(parent.hash_slow(), genesis_hash, "the Go genesis hashes to the same block 0 here");
    let mut state = FixtureProvider::from_json(GO_X2_GENESIS);
    state.set_block_hash(0, genesis_hash);
    let client = Client {
        chain_spec,
        parent_hash: genesis_hash,
        state,
        extra_headers: Vec::new(),
        finalized: 0,
        best_number: 0,
        persisted_number: 0,
        fail_finalized: false,
    };
    let builder_config = Arc::new(OnceLock::new());
    builder_config
        .set(
            EthereumBuilderConfig::new()
                .with_gas_limit(profile().max_gas)
                .with_await_payload_on_missing(false),
        )
        .unwrap();
    let context = SealBuildContext {
        state: SealBuildState {
            registry: SealJobRegistry::new(),
            builder_config,
            seal: UnicitySealConfig {
                profile: profile(),
                fee_collector: FEE_COLLECTOR,
                pins: pair_pins(),
                b1: b1::context(),
            },
            parent_accounting: UnicityParentAccountings::default(),
            execution_inputs: UnicityBlockExecutionRegistry::default(),
            retention: UnicityRetentionConfig::default(),
        },
        store: Arc::new(NoopCompanionSink),
    };
    (client, parent, context, validator)
}

#[derive(Debug, PartialEq, Eq)]
struct GoSubsetOutcome {
    block_hash: B256,
    state_root: B256,
    extra_data: Vec<u8>,
    execution_payload: String,
    registry: BTreeMap<U256, U256>,
}

/// Applies one subset's vector through the builder route, the follower route and replay, each on a
/// fresh context.
async fn apply_go_subset(
    vector: &serde_json::Value,
    subset: &serde_json::Value,
    leak_signer_into_input: bool,
) -> GoSubsetOutcome {
    let genesis_hash = B256::from_slice(&go_hex(&vector["parent_hash"]));
    let mut root_input = go_hex(&vector["root_input"]);
    let mut b1_update = go_hex(&vector["b1_update"]);
    let mut records = go_hex(&vector["records"]);
    if leak_signer_into_input {
        // Negative control: a root input that differed per signer subset (here: the unicity tree
        // root) must NOT compare equal.
        let mut leaked = RootInputV2::from_canonical_cbor(&root_input).unwrap();
        leaked.origin.tree_root = B256::repeat_byte(0xee);
        b1::reseal(&mut leaked);
        b1_update = b1::job(&leaked).update.to_vec();
        records = b1::job(&leaked).records.to_vec();
        root_input = leaked.canonical_cbor().unwrap();
    }
    let beacon_root = B256::from_slice(&go_hex(&vector["parent_beacon_block_root"]));
    let mut build_input = SealBuildInput {
        root_input: root_input.clone().into(),
        transitions: vec![go_hex(&vector["transition"]).into()],
        b1_update: b1_update.clone().into(),
        records: records.clone().into(),
        pair_binding: Default::default(),
    };
    let mut companion = SealCompanion {
        root_input: root_input.clone().into(),
        b1_update: b1_update.into(),
        records: records.into(),
        pair_binding: Default::default(),
        witnesses: subset["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| go_hex(w).into())
            .collect(),
        provenance: "newPayload".into(),
    };
    let root = build_input.decode_root_input().expect("bft-core's build input decodes");
    assert_eq!(root, companion.decode_root_input().unwrap());
    assert_eq!(root.transitions.len(), 1, "a nonempty assignment transition");
    let attrs = attributes(&root, root_timestamp_parent(genesis_hash));

    // Builder route: prepare the seal build, build the payload on the frozen parent, serve it
    // through getPayloadWithSealV1.
    let (client, parent, mut context, validator) = go_genesis_fixture(genesis_hash);
    let (_dir, store) = temp_store();
    context.store = store;
    // This pair's own verification names the build; the vector supplies the input it derived.
    build_input.pair_binding = pair_binding_on(genesis_hash, &parent, &root, build_subject(&attrs))
        .canonical_cbor()
        .into();
    prepare_seal_build(
        &client,
        &context,
        &validator,
        &ForkchoiceState::same_hash(genesis_hash),
        Some(&attrs),
        &build_input,
    )
    .expect("the builder route accepts bft-core's build input");
    let config = PayloadConfig::new(parent.clone(), attrs.clone(), attrs.payload_id(&genesis_hash));
    let builder = UnicityExecutionPayloadBuilder::new(
        client.clone(),
        test_pool(),
        context.registry.clone(),
        context.builder_config.get().unwrap().clone(),
    )
    .with_parent_accounting(context.parent_accounting.clone());
    let payload = builder.build_empty_payload(config.clone()).unwrap();
    assert!(payload.block().body().transactions.is_empty());

    // Replay route: re-execute the built block against the parent state.
    let evm = context.registry.resolve(&config).unwrap();
    let recovered = RecoveredBlock::try_new(
        payload.block().clone().into_block(),
        vec![],
        payload.block().hash(),
    )
    .unwrap();
    let replay =
        replay_complete(&evm, StateProviderDatabase::new(&client.state), &client.state, &recovered)
            .expect("replay applies the built block");
    let mut post = client.state.clone();
    post.apply_bundle(&replay.output.state);
    post.set_block_hash(1, payload.block().hash());
    assert_eq!(
        post.root(),
        payload.block().header().state_root,
        "replayed state is the header's state"
    );

    let response = get_payload_with_seal_response(
        client.clone(),
        context.clone(),
        validator.clone(),
        attrs.payload_id(&genesis_hash),
        payload.clone(),
    )
    .await;
    assert_eq!(declared_block_hash(&response.execution_payload), payload.block().hash());

    // Follower route: a fresh node imports the same payload with the companion bft-core's follower
    // forwarded for this subset, bound by the follower pair's own verification of this block.
    companion.pair_binding = pair_binding_on(
        genesis_hash,
        &parent,
        &root,
        ExpectedSubject::Import { block_hash: declared_block_hash(&response.execution_payload) },
    )
    .canonical_cbor()
    .into();
    let (follower_client, _, mut follower_context, follower_validator) =
        go_genesis_fixture(genesis_hash);
    let (_follower_dir, follower_store) = temp_store();
    follower_context.store = follower_store.clone();
    let (engine, seen) = fake_engine(PayloadStatus::new(
        PayloadStatusEnum::Valid,
        Some(declared_block_hash(&response.execution_payload)),
    ))
    .await;
    let handler =
        seal_import_handler(follower_client, follower_context, follower_validator, engine);
    let status = handler
        .new_payload_with_seal(response.execution_payload.clone(), vec![], beacon_root, &companion)
        .await
        .unwrap();
    assert!(status.is_valid(), "follower route rejected bft-core's companion: {status:?}");
    assert_eq!(seen.await.unwrap().block_hash(), declared_block_hash(&response.execution_payload));
    match follower_store.get(declared_block_hash(&response.execution_payload)).unwrap() {
        Lookup::Found(found) => {
            assert_eq!(found, companion, "the follower retains exactly the subset's companion")
        }
        other => panic!("follower route did not retain the companion: {other:?}"),
    }

    GoSubsetOutcome {
        block_hash: payload.block().hash(),
        state_root: payload.block().header().state_root,
        extra_data: payload.block().header().extra_data.to_vec(),
        execution_payload: format!("{:?}", response.execution_payload),
        registry: post.storage_of(SEAL_REGISTRY),
    }
}

fn root_timestamp_parent(genesis_hash: B256) -> u64 {
    let (_, parent, _, _) = go_genesis_fixture(genesis_hash);
    parent.timestamp
}

#[tokio::test]
async fn go_signer_subset_vectors_reach_identical_state_through_builder_follower_and_replay() {
    let vector = go_x2_vector();
    let subsets = vector["subsets"].as_array().unwrap();
    assert!(subsets.len() >= 2);
    assert_ne!(
        subsets[0]["witnesses"], subsets[1]["witnesses"],
        "the subsets differ, in the witnesses only"
    );

    let mut outcomes = Vec::new();
    for subset in subsets {
        outcomes.push(apply_go_subset(&vector, subset, false).await);
    }
    for other in &outcomes[1..] {
        assert_eq!(
            &outcomes[0], other,
            "every subset yields identical block, state root and registry state"
        );
    }
    assert_eq!(
        outcomes[0].extra_data,
        go_hex(&vector["commitment"]),
        "the header commits to the input's commitment"
    );

    // The comparison discriminates: a subset-dependent root input is told apart.
    let leaked = apply_go_subset(&vector, &subsets[1], true).await;
    assert_ne!(outcomes[0].block_hash, leaked.block_hash);
    assert_ne!(outcomes[0].extra_data, leaked.extra_data);
    assert_ne!(outcomes[0], leaked);

    let registry = &outcomes[0].registry;
    assert_eq!(registry[&go_registry_slot("assignment.rootEpoch")], U256::from(2));
    assert_eq!(registry[&go_registry_slot("assignment.epoch")], U256::from(1));
    assert_eq!(registry[&go_registry_slot("transition.cursor")], U256::from(1));
    assert_eq!(
        registry[&go_registry_slot("round.authorized")],
        U256::from(vector["authorized_round"].as_u64().unwrap())
    );
}

// ---- the paired-execution binding gate ----

fn flip(word: B256) -> B256 {
    B256::from(word.0.map(|byte| byte ^ 0xff))
}

/// The bytes of a binding for `subject` with `change` applied to it.
fn binding_bytes(
    parent: &SealedHeader,
    root: &RootInputV2,
    subject: ExpectedSubject,
    change: impl FnOnce(&mut PairBinding),
) -> Vec<u8> {
    let mut binding = pair_binding(parent, root, subject);
    change(&mut binding);
    binding.canonical_cbor()
}

/// Runs the build preparation with the binding bytes `make` returns and reports the outcome and
/// the context, so a test can assert that nothing was installed.
fn build_under(
    context_change: impl FnOnce(&mut SealBuildContext),
    make: impl FnOnce(&SealedHeader, &RootInputV2, &UnicityPayloadAttributes) -> Vec<u8>,
) -> (Result<UnicityPayloadAttributes, SealBuildError>, SealBuildContext) {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    context_change(&mut context);
    let mut input = seal_input(&parent, &root, &attrs);
    input.pair_binding = make(&parent, &root, &attrs).into();
    let outcome = prepare_seal_build(
        &client,
        &context,
        &validator,
        &ForkchoiceState::same_hash(genesis_hash()),
        Some(&attrs),
        &input,
    );
    (outcome, context)
}

fn assert_build_refused(
    outcome: Result<UnicityPayloadAttributes, SealBuildError>,
    context: &SealBuildContext,
    expected: PairBindingError,
) {
    assert_eq!(outcome.unwrap_err(), SealBuildError::PairBinding(expected.clone()));
    assert!(context.registry.is_empty(), "a refused binding must install no job");
    let response = refusal_response(SealBuildError::PairBinding(expected)).unwrap();
    assert!(response.payload_status.is_invalid());
}

#[test]
fn a_build_names_its_pair_binding_and_retains_it_on_the_job() {
    let (outcome, context) = build_under(
        |_| {},
        |parent, root, attrs| binding_bytes(parent, root, build_subject(attrs), |_| {}),
    );
    let attrs = outcome.unwrap();
    assert_eq!(context.registry.len(), 1);
    let retained = context.registry.pair_binding(&attrs.payload_id(&genesis_hash())).unwrap();
    assert_eq!(retained.network_id, pair_pins().network_id);
    assert_eq!(retained.parent_hash, genesis_hash());
}

#[test]
fn a_build_without_a_binding_installs_nothing() {
    let (outcome, context) = build_under(|_| {}, |_, _, _| Vec::new());
    assert_build_refused(outcome, &context, PairBindingError::Missing);
}

#[test]
fn a_build_under_a_binding_for_another_parent_installs_nothing() {
    let (outcome, context) = build_under(
        |_| {},
        |parent, root, attrs| {
            binding_bytes(parent, root, build_subject(attrs), |b| {
                b.parent_hash = flip(b.parent_hash)
            })
        },
    );
    assert_build_refused(outcome, &context, PairBindingError::ParentHashMismatch);
}

#[test]
fn a_build_under_a_binding_for_another_job_installs_nothing() {
    let (outcome, context) = build_under(
        |_| {},
        |parent, root, attrs| {
            let mut other = attrs.clone();
            other.inner.timestamp += 1;
            binding_bytes(parent, root, build_subject(&other), |_| {})
        },
    );
    assert_build_refused(outcome, &context, PairBindingError::JobMismatch);
}

#[test]
fn a_build_under_an_import_binding_installs_nothing() {
    let (outcome, context) = build_under(
        |_| {},
        |parent, root, _| {
            binding_bytes(
                parent,
                root,
                ExpectedSubject::Import { block_hash: B256::repeat_byte(5) },
                |_| {},
            )
        },
    );
    assert_build_refused(
        outcome,
        &context,
        PairBindingError::WrongSubjectKind { expected: SUBJECT_BUILD, found: SUBJECT_IMPORT },
    );
}

#[test]
fn a_build_under_a_binding_for_another_root_input_installs_nothing() {
    let (outcome, context) = build_under(
        |_| {},
        |parent, root, attrs| {
            binding_bytes(parent, root, build_subject(attrs), |b| {
                b.root_input_hash = flip(b.root_input_hash)
            })
        },
    );
    assert_build_refused(outcome, &context, PairBindingError::RootInputMismatch);
}

#[test]
fn a_build_under_another_pinned_network_installs_nothing() {
    let (outcome, context) = build_under(
        |context| context.state.seal.pins.network_id += 1,
        |parent, root, attrs| binding_bytes(parent, root, build_subject(attrs), |_| {}),
    );
    assert_build_refused(outcome, &context, PairBindingError::NetworkMismatch);
}

#[test]
fn a_build_under_another_pinned_root_genesis_installs_nothing() {
    let (outcome, context) = build_under(
        |context| {
            context.state.seal.pins.root_genesis_id = flip(context.state.seal.pins.root_genesis_id)
        },
        |parent, root, attrs| binding_bytes(parent, root, build_subject(attrs), |_| {}),
    );
    assert_build_refused(outcome, &context, PairBindingError::RootGenesisMismatch);
}

#[test]
fn a_repeated_build_must_carry_the_same_binding() {
    let (client, parent, root, attrs, context, validator) = seal_fixture();
    let state = ForkchoiceState::same_hash(genesis_hash());
    let first = seal_input(&parent, &root, &attrs);
    prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &first).unwrap();
    // The activation is the one field with no local comparison when no transition is carried, so
    // a second binding that differs only there is well formed and verifies. The registry must still
    // tell it from the first.
    let mut other = first;
    other.pair_binding = binding_bytes(&parent, &root, build_subject(&attrs), |b| {
        b.activation_id = flip(b.activation_id)
    })
    .into();
    let error = prepare_seal_build(&client, &context, &validator, &state, Some(&attrs), &other)
        .unwrap_err();
    assert_eq!(error, SealBuildError::DuplicatePayloadId);
    assert_eq!(context.registry.len(), 1);
}

#[tokio::test]
async fn a_job_without_a_retained_binding_cannot_produce_a_companion() {
    let (client, parent, root, _attrs, context, validator) = seal_fixture();
    // Installed behind the gate's back, as a library caller could: no binding is retained.
    let base = context.builder_config.get().unwrap().clone();
    let (job, attrs) = resolved_job(&client.chain_spec, &parent, &Arc::new(root), &base);
    context.registry.insert(job).unwrap();
    let payload_id = attrs.payload_id(&parent.hash());
    assert!(context.registry.pair_binding(&payload_id).is_none());
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
    match handler.get_payload_with_seal(payload_id).await.unwrap_err() {
        EngineApiError::Other(error) => assert_eq!(error.code(), COMPANION_NOT_RETAINED_CODE),
        other => panic!("expected the unretained-companion error, got {other:?}"),
    }
}

/// An import of the genesis-parent block under `make`'s companion edit; returns the status, whether
/// the engine saw the block, and the context and store for the follow-up assertions.
async fn import_under(
    make: impl FnOnce(&SealedHeader, &RootInputV2, &UnicityPayloadAttributes, &mut SealCompanion),
) -> (PayloadStatus, bool, SealBuildContext, Arc<CompanionStore>) {
    let (client, parent, root, attrs, mut context, validator) = seal_fixture();
    let (dir, store) = temp_store();
    std::mem::forget(dir);
    context.store = store.clone();
    let payload = build_genesis_seal_payload(&client, &parent, &root, &attrs, &context, &validator);
    let block_hash = payload.block().hash();
    let (execution_payload, mut companion, beacon_root) =
        payload_for_import(&payload, &parent, &root, |_| {});
    make(&parent, &root, &attrs, &mut companion);
    let (engine, seen) =
        fake_engine(PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash))).await;
    let probe = context.clone();
    let handler = seal_import_handler(client, context, validator, engine);
    let status = handler
        .new_payload_with_seal(execution_payload, vec![], beacon_root, &companion)
        .await
        .unwrap();
    drop(handler);
    (status, seen.await.is_ok(), probe, store)
}

async fn assert_import_refused(
    outcome: (PayloadStatus, bool, SealBuildContext, Arc<CompanionStore>),
    expected: PairBindingError,
) {
    let (status, forwarded, context, store) = outcome;
    assert!(status.is_invalid(), "{status:?}");
    assert_eq!(
        status.status.validation_error().unwrap(),
        SealImportError::PairBinding(expected).to_string()
    );
    assert!(!forwarded, "a refused binding must not reach the Engine");
    assert!(context.parent_accounting.is_empty(), "no accounting before the gate passes");
    assert!(
        store.entries_in_range(0, u64::MAX).unwrap().is_empty(),
        "a refused binding must retain no companion"
    );
}

#[tokio::test]
async fn an_import_with_its_binding_is_retained_with_that_binding() {
    let (status, forwarded, _context, store) = import_under(|_, _, _, _| {}).await;
    assert!(status.is_valid(), "{status:?}");
    assert!(forwarded);
    let hash = status.latest_valid_hash.unwrap();
    match store.get(hash).unwrap() {
        Lookup::Found(found) => {
            assert!(PairBinding::from_canonical_cbor(&found.pair_binding).is_ok());
        }
        other => panic!("the admitted companion must be retained with its binding: {other:?}"),
    }
}

#[tokio::test]
async fn an_import_without_a_binding_is_refused_whatever_its_provenance() {
    // Live follow, fresh paired sync and re-execution all arrive through this one method, and the
    // provenance label is not a way around the gate.
    for provenance in ["newPayload", "devp2p", "reexec", "build"] {
        let outcome = import_under(|_, _, _, companion| {
            companion.pair_binding = Default::default();
            companion.provenance = provenance.to_owned();
        })
        .await;
        assert_import_refused(outcome, PairBindingError::Missing).await;
    }
}

#[tokio::test]
async fn an_import_under_a_binding_for_another_block_is_refused() {
    let outcome = import_under(|parent, root, _, companion| {
        companion.pair_binding = binding_bytes(
            parent,
            root,
            ExpectedSubject::Import { block_hash: B256::repeat_byte(0x42) },
            |_| {},
        )
        .into();
    })
    .await;
    assert_import_refused(outcome, PairBindingError::BlockMismatch).await;
}

#[tokio::test]
async fn an_import_under_a_build_binding_is_refused() {
    let outcome = import_under(|parent, root, attrs, companion| {
        companion.pair_binding = binding_bytes(parent, root, build_subject(attrs), |_| {}).into();
    })
    .await;
    assert_import_refused(
        outcome,
        PairBindingError::WrongSubjectKind { expected: SUBJECT_IMPORT, found: SUBJECT_BUILD },
    )
    .await;
}

#[tokio::test]
async fn an_import_under_a_binding_for_another_parent_is_refused() {
    let outcome = import_under(|parent, root, _, companion| {
        let other_parent = SealedHeader::new(
            alloy_consensus::Header { number: parent.number + 1, ..parent.header().clone() },
            parent.hash(),
        );
        // The binding is internally consistent for a parent at another height.
        let hash = companion_block_hash(companion, parent, root);
        companion.pair_binding = binding_bytes(
            &other_parent,
            root,
            ExpectedSubject::Import { block_hash: hash },
            |_| {},
        )
        .into();
    })
    .await;
    assert_import_refused(outcome, PairBindingError::ParentNumberMismatch).await;
}

/// The block hash `import_companion` named, read back from the companion's own binding.
fn companion_block_hash(
    companion: &SealCompanion,
    _parent: &SealedHeader,
    _root: &RootInputV2,
) -> B256 {
    match PairBinding::from_canonical_cbor(&companion.pair_binding).unwrap().subject {
        PairSubject::Import { block_hash } => block_hash,
        PairSubject::Build { .. } => panic!("an import companion names an import"),
    }
}

#[tokio::test]
async fn recovery_refuses_a_retained_binding_that_no_longer_names_the_canonical_block() {
    let history = capture_paid_idle_transition_fixture().await;
    let first = &history.blocks[0];
    let hash = first.payload.block().hash();
    let provider = history.recovery_provider(1);
    // What the local Go side presents for the head: its own import binding of the exact block.
    let presented = first.import_companion.pair_binding.clone();

    let repair = |companion: &SealCompanion, pins: PairPins| {
        let (_dir, store) = temp_store();
        store.put(hash, 1, companion).unwrap();
        reth_unicity_payload::recovery::admit_recovered_head(
            &provider,
            &store,
            &UnicityParentAccountings::default(),
            UnicitySealConfig {
                profile: profile(),
                fee_collector: FEE_COLLECTOR,
                pins,
                b1: b1::context(),
            },
            &presented,
            1,
        )
    };
    let with_binding =
        |bytes: Vec<u8>| SealCompanion { pair_binding: bytes.into(), ..first.companion.clone() };
    let parent = &first.parent;
    let root = &first.root;
    let attrs = attributes(root, parent.timestamp);

    // Both subject kinds the node itself retains replay.
    repair(&first.companion, pair_pins()).unwrap();
    repair(&first.import_companion, pair_pins()).unwrap();

    let retained_refused = |error: eyre::Report, expected: PairBindingError| match error
        .downcast_ref::<RecoveryError>(
    ) {
        Some(RecoveryError::RetainedRefused { number: 1, source }) => {
            assert_eq!(*source, expected)
        }
        other => panic!("expected RetainedRefused({expected:?}), got {other:?}"),
    };
    match repair(&with_binding(Vec::new()), pair_pins())
        .unwrap_err()
        .downcast_ref::<RecoveryError>()
    {
        Some(RecoveryError::RetainedUnusable { number: 1, source: PairBindingError::Missing }) => {}
        other => {
            panic!("an empty retained binding must be RetainedUnusable(Missing), got {other:?}")
        }
    }
    retained_refused(
        repair(
            &with_binding(binding_bytes(parent, root, build_subject(&attrs), |b| {
                b.parent_hash = flip(b.parent_hash)
            })),
            pair_pins(),
        )
        .unwrap_err(),
        PairBindingError::ParentHashMismatch,
    );
    let mut other_job = attrs;
    other_job.inner.timestamp += 1;
    retained_refused(
        repair(
            &with_binding(binding_bytes(parent, root, build_subject(&other_job), |_| {})),
            pair_pins(),
        )
        .unwrap_err(),
        PairBindingError::JobMismatch,
    );
    retained_refused(
        repair(
            &with_binding(binding_bytes(
                parent,
                root,
                ExpectedSubject::Import { block_hash: B256::repeat_byte(0x42) },
                |_| {},
            )),
            pair_pins(),
        )
        .unwrap_err(),
        PairBindingError::BlockMismatch,
    );
    retained_refused(
        repair(
            &first.companion,
            PairPins { network_id: pair_pins().network_id + 1, ..pair_pins() },
        )
        .unwrap_err(),
        PairBindingError::NetworkMismatch,
    );
    retained_refused(
        repair(
            &first.companion,
            PairPins { root_genesis_id: flip(pair_pins().root_genesis_id), ..pair_pins() },
        )
        .unwrap_err(),
        PairBindingError::RootGenesisMismatch,
    );
}

/// The restart review control: accounting a previous process persisted, read back into a fresh
/// cache, must not stand in for admission. Each negative changes one thing from the control.
#[tokio::test]
async fn restored_accounting_resolves_only_after_recovery_admission() {
    let history = capture_paid_idle_transition_fixture().await;
    let first = &history.blocks[0];
    let hash = first.payload.block().hash();
    let head = SealedHeader::new(first.payload.block().header().clone(), hash);
    let provider = history.recovery_provider(1);
    let chain = history.chain_spec.clone();
    let presented = first.import_companion.pair_binding.clone();
    let seal = UnicitySealConfig {
        profile: profile(),
        fee_collector: FEE_COLLECTOR,
        pins: pair_pins(),
        b1: b1::context(),
    };

    // A previous process persisted the head's accounting; this one starts with an empty cache,
    // hydrates it from disk, and has the companion `companion` retained.
    let restart = |companion: Option<&SealCompanion>| {
        let (dir, store) = temp_store();
        let previous = UnicityParentAccountings::new().require_durability();
        previous.attach_store(store.clone());
        previous
            .publish(hash, 1, chain.chain().id(), chain.genesis_hash(), first.completed)
            .unwrap();
        if let Some(companion) = companion {
            store.put(hash, 1, companion).unwrap();
        }
        let fresh = UnicityParentAccountings::new().require_durability();
        fresh.attach_store(store.clone());
        reth_unicity_payload::recovery::hydrate_accounting(&provider, &fresh, profile()).unwrap();
        (dir, store, fresh)
    };
    let resolves =
        |tokens: &UnicityParentAccountings| tokens.resolve(&head, &chain, profile()).is_ok();
    let admit =
        |store: &CompanionStore, tokens: &UnicityParentAccountings, seal, presented: &[u8]| {
            reth_unicity_payload::recovery::admit_recovered_head(
                &provider, store, tokens, seal, presented, 1,
            )
        };

    // Control: hydrated, cached, and still unusable; admission with the right context admits it.
    let (_dir, store, tokens) = restart(Some(&first.companion));
    assert!(tokens.get(&hash).is_some(), "the cache holds the token");
    assert!(!resolves(&tokens), "a cached token must not resolve before admission");
    admit(&store, &tokens, seal, &presented).unwrap();
    assert!(resolves(&tokens), "admission makes the cached token usable");

    let refused = |error: eyre::Report| -> RecoveryError {
        match error.downcast::<RecoveryError>() {
            Ok(typed) => typed,
            Err(other) => panic!("expected a typed recovery refusal, got {other:#}"),
        }
    };
    // No companion retained.
    let (_dir, store, tokens) = restart(None);
    assert!(matches!(
        refused(admit(&store, &tokens, seal, &presented).unwrap_err()),
        RecoveryError::CompanionMissing(1)
    ));
    assert!(!resolves(&tokens));
    // An empty retained binding.
    let empty = SealCompanion { pair_binding: Vec::new().into(), ..first.companion.clone() };
    let (_dir, store, tokens) = restart(Some(&empty));
    assert!(matches!(
        refused(admit(&store, &tokens, seal, &presented).unwrap_err()),
        RecoveryError::RetainedUnusable { number: 1, source: PairBindingError::Missing }
    ));
    assert!(!resolves(&tokens));
    // Another pair: a changed root-genesis pin.
    let other_pair = UnicitySealConfig {
        pins: PairPins { root_genesis_id: flip(pair_pins().root_genesis_id), ..pair_pins() },
        ..seal
    };
    let (_dir, store, tokens) = restart(Some(&first.companion));
    assert!(matches!(
        refused(admit(&store, &tokens, other_pair, &presented).unwrap_err()),
        RecoveryError::RetainedRefused { number: 1, source: PairBindingError::RootGenesisMismatch }
    ));
    assert!(!resolves(&tokens));
    // Go presents nothing, or a binding for another parent, or another activation.
    let (_dir, store, tokens) = restart(Some(&first.companion));
    assert!(matches!(
        refused(admit(&store, &tokens, seal, &[]).unwrap_err()),
        RecoveryError::PresentedRefused { number: 1, source: PairBindingError::Missing }
    ));
    let wrong_parent = binding_bytes(
        &first.parent,
        &first.root,
        ExpectedSubject::Import { block_hash: hash },
        |b| b.parent_hash = flip(b.parent_hash),
    );
    assert!(matches!(
        refused(admit(&store, &tokens, seal, &wrong_parent).unwrap_err()),
        RecoveryError::PresentedRefused { number: 1, source: PairBindingError::ParentHashMismatch }
    ));
    let other_activation = binding_bytes(
        &first.parent,
        &first.root,
        ExpectedSubject::Import { block_hash: hash },
        |b| b.activation_id = flip(b.activation_id),
    );
    assert!(matches!(
        refused(admit(&store, &tokens, seal, &other_activation).unwrap_err()),
        RecoveryError::PresentedDiffers(1)
    ));
    assert!(!resolves(&tokens), "no refused admission leaves a usable token behind");
}

/// Regression of ureth#60: a recovery admission refused the head with "no token for the admitted
/// head" when the store, at its capacity, also held a token newer than the head (the token of a
/// build in flight). Restoring the window behind the head inserted older tokens, each evicting the
/// oldest unpinned entry, and the cascade ended by evicting the head itself.
///
/// The store here is the shape of a running node whose shard node restarts: the tokens of the
/// canonical window are cached and admitted, one token newer than the head is cached too, and
/// every older token is on disk. The twenty blocks exceed the window and the capacity.
#[tokio::test]
async fn recovery_admission_keeps_the_head_when_a_newer_token_crowds_the_store() {
    const HEAD: u64 = 20;
    let mut schedule = vec![(1, 1, true)];
    schedule.extend((2..HEAD).map(|round| (round, 1, false)));
    schedule.push((HEAD, 2, false));
    let history = capture_route_history(&schedule).await;
    let provider = history.recovery_provider(history.blocks.len());
    let seal = || UnicitySealConfig {
        profile: profile(),
        fee_collector: FEE_COLLECTOR,
        pins: pair_pins(),
        b1: b1::context(),
    };
    let chain_id = history.chain_spec.chain().id();
    let genesis = history.chain_spec.genesis_hash();
    let head = history.blocks.last().unwrap();
    let head_hash = head.payload.block().hash();
    let presented = &head.import_companion.pair_binding;

    // Every block's accounting is on disk, as a running node leaves it.
    let writer = UnicityParentAccountings::default().require_durability();
    writer.attach_store(history.store.clone());
    for captured in &history.blocks {
        let block = captured.payload.block();
        writer
            .publish(block.hash(), block.header().number, chain_id, genesis, captured.completed)
            .unwrap();
    }

    // The running node's cache: the window behind the head and the head, admitted, and one token
    // newer than the head.
    let live = UnicityParentAccountings::default().require_durability();
    live.attach_store(history.store.clone());
    for captured in &history.blocks[history.blocks.len() - 15..] {
        let block = captured.payload.block();
        live.insert_for_chain(block.hash(), captured.completed, chain_id, genesis);
    }
    live.insert_for_chain(B256::repeat_byte(0xEE), head.completed, chain_id, genesis);
    assert_eq!(live.len(), 16, "the store is at its capacity");

    reth_unicity_payload::recovery::admit_recovered_head(
        &provider,
        &history.store,
        &live,
        seal(),
        presented,
        64,
    )
    .expect("the head must survive the restoration of its window");
    assert!(live.is_admitted(&head_hash), "the admitted head resolves");
    assert!(live.len() <= 17, "the pin released: the store is back within a pin of its capacity");
}
