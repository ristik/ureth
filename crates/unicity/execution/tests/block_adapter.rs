//! Real shared build/replay integration over the test-only standard-JSON genesis.

mod support;

use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip4844, TxLegacy};
use alloy_eips::eip4788::BEACON_ROOTS_ADDRESS;
use alloy_evm::block::BlockExecutor;
use alloy_genesis::Genesis;
use alloy_primitives::{b256, Address, Bytes, Signature, TxKind, B256, B64, U256};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, Transaction, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, BlockBody, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_storage_api::{AccountReader, StateProvider};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{
        build_complete, replay_complete, BoundExecutionInput, CompletedParent, UnicityEvmConfig,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp, technical_record_hash,
    wire::bind_completed_parent,
    InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2, SEAL_REGISTRY, SYSTEM_CALLER,
};
use revm::database::State;
use std::sync::{Arc, Mutex};
use support::provider::FixtureProvider;

const GENESIS_HASH: B256 =
    b256!("82430ee9e534f0e454399cdaa06042c5dcc52b0378f48609e9c45c3cc1ae01f0");
const GENESIS_ROOT: B256 =
    b256!("cc17df719a9c043b34c3b5c0297775feb4c9ff8cfecf3b77ffe29bee9b0fe40a");
const FEE_COLLECTOR: Address = Address::new([0x77; 20]);
const PROFILE: BlockProfile = BlockProfile {
    max_gas: 30_000_001,
    system_gas: 500_001,
    base_fee_floor: 7,
    elasticity: 2,
    change_denominator: 8,
};

fn signed_call(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    to: Address,
    value: U256,
    gas_limit: u64,
) -> TransactionSigned {
    let transaction = Transaction::Legacy(TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: Default::default(),
    });
    let key = B256::with_last_byte(1);
    let signature = sign_message(key, transaction.signature_hash()).unwrap();
    TransactionSigned::new_unhashed(transaction, signature)
}

fn expected_next_base_fee(parent_base: u64, ordinary_used: u64) -> u64 {
    let target = (PROFILE.max_gas - PROFILE.system_gas) / PROFILE.elasticity;
    let delta = u128::from(parent_base) * u128::from(ordinary_used.abs_diff(target)) /
        u128::from(target) /
        u128::from(PROFILE.change_denominator);
    if ordinary_used > target {
        parent_base + u64::try_from(delta).unwrap().max(1)
    } else {
        parent_base.saturating_sub(u64::try_from(delta).unwrap()).max(PROFILE.base_fee_floor)
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

fn attributes(input: &RootInputV2, parent_timestamp: u64) -> NextBlockEnvAttributes {
    NextBlockEnvAttributes {
        timestamp: derive_timestamp(input.origin.reference_time, parent_timestamp).unwrap(),
        suggested_fee_recipient: FEE_COLLECTOR,
        prev_randao: derive_prev_randao(input.origin.root_round, input.authorized_round),
        gas_limit: PROFILE.max_gas,
        parent_beacon_block_root: Some(derive_beacon_root(
            input.origin.root_round,
            input.authorized_round,
        )),
        withdrawals: Some(Default::default()),
        extra_data: input.input_commitment().unwrap().to_vec().into(),
        slot_number: None,
    }
}

#[test]
fn payload_job_binding_names_gas_and_fee_mismatches() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = SealedHeader::new(chain_spec.genesis_header().clone(), GENESIS_HASH);
    let root = Arc::new(input(1, 1, GENESIS_HASH));
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root.clone(),
            PROFILE,
            &parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec), bound);
    let mut attrs = attributes(&root, parent.timestamp);

    attrs.gas_limit += 1;
    assert_eq!(
        config.validate_payload_job(&parent, &attrs).unwrap_err().message(),
        "next-block gas_limit mismatch"
    );
    attrs.gas_limit = PROFILE.max_gas;
    attrs.suggested_fee_recipient = Address::ZERO;
    assert_eq!(
        config.validate_payload_job(&parent, &attrs).unwrap_err().message(),
        "next-block suggested_fee_recipient mismatch"
    );
}

#[test]
fn build_replay_and_opaque_parent_token_agree_across_two_blocks() {
    let genesis_json = include_str!("../testdata/signed-beacon-genesis.json");
    let genesis: Genesis = serde_json::from_str(genesis_json).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let genesis_header = chain_spec.genesis_header().clone();
    assert_eq!(genesis_header.hash_slow(), GENESIS_HASH);
    assert_eq!(genesis_header.state_root, GENESIS_ROOT);
    let parent = SealedHeader::new(genesis_header.clone(), GENESIS_HASH);
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, GENESIS_HASH);
    assert_eq!(provider.root(), GENESIS_ROOT);
    let signer =
        Address::parse_checksummed("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", None).unwrap();
    let initial_signer = provider.basic_account(&signer).unwrap().unwrap();

    let first_input = Arc::new(input(1, 1, GENESIS_HASH));
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            first_input.clone(),
            PROFILE,
            &parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), bound);
    let over_capacity = signed_call(
        chain_spec.chain.id(),
        0,
        u128::from(genesis_header.base_fee_per_gas.unwrap()) + 100,
        Address::repeat_byte(0x42),
        U256::ZERO,
        PROFILE.ordinary_capacity().unwrap() + 1,
    )
    .try_into_recovered()
    .unwrap();
    let mut rejected_state =
        State::builder().with_database(provider.clone()).with_bundle_update().build();
    assert!(build_complete(
        &config,
        &parent,
        attributes(&first_input, parent.timestamp),
        &mut rejected_state,
        provider.clone(),
        vec![over_capacity],
    )
    .is_err());
    let mut build_state =
        State::builder().with_database(provider.clone()).with_bundle_update().build();
    let commits = Arc::new(Mutex::new(Vec::<Vec<Address>>::new()));
    let observed = commits.clone();
    build_state.set_state_hook(Some(Box::new(move |state: revm::state::EvmState| {
        observed.lock().unwrap().push(state.keys().copied().collect());
    })));
    let transfer = signed_call(
        chain_spec.chain.id(),
        0,
        u128::from(genesis_header.base_fee_per_gas.unwrap()) + 100,
        Address::repeat_byte(0x42),
        U256::from(1),
        21_000,
    )
    .try_into_recovered()
    .unwrap();
    assert_eq!(transfer.signer(), signer,);
    let built = build_complete(
        &config,
        &parent,
        attributes(&first_input, parent.timestamp),
        &mut build_state,
        provider.clone(),
        vec![transfer],
    )
    .unwrap();
    assert!(built.outcome.execution_result.gas_used > 0);
    assert_eq!(built.outcome.execution_result.receipts.len(), 1);
    assert!(built.outcome.execution_result.receipts[0].success);
    let commits = commits.lock().unwrap();
    assert!(commits[0].contains(&SEAL_REGISTRY));
    assert!(commits[1].contains(&SEAL_REGISTRY));
    assert!(commits[2].contains(&BEACON_ROOTS_ADDRESS));
    assert!(commits.iter().skip(3).any(|state| state.contains(&signer)));
    drop(commits);

    let first_block = built.outcome.block.clone();
    let replayed = replay_complete(&config, provider.clone(), &provider, &first_block).unwrap();
    assert_eq!(replayed.output.result, built.outcome.execution_result);

    let (mut wrong_root_block, senders) = first_block.clone().split();
    wrong_root_block.header.state_root = B256::repeat_byte(0x99);
    let wrong_root = RecoveredBlock::new_unhashed(wrong_root_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &wrong_root).is_err());
    let (mut wrong_tx_root_block, senders) = first_block.clone().split();
    wrong_tx_root_block.header.transactions_root = B256::repeat_byte(0x88);
    let wrong_tx_root = RecoveredBlock::new_unhashed(wrong_tx_root_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &wrong_tx_root).is_err());
    let (mut wrong_gas_block, senders) = first_block.clone().split();
    wrong_gas_block.header.gas_used += 1;
    let wrong_gas = RecoveredBlock::new_unhashed(wrong_gas_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &wrong_gas).is_err());
    let (mut wrong_beneficiary_block, senders) = first_block.clone().split();
    wrong_beneficiary_block.header.beneficiary = Address::repeat_byte(0x66);
    let wrong_beneficiary = RecoveredBlock::new_unhashed(wrong_beneficiary_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &wrong_beneficiary).is_err());
    let (mut wrong_nonce_block, senders) = first_block.clone().split();
    wrong_nonce_block.header.nonce = B64::repeat_byte(1);
    let wrong_nonce = RecoveredBlock::new_unhashed(wrong_nonce_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &wrong_nonce).is_err());
    let (mut later_field_block, senders) = first_block.clone().split();
    later_field_block.header.requests_hash = Some(B256::repeat_byte(0x77));
    let later_field = RecoveredBlock::new_unhashed(later_field_block, senders);
    assert!(replay_complete(&config, provider.clone(), &provider, &later_field).is_err());

    let first_header = first_block.into_sealed_block().into_sealed_header();
    let stored = built.parent.for_local_storage();
    assert!(CompletedParent::from_local_storage(stored, &first_header, PROFILE).is_ok());
    let mut wrong_accounting = stored;
    wrong_accounting.ordinary_gas += 1;
    assert!(CompletedParent::from_local_storage(wrong_accounting, &first_header, PROFILE).is_err());
    let mut wrong_hash = stored;
    wrong_hash.block_hash = B256::ZERO;
    assert!(CompletedParent::from_local_storage(wrong_hash, &first_header, PROFILE).is_err());
    assert!(CompletedParent::from_local_storage(
        stored,
        &first_header,
        BlockProfile { base_fee_floor: 8, ..PROFILE },
    )
    .is_err());
    assert_eq!(
        first_header.base_fee_per_gas.unwrap(),
        expected_next_base_fee(genesis_header.base_fee_per_gas.unwrap(), 0),
    );
    let second_input = Arc::new(input(2, 2, first_header.hash()));
    let wrong_parent_input = Arc::new(input(2, 2, B256::ZERO));
    assert!(BoundExecutionInput::from_completed_parent(
        wrong_parent_input,
        PROFILE,
        &first_header,
        built.parent,
        FEE_COLLECTOR,
    )
    .is_err());
    assert!(BoundExecutionInput::from_completed_parent(
        second_input.clone(),
        BlockProfile { base_fee_floor: 8, ..PROFILE },
        &first_header,
        built.parent,
        FEE_COLLECTOR,
    )
    .is_err());
    let mut forged_parent_header = first_header.header().clone();
    forged_parent_header.timestamp += 1;
    let forged_parent = SealedHeader::new(forged_parent_header, first_header.hash());
    assert!(BoundExecutionInput::from_completed_parent(
        second_input.clone(),
        PROFILE,
        &forged_parent,
        built.parent,
        FEE_COLLECTOR,
    )
    .is_err());
    let build_bound = Arc::new(
        bind_completed_parent(
            (*second_input).clone(),
            PROFILE,
            &first_header,
            built.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let replay_bound = Arc::new(
        BoundExecutionInput::from_completed_parent(
            second_input.clone(),
            PROFILE,
            &first_header,
            replayed.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let mut post_build = provider.clone();
    post_build.apply_bundle(&build_state.bundle_state);
    post_build.set_block_hash(1, first_header.hash());
    assert_eq!(post_build.root(), first_header.state_root);
    let after_transfer = post_build.basic_account(&signer).unwrap().unwrap();
    let first_receipt_gas = built.outcome.execution_result.receipts[0].cumulative_gas_used;
    let first_price = u128::from(genesis_header.base_fee_per_gas.unwrap()) + 100;
    assert_eq!(after_transfer.nonce, 1);
    assert_eq!(
        after_transfer.balance,
        initial_signer.balance -
            U256::from(1) -
            U256::from(first_receipt_gas) * U256::from(first_price),
    );
    assert_eq!(
        post_build.basic_account(&FEE_COLLECTOR).unwrap().unwrap().balance,
        U256::from(first_receipt_gas) *
            U256::from(first_price - u128::from(first_header.base_fee_per_gas.unwrap())),
    );
    assert_eq!(
        post_build.basic_account(&Address::repeat_byte(0x42)).unwrap().unwrap().balance,
        U256::from(1),
    );
    let timestamp_slot = U256::from(first_header.timestamp % 8_191);
    let root_slot = timestamp_slot + U256::from(8_191);
    assert_eq!(
        post_build.storage(BEACON_ROOTS_ADDRESS, timestamp_slot.into()).unwrap(),
        Some(U256::from(first_header.timestamp)),
    );
    assert_eq!(
        post_build.storage(BEACON_ROOTS_ADDRESS, root_slot.into()).unwrap(),
        Some(U256::from_be_bytes(derive_beacon_root(1, 1).0)),
    );
    let mut state_a =
        State::builder().with_database(post_build.clone()).with_bundle_update().build();
    let mut state_b =
        State::builder().with_database(post_build.clone()).with_bundle_update().build();
    let attrs = attributes(&second_input, first_header.timestamp);
    let reverted = signed_call(
        chain_spec.chain.id(),
        1,
        u128::from(first_header.base_fee_per_gas.unwrap()) + 100,
        SEAL_REGISTRY,
        U256::ZERO,
        100_000,
    )
    .try_into_recovered()
    .unwrap();
    let block_a = build_complete(
        &UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), build_bound),
        &first_header,
        attrs.clone(),
        &mut state_a,
        post_build.clone(),
        vec![reverted.clone()],
    )
    .unwrap();
    let block_b = build_complete(
        &UnicityEvmConfig::new(EthEvmConfig::new(chain_spec), replay_bound),
        &first_header,
        attrs,
        &mut state_b,
        post_build.clone(),
        vec![reverted],
    )
    .unwrap();
    assert_eq!(block_a.outcome.block.hash(), block_b.outcome.block.hash());
    assert_eq!(block_a.outcome.execution_result, block_b.outcome.execution_result);
    let second_base_fee = block_a.outcome.block.header().base_fee_per_gas.unwrap();
    assert_eq!(
        second_base_fee,
        expected_next_base_fee(first_header.base_fee_per_gas.unwrap(), first_receipt_gas),
    );
    assert_ne!(
        second_base_fee,
        expected_next_base_fee(
            first_header.base_fee_per_gas.unwrap(),
            built.outcome.execution_result.gas_used,
        ),
    );
    assert!(!block_a.outcome.execution_result.receipts[0].success);
    let mut after_second = post_build.clone();
    after_second.apply_bundle(&state_a.bundle_state);
    assert_eq!(after_second.root(), block_a.outcome.block.header().state_root);
    let second_receipt_gas = block_a.outcome.execution_result.receipts[0].cumulative_gas_used;
    let second_price = u128::from(first_header.base_fee_per_gas.unwrap()) + 100;
    let final_signer = after_second.basic_account(&signer).unwrap().unwrap();
    assert_eq!(final_signer.nonce, 2);
    assert_eq!(
        final_signer.balance,
        after_transfer.balance - U256::from(second_receipt_gas) * U256::from(second_price),
    );
    assert_eq!(
        after_second.basic_account(&FEE_COLLECTOR).unwrap().unwrap().balance,
        U256::from(first_receipt_gas) *
            U256::from(first_price - u128::from(first_header.base_fee_per_gas.unwrap())) +
            U256::from(second_receipt_gas) *
                U256::from(
                    second_price -
                        u128::from(block_a.outcome.block.header().base_fee_per_gas.unwrap()),
                ),
    );
}

/// Genesis fixture with one valid first block, shared by the impersonation tests.
struct ImportFixture {
    chain_spec: Arc<ChainSpec>,
    config: UnicityEvmConfig,
    provider: FixtureProvider,
    first_block: RecoveredBlock<Block>,
}

fn import_fixture() -> ImportFixture {
    let genesis_json = include_str!("../testdata/signed-beacon-genesis.json");
    let genesis: Genesis = serde_json::from_str(genesis_json).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let genesis_header = chain_spec.genesis_header().clone();
    let parent = SealedHeader::new(genesis_header.clone(), GENESIS_HASH);
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, GENESIS_HASH);
    let first_input = Arc::new(input(1, 1, GENESIS_HASH));
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            first_input.clone(),
            PROFILE,
            &parent,
            GENESIS_HASH,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(EthEvmConfig::new(chain_spec.clone()), bound);
    let mut build_state =
        State::builder().with_database(provider.clone()).with_bundle_update().build();
    let transfer = signed_call(
        chain_spec.chain.id(),
        0,
        u128::from(genesis_header.base_fee_per_gas.unwrap()) + 100,
        Address::repeat_byte(0x42),
        U256::from(1),
        21_000,
    )
    .try_into_recovered()
    .unwrap();
    let built = build_complete(
        &config,
        &parent,
        attributes(&first_input, parent.timestamp),
        &mut build_state,
        provider.clone(),
        vec![transfer],
    )
    .unwrap();
    ImportFixture { chain_spec, config, provider, first_block: built.outcome.block }
}

/// Returns a copy of `block` with `transactions` and the matching `senders`, recomputing only the
/// transaction root.
///
/// Every other header field is left as it was, so the block is internally inconsistent in the
/// fields that are checked after the rule under test. Pre-execution checks the transaction root and
/// the header, not the state root, receipts or gas, so the intended rule is what rejects the block.
fn with_transactions(
    block: &RecoveredBlock<Block>,
    transactions: Vec<TransactionSigned>,
    senders: Vec<Address>,
) -> RecoveredBlock<Block> {
    let (mut inner, _) = block.clone().split();
    inner.body.transactions = transactions;
    inner.header.transactions_root = inner.body.calculate_tx_root();
    RecoveredBlock::new_unhashed(inner, senders)
}

/// A signed EIP-4844 transaction carrying one blob versioned hash.
fn blob_tx(chain_id: u64) -> TransactionSigned {
    TransactionSigned::new_unhashed(
        Transaction::Eip4844(TxEip4844 {
            chain_id,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 0,
            to: Address::repeat_byte(0x42),
            value: U256::ZERO,
            access_list: Default::default(),
            blob_versioned_hashes: vec![B256::repeat_byte(0x01)],
            max_fee_per_blob_gas: 1,
            input: Bytes::new(),
        }),
        Signature::new(U256::default(), U256::default(), true),
    )
}

/// Rule: an ordinary transaction whose signer is `SYSTEM_CALLER` is refused.
///
/// This is the malicious-builder shape driven through the import entry point, because that is where
/// a hostile block actually arrives. The block is otherwise well formed, and its transaction root
/// is recomputed, so the refusal is the reserved-sender rule rather than a structural check.
#[test]
fn import_refuses_a_block_that_forges_the_system_sender() {
    let fixture = import_fixture();
    let hostile = signed_call(
        fixture.chain_spec.chain.id(),
        1,
        1_000,
        Address::repeat_byte(0x42),
        U256::ZERO,
        21_000,
    );
    let block = with_transactions(&fixture.first_block, vec![hostile], vec![SYSTEM_CALLER]);

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(
        error.to_string().contains("reserved sender"),
        "expected the reserved-sender refusal, got: {error}"
    );
}

/// Rule: an extra transaction claiming the system sender, appended after the legitimate prefix, is
/// refused. This is the "cannot repeat" half of the clause.
///
/// The block first carries the legitimate paying user transaction, so the executor has already run
/// the real system prefix, and only then reaches the repeated system-sender transaction. The
/// refusal must fall out of the same reserved-sender rule as the forged-sender case, which the
/// assertion confirms rather than assumes.
#[test]
fn import_refuses_a_repeated_system_sender_after_the_legitimate_prefix() {
    let fixture = import_fixture();
    let (inner, mut senders) = fixture.first_block.clone().split();
    let mut transactions = inner.body.transactions;
    transactions.push(signed_call(
        fixture.chain_spec.chain.id(),
        9,
        1_000,
        Address::repeat_byte(0x42),
        U256::ZERO,
        21_000,
    ));
    senders.push(SYSTEM_CALLER);
    let block = with_transactions(&fixture.first_block, transactions, senders);

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(
        error.to_string().contains("reserved sender"),
        "a repeated system sender must hit the reserved-sender rule, got: {error}"
    );
}

/// Rule: an ordinary transaction executed before the system prefix is refused.
///
/// This one is executor-level, not import-level. On the import path `BasicBlockExecutor` always
/// calls `apply_pre_execution_changes` before any transaction, so a transaction before the prefix
/// cannot be expressed in a block at all and the ordering is enforced structurally. The check still
/// protects direct executor use, so it is exercised here by calling `execute_transaction` on a
/// freshly created executor whose prefix is still `Pending`.
#[test]
fn executor_refuses_an_ordinary_transaction_before_the_system_prefix() {
    let fixture = import_fixture();
    let mut state =
        State::builder().with_database(fixture.provider.clone()).with_bundle_update().build();
    let mut executor =
        fixture.config.executor_for_block(&mut state, fixture.first_block.sealed_block()).unwrap();
    let tx = signed_call(
        fixture.chain_spec.chain.id(),
        0,
        1_000,
        Address::repeat_byte(0x42),
        U256::ZERO,
        21_000,
    )
    .try_into_recovered()
    .unwrap();

    let error = executor.execute_transaction(tx).unwrap_err();
    assert!(
        error.to_string().contains("ordinary transaction before system prefix"),
        "expected the ordering refusal, got: {error}"
    );
}

/// Rule: a blob transaction is refused.
///
/// This is executor-level for the same reason as the ordering rule: on the import path the
/// header/body blob-gas consistency check in `validate_block_pre_execution` rejects a block with a
/// blob transaction before execution starts, so the executor's own blob rule only fires when the
/// executor is driven directly with the prefix already applied.
#[test]
fn executor_refuses_a_blob_transaction() {
    let fixture = import_fixture();
    let mut state =
        State::builder().with_database(fixture.provider.clone()).with_bundle_update().build();
    let mut executor =
        fixture.config.executor_for_block(&mut state, fixture.first_block.sealed_block()).unwrap();
    executor.apply_pre_execution_changes().unwrap();
    let blob = Recovered::new_unchecked(
        blob_tx(fixture.chain_spec.chain.id()),
        Address::repeat_byte(0x42),
    );

    let error = executor.execute_transaction(blob).unwrap_err();
    assert!(
        error.to_string().contains("blob transactions are unsupported"),
        "expected the blob refusal, got: {error}"
    );
}

/// The import path rejects a blob transaction earlier than the executor rule.
///
/// A blob transaction in the body makes the block's blob gas disagree with the header's
/// `blob_gas_used`, and `validate_block_pre_execution` rejects that mismatch before execution. This
/// test records which rule actually protects the import path, so the executor-level blob test above
/// is not mistaken for import-path coverage.
#[test]
fn import_rejects_a_blob_transaction_at_the_header_blob_gas_check() {
    let fixture = import_fixture();
    let block = with_transactions(
        &fixture.first_block,
        vec![blob_tx(fixture.chain_spec.chain.id())],
        vec![Address::repeat_byte(0x42)],
    );

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(
        error.to_string().contains("blob gas used mismatch"),
        "expected the header blob-gas mismatch to reject the block first, got: {error}"
    );
    assert!(
        !error.to_string().contains("blob transactions are unsupported"),
        "the executor rule must not be the one that fires on the import path, got: {error}"
    );
}
