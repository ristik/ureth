//! Real shared build/replay integration over the test-only standard-JSON genesis.

mod support;

use alloy_consensus::{Header, SignableTransaction, TxEip4844, TxEip7702, TxLegacy};
use alloy_eips::{
    eip4788::BEACON_ROOTS_ADDRESS,
    eip4844::DATA_GAS_PER_BLOB,
    eip4895::{Withdrawal, Withdrawals},
    eip7685::EMPTY_REQUESTS_HASH,
    eip7702::Authorization,
};
use alloy_evm::block::{BlockExecutionError, BlockExecutor, BlockValidationError};
use alloy_genesis::Genesis;
use alloy_primitives::{hex, keccak256, Address, Bytes, TxKind, B256, B64, U256};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_consensus::ConsensusError;
use reth_ethereum_primitives::{Block, Transaction, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, BlockBody, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_storage_api::{AccountReader, HashedPostStateProvider, StateProvider};
use reth_unicity_execution::{
    block::{BlockAccountingError, BlockProfile},
    block_executor::{
        build_complete, replay_complete, BoundExecutionInput, CompletedParent, UnicityEvmConfig,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    evm_factory::unicity_eth_config,
    testing::{self, Tail, GENESIS_TAIL},
    update::{B1Context, B1Job},
    wire::bind_completed_parent,
    RootInputV2, SEAL_REGISTRY, SYSTEM_CALLER,
};
use revm::{
    context_interface::result::InvalidTransaction, database::State, primitives::hardfork::SpecId,
};
use std::{
    mem::discriminant,
    sync::{Arc, Mutex},
};
use support::{
    b1::{ack_input, context, genesis_hash, input, profile, sealed},
    provider::FixtureProvider,
};

const FEE_COLLECTOR: Address = Address::new([0x77; 20]);
fn genesis_root() -> B256 {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis-oracle.json"))
            .unwrap();
    oracle["stateRoot"].as_str().unwrap().parse().unwrap()
}

fn signed_call(
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    to: Address,
    value: U256,
    gas_limit: u64,
) -> TransactionSigned {
    signed_transaction(Transaction::Legacy(TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: Default::default(),
    }))
}

fn signed_transaction(transaction: Transaction) -> TransactionSigned {
    let signature = sign_message(B256::with_last_byte(1), transaction.signature_hash()).unwrap();
    TransactionSigned::new_unhashed(transaction, signature)
}

fn expected_next_base_fee(parent_base: u64, ordinary_used: u64) -> u64 {
    let target = (profile().max_gas - profile().system_gas) / profile().elasticity;
    let delta = u128::from(parent_base) * u128::from(ordinary_used.abs_diff(target)) /
        u128::from(target) /
        u128::from(profile().change_denominator);
    if ordinary_used > target {
        parent_base + u64::try_from(delta).unwrap().max(1)
    } else {
        parent_base.saturating_sub(u64::try_from(delta).unwrap()).max(profile().base_fee_floor)
    }
}

fn attributes(input: &RootInputV2, parent_timestamp: u64) -> NextBlockEnvAttributes {
    NextBlockEnvAttributes {
        timestamp: derive_timestamp(input.origin.reference_time, parent_timestamp).unwrap(),
        suggested_fee_recipient: FEE_COLLECTOR,
        prev_randao: derive_prev_randao(input.origin.root_round, input.authorized_round),
        gas_limit: profile().max_gas,
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
fn acknowledgement_replays_before_a_paid_successor_transaction() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash());
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, genesis_hash());
    let (ack_input, ack_job) = sealed(ack_input(genesis_hash()), 0, GENESIS_TAIL);
    // A same-height uncertified fork is not the frozen parent named by this acknowledgement.
    let mut fork_header = chain_spec.genesis_header().clone();
    fork_header.extra_data = vec![0x99].into();
    let fork_hash = fork_header.hash_slow();
    let fork_parent = SealedHeader::new(fork_header, fork_hash);
    assert_ne!(fork_hash, genesis_hash());
    assert!(
        BoundExecutionInput::from_validated_genesis(
            ack_input.clone(),
            ack_job.clone(),
            profile(),
            &fork_parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .is_err(),
        "the ack candidate must be rebuilt on the certified frozen parent"
    );
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            ack_input.clone(),
            ack_job,
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(
        unicity_eth_config(chain_spec.clone(), &reth_unicity_execution::testing::b1_context()),
        bound,
    );
    let mut refused_state =
        State::builder().with_database(provider.clone()).with_bundle_update().build();
    let transfer = signed_call(
        chain_spec.chain.id(),
        0,
        u128::from(parent.base_fee_per_gas.unwrap()) + 100,
        Address::repeat_byte(0x42),
        U256::from(1),
        21_000,
    )
    .try_into_recovered()
    .unwrap();
    assert!(build_complete(
        &config,
        &parent,
        attributes(&ack_input, parent.timestamp),
        &mut refused_state,
        provider.clone(),
        vec![transfer.clone()]
    )
    .is_err());
    let mut ack_state =
        State::builder().with_database(provider.clone()).with_bundle_update().build();
    let ack = build_complete(
        &config,
        &parent,
        attributes(&ack_input, parent.timestamp),
        &mut ack_state,
        provider.clone(),
        vec![],
    )
    .unwrap();
    assert!(ack.outcome.block.body().transactions.is_empty());
    let replay = replay_complete(&config, provider.clone(), &provider, &ack.outcome.block).unwrap();
    assert_eq!(replay.output.result, ack.outcome.execution_result);
    let with_user = with_transactions(
        &ack.outcome.block,
        vec![signed_call(
            chain_spec.chain.id(),
            0,
            u128::from(parent.base_fee_per_gas.unwrap()) + 100,
            Address::repeat_byte(0x42),
            U256::from(1),
            21_000,
        )],
        vec![transfer.signer()],
    );
    assert!(replay_complete(&config, provider.clone(), &provider, &with_user)
        .unwrap_err()
        .to_string()
        .contains("acknowledgement block contains user transactions"));
    let ack_header = ack.outcome.block.into_sealed_block().into_sealed_header();
    let mut post_ack = provider.clone();
    post_ack.apply_bundle(&ack_state.bundle_state);
    post_ack.set_block_hash(1, ack_header.hash());
    assert_eq!(post_ack.root(), ack_header.state_root);
    let mut next_input = input(2, 2, ack_header.hash());
    next_input.origin.root_epoch = 2;
    next_input.certified_epoch = 1;
    next_input.authorized_epoch = 1;
    next_input.technical.epoch = 1;
    next_input.origin.input_record.epoch = 1;
    next_input.origin.shard_conf_hash = B256::repeat_byte(0x56);
    next_input.origin.tr_hash =
        reth_unicity_execution::technical_record_hash(&next_input.technical);
    let (next_input, next_job) = sealed(next_input, 1, Tail { epoch: 2, start: 1 });
    let next_bound = Arc::new(
        BoundExecutionInput::from_completed_parent(
            next_input.clone(),
            next_job,
            profile(),
            &ack_header,
            ack.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let next_config = UnicityEvmConfig::new(
        unicity_eth_config(chain_spec, &reth_unicity_execution::testing::b1_context()),
        next_bound,
    );
    let mut next_state =
        State::builder().with_database(post_ack.clone()).with_bundle_update().build();
    let paid = build_complete(
        &next_config,
        &ack_header,
        attributes(&next_input, ack_header.timestamp),
        &mut next_state,
        post_ack.clone(),
        vec![transfer],
    )
    .unwrap();
    assert_eq!(paid.outcome.execution_result.receipts.len(), 1);
    assert!(paid.outcome.execution_result.receipts[0].success);
    let replay =
        replay_complete(&next_config, post_ack.clone(), &post_ack, &paid.outcome.block).unwrap();
    assert_eq!(replay.output.result, paid.outcome.execution_result);
}

#[test]
fn payload_job_binding_names_gas_and_fee_mismatches() {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash());
    let (root, job) = sealed(input(1, 1, genesis_hash()), 0, GENESIS_TAIL);
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root.clone(),
            job,
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(
        unicity_eth_config(chain_spec, &reth_unicity_execution::testing::b1_context()),
        bound,
    );
    let mut attrs = attributes(&root, parent.timestamp);

    attrs.gas_limit += 1;
    assert_eq!(
        config.validate_payload_job(&parent, &attrs).unwrap_err().message(),
        "next-block gas_limit mismatch"
    );
    attrs.gas_limit = profile().max_gas;
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
    assert_eq!(genesis_header.hash_slow(), genesis_hash());
    assert_eq!(genesis_header.state_root, genesis_root());
    let parent = SealedHeader::new(genesis_header.clone(), genesis_hash());
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, genesis_hash());
    assert_eq!(provider.root(), genesis_root());
    let signer =
        Address::parse_checksummed("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", None).unwrap();
    let initial_signer = provider.basic_account(&signer).unwrap().unwrap();

    let (first_input, first_job) = sealed(input(1, 1, genesis_hash()), 0, GENESIS_TAIL);
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            first_input.clone(),
            first_job,
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(
        unicity_eth_config(chain_spec.clone(), &reth_unicity_execution::testing::b1_context()),
        bound,
    );
    let over_capacity = signed_call(
        chain_spec.chain.id(),
        0,
        u128::from(genesis_header.base_fee_per_gas.unwrap()) + 100,
        Address::repeat_byte(0x42),
        U256::ZERO,
        profile().ordinary_capacity().unwrap() + 1,
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
    // The approved order: open, the root-record import, finalize, then the stock EIP-4788 call.
    assert!(commits[0].contains(&SEAL_REGISTRY), "open");
    assert!(commits[1].contains(&SEAL_REGISTRY), "importRootRecords");
    assert!(commits[2].contains(&SEAL_REGISTRY), "finalize");
    assert!(commits[3].contains(&BEACON_ROOTS_ADDRESS), "EIP-4788");
    assert!(commits.iter().skip(4).any(|state| state.contains(&signer)));
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
    assert!(CompletedParent::from_local_storage(stored, &first_header, profile()).is_ok());
    let mut wrong_accounting = stored;
    wrong_accounting.ordinary_gas += 1;
    assert!(
        CompletedParent::from_local_storage(wrong_accounting, &first_header, profile()).is_err()
    );
    let mut wrong_hash = stored;
    wrong_hash.block_hash = B256::ZERO;
    assert!(CompletedParent::from_local_storage(wrong_hash, &first_header, profile()).is_err());
    assert!(CompletedParent::from_local_storage(
        stored,
        &first_header,
        BlockProfile { base_fee_floor: 8, ..profile() },
    )
    .is_err());
    assert_eq!(
        first_header.base_fee_per_gas.unwrap(),
        expected_next_base_fee(genesis_header.base_fee_per_gas.unwrap(), 0),
    );
    let (second_input, second_job) = sealed(input(2, 2, first_header.hash()), 1, GENESIS_TAIL);
    let (wrong_parent_input, wrong_parent_job) = sealed(input(2, 2, B256::ZERO), 1, GENESIS_TAIL);
    assert!(BoundExecutionInput::from_completed_parent(
        wrong_parent_input,
        wrong_parent_job,
        profile(),
        &first_header,
        built.parent,
        FEE_COLLECTOR,
    )
    .is_err());
    assert!(BoundExecutionInput::from_completed_parent(
        second_input.clone(),
        second_job.clone(),
        BlockProfile { base_fee_floor: 8, ..profile() },
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
        second_job.clone(),
        profile(),
        &forged_parent,
        built.parent,
        FEE_COLLECTOR,
    )
    .is_err());
    // The completed-parent path refuses an update or a context the root input does not commit to,
    // as the genesis path does: every non-genesis build, import and recovery binds here.
    let swapped = B1Job { update: Bytes::from_static(b"another update"), ..second_job.clone() };
    assert_eq!(
        bind_completed_parent(
            (*second_input).clone(),
            swapped,
            profile(),
            &first_header,
            built.parent,
            FEE_COLLECTOR,
        )
        .unwrap_err(),
        BlockAccountingError::UpdateHashMismatch
    );
    let swapped_records =
        B1Job { records: Bytes::from_static(b"another import"), ..second_job.clone() };
    assert_eq!(
        bind_completed_parent(
            (*second_input).clone(),
            swapped_records,
            profile(),
            &first_header,
            built.parent,
            FEE_COLLECTOR,
        )
        .unwrap_err(),
        BlockAccountingError::RecordsHashMismatch
    );
    let unmeasured =
        B1Job { context: B1Context { max_epochs: 1, ..second_job.context }, ..second_job.clone() };
    assert_eq!(
        bind_completed_parent(
            (*second_input).clone(),
            unmeasured,
            profile(),
            &first_header,
            built.parent,
            FEE_COLLECTOR,
        )
        .unwrap_err(),
        BlockAccountingError::B1Profile
    );
    let build_bound = Arc::new(
        bind_completed_parent(
            (*second_input).clone(),
            second_job.clone(),
            profile(),
            &first_header,
            built.parent,
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let replay_bound = Arc::new(
        BoundExecutionInput::from_completed_parent(
            second_input.clone(),
            second_job,
            profile(),
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
        &UnicityEvmConfig::new(
            unicity_eth_config(chain_spec.clone(), &reth_unicity_execution::testing::b1_context()),
            build_bound,
        ),
        &first_header,
        attrs.clone(),
        &mut state_a,
        post_build.clone(),
        vec![reverted.clone()],
    )
    .unwrap();
    let block_b = build_complete(
        &UnicityEvmConfig::new(
            unicity_eth_config(chain_spec, &reth_unicity_execution::testing::b1_context()),
            replay_bound,
        ),
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
    assert!(chain_spec.is_cancun_active_at_timestamp(genesis_header.timestamp));
    assert!(!chain_spec.is_prague_active_at_timestamp(genesis_header.timestamp));
    let parent = SealedHeader::new(genesis_header.clone(), genesis_hash());
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, genesis_hash());
    let (first_input, first_job) = sealed(input(1, 1, genesis_hash()), 0, GENESIS_TAIL);
    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            first_input.clone(),
            first_job,
            profile(),
            &parent,
            genesis_hash(),
            FEE_COLLECTOR,
        )
        .unwrap(),
    );
    let config = UnicityEvmConfig::new(
        unicity_eth_config(chain_spec.clone(), &reth_unicity_execution::testing::b1_context()),
        bound,
    );
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
    signed_transaction(Transaction::Eip4844(TxEip4844 {
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
    }))
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
fn release_profile_executor_refuses_a_blob_transaction() {
    let fixture = import_fixture();
    let mut state =
        State::builder().with_database(fixture.provider.clone()).with_bundle_update().build();
    let mut executor =
        fixture.config.executor_for_block(&mut state, fixture.first_block.sealed_block()).unwrap();
    executor.apply_pre_execution_changes().unwrap();
    let blob = blob_tx(fixture.chain_spec.chain.id()).try_into_recovered().unwrap();
    let tx_hash = *blob.tx_hash();

    let error = executor.execute_transaction(blob).unwrap_err();
    assert!(
        matches!(error.as_validation(), Some(BlockValidationError::InvalidTx { hash, error })
            if *hash == tx_hash && error.to_string() == "blob transactions are unsupported"),
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
fn release_profile_import_rejects_blob_gas_in_the_transaction_body() {
    let fixture = import_fixture();
    let blob = blob_tx(fixture.chain_spec.chain.id()).try_into_recovered().unwrap();
    let (tx, sender) = blob.into_parts();
    let block = with_transactions(&fixture.first_block, vec![tx], vec![sender]);

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(
        matches!(consensus_rejection(&error), Some(ConsensusError::BlobGasUsedDiff(diff))
            if diff.got == 0 && diff.expected == DATA_GAS_PER_BLOB),
        "expected the header blob-gas mismatch to reject the block first, got: {error}"
    );
}

fn consensus_rejection(error: &BlockExecutionError) -> Option<&ConsensusError> {
    error.as_internal()?.downcast_other()
}

#[test]
fn release_profile_import_rejects_nonempty_withdrawals() {
    let fixture = import_fixture();
    let (mut block, senders) = fixture.first_block.split();
    block.body.withdrawals = Some(Withdrawals::new(vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: Address::repeat_byte(0x42),
        amount: 1,
    }]));
    block.header.withdrawals_root = block.body.calculate_withdrawals_root();
    let block = RecoveredBlock::new_unhashed(block, senders);

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(error.as_internal().is_some(), "{error:?}");
    assert_eq!(error.to_string(), "withdrawals are unsupported");
}

#[test]
fn release_profile_import_rejects_type_4_under_cancun() {
    let fixture = import_fixture();
    let chain_id = fixture.chain_spec.chain.id();
    let auth = Authorization {
        chain_id: U256::from(chain_id),
        address: Address::repeat_byte(0xde),
        nonce: 0,
    };
    let auth_signature = sign_message(B256::with_last_byte(2), auth.signature_hash()).unwrap();
    let tx = signed_transaction(Transaction::Eip7702(TxEip7702 {
        chain_id,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1,
        to: Address::repeat_byte(0x42),
        value: U256::ZERO,
        access_list: Default::default(),
        authorization_list: vec![auth.into_signed(auth_signature)],
        input: Bytes::new(),
    }))
    .try_into_recovered()
    .unwrap();
    let tx_hash = *tx.tx_hash();
    let (tx, sender) = tx.into_parts();
    let block = with_transactions(&fixture.first_block, vec![tx], vec![sender]);
    assert_eq!(fixture.config.evm_env(block.header()).unwrap().cfg_env.spec, SpecId::CANCUN);

    let error =
        replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
            .unwrap_err();
    assert!(
        matches!(error.as_validation(), Some(BlockValidationError::InvalidTx { hash, error })
            if *hash == tx_hash && matches!(error.as_invalid_tx_err(), Some(InvalidTransaction::Eip7702NotSupported))),
        "expected the Cancun execution rule to refuse the authorization transaction, got: {error}"
    );
}

#[test]
fn release_profile_import_rejects_later_fork_header_fields() {
    let fixture = import_fixture();
    let (block, senders) = fixture.first_block.split();
    for (header, expected) in [
        (
            Header { requests_hash: Some(EMPTY_REQUESTS_HASH), ..block.header.clone() },
            ConsensusError::RequestsHashUnexpected,
        ),
        (
            Header {
                block_access_list_hash: Some(B256::repeat_byte(0x42)),
                ..block.header.clone()
            },
            ConsensusError::BlockAccessListHashUnexpected,
        ),
        (
            Header { slot_number: Some(1), ..block.header.clone() },
            ConsensusError::SlotNumberUnexpected,
        ),
    ] {
        let block = RecoveredBlock::new_unhashed(
            Block { header, body: block.body.clone() },
            senders.clone(),
        );
        let error =
            replay_complete(&fixture.config, fixture.provider.clone(), &fixture.provider, &block)
                .unwrap_err();
        assert_eq!(
            consensus_rejection(&error).map(discriminant),
            Some(discriminant(&expected)),
            "expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn release_profile_build_and_replay_agree_after_storage_wipe_and_recreate() {
    // Init code stores the block number in the slot with that number, then returns
    // the runtime CALLER SELFDESTRUCT. Its CREATE2 address is the same in both blocks.
    const CHILD_INIT: [u8; 13] = hex!("4343556133ff5f526002601ef3");
    let mut factory = vec![0x6c]; // PUSH13
    factory.extend_from_slice(&CHILD_INIT);
    factory.extend_from_slice(&hex!(
        "5f52 5f600d60135ff5" // MSTORE the init code, then CREATE2 with salt zero
        "8015603257"          // revert if creation returned zero
        "3615603057"          // empty calldata keeps the child
        "5f52 5f5f5f5f5f5f515af1 15603257" // otherwise CALL the child in this transaction
        "5b00 5b5f5ffd"       // stop or revert
    ));
    let len = u8::try_from(factory.len()).unwrap();
    let mut deployment = vec![0x60, len, 0x60, 10, 0x5f, 0x39, 0x60, len, 0x5f, 0xf3];
    deployment.extend_from_slice(&factory);

    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let mut parent = SealedHeader::seal_slow(chain_spec.genesis_header().clone());
    assert_eq!(parent.hash(), genesis_hash());
    assert!(chain_spec.is_cancun_active_at_timestamp(parent.timestamp));
    let tx = |nonce, to, input| {
        signed_transaction(Transaction::Legacy(TxLegacy {
            chain_id: Some(chain_spec.chain.id()),
            nonce,
            gas_price: 10_000_000_000,
            gas_limit: 250_000,
            to,
            value: U256::ZERO,
            input,
        }))
        .try_into_recovered()
        .unwrap()
    };
    let deploy = tx(0, TxKind::Create, deployment.into());
    let factory = deploy.signer().create(0);
    let child = factory.create2(B256::ZERO, keccak256(CHILD_INIT));
    // Funding the address before CREATE2 gives the wipe an account to remove
    // from the parent state. The account still has zero nonce and no code.
    let fund = signed_call(chain_spec.chain.id(), 1, 10_000_000_000, child, U256::from(1), 21_000)
        .try_into_recovered()
        .unwrap();
    let wipe = tx(2, TxKind::Call(factory), Bytes::from_static(&[1]));
    let recreate = tx(3, TxKind::Call(factory), Bytes::new());
    let mut builder = FixtureProvider::signed_genesis();
    builder.set_block_hash(0, parent.hash());
    let mut follower = builder.clone();
    let mut completed = None;
    for transactions in [vec![deploy, fund], vec![wipe], vec![recreate]] {
        let height = parent.number + 1;
        let (root, job) = sealed(input(height, height, parent.hash()), parent.number, GENESIS_TAIL);
        let bound = match completed {
            Some(accounting) => BoundExecutionInput::from_completed_parent(
                root.clone(),
                job,
                profile(),
                &parent,
                accounting,
                FEE_COLLECTOR,
            ),
            None => BoundExecutionInput::from_validated_genesis(
                root.clone(),
                job,
                profile(),
                &parent,
                genesis_hash(),
                FEE_COLLECTOR,
            ),
        }
        .unwrap();
        let config = UnicityEvmConfig::new(
            unicity_eth_config(chain_spec.clone(), &context()),
            Arc::new(bound),
        );
        let mut state =
            State::builder().with_database(builder.clone()).with_bundle_update().build();
        let expected_receipts = transactions.len();
        let built = build_complete(
            &config,
            &parent,
            attributes(&root, parent.timestamp),
            &mut state,
            builder.clone(),
            transactions,
        )
        .unwrap();
        let replay =
            replay_complete(&config, follower.clone(), &follower, &built.outcome.block).unwrap();
        assert_eq!(replay.output.result, built.outcome.execution_result);
        assert_eq!(replay.output.result.receipts.len(), expected_receipts);
        assert!(replay.output.result.receipts.iter().all(|receipt| receipt.success));
        assert_eq!(replay.parent.for_local_storage(), built.parent.for_local_storage());

        if height == 2 {
            let account = replay
                .output
                .state
                .state
                .get(&child)
                .expect("the Cancun wipe reached the execution bundle");
            assert!(account.status.was_destroyed());
            assert!(account.info.is_none());
            let hashed = follower.hashed_post_state(&replay.output.state).unwrap();
            assert!(hashed.storages[&keccak256(child)].wiped);
        }
        builder.apply_bundle(&state.bundle_state);
        follower.apply_bundle(&replay.output.state);
        parent = built.outcome.block.into_sealed_block().into_sealed_header();
        completed = Some(built.parent);
        for state in [&mut builder, &mut follower] {
            state.set_block_hash(height, parent.hash());
            assert_eq!(state.root(), parent.state_root);
            let account = state.basic_account(&child).unwrap();
            if height == 1 {
                assert_eq!(account.unwrap().balance, U256::from(1));
            } else if height == 2 {
                assert!(account.is_none(), "the pre-existing account was deleted");
            } else {
                assert_eq!(account.unwrap().bytecode_hash, Some(keccak256(hex!("33ff"))));
            }
            let expected = if height < 3 {
                Default::default()
            } else {
                [(U256::from(3), U256::from(3))].into()
            };
            assert_eq!(state.storage_of(child), expected);
        }
    }
}

/// The hook-enabled bound block 1: `import` as its records, `hook` as the pinned records hook,
/// over a provider that also holds the custody stand-in at `custody`.
struct HookWorld {
    provider: FixtureProvider,
    parent: SealedHeader<alloy_consensus::Header>,
    root: RootInputV2,
    chain_spec: Arc<ChainSpec>,
    import: Vec<u8>,
    update: Bytes,
    /// System gas reserved beyond the records hook's, for a world whose profile pins an election.
    extra_gas: u64,
    /// A private rule resolver for the world, so no process-wide state leaks between tests.
    rules: reth_unicity_execution::rules::UnicityRules,
}

fn hook_world(import: &[u8], custody: Address) -> HookWorld {
    hook_world_with(import, |provider| {
        provider.insert_contract(
            custody,
            testing::custody_code(testing::ADVANCE),
            U256::ZERO,
            &[(U256::from(1), U256::from(32))], // limits.maxBatch
        )
    })
}

fn hook_world_with(import: &[u8], install: impl FnOnce(&mut FixtureProvider)) -> HookWorld {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash());
    let mut provider = FixtureProvider::signed_genesis();
    provider.set_block_hash(0, genesis_hash());
    install(&mut provider);
    let mut root = input(1, 1, genesis_hash());
    let update = testing::seal_with_import(&mut root, 0, GENESIS_TAIL, import);
    HookWorld {
        provider,
        parent,
        root,
        chain_spec,
        import: import.to_vec(),
        update,
        extra_gas: 0,
        rules: private_rules(),
    }
}

impl HookWorld {
    /// The block profile with a system reservation that covers the largest hook the tests pin, so
    /// the hooked and unhooked blocks differ in nothing but the hook.
    fn profile(&self) -> BlockProfile {
        let base = profile();
        let hook = RecordsHook {
            custody: Address::repeat_byte(1),
            h_records: 3,
            record_gas: 3_000_000,
            ..Default::default()
        };
        let system_gas = base.system_gas + hook.envelope_gas().unwrap() + self.extra_gas;
        BlockProfile { system_gas, max_gas: base.max_gas + (system_gas - base.system_gas), ..base }
    }

    fn attributes(&self) -> NextBlockEnvAttributes {
        NextBlockEnvAttributes {
            gas_limit: self.profile().max_gas,
            ..attributes(&self.root, self.parent.timestamp)
        }
    }

    fn config(&self, hook: RecordsHook) -> UnicityEvmConfig {
        self.config_with(hook, true)
    }

    /// The job, with its EVM spec resolved from the parent state as every production bind site
    /// does (`resolve`), or left at the genesis spec.
    fn config_with(&self, hook: RecordsHook, resolve: bool) -> UnicityEvmConfig {
        let mut job = B1Job {
            context: context(),
            update: self.update.clone(),
            records: self.import.clone().into(),
        };
        job.context.hook = hook;
        let bound = Arc::new(
            BoundExecutionInput::from_validated_genesis(
                Arc::new(self.root.clone()),
                job,
                self.profile(),
                &self.parent,
                genesis_hash(),
                FEE_COLLECTOR,
            )
            .unwrap()
            .with_rules(self.rules.clone()),
        );
        let bound = if resolve {
            Arc::new(Arc::unwrap_or_clone(bound).with_parent_spec(&mut self.provider.clone()))
        } else {
            bound
        };
        UnicityEvmConfig::new(
            unicity_eth_config(
                self.chain_spec.clone(),
                &reth_unicity_execution::testing::b1_context(),
            ),
            bound,
        )
    }

    /// Builds the block and returns it with the state after it.
    fn build(
        &self,
        hook: RecordsHook,
    ) -> (reth_unicity_execution::block_executor::CompletedBuild, FixtureProvider) {
        let config = self.config(hook);
        let mut state =
            State::builder().with_database(self.provider.clone()).with_bundle_update().build();
        let built = build_complete(
            &config,
            &self.parent,
            self.attributes(),
            &mut state,
            self.provider.clone(),
            vec![],
        )
        .unwrap();
        let mut after = self.provider.clone();
        after.apply_bundle(&state.bundle_state);
        (built, after)
    }
}

use reth_unicity_execution::hook::RecordsHook;

fn private_rules() -> reth_unicity_execution::rules::UnicityRules {
    reth_unicity_execution::rules::UnicityRules::with_known(
        reth_unicity_execution::rules::builtin_rules(),
    )
}

#[test]
fn the_records_hook_runs_after_eip_4788_and_its_gas_joins_the_system_total_only() {
    let custody = Address::repeat_byte(0xc5);
    let world = hook_world(&testing::import_of(3), custody);
    let off = RecordsHook::default();
    let on = RecordsHook { custody, h_records: 2, record_gas: 1_000_000, ..Default::default() };

    let (plain, plain_state) = world.build(off);
    let (hooked, hooked_state) = world.build(on);

    // the hook applied exactly H = 2 of the 3 imported records, once
    assert_eq!(plain_state.storage_of(custody).get(&U256::ZERO), None);
    assert_eq!(hooked_state.storage_of(custody)[&U256::ZERO], U256::from(2));
    // the registry holds the same words with and without the hook: it runs after finalize, so
    // the outcome commitment finalize wrote does not mention it
    assert_eq!(plain_state.storage_of(SEAL_REGISTRY), hooked_state.storage_of(SEAL_REGISTRY));
    // with no transactions the header's gas is the system total, and the hook's gross gas is the
    // whole difference: a few reads and one call, well inside the reserved envelope
    let (g_plain, g_hooked) =
        (plain.outcome.execution_result.gas_used, hooked.outcome.execution_result.gas_used);
    assert!(g_hooked > g_plain, "{g_hooked} vs {g_plain}");
    assert!(g_hooked - g_plain < on.envelope_gas().unwrap(), "{}", g_hooked - g_plain);
    // the hooked block replays to exactly itself
    let replay = replay_complete(
        &world.config(on),
        world.provider.clone(),
        &world.provider,
        &hooked.outcome.block,
    )
    .unwrap();
    assert_eq!(replay.output.result, hooked.outcome.execution_result);
    // a node that pins no hook (or another H) computes another state root and refuses the block
    for other in [off, RecordsHook { h_records: 3, ..on }] {
        assert!(
            replay_complete(
                &world.config(other),
                world.provider.clone(),
                &world.provider,
                &hooked.outcome.block
            )
            .is_err(),
            "{other:?}"
        );
    }
}

#[test]
fn a_hook_that_cannot_run_invalidates_the_block() {
    let custody = Address::repeat_byte(0xc5);
    let world = hook_world(&testing::import_of(3), custody);
    let genesis_config = |hook| world.config(hook);
    // no code at the pinned custody: the cursor read returns nothing
    let missing = RecordsHook {
        custody: Address::repeat_byte(0xee),
        h_records: 1,
        record_gas: 1,
        ..Default::default()
    };
    let mut state =
        State::builder().with_database(world.provider.clone()).with_bundle_update().build();
    let Err(err) = build_complete(
        &genesis_config(missing),
        &world.parent,
        world.attributes(),
        &mut state,
        world.provider.clone(),
        vec![],
    ) else {
        panic!("a hook against a missing custody must invalidate the block")
    };
    assert!(err.to_string().contains("BadReturn") || err.to_string().contains("Hook"), "{err}");
}

// ---- the real StakeCustody runtime -----------------------------------------------------------
//
// `testdata/hook-<scenario>.json` is generated by unicity-pos-contracts `test/p85/HookState.t.sol`:
// the three P85 modules as forge deployed them on chain id 1337 with `roots` pointing at the
// registry's fixed address, the records the scenario applies, and the storage custody ends with
// when it applies them. The same bytes must run here, in the registry's world.

use std::collections::BTreeMap;

struct Real {
    world: HookWorld,
    custody: Address,
    election: Address,
    pre: Vec<(Address, BTreeMap<U256, U256>)>,
    extra: serde_json::Value,
    post: Vec<(Address, BTreeMap<U256, U256>)>,
    records: Vec<reth_unicity_execution::records::RecordEntry>,
}

fn word(hex: &str) -> U256 {
    U256::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap()
}

fn real(
    name: &str,
    edit: impl FnOnce(&mut Vec<reth_unicity_execution::records::RecordEntry>, &mut serde_json::Value),
) -> Real {
    let raw = match name {
        "ack" => include_str!("../testdata/hook-ack.json"),
        "recovery" => include_str!("../testdata/hook-recovery.json"),
        "elect" => include_str!("../testdata/hook-elect.json"),
        other => panic!("no fixture {other}"),
    };
    let mut fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    assert_eq!(fixture["chainId"], 1337, "the state was produced on the chain the world runs");
    let mut records: Vec<reth_unicity_execution::records::RecordEntry> = Vec::new();
    for r in fixture["records"].as_array().unwrap() {
        let predecessor = records.last().map_or(B256::ZERO, |e| e.record_id);
        let entry = testing::record_entry(
            r["index"].as_u64().unwrap(),
            predecessor,
            r["kind"].as_u64().unwrap() as u8,
            r["progress"].as_u64().unwrap(),
            r["ucTime"].as_u64().unwrap(),
            r["data"].as_str().unwrap().parse::<Bytes>().unwrap().to_vec(),
        );
        assert_eq!(
            entry.record_id,
            r["recordId"].as_str().unwrap().parse::<B256>().unwrap(),
            "the identifier forge computed is the one this crate computes"
        );
        records.push(entry);
    }
    edit(&mut records, &mut fixture);
    let custody: Address = fixture["modules"]["custody"].as_str().unwrap().parse().unwrap();
    let election: Address = fixture["modules"]["election"].as_str().unwrap().parse().unwrap();
    let extra = fixture.get("extra").cloned().unwrap_or(serde_json::Value::Null);
    let import = testing::import_of_entries(records.clone());
    let pre = fixture["pre"].as_object().unwrap().clone();
    let mut world = hook_world_with(&import, |provider| {
        for (address, account) in &pre {
            let storage: Vec<(U256, U256)> = account["storage"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (word(k), word(v.as_str().unwrap())))
                .collect();
            let code: Bytes = account["code"].as_str().unwrap().parse().unwrap();
            assert_eq!(
                alloy_primitives::keccak256(&code),
                account["codeHash"].as_str().unwrap().parse::<B256>().unwrap()
            );
            provider.insert_contract(
                address.parse().unwrap(),
                code,
                word(account["balance"].as_str().unwrap()),
                &storage,
            );
        }
    });
    let pre_state = fixture["pre"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, account)| {
            let slots = account["storage"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (word(k), word(v.as_str().unwrap())))
                .collect();
            (address.parse().unwrap(), slots)
        })
        .collect();
    if extra.is_object() {
        world.extra_gas = 80_000_000;
    }
    let post = fixture["post"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, account)| {
            let slots = account["storage"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (word(k), word(v.as_str().unwrap())))
                .collect();
            (address.parse().unwrap(), slots)
        })
        .collect();
    Real { world, custody, election, pre: pre_state, extra, post, records }
}

const fn pinned(custody: Address, h: u32) -> RecordsHook {
    RecordsHook {
        custody,
        h_records: h,
        record_gas: 3_000_000,
        election: Address::ZERO,
        elect_gas: 0,
    }
}

#[test]
fn the_real_custody_applies_real_records_to_exactly_the_state_forge_computed() {
    for scenario in ["ack", "recovery"] {
        let r = real(scenario, |_, _| {});
        let hook = pinned(r.custody, 1);
        let (plain, _) = r.world.build(RecordsHook::default());
        let (hooked, after) = r.world.build(hook);
        for (address, expected) in &r.post {
            let got = after.storage_of(*address);
            let mut diff = Vec::new();
            for key in got.keys().chain(expected.keys()).collect::<std::collections::BTreeSet<_>>()
            {
                if got.get(key) != expected.get(key) {
                    diff.push(format!(
                        "slot {key:#x}: hook {:?} forge {:?}",
                        got.get(key),
                        expected.get(key)
                    ));
                }
            }
            assert!(
                diff.is_empty(),
                "{scenario}: storage of {address} after the hook differs from what custody computed on chain id 1337:\n{}",
                diff.join("\n")
            );
        }
        let spent =
            hooked.outcome.execution_result.gas_used - plain.outcome.execution_result.gas_used;
        println!("p85-hook: {scenario}: hook gross gas {spent} for {} record(s)", r.records.len());
        assert!(spent > 100_000 && spent < hook.envelope_gas().unwrap(), "{scenario}: {spent}");
        // the block replays to exactly itself
        let replay = replay_complete(
            &r.world.config(hook),
            r.world.provider.clone(),
            &r.world.provider,
            &hooked.outcome.block,
        )
        .unwrap();
        assert_eq!(replay.output.result, hooked.outcome.execution_result, "{scenario}");
    }
}

#[test]
fn a_record_the_real_custody_cannot_apply_invalidates_the_block() {
    // an Ack of the reserved session whose replaced H round precedes the incumbent's first round:
    // the registry imports it (it checks the log, not custody), custody reverts. (An Ack of a
    // session custody never reserved is a foreign no-op since VT-15, see the test below.)
    let r = real("ack", |records, _| {
        records[0].data[32..64].fill(0);
        let e = &records[0];
        records[0] = testing::record_entry(
            e.index,
            e.predecessor,
            e.kind,
            e.progress,
            e.uc_time,
            e.data.clone(),
        );
    });
    let mut state =
        State::builder().with_database(r.world.provider.clone()).with_bundle_update().build();
    let Err(err) = build_complete(
        &r.world.config(pinned(r.custody, 1)),
        &r.world.parent,
        r.world.attributes(),
        &mut state,
        r.world.provider.clone(),
        vec![],
    ) else {
        panic!("a record custody cannot apply must invalidate the block")
    };
    assert!(err.to_string().contains("applyRootRecords"), "{err}");
}

#[test]
fn h_above_the_deployed_custodys_max_batch_invalidates_the_block() {
    // custody.limits (slot 11) packs (vMax, lMax, rMax, maxBatch) low to high; pin maxBatch = 1 and
    // ask for two records per block
    let r = real("ack", |_, fixture| {
        let custody = fixture["modules"]["custody"].as_str().unwrap().to_string();
        let key = format!("0x{:064x}", 11);
        let slot = &mut fixture["pre"][&custody]["storage"][&key];
        let w = word(slot.as_str().unwrap());
        let mask: U256 = U256::from(u32::MAX) << 96usize;
        *slot = serde_json::Value::String(format!(
            "0x{:064x}",
            (w & !mask) | (U256::from(1u64) << 96usize)
        ));
    });
    let mut state =
        State::builder().with_database(r.world.provider.clone()).with_bundle_update().build();
    let Err(err) = build_complete(
        &r.world.config(pinned(r.custody, 2)),
        &r.world.parent,
        r.world.attributes(),
        &mut state,
        r.world.provider.clone(),
        vec![],
    ) else {
        panic!("H above maxBatch must invalidate the block")
    };
    assert!(err.to_string().contains("HExceedsMaxBatch"), "{err}");
    // within the limit the same state applies
    assert!(!r.world.build(pinned(r.custody, 1)).1.storage_of(r.custody).is_empty());
}

#[test]
fn a_record_of_a_result_the_real_custody_never_had_is_consumed() {
    // validator-registry design section 4.2: an Ack of a result with no custody session is a
    // foreign no-op that advances custody's cursor; the block is valid
    let r = real("ack", |records, _| {
        records[0].data[0] ^= 1;
        let e = &records[0];
        records[0] = testing::record_entry(
            e.index,
            e.predecessor,
            e.kind,
            e.progress,
            e.uc_time,
            e.data.clone(),
        );
    });
    let (_, after) = r.world.build(pinned(r.custody, 1));
    assert!(!after.storage_of(r.custody).is_empty(), "custody consumed the record");
}

// ---- the real ElectionPolicy in the hook
// ---------------------------------------------------------

const fn elected(r: &Real, elect_gas: u64) -> RecordsHook {
    RecordsHook {
        custody: r.custody,
        h_records: 1,
        record_gas: 3_000_000,
        election: r.election,
        elect_gas,
    }
}

fn diff(got: &BTreeMap<U256, U256>, expected: &BTreeMap<U256, U256>) -> Vec<String> {
    got.keys()
        .chain(expected.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|k| got.get(*k) != expected.get(*k))
        .map(|k| format!("slot {k:#x}: hook {:?} forge {:?}", got.get(k), expected.get(k)))
        .collect()
}

#[test]
fn the_real_election_runs_in_the_hook_and_reproduces_the_state_forge_computed() {
    let r = real("elect", |_, _| {});
    let origin = r.world.root.origin_identity().unwrap();
    assert_eq!(
        origin,
        r.extra["origin"].as_str().unwrap().parse::<B256>().unwrap(),
        "forge elected under the origin identity this block carries"
    );
    let hook = elected(&r, 60_000_000);
    let (plain, _) = r.world.build(RecordsHook { election: Address::ZERO, elect_gas: 0, ..hook });
    let (hooked, after) = r.world.build(hook);
    for (address, expected) in &r.post {
        let d = diff(&after.storage_of(*address), expected);
        assert!(
            d.is_empty(),
            "storage of {address} after the hook differs from what the contracts computed:\n{}",
            d.join("\n")
        );
    }
    let result = r.extra["resultId"].as_str().unwrap().parse::<B256>().unwrap();
    let open = after.storage_of(r.election).get(&U256::from(12)).copied().unwrap_or_default();
    assert_eq!(open, U256::from_be_bytes(result.0), "the election opened the result forge named");
    let spent = hooked.outcome.execution_result.gas_used - plain.outcome.execution_result.gas_used;
    println!("p85-hook: election hook gross gas {spent} (4 members)");
    assert!(spent > 500_000 && spent < 60_000_000, "{spent}");
    let replay = replay_complete(
        &r.world.config(hook),
        r.world.provider.clone(),
        &r.world.provider,
        &hooked.outcome.block,
    )
    .unwrap();
    assert_eq!(replay.output.result, hooked.outcome.execution_result);
}

#[test]
fn an_election_that_is_not_due_changes_nothing() {
    let mut r = real("elect", |_, _| {});
    // the election's anchorProgress (slot 10, low 8 bytes) is 100: the threshold is 100 + 100 =
    // 200, beyond the registry's 150
    r.world.provider.set_storage(r.election, U256::from(10), U256::from(100u64));
    let (hooked, after) = r.world.build(elected(&r, 60_000_000));
    let (_, mut expected) = r.pre.iter().find(|(a, _)| *a == r.election).unwrap().clone();
    expected.insert(U256::from(10), U256::from(100u64));
    let d = diff(&after.storage_of(r.election), &expected);
    assert!(d.is_empty(), "nothing is stored before the threshold:\n{}", d.join("\n"));
    assert!(hooked.outcome.execution_result.gas_used > 0);
}

#[test]
fn an_election_priced_below_its_cost_invalidates_the_block() {
    let r = real("elect", |_, _| {});
    let mut state =
        State::builder().with_database(r.world.provider.clone()).with_bundle_update().build();
    let Err(err) = build_complete(
        &r.world.config(elected(&r, 1_000_000)),
        &r.world.parent,
        r.world.attributes(),
        &mut state,
        r.world.provider.clone(),
        vec![],
    ) else {
        panic!("an election that cannot finish inside its reserved gas must invalidate the block")
    };
    assert!(err.to_string().contains("elect"), "{err}");
}

// ---- VT-07b: the rule resolver at the executor sites (builder, importer, replay) ----

mod rules_sites {
    use super::*;
    use reth_unicity_execution::{
        rules::{noop_test_rule_id, rule_id, schedule_storage, EntryState, ScheduleEntry},
        VALIDATOR_REGISTRY,
    };

    const CUSTODY: Address = Address::new([0xc5; 20]);

    const fn entry(id: B256, epoch: u64, state: EntryState) -> ScheduleEntry {
        ScheduleEntry {
            rule_id: id,
            release_digest: B256::repeat_byte(0xd1),
            root_epoch: epoch,
            not_before_uc_time: 0,
            state,
            change_id: 1,
        }
    }

    /// The hook world whose genesis also holds VR (a stand-in account) with `entries`.
    fn world_with_schedule(entries: &[ScheduleEntry]) -> HookWorld {
        let slots = schedule_storage(entries);
        hook_world_with(&testing::import_of(3), |provider| {
            provider.insert_contract(
                CUSTODY,
                testing::custody_code(testing::ADVANCE),
                U256::ZERO,
                &[(U256::from(1), U256::from(32))], // limits.maxBatch
            );
            provider.insert_contract(
                VALIDATOR_REGISTRY,
                Bytes::from_static(testing::NOTHING),
                U256::ZERO,
                &slots,
            );
        })
    }

    fn hook() -> RecordsHook {
        RecordsHook { custody: CUSTODY, h_records: 2, record_gas: 1_000_000, ..Default::default() }
    }

    fn built_error(world: &HookWorld) -> String {
        let config = world.config(hook());
        let mut state =
            State::builder().with_database(world.provider.clone()).with_bundle_update().build();
        match build_complete(
            &config,
            &world.parent,
            world.attributes(),
            &mut state,
            world.provider.clone(),
            vec![],
        ) {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn unknown_active_rule_is_refused_by_builder_and_replay_known_rule_changes_nothing() {
        let clean = world_with_schedule(&[]);
        let (plain, plain_state) = clean.build(hook());

        // block root epoch is 1: a known rule active from 1 changes nothing observable. A binary
        // built with `no-test-rule` lacks the rule, so there the same schedule must refuse.
        let known = world_with_schedule(&[entry(noop_test_rule_id(), 1, EntryState::Active)]);
        if cfg!(feature = "no-test-rule") {
            assert!(built_error(&known).contains("UpgradeRequired"));
        } else {
            let (known_built, known_state) = known.build(hook());
            // (the state roots differ only by the schedule words themselves)
            assert_eq!(
                known_built.outcome.execution_result.gas_used,
                plain.outcome.execution_result.gas_used
            );
            assert_eq!(known_state.storage_of(CUSTODY)[&U256::ZERO], U256::from(2));
        }
        let _ = plain_state;

        // an unknown rule effective at epoch 1 refuses the builder ...
        for state in [EntryState::Active, EntryState::Latched] {
            let unknown = world_with_schedule(&[entry(rule_id("future-rule"), 1, state)]);
            let err = built_error(&unknown);
            assert!(err.contains("UpgradeRequired"), "{state:?}: {err}");
            // ... and replay of a block that was built without it
            let replay = replay_complete(
                &unknown.config(hook()),
                unknown.provider.clone(),
                &unknown.provider,
                &plain.outcome.block,
            );
            assert!(replay.unwrap_err().to_string().contains("UpgradeRequired"), "{state:?}");
        }
        // scheduled for a later epoch: still runs (the warning fires, the gauge is set)
        let ahead = world_with_schedule(&[entry(rule_id("future-rule"), 2, EntryState::Active)]);
        assert_eq!(built_error(&ahead), "");
        // a superseded (postponed) entry is ignored
        let postponed =
            world_with_schedule(&[entry(rule_id("future-rule"), 1, EntryState::Superseded)]);
        assert_eq!(built_error(&postponed), "");
    }

    /// A supported rule that selects Prague moves the whole block, ordinary transactions included
    /// (bft-core#1230): `next_evm_env` for the builder, `evm_env` for replay, the system VMs, and
    /// replay reproduces the build. A job bound without its parent's spec is refused rather than
    /// half applied (system VMs on Prague, transactions on Cancun).
    #[test]
    fn a_rule_that_selects_prague_runs_the_whole_block_under_it() {
        use reth_unicity_execution::rules::{KnownRule, UnicityRules};
        use revm::primitives::hardfork::SpecId;
        let fork = rule_id("fork-rule");
        let known = vec![KnownRule { name: "fork-rule", id: fork, spec: SpecId::PRAGUE }];
        for (epoch, spec) in [(1, SpecId::PRAGUE), (2, SpecId::CANCUN)] {
            let mut world = world_with_schedule(&[entry(fork, epoch, EntryState::Active)]);
            world.rules = UnicityRules::with_known(known.clone());
            let config = world.config(hook());
            let next = config.next_evm_env(world.parent.header(), &world.attributes()).unwrap();
            assert_eq!(next.cfg_env.spec, spec, "rule at {epoch}, block at 1");
            let (built, _) = world.build(hook());
            let env = config.evm_env(built.outcome.block.header()).unwrap();
            assert_eq!(env.cfg_env.spec, spec);
            assert_eq!(
                env.cfg_env.gas_params,
                revm::context::CfgEnv::new_with_spec(spec).gas_params
            );
            let replay = replay_complete(
                &world.config(hook()),
                world.provider.clone(),
                &world.provider,
                &built.outcome.block,
            )
            .unwrap();
            assert_eq!(replay.output.result, built.outcome.execution_result);
            if spec == SpecId::PRAGUE {
                // without the bind-time resolution the environment stays Cancun: refused
                let unresolved = world.config_with(hook(), false);
                assert_eq!(
                    unresolved.evm_env(built.outcome.block.header()).unwrap().cfg_env.spec,
                    SpecId::CANCUN
                );
                let err = replay_complete(
                    &unresolved,
                    world.provider.clone(),
                    &world.provider,
                    &built.outcome.block,
                )
                .unwrap_err()
                .to_string();
                assert!(err.contains("resolves spec PRAGUE"), "{err}");
                let mut state = State::builder()
                    .with_database(world.provider.clone())
                    .with_bundle_update()
                    .build();
                let err = build_complete(
                    &unresolved,
                    &world.parent,
                    world.attributes(),
                    &mut state,
                    world.provider.clone(),
                    vec![],
                )
                .unwrap_err()
                .to_string();
                assert!(err.contains("resolves spec PRAGUE"), "{err}");
            }
        }
    }
}
