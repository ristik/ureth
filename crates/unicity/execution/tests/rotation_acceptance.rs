//! Two independent pairs through a root-epoch rotation, a supersession, a reorg and a restart.
//!
//! Each pair keeps only what a real one keeps: its own state, its head and the accounting token
//! its executor minted. The builder derives every block's committed update from its own view and
//! executes it; the follower receives only the block, the root input and the exact update bytes
//! (the companion) and must reproduce the same header, state root, gas and registry words without
//! ever seeing the builder's state. A restart rebuilds a pair from its persisted token record and
//! continues; a reorg rewinds a pair to the common parent and applies the other branch.
//!
//! Real certificate signatures do not appear here: each pair's Go node authenticates history and
//! derives the update; this crate executes it. The actual-STATICCALL and RPC tests cover the
//! signature kernels over the registry state these chains leave behind.

mod support;

use alloy_consensus::{transaction::Recovered, SignableTransaction, TxLegacy};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, TxKind, B256, U256};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, Transaction, TransactionSigned};
use reth_evm::NextBlockEnvAttributes;
use reth_primitives_traits::{
    crypto::secp256k1::sign_message, RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_unicity_execution::{
    block::{BlockAccountingError, BlockProfile},
    block_executor::{
        build_complete, replay_complete, BoundExecutionInput, CompletedParent, UnicityEvmConfig,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    evm_factory::unicity_eth_config,
    testing::{self, Assignment, Tail},
    update::B1Job,
    RootInputV2, SEAL_REGISTRY,
};
use revm::database::State;
use std::sync::Arc;
use support::{
    b1::{context, genesis_hash, input, profile},
    provider::FixtureProvider,
};

const FEE_COLLECTOR: Address = Address::new([0x77; 20]);

fn slot(name: &str) -> U256 {
    reth_unicity_b1::fixed_slot(name)
}

/// What one pair holds between blocks.
#[derive(Clone)]
struct Pair {
    chain_spec: Arc<ChainSpec>,
    state: FixtureProvider,
    head: SealedHeader,
    token: Option<CompletedParent>,
    tail: Tail,
    assigned: Assignment,
    nonce: u64,
}

/// A block as it travels between pairs: the block, the root input and the exact update bytes.
#[derive(Clone)]
struct Companion {
    block: RecoveredBlock<Block>,
    input: Arc<RootInputV2>,
    job: B1Job,
}

impl Pair {
    fn genesis() -> Self {
        let genesis: Genesis =
            serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
        let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
        let head = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash());
        let mut state = FixtureProvider::signed_genesis();
        state.set_block_hash(0, genesis_hash());
        Self {
            chain_spec,
            state,
            head,
            token: None,
            tail: testing::GENESIS_TAIL,
            assigned: testing::genesis_assignment(),
            nonce: 0,
        }
    }

    /// The block's root input and committed update as this pair's Go node would derive them for
    /// its own head: a rotation to `epoch` when it differs from the assigned one.
    fn derive(&self, root_round: u64, epoch: u64, tree_root: u8) -> (Arc<RootInputV2>, B1Job) {
        let number = self.head.number + 1;
        let mut input = input(number, root_round, self.head.hash());
        input.origin.tree_root = B256::repeat_byte(tree_root);
        input.certified_epoch = self.assigned.shard_epoch;
        input.authorized_epoch = self.assigned.shard_epoch;
        input.technical.epoch = self.assigned.shard_epoch;
        input.origin.input_record.epoch = self.assigned.shard_epoch;
        input.origin.shard_conf_hash = self.assigned.conf;
        input.origin.tr_hash = reth_unicity_execution::technical_record_hash(&input.technical);
        input.origin.root_epoch = epoch;
        if epoch != self.assigned.root_epoch {
            testing::rotate(&mut input, self.assigned);
        }
        let update = testing::seal(&mut input, self.head.number, self.tail);
        (Arc::new(input), B1Job { context: context(), update, records: testing::empty_import() })
    }

    fn config(&self, input: &Arc<RootInputV2>, job: &B1Job) -> UnicityEvmConfig {
        let bound = match self.token {
            None => BoundExecutionInput::from_validated_genesis(
                input.clone(),
                job.clone(),
                profile(),
                &self.head,
                genesis_hash(),
                FEE_COLLECTOR,
            ),
            Some(token) => BoundExecutionInput::from_completed_parent(
                input.clone(),
                job.clone(),
                profile(),
                &self.head,
                token,
                FEE_COLLECTOR,
            ),
        }
        .expect("the pair binds its own derivation to its own head");
        UnicityEvmConfig::new(unicity_eth_config(self.chain_spec.clone()), Arc::new(bound))
    }

    fn attributes(&self, input: &RootInputV2) -> NextBlockEnvAttributes {
        NextBlockEnvAttributes {
            timestamp: derive_timestamp(input.origin.reference_time, self.head.timestamp).unwrap(),
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

    fn transfer(&self) -> Recovered<TransactionSigned> {
        let transaction = Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce: self.nonce,
            gas_price: u128::from(self.head.base_fee_per_gas.unwrap()) + 100,
            gas_limit: 21_000,
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::from(1),
            input: Default::default(),
        });
        let signature =
            sign_message(B256::with_last_byte(1), transaction.signature_hash()).unwrap();
        TransactionSigned::new_unhashed(transaction, signature).try_into_recovered().unwrap()
    }

    /// Builds the next block on this pair's head and adopts it.
    fn build(&mut self, root_round: u64, epoch: u64, tree_root: u8, paid: bool) -> Companion {
        let (input, job) = self.derive(root_round, epoch, tree_root);
        let config = self.config(&input, &job);
        let mut state =
            State::builder().with_database(self.state.clone()).with_bundle_update().build();
        let transactions = if paid { vec![self.transfer()] } else { vec![] };
        let built = build_complete(
            &config,
            &self.head,
            self.attributes(&input),
            &mut state,
            self.state.clone(),
            transactions,
        )
        .expect("the builder executes its own derivation");
        let header = built.outcome.block.clone().into_sealed_block().into_sealed_header();
        self.adopt(&input, &state.bundle_state, header, built.parent, paid);
        Companion { block: built.outcome.block, input, job }
    }

    /// Follows a block knowing only its companion.
    fn follow(&mut self, companion: &Companion) {
        let config = self.config(&companion.input, &companion.job);
        let replay =
            replay_complete(&config, self.state.clone(), &self.state, &companion.block).unwrap();
        let header = companion.block.clone().into_sealed_block().into_sealed_header();
        let paid = !companion.block.body().transactions.is_empty();
        self.adopt(&companion.input, &replay.output.state, header, replay.parent, paid);
    }

    fn adopt(
        &mut self,
        input: &RootInputV2,
        bundle: &revm::database::BundleState,
        header: SealedHeader,
        token: CompletedParent,
        paid: bool,
    ) {
        self.state.apply_bundle(bundle);
        self.state.set_block_hash(header.number, header.hash());
        assert_eq!(self.state.root(), header.state_root, "the header names the applied state");
        if input.origin.root_epoch != self.assigned.root_epoch {
            self.assigned = testing::Assignment {
                root_epoch: input.origin.root_epoch,
                shard_epoch: input.authorized_epoch,
                conf: input.origin.shard_conf_hash,
            };
            self.tail = Tail { epoch: input.origin.root_epoch, start: input.origin.root_round };
        }
        self.head = header;
        self.token = Some(token);
        self.nonce += u64::from(paid);
    }

    fn word(&self, name: &str) -> U256 {
        self.state.storage_of(SEAL_REGISTRY).get(&slot(name)).copied().unwrap_or_default()
    }

    /// Epochs of the live set, oldest first, read from the ring in the pair's own state.
    fn live(&self) -> Vec<u64> {
        let storage = self.state.storage_of(SEAL_REGISTRY);
        let ring = u64::try_from(self.word("b1.wCert")).unwrap() + 1;
        let (head, count) = (
            u64::try_from(self.word("b1.head")).unwrap(),
            u64::try_from(self.word("b1.count")).unwrap(),
        );
        (0..count)
            .map(|i| {
                let mut bytes = slot("b1.queue").to_be_bytes::<32>().to_vec();
                bytes.extend_from_slice(&U256::from((head + i) % ring).to_be_bytes::<32>());
                let key = U256::from_be_bytes(alloy_primitives::keccak256(bytes).0);
                u64::try_from(storage.get(&key).copied().unwrap_or_default()).unwrap()
            })
            .collect()
    }

    const fn system_gas(&self) -> u64 {
        let token = self.token.unwrap().for_local_storage();
        token.system_gas
    }
}

/// Two pairs hold byte-identical state.
fn assert_same(a: &Pair, b: &Pair) {
    assert_eq!(a.head.hash(), b.head.hash());
    assert_eq!(a.state.root(), b.state.root());
    assert_eq!(a.state.storage_of(SEAL_REGISTRY), b.state.storage_of(SEAL_REGISTRY));
    assert_eq!(a.token.unwrap().for_local_storage(), b.token.unwrap().for_local_storage());
}

#[test]
fn a_follower_reproduces_every_block_of_a_rotation_and_a_supersession() {
    let mut builder = Pair::genesis();
    let mut follower = Pair::genesis();
    assert_eq!(builder.live(), vec![1]);

    // 1: a paid block in the genesis epoch.
    let one = builder.build(1, 1, 0xc0, true);
    follower.follow(&one);
    assert_same(&builder, &follower);

    // 2: root epoch 1 to 2 as a root-only acknowledgement. Genesis [0, 1) is closed at the first
    // successor start and stays live inside the window; epoch 2 is inserted.
    let two = builder.build(2, 2, 0xc0, false);
    assert!(
        two.block.body().transactions.is_empty(),
        "an acknowledgement block carries no user tx"
    );
    follower.follow(&two);
    assert_same(&builder, &follower);
    assert_eq!(builder.live(), vec![1, 2]);
    assert_eq!(builder.word("assignment.rootEpoch"), U256::from(2));

    // 3: a quiet block in the new epoch, then a paid one.
    let three = builder.build(3, 2, 0xc0, true);
    follower.follow(&three);
    assert_same(&builder, &follower);
    let rotation_gas = follower.system_gas();

    // 4: supersession of epochs 3 and 4 in one acknowledgement (root 2 to 4, shard 0 to 2). Both
    // survive the window, epoch 2 expires, and the former tip is closed once by the update.
    let four = builder.build(10, 4, 0xc0, false);
    follower.follow(&four);
    assert_same(&builder, &follower);
    assert_eq!(builder.live(), vec![3, 4]);
    assert_eq!(builder.word("assignment.rootEpoch"), U256::from(4));
    assert_eq!(builder.word("assignment.epoch"), U256::from(2));
    assert!(
        builder.system_gas() > rotation_gas,
        "inserting two entries and expiring one costs more system gas than a quiet block"
    );
    assert!(builder.system_gas() <= profile().system_gas);

    // 5: ordinary traffic continues on the superseded configuration. One round later the window
    // floor reaches epoch 3's end, so a quiet-origin block prunes it (end equal to the floor is
    // removed) and only the open tail remains.
    let five = builder.build(11, 4, 0xc0, true);
    follower.follow(&five);
    assert_same(&builder, &follower);
    assert_eq!(builder.live(), vec![4]);
}

#[test]
fn a_restarted_pair_continues_from_its_persisted_accounting_and_agrees() {
    let mut running = Pair::genesis();
    let one = running.build(1, 1, 0xc0, true);
    let two = running.build(2, 2, 0xc0, false);
    let mut restarted = Pair::genesis();
    restarted.follow(&one);
    restarted.follow(&two);

    // Persist only the local accounting record, drop the in-memory pair, and rebuild it: the token
    // is restored against the exact head and profile or not at all.
    let record = restarted.token.unwrap().for_local_storage();
    let head = restarted.head.clone();
    let restored = CompletedParent::from_local_storage(record, &head, profile())
        .expect("the record matches the canonical head");
    let mut after_restart = Pair { token: Some(restored), ..restarted.clone() };
    drop(restarted);

    let three = running.build(11, 4, 0xc0, false);
    after_restart.follow(&three);
    assert_same(&running, &after_restart);

    // A record for another head or profile is refused, not guessed.
    let wrong = BlockProfile { base_fee_floor: 8, ..profile() };
    assert!(CompletedParent::from_local_storage(record, &head, wrong).is_err());
}

#[test]
fn a_reorg_applies_the_other_branch_to_the_common_parent_only() {
    let mut canonical = Pair::genesis();
    let one = canonical.build(1, 1, 0xc0, true);
    let common = canonical.clone();

    // Branch A rotates; branch B stays quiet in epoch 1 with a different tree root. Each builds on
    // the same parent from its own derivation.
    let mut a = common.clone();
    let a_two = a.build(2, 2, 0xc0, false);
    let mut b = common.clone();
    let b_two = b.build(2, 1, 0xd0, false);
    assert_ne!(a.head.hash(), b.head.hash());
    assert_eq!(a.live(), vec![1, 2]);
    assert_eq!(b.live(), vec![1]);

    // A follower on branch A that reorgs to B rewinds to the common parent and applies B's
    // companion: B's rotation-free registry words, with none of A's.
    let mut follower = Pair::genesis();
    follower.follow(&one);
    follower.follow(&a_two);
    assert_eq!(follower.live(), vec![1, 2]);
    let mut reorged = common;
    reorged.follow(&b_two);
    assert_same(&reorged, &b);
    assert_eq!(reorged.live(), vec![1]);
    assert_eq!(reorged.word("assignment.rootEpoch"), U256::from(1));

    // Branch B continues, and the abandoned branch's rotation can still be built on its own
    // parent without ever having touched B.
    let b_three = b.build(3, 1, 0xd0, true);
    reorged.follow(&b_three);
    assert_same(&reorged, &b);
    assert_eq!(a.word("assignment.rootEpoch"), U256::from(2));
}

#[test]
fn a_companion_with_another_update_cannot_ride_under_the_same_header() {
    let mut builder = Pair::genesis();
    let one = builder.build(1, 1, 0xc0, false);
    let mut follower = Pair::genesis();
    follower.follow(&one);
    let two = builder.build(2, 2, 0xc0, false);

    // The same block under a rotation-free update: the root input commits to the real one, so the
    // follower's own binding refuses it before any execution.
    let (_, quiet) = follower.derive(2, 1, 0xc0);
    let tampered = B1Job { update: quiet.update, ..two.job.clone() };
    assert_eq!(
        BoundExecutionInput::from_completed_parent(
            two.input.clone(),
            tampered,
            profile(),
            &follower.head,
            follower.token.unwrap(),
            FEE_COLLECTOR,
        )
        .unwrap_err(),
        BlockAccountingError::UpdateHashMismatch
    );
    follower.follow(&two);
    assert_eq!(follower.live(), vec![1, 2]);
}
