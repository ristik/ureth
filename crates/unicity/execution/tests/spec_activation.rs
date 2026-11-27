//! bft-core#1230: a known rule activates Prague at root epoch `E` through the VR activation
//! schedule, and ordinary transactions run under it.
//!
//! The schedule sits in the genesis state: one entry, a rule this binary knows, selecting Prague
//! from `E`. Blocks of epoch `E - 1` run Cancun, so an EIP-7702 (type-4) transaction is refused.
//! The epoch acknowledgement into `E` is the first Prague block. After it, the same transaction
//! executes and installs the delegation. A builder, a follower that knows only the companions, and
//! the engine's node-level configuration reach the same environment and the same result. A node
//! restarted across `E` with a cold resolver, and a node that replays from genesis, end with the
//! same state. A binary that lacks the rule refuses from `E` on.

mod support;

use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip7702, TxLegacy};
use alloy_eips::eip7702::Authorization;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, Transaction, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEngineEvm, ConfigureEvm, NextBlockEnvAttributes};
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, sign_message},
    RecoveredBlock, SealedHeader, SignedTransaction,
};
use reth_unicity_execution::{
    block_executor::{
        build_complete, replay_complete, BoundExecutionInput, CompletedParent, UnicityEvmConfig,
    },
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    evm_factory::unicity_eth_config,
    node_evm::{UnicityBlockExecutionRegistry, UnicityNodeEvmConfig},
    rules::{
        builtin_rules, rule_id, schedule_storage, EntryState, KnownRule, ScheduleEntry,
        UnicityRules,
    },
    testing::{self, Assignment, Tail},
    update::B1Job,
    RootInputV2, SEAL_REGISTRY, VALIDATOR_REGISTRY,
};
use revm::{database::State, primitives::hardfork::SpecId};
use std::sync::Arc;
use support::{
    b1::{context, genesis_hash, input, profile},
    provider::FixtureProvider,
};

const FEE_COLLECTOR: Address = Address::new([0x77; 20]);
/// The root epoch the Prague rule takes effect from.
const E: u64 = 2;
const RULE: &str = "prague-activation-test";
/// The contract the authority delegates to.
const DELEGATE: Address = Address::new([0xde; 20]);
/// The transaction sender (funded in the signed genesis) and the authority that delegates.
const SENDER_KEY: B256 = B256::with_last_byte(1);
const AUTHORITY_KEY: B256 = B256::with_last_byte(2);

fn prague_rule() -> KnownRule {
    KnownRule { name: RULE, id: rule_id(RULE), spec: SpecId::PRAGUE }
}

/// A fresh (cold) resolver that knows the Prague rule.
fn knowing() -> UnicityRules {
    UnicityRules::with_known(vec![prague_rule()])
}

fn address_of(key: B256) -> Address {
    let hash = B256::repeat_byte(0x11);
    recover_signer(&sign_message(key, hash).unwrap(), hash).unwrap()
}

/// What one pair holds between blocks (as in `rotation_acceptance.rs`), plus its rule resolver.
#[derive(Clone)]
struct Pair {
    chain_spec: Arc<ChainSpec>,
    state: FixtureProvider,
    head: SealedHeader,
    token: Option<CompletedParent>,
    tail: Tail,
    assigned: Assignment,
    nonce: u64,
    rules: UnicityRules,
}

/// A block as it travels between pairs.
#[derive(Clone)]
struct Companion {
    block: RecoveredBlock<Block>,
    input: Arc<RootInputV2>,
    job: B1Job,
}

impl Pair {
    fn genesis(rules: UnicityRules) -> Self {
        Self::genesis_at(rules, E)
    }

    /// A pair whose genesis schedules the Prague rule from root epoch `e`.
    fn genesis_at(rules: UnicityRules, e: u64) -> Self {
        let genesis: Genesis =
            serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
        let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
        let head = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash());
        let mut state = FixtureProvider::signed_genesis();
        state.set_block_hash(0, genesis_hash());
        let schedule = [ScheduleEntry {
            rule_id: rule_id(RULE),
            release_digest: B256::repeat_byte(0xd1),
            root_epoch: e,
            not_before_uc_time: 0,
            state: EntryState::Active,
            change_id: 1,
        }];
        state.insert_contract(
            VALIDATOR_REGISTRY,
            Bytes::from_static(testing::NOTHING),
            U256::ZERO,
            &schedule_storage(&schedule),
        );
        Self {
            chain_spec,
            state,
            head,
            token: None,
            tail: testing::GENESIS_TAIL,
            assigned: testing::genesis_assignment(),
            nonce: 0,
            rules,
        }
    }

    fn derive(&self, root_round: u64, epoch: u64) -> (Arc<RootInputV2>, B1Job) {
        let number = self.head.number + 1;
        let mut input = input(number, root_round, self.head.hash());
        input.origin.tree_root = B256::repeat_byte(0xc0);
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

    /// The job bound as production binds it: to this pair's head and token, with this pair's
    /// resolver, and its spec resolved from this pair's own parent state.
    fn bound(&self, input: &Arc<RootInputV2>, job: &B1Job) -> BoundExecutionInput {
        match self.token {
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
        .expect("the pair binds its own derivation to its own head")
        .with_rules(self.rules.clone())
        .with_parent_spec(&mut self.state.clone())
    }

    fn inner_config(&self) -> reth_unicity_execution::evm_factory::UnicityInnerEvmConfig {
        unicity_eth_config(self.chain_spec.clone(), &reth_unicity_execution::testing::b1_context())
    }

    fn config(&self, input: &Arc<RootInputV2>, job: &B1Job) -> UnicityEvmConfig {
        UnicityEvmConfig::new(self.inner_config(), Arc::new(self.bound(input, job)))
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

    fn fee(&self) -> u128 {
        u128::from(self.head.base_fee_per_gas.unwrap()) + 100
    }

    fn transfer(&self) -> Recovered<TransactionSigned> {
        let transaction = Transaction::Legacy(TxLegacy {
            chain_id: Some(self.chain_spec.chain.id()),
            nonce: self.nonce,
            gas_price: self.fee(),
            gas_limit: 21_000,
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::from(1),
            input: Default::default(),
        });
        let signature = sign_message(SENDER_KEY, transaction.signature_hash()).unwrap();
        TransactionSigned::new_unhashed(transaction, signature).try_into_recovered().unwrap()
    }

    /// An EIP-7702 transaction: the authority (nonce 0) delegates its code to [`DELEGATE`].
    fn delegation(&self) -> Recovered<TransactionSigned> {
        let authorization = Authorization {
            chain_id: U256::from(self.chain_spec.chain.id()),
            address: DELEGATE,
            nonce: 0,
        };
        let auth_signature = sign_message(AUTHORITY_KEY, authorization.signature_hash()).unwrap();
        let transaction = Transaction::Eip7702(TxEip7702 {
            chain_id: self.chain_spec.chain.id(),
            nonce: self.nonce,
            gas_limit: 100_000,
            max_fee_per_gas: self.fee(),
            max_priority_fee_per_gas: 1,
            to: Address::repeat_byte(0x42),
            value: U256::ZERO,
            access_list: Default::default(),
            authorization_list: vec![authorization.into_signed(auth_signature)],
            input: Default::default(),
        });
        let signature = sign_message(SENDER_KEY, transaction.signature_hash()).unwrap();
        TransactionSigned::new_unhashed(transaction, signature).try_into_recovered().unwrap()
    }

    /// Builds the next block on this pair's head without adopting it.
    fn try_build(
        &self,
        root_round: u64,
        epoch: u64,
        transactions: Vec<Recovered<TransactionSigned>>,
    ) -> Result<
        (Companion, revm::database::BundleState, CompletedParent),
        alloy_evm::block::BlockExecutionError,
    > {
        let (input, job) = self.derive(root_round, epoch);
        let config = self.config(&input, &job);
        let mut state =
            State::builder().with_database(self.state.clone()).with_bundle_update().build();
        let built = build_complete(
            &config,
            &self.head,
            self.attributes(&input),
            &mut state,
            self.state.clone(),
            transactions,
        )?;
        Ok((Companion { block: built.outcome.block, input, job }, state.bundle_state, built.parent))
    }

    fn build(
        &mut self,
        root_round: u64,
        epoch: u64,
        transactions: Vec<Recovered<TransactionSigned>>,
    ) -> Companion {
        let (companion, bundle, token) =
            self.try_build(root_round, epoch, transactions).expect("the builder executes");
        let header = companion.block.clone().into_sealed_block().into_sealed_header();
        let sent = companion.block.body().transactions.len() as u64;
        self.adopt(&companion.input, &bundle, header, token, sent);
        companion
    }

    /// The spec the builder's and the replay's environments run `companion` under, checked equal.
    fn env_spec(&self, companion: &Companion) -> SpecId {
        let config = self.config(&companion.input, &companion.job);
        let next =
            config.next_evm_env(self.head.header(), &self.attributes(&companion.input)).unwrap();
        let replay = config.evm_env(companion.block.header()).unwrap();
        assert_eq!(next.cfg_env.spec, replay.cfg_env.spec);
        assert_eq!(next.cfg_env.gas_params, replay.cfg_env.gas_params);
        replay.cfg_env.spec
    }

    /// Follows a block knowing only its companion: replay (the import path), then the engine's
    /// node-level configuration over the registered input, which must agree with it.
    fn follow(&mut self, companion: &Companion) {
        let config = self.config(&companion.input, &companion.job);
        let replay =
            replay_complete(&config, self.state.clone(), &self.state, &companion.block).unwrap();

        let registry = UnicityBlockExecutionRegistry::default();
        let bound = Arc::new(self.bound(&companion.input, &companion.job));
        registry.insert(companion.input.input_commitment().unwrap(), bound.clone()).unwrap();
        let node = UnicityNodeEvmConfig::new(self.inner_config(), registry);
        let block = companion.block.clone().into_sealed_block();
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        let for_payload = node.evm_env_for_payload(&ExecutionData { payload, sidecar }).unwrap();
        let for_header = node.evm_env(companion.block.header()).unwrap();
        assert_eq!(for_payload.cfg_env.spec, bound.env_spec());
        assert_eq!(for_header.cfg_env.spec, bound.env_spec());
        let engine = node.executor(self.state.clone()).execute(&companion.block).unwrap();
        assert_eq!(engine.result, replay.output.result, "the engine agrees with the import replay");

        let header = companion.block.clone().into_sealed_block().into_sealed_header();
        let sent = companion
            .block
            .transactions_with_sender()
            .filter(|(sender, _)| **sender == address_of(SENDER_KEY))
            .count() as u64;
        self.adopt(&companion.input, &replay.output.state, header, replay.parent, sent);
    }

    fn adopt(
        &mut self,
        input: &RootInputV2,
        bundle: &revm::database::BundleState,
        header: SealedHeader,
        token: CompletedParent,
        sent: u64,
    ) {
        self.state.apply_bundle(bundle);
        self.state.set_block_hash(header.number, header.hash());
        assert_eq!(self.state.root(), header.state_root, "the header names the applied state");
        if input.origin.root_epoch != self.assigned.root_epoch {
            self.assigned = Assignment {
                root_epoch: input.origin.root_epoch,
                shard_epoch: input.authorized_epoch,
                conf: input.origin.shard_conf_hash,
            };
            self.tail = Tail { epoch: input.origin.root_epoch, start: input.origin.root_round };
        }
        self.head = header;
        self.token = Some(token);
        self.nonce += sent;
    }

    fn code_of(&self, address: Address) -> Option<Bytes> {
        use reth_storage_api::{AccountReader, BytecodeReader};
        let account = self.state.basic_account(&address).unwrap()?;
        let hash = account.bytecode_hash?;
        self.state.bytecode_by_hash(&hash).unwrap().map(|code| code.original_bytes())
    }
}

fn assert_same(a: &Pair, b: &Pair) {
    assert_eq!(a.head.hash(), b.head.hash());
    assert_eq!(a.state.root(), b.state.root());
    assert_eq!(a.state.storage_of(SEAL_REGISTRY), b.state.storage_of(SEAL_REGISTRY));
    assert_eq!(a.token.unwrap().for_local_storage(), b.token.unwrap().for_local_storage());
}

/// The EIP-7702 designator `0xef0100 || address`.
fn designator(address: Address) -> Bytes {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(address.as_slice());
    code.into()
}

/// The four blocks around `E`: a paid block in `E - 1`, the acknowledgement into `E`, the
/// delegation and a paid block after it.
fn chain(builder: &mut Pair) -> Vec<Companion> {
    let one = builder.build(1, E - 1, vec![builder.transfer()]);
    let two = builder.build(2, E, vec![]);
    let three = builder.build(3, E, vec![builder.delegation()]);
    let four = builder.build(4, E, vec![builder.transfer()]);
    vec![one, two, three, four]
}

#[test]
fn prague_activates_at_e_for_build_import_and_engine() {
    let mut builder = Pair::genesis(knowing());
    let mut follower = Pair::genesis(knowing());
    let authority = address_of(AUTHORITY_KEY);

    // E - 1: Cancun. The builder refuses the type-4 transaction; the block carries a transfer.
    let refused = builder.try_build(1, E - 1, vec![builder.delegation()]).err().expect("refused");
    assert!(refused.to_string().to_lowercase().contains("7702"), "{refused}");
    let one = builder.build(1, E - 1, vec![builder.transfer()]);
    assert_eq!(follower.env_spec(&one), SpecId::CANCUN);
    follower.follow(&one);
    assert_same(&builder, &follower);

    // E: the acknowledgement into E is the first Prague block (its parent is the last block of
    // E - 1; the schedule is read there). It carries no user transaction.
    let two = builder.build(2, E, vec![]);
    assert_eq!(follower.env_spec(&two), SpecId::PRAGUE, "E is inclusive");
    follower.follow(&two);
    assert_same(&builder, &follower);

    // After E the same kind of transaction executes and installs the delegation.
    assert_eq!(builder.code_of(authority), None);
    let three = builder.build(3, E, vec![builder.delegation()]);
    assert_eq!(three.block.body().transactions.len(), 1);
    assert!(three.block.body().transactions[0].is_eip7702());
    assert_eq!(follower.env_spec(&three), SpecId::PRAGUE);
    follower.follow(&three);
    assert_same(&builder, &follower);
    assert_eq!(follower.code_of(authority), Some(designator(DELEGATE)));

    // Ordinary traffic continues under Prague, and system gas stays inside the reservation.
    let four = builder.build(4, E, vec![builder.transfer()]);
    follower.follow(&four);
    assert_same(&builder, &follower);
    let system = follower.token.unwrap().for_local_storage().system_gas;
    assert!(system <= profile().system_gas, "{system}");
}

#[test]
fn a_node_restarted_across_e_replays_identically() {
    let mut running = Pair::genesis(knowing());
    let blocks = chain(&mut running);

    // A node that followed E - 1, then restarted: only its accounting record survives, and its
    // resolver is a cold one. It replays across E to the same state.
    let mut node = Pair::genesis(knowing());
    node.follow(&blocks[0]);
    let record = node.token.unwrap().for_local_storage();
    let restored = CompletedParent::from_local_storage(record, &node.head, profile()).unwrap();
    let mut restarted = Pair { token: Some(restored), rules: knowing(), ..node.clone() };
    drop(node);
    for companion in &blocks[1..] {
        restarted.follow(companion);
    }
    assert_same(&running, &restarted);

    // A node restarted after E (between the acknowledgement and the delegation) agrees too.
    let mut node = Pair::genesis(knowing());
    node.follow(&blocks[0]);
    node.follow(&blocks[1]);
    let mut restarted = Pair { rules: knowing(), ..node.clone() };
    drop(node);
    restarted.follow(&blocks[2]);
    restarted.follow(&blocks[3]);
    assert_same(&running, &restarted);

    // A cold node replaying from genesis ends identical.
    let mut cold = Pair::genesis(knowing());
    for companion in &blocks {
        cold.follow(companion);
    }
    assert_same(&running, &cold);
}

#[test]
fn a_binary_without_the_rule_refuses_from_e() {
    let mut running = Pair::genesis(knowing());
    let blocks = chain(&mut running);
    let mut old = Pair::genesis(UnicityRules::with_known(builtin_rules()));
    old.follow(&blocks[0]);
    let config = old.config(&blocks[1].input, &blocks[1].job);
    let err = replay_complete(&config, old.state.clone(), &old.state, &blocks[1].block)
        .unwrap_err()
        .to_string();
    assert!(err.contains("UpgradeRequired"), "{err}");
}

/// A peer's block that carries a type-4 transaction before `E` is refused by an honest follower,
/// on import replay and on the engine's node-level executor, before the state-root comparison. The
/// block comes from a dishonest builder whose state schedules Prague from epoch 1; the honest
/// follower's schedule says `E`. This pins the safety argument for leaving type-4 transactions to
/// execution in the engine validator.
#[test]
fn a_peer_type4_block_before_e_is_refused_by_replay_and_engine() {
    let mut dishonest = Pair::genesis_at(knowing(), 1);
    let bad = dishonest.build(1, E - 1, vec![dishonest.delegation()]);
    assert_eq!(bad.block.body().transactions.len(), 1);
    assert!(bad.block.body().transactions[0].is_eip7702());

    let honest = Pair::genesis(knowing());
    let config = honest.config(&bad.input, &bad.job);
    assert_eq!(config.evm_env(bad.block.header()).unwrap().cfg_env.spec, SpecId::CANCUN);
    let err = replay_complete(&config, honest.state.clone(), &honest.state, &bad.block)
        .unwrap_err()
        .to_string();
    assert!(err.to_lowercase().contains("7702"), "{err}");
    assert!(!err.contains("state root"), "refused before the state-root comparison: {err}");

    let registry = UnicityBlockExecutionRegistry::default();
    let bound = Arc::new(honest.bound(&bad.input, &bad.job));
    registry.insert(bad.input.input_commitment().unwrap(), bound).unwrap();
    let node = UnicityNodeEvmConfig::new(honest.inner_config(), registry);
    let block = bad.block.clone().into_sealed_block();
    let (payload, sidecar) =
        ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
    let env = node.evm_env_for_payload(&ExecutionData { payload, sidecar }).unwrap();
    assert_eq!(env.cfg_env.spec, SpecId::CANCUN);
    let err = node.executor(honest.state).execute(&bad.block).unwrap_err().to_string();
    assert!(err.to_lowercase().contains("7702"), "{err}");
}

/// A reorg across `E`: two siblings on one parent in `E - 1`. One stays in `E - 1` and runs
/// Cancun; the other acknowledges `E` and runs Prague. Each branch resolves its own spec from the
/// same parent and epoch alone: the Cancun branch still refuses the type-4 transaction, the Prague
/// branch executes it, and each follower agrees with its builder.
#[test]
fn sibling_blocks_across_e_resolve_per_branch() {
    let mut a = Pair::genesis(knowing());
    let one = a.build(1, E - 1, vec![a.transfer()]);
    let mut b = a.clone();
    let stay = a.build(2, E - 1, vec![a.transfer()]);
    let ack = b.build(2, E, vec![]);
    let mut follower = Pair::genesis(knowing());
    follower.follow(&one);
    let mut on_a = follower.clone();
    let mut on_b = follower.clone();
    assert_eq!(on_a.env_spec(&stay), SpecId::CANCUN);
    assert_eq!(on_b.env_spec(&ack), SpecId::PRAGUE);
    on_a.follow(&stay);
    on_b.follow(&ack);
    assert_same(&a, &on_a);
    assert_same(&b, &on_b);
    // a follower that switches from branch A to branch B rewinds to the common parent first
    let mut reorged = follower.clone();
    reorged.follow(&ack);
    assert_same(&b, &reorged);

    assert!(on_a.try_build(3, E - 1, vec![on_a.delegation()]).is_err());
    let three = b.build(3, E, vec![b.delegation()]);
    on_b.follow(&three);
    reorged.follow(&three);
    assert_same(&b, &on_b);
    assert_same(&b, &reorged);
}
