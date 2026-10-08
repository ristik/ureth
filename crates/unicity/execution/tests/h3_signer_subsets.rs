//! H3 #20 criterion X2, execution side: one nonempty assignment acknowledgement certified by two
//! distinct valid signer subsets of the old root quorum is applied by this kernel to identical
//! state.
//!
//! The two subsets differ only in the companion witnesses, which are opaque to this crate: the
//! root input, the transition body, the committed B1 update and therefore the header are the
//! same bytes. The acknowledgement rotates root epoch 1 to 2, so the block also carries the
//! update that closes the genesis interval and inserts epoch 2.

mod support;

use alloy_genesis::Genesis;
use alloy_primitives::{keccak256, Address, B256, U256};
use reth_chainspec::ChainSpec;
use reth_evm::NextBlockEnvAttributes;
use reth_primitives_traits::SealedHeader;
use reth_unicity_execution::{
    block_executor::{build_complete, replay_complete, BoundExecutionInput, UnicityEvmConfig},
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    evm_factory::unicity_eth_config,
    testing::GENESIS_TAIL,
    wire::{SealBuildInput, SealCompanion},
    RootInputV2, SEAL_REGISTRY,
};
use revm::database::State;
use std::{collections::BTreeMap, sync::Arc};
use support::{
    b1::{ack_input, genesis_hash, profile, sealed},
    provider::FixtureProvider,
};

const GENESIS: &str = include_str!("../testdata/signed-beacon-genesis.json");
const FEE_COLLECTOR: Address = Address::new([0x77; 20]);

fn slot(name: &str) -> U256 {
    U256::from_be_bytes(keccak256(format!("unicity.seal-registry/{name}")).0)
}

/// What one application of one subset's vector produced.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    block_hash: B256,
    state_root: B256,
    extra_data: Vec<u8>,
    execution_result: String,
    registry: BTreeMap<U256, U256>,
    post_state_root: B256,
}

fn apply(witnesses: Vec<Vec<u8>>) -> Outcome {
    let genesis_hash = genesis_hash();
    let (root, job) = sealed(ack_input(genesis_hash), 0, GENESIS_TAIL);
    let root_input = root.canonical_cbor().unwrap();
    // Builder wire shape and follower wire shape decode through the one codec and must agree.
    let build = SealBuildInput {
        root_input: root_input.clone().into(),
        transitions: root.transitions.iter().cloned().map(Into::into).collect(),
        b1_update: job.update.clone(),
        records: job.records.clone(),
        pair_binding: Default::default(),
    };
    let companion = SealCompanion {
        root_input: root_input.into(),
        b1_update: job.update.clone(),
        records: job.records.clone(),
        pair_binding: Default::default(),
        witnesses: witnesses.into_iter().map(Into::into).collect(),
        provenance: "newPayload".into(),
    };
    let decoded: RootInputV2 = build.decode_root_input().expect("the build input decodes");
    assert_eq!(decoded, companion.decode_root_input().expect("the companion decodes"));
    assert_eq!(decoded, *root);
    assert_eq!(decoded.transitions.len(), 1, "a nonempty assignment transition");

    let genesis: Genesis = serde_json::from_str(GENESIS).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(genesis));
    let parent = SealedHeader::new(chain_spec.genesis_header().clone(), genesis_hash);
    assert_eq!(parent.hash_slow(), genesis_hash, "the oracle genesis hashes to block 0 here");
    let mut provider = FixtureProvider::from_json(GENESIS);
    provider.set_block_hash(0, genesis_hash);

    let bound = Arc::new(
        BoundExecutionInput::from_validated_genesis(
            root.clone(),
            job,
            profile(),
            &parent,
            genesis_hash,
            FEE_COLLECTOR,
        )
        .expect("the acknowledgement binds to the genesis parent"),
    );
    let config = UnicityEvmConfig::new(unicity_eth_config(chain_spec), bound);
    let attrs = NextBlockEnvAttributes {
        timestamp: derive_timestamp(root.origin.reference_time, parent.timestamp).unwrap(),
        suggested_fee_recipient: FEE_COLLECTOR,
        prev_randao: derive_prev_randao(root.origin.root_round, root.authorized_round),
        gas_limit: profile().max_gas,
        parent_beacon_block_root: Some(derive_beacon_root(
            root.origin.root_round,
            root.authorized_round,
        )),
        withdrawals: Some(Default::default()),
        extra_data: root.input_commitment().unwrap().to_vec().into(),
        slot_number: None,
    };
    let mut state = State::builder().with_database(provider.clone()).with_bundle_update().build();
    let built = build_complete(&config, &parent, attrs, &mut state, provider.clone(), vec![])
        .expect("builder path applies the acknowledgement");
    let replay = replay_complete(&config, provider.clone(), &provider, &built.outcome.block)
        .expect("replay path applies the same block");
    assert_eq!(replay.output.result, built.outcome.execution_result, "builder and replay agree");

    let header = built.outcome.block.clone().into_sealed_block().into_sealed_header();
    let mut post = provider.clone();
    post.apply_bundle(&state.bundle_state);
    assert_eq!(
        post.root(),
        header.state_root,
        "the header's state root is the applied state's root"
    );
    Outcome {
        block_hash: header.hash(),
        state_root: header.state_root,
        extra_data: header.extra_data.to_vec(),
        execution_result: format!("{:?}", built.outcome.execution_result),
        registry: post.storage_of(SEAL_REGISTRY),
        post_state_root: post.root(),
    }
}

#[test]
fn distinct_signer_subsets_of_a_nonempty_assignment_transition_reach_identical_state() {
    // Two valid subsets of a four-member root quorum: the only difference is the witnesses.
    let subsets: Vec<Vec<Vec<u8>>> = vec![
        vec![vec![0x01; 65], vec![0x02; 65], vec![0x03; 65]],
        vec![vec![0x01; 65], vec![0x02; 65], vec![0x04; 65]],
    ];
    assert_ne!(subsets[0], subsets[1]);
    let outcomes: Vec<Outcome> = subsets.into_iter().map(apply).collect();
    assert_eq!(
        outcomes[0], outcomes[1],
        "every subset yields identical block, state root and registry state"
    );
    let (root, _) = sealed(ack_input(genesis_hash()), 0, GENESIS_TAIL);
    assert_eq!(outcomes[0].extra_data, root.input_commitment().unwrap().as_slice());

    // The registry is acknowledged: root epoch 2, shard epoch 1, one transition consumed, and
    // B1 history now has the genesis epoch closed at the acknowledgement's first round.
    let registry = &outcomes[0].registry;
    assert_eq!(registry[&slot("assignment.rootEpoch")], U256::from(2));
    assert_eq!(registry[&slot("assignment.epoch")], U256::from(1));
    assert_eq!(registry[&slot("transition.cursor")], U256::from(1));
    assert_eq!(registry[&slot("round.authorized")], U256::from(root.authorized_round));
    assert_eq!(registry[&slot("b1.count")], U256::from(2));
}
