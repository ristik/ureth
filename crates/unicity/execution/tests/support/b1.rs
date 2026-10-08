//! The B1 world every block-level test runs in: bft-core's K=2 deployment, its genesis and the
//! updates an honest pair derives for each block.
//!
//! Each test crate includes this module and uses a subset of it.
#![allow(dead_code)]

use alloy_primitives::B256;
use reth_unicity_execution::{
    block::BlockProfile,
    technical_record_hash,
    testing::{self, Tail},
    update::{B1Context, B1Job},
    InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2,
};
use std::sync::Arc;

pub(crate) fn world() -> &'static testing::World {
    testing::world()
}

pub(crate) fn genesis_hash() -> B256 {
    world().genesis_hash
}

pub(crate) fn initial_active_conf_hash() -> B256 {
    world().shard_conf_hash
}

pub(crate) fn context() -> B1Context {
    testing::b1_context()
}

/// The gas profile of the vector deployment: its real `g_sys` and header gas limit.
pub(crate) fn profile() -> BlockProfile {
    BlockProfile {
        max_gas: world().max_gas,
        system_gas: world().system_gas,
        base_fee_floor: 7,
        elasticity: 2,
        change_denominator: 8,
    }
}

/// A quiet or bootstrap root input for the epoch-1 registry state.
pub(crate) fn input(round: u64, root_round: u64, parent_hash: B256) -> RootInputV2 {
    let technical = TechnicalRecordV2 {
        round,
        epoch: 0,
        leader: "evm-node".into(),
        stat_hash: B256::repeat_byte(0xe0),
        fee_hash: B256::repeat_byte(0xf0),
    };
    RootInputV2 {
        version: 2,
        network_id: u64::from(world().network),
        partition_id: 8,
        shard_id: vec![],
        authorized_round: round,
        certified_epoch: 0,
        authorized_epoch: 0,
        parent_hash,
        origin: RootOriginV2 {
            network_id: u64::from(world().network),
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
            shard_conf_hash: initial_active_conf_hash(),
        },
        technical,
        transitions: vec![],
        b1_update_hash: B256::repeat_byte(0xb1),
    }
}

/// The acknowledgement of root epoch 2 and shard epoch 1 frozen on `parent`.
pub(crate) fn acknowledgement_bytes(parent: B256) -> Vec<u8> {
    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&[0x58, value.len() as u8]);
        out.extend_from_slice(value);
    }
    fn text(out: &mut Vec<u8>, value: &str) {
        if value.len() < 24 {
            out.push(0x60 + value.len() as u8);
        } else {
            out.extend_from_slice(&[0x78, value.len() as u8]);
        }
        out.extend_from_slice(value.as_bytes());
    }
    let mut ack = vec![0x88];
    text(&mut ack, "UNICITY_HANDOFF_ACK");
    ack.push(2);
    for word in
        [B256::repeat_byte(0x41), B256::repeat_byte(0x42), parent, parent, B256::repeat_byte(0x43)]
    {
        bytes(&mut ack, word.as_slice());
    }
    ack.push(1);
    let new_conf = B256::repeat_byte(0x56);
    let mut transition = vec![0x8d];
    text(&mut transition, "UNICITY_HANDOFF_EVM_TRANSITION");
    transition.extend_from_slice(&[3, 1, 2, 0, 1]);
    bytes(&mut transition, initial_active_conf_hash().as_slice());
    bytes(&mut transition, new_conf.as_slice());
    transition.push(0);
    bytes(&mut transition, B256::ZERO.as_slice());
    bytes(&mut transition, B256::repeat_byte(0x44).as_slice());
    bytes(&mut transition, B256::repeat_byte(0x45).as_slice());
    bytes(&mut transition, &ack);
    transition
}

/// The first block's acknowledgement input: root epoch 1 to 2, shard epoch 0 to 1.
pub(crate) fn ack_input(parent_hash: B256) -> RootInputV2 {
    let mut ack = input(1, 1, parent_hash);
    ack.origin.root_epoch = 2;
    ack.certified_epoch = 0;
    ack.authorized_epoch = 1;
    ack.technical.epoch = 1;
    ack.origin.input_record.epoch = 0;
    ack.origin.shard_conf_hash = B256::repeat_byte(0x56);
    ack.origin.tr_hash = technical_record_hash(&ack.technical);
    ack.transitions = vec![acknowledgement_bytes(parent_hash)];
    ack
}

/// Commits `input` to the update an honest pair derives for a parent at `parent_number` whose
/// open tail is `tail`, and returns the committed input with the job that carries the bytes.
pub(crate) fn sealed(
    mut input: RootInputV2,
    parent_number: u64,
    tail: Tail,
) -> (Arc<RootInputV2>, B1Job) {
    let update = testing::seal(&mut input, parent_number, tail);
    (Arc::new(input), B1Job { context: context(), update })
}
