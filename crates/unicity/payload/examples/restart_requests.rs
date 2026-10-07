//! Emits the next seal build request for the process restart smoke test.
//!
//! Arguments: `round parent_hash parent_timestamp parent_number execution_genesis_hash
//! root_genesis_id`. The binding it emits is the one a local Go verification would supply; the
//! node under test is pinned to network 3 and the given root genesis.

use alloy_primitives::{b256, Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use reth_unicity_execution::{
    derive_beacon_root, derive_prev_randao, derive_timestamp,
    pairing::{attributes_digest, transitions_hash, PairBinding, PairSubject},
    technical_record_hash,
    wire::SealBuildInput,
    InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2,
};
use reth_unicity_payload::UnicityPayloadAttributes;
use std::str::FromStr;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let round: u64 = args[1].parse().unwrap();
    let parent_hash = B256::from_str(&args[2]).unwrap();
    let parent_timestamp: u64 = args[3].parse().unwrap();
    let parent_number: u64 = args[4].parse().unwrap();
    let execution_genesis_hash = B256::from_str(&args[5]).unwrap();
    let root_genesis_id = B256::from_str(&args[6]).unwrap();
    let technical = TechnicalRecordV2 {
        round,
        epoch: 0,
        leader: "evm-node".into(),
        stat_hash: B256::repeat_byte(0xe0),
        fee_hash: B256::repeat_byte(0xf0),
    };
    let root = RootInputV2 {
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
            root_round: round,
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
                "002a719ed27ff7b185660ac29fe1f32269b0e3ab3f126716a52c47ec2b8a92dd"
            ),
        },
        technical,
        transitions: vec![],
    };
    let attrs = UnicityPayloadAttributes {
        inner: PayloadAttributes {
            timestamp: derive_timestamp(root.origin.reference_time, parent_timestamp).unwrap(),
            prev_randao: derive_prev_randao(round, round),
            suggested_fee_recipient: Address::repeat_byte(0x77),
            withdrawals: Some(vec![]),
            parent_beacon_block_root: Some(derive_beacon_root(round, round)),
            slot_number: None,
            target_gas_limit: Some(30_000_001),
        },
        commitment: root.input_commitment().unwrap(),
    };
    let binding = PairBinding {
        network_id: root.network_id,
        root_genesis_id,
        execution_genesis_hash,
        parent_hash,
        parent_number,
        origin_root_epoch: root.origin.root_epoch,
        origin_root_round: root.origin.root_round,
        configuration_id: root.origin.shard_conf_hash,
        activation_id: B256::repeat_byte(0xac),
        root_input_hash: root.input_commitment().unwrap(),
        transitions_hash: transitions_hash(&root.transitions),
        subject: PairSubject::Build {
            attributes_digest: attributes_digest(
                attrs.inner.timestamp,
                attrs.inner.prev_randao,
                attrs.inner.suggested_fee_recipient,
                attrs.inner.parent_beacon_block_root.unwrap(),
            ),
        },
    };
    let input = SealBuildInput {
        root_input: root.canonical_cbor().unwrap().into(),
        transitions: vec![],
        pair_binding: binding.canonical_cbor().into(),
    };
    println!("{}", serde_json::json!({"attributes": attrs, "input": input}));
}
