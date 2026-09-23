//! Emits the next seal build request for the process restart smoke test.

use alloy_primitives::{b256, Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use reth_unicity_execution::{
    derive_beacon_root, derive_prev_randao, derive_timestamp, technical_record_hash,
    wire::SealBuildInput, InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2,
};
use reth_unicity_payload::UnicityPayloadAttributes;
use std::str::FromStr;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let round: u64 = args[1].parse().unwrap();
    let parent_hash = B256::from_str(&args[2]).unwrap();
    let parent_timestamp: u64 = args[3].parse().unwrap();
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
                "4ba6ed4d7f56b668f781eb698b9ad1101d823050c677c8bc03b88b3b3b92a6ba"
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
    let input =
        SealBuildInput { root_input: root.canonical_cbor().unwrap().into(), transitions: vec![] };
    println!("{}", serde_json::json!({"attributes": attrs, "input": input}));
}
