//! Replays bft-core's B7 relation vectors (`b7rel`, `testdata/b7-relation-vectors-v1.json`).

use alloy_primitives::{hex, keccak256, B256};
use reth_unicity_b7::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("testdata/b7-relation-vectors-v1.json")).expect("vectors")
}

fn b256(v: &Value) -> B256 {
    v.as_str().expect("hex").parse().expect("b256")
}

#[test]
fn domains_limits_and_relation_id_are_gos() {
    let v = vectors();
    assert_eq!(relation_domain(), b256(&v["relationDomain"]));
    assert_eq!(commitment_domain(), b256(&v["commitmentDomain"]));
    assert_eq!(journal_domain(), b256(&v["journalDomain"]));
    let l = &v["limits"];
    for (name, ours) in [
        ("maxLeaves", MAX_LEAVES),
        ("maxTransfers", MAX_TRANSFERS),
        ("maxEpochs", MAX_EPOCHS),
        ("maxAnchors", MAX_ANCHORS),
        ("maxSemanticBytes", MAX_SEMANTIC_BYTES),
        ("maxWitnessBytes", MAX_WITNESS_BYTES),
        ("maxMembersPerEpoch", MAX_MEMBERS_PER_EPOCH),
        ("maxRSMTSiblings", MAX_RSMT_SIBLINGS),
    ] {
        assert_eq!(l[name].as_u64(), Some(ours), "{name}");
    }
    assert_eq!(relation_id(), b256(&v["relationId"]));
}

#[test]
fn every_epoch_commitment_is_gos() {
    let v = vectors();
    let cs = v["commitments"].as_array().expect("commitments");
    assert!(cs.len() >= 6);
    for c in cs {
        let meta: Vec<B256> =
            c["metadata"].as_array().expect("metadata").iter().map(b256).collect();
        let meta: [B256; 11] = meta.try_into().expect("11 words");
        let members: Vec<[B256; 8]> = c["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(|m| {
                let w: Vec<B256> = m.as_array().expect("member").iter().map(b256).collect();
                w.try_into().expect("8 words")
            })
            .collect();
        let got = epoch_commitment(
            b256(&c["genesisCommitment"]),
            b256(&c["profileHash"]),
            c["epoch"].as_u64().expect("epoch"),
            &meta,
            &members,
        );
        assert_eq!(got, b256(&c["commitment"]), "{}", c["name"]);
    }
}

#[test]
fn every_journal_is_decoded_or_refused_as_go_and_round_trips() {
    let v = vectors();
    let (mut valid, mut refused) = (0, 0);
    for j in v["journals"].as_array().expect("journals") {
        let bytes = hex::decode(j["journal"].as_str().expect("hex")).expect("bytes");
        let name = j["name"].as_str().expect("name");
        if j["valid"].as_bool().expect("valid") {
            let decoded = Journal::decode(&bytes).unwrap_or_else(|_| panic!("{name}"));
            assert_eq!(decoded.relation_id, relation_id(), "{name}");
            assert_eq!(decoded.encode().expect("encode"), bytes, "{name}: round trip");
            assert_eq!(keccak256(&bytes), b256(&j["digest"]), "{name}");
            valid += 1;
        } else {
            assert_eq!(Journal::decode(&bytes), Err(JournalMalformed), "{name}");
            refused += 1;
        }
    }
    assert_eq!(valid, 4);
    assert!(refused >= 16);
}
