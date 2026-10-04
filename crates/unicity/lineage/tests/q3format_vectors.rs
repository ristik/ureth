//! The Go golden vectors of bft-core's `q3format` (`testdata/q3format-vectors.json`, #406/#407):
//! the protocol tuple, the V3 body and its predecessor hashes, the readiness receipt message, and
//! the proof envelope. They are produced there by an independent Python encoder; here the Rust
//! encoders must reproduce every byte and the Rust decoders must read them back.

mod support;

use reth_unicity_lineage::{
    votesig, BodyV3, Envelope, Kind, Prior, ProtocolConfig, ReceiptContext,
};
use serde::Deserialize;
use support::{array32, hex, testdata, unhex};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    config_encoding: String,
    config_identity: String,
    body_encoding: String,
    body_identity: String,
    predecessor_from_v1: String,
    predecessor_from_v2: String,
    receipt_message: String,
    receipt_message_hash: String,
    envelope: String,
}

fn load() -> Vectors {
    serde_json::from_str(&testdata("q3format-vectors.json")).expect("vectors parse")
}

const NETWORK: u64 = 5;
const GENESIS: [u8; 32] = [7; 32];
const PRIOR_ID: [u8; 32] = [0x11; 32];

#[test]
fn the_tuple_encoding_and_identity() {
    let v = load();
    let c = ProtocolConfig::q3(NETWORK, GENESIS);
    assert_eq!(hex(&c.encode()), v.config_encoding);
    assert_eq!(hex(&c.identity()), v.config_identity);
    assert!(c.validate().is_ok());
}

#[test]
fn every_partial_or_altered_tuple_is_refused_naming_the_field() {
    let q3 = ProtocolConfig::q3(NETWORK, GENESIS);
    type Alter = fn(&mut ProtocolConfig);
    let alterations: [(&str, Alter); 9] = [
        ("revision", |c| c.revision = 2),
        ("signingScheme", |c| c.signing_scheme = 1),
        ("voteCodec", |c| c.vote_codec = 1),
        ("quorumProfile", |c| c.quorum_profile = "D2".into()),
        ("evmRequestPolicy", |c| c.evm_request_policy = "unit".into()),
        ("aggregatorPolicy", |c| c.aggregator_policy = "weighted".into()),
        ("requiredPeerProtocol", |c| c.required_peer_protocol = "q3/2".into()),
        ("requiredExecutionProtocol", |c| c.required_execution_protocol = String::new()),
        ("registryLayout", |c| c.registry_layout = 1),
    ];
    for (field, alter) in alterations {
        let mut c = q3.clone();
        alter(&mut c);
        let e = c.validate().expect_err(field);
        assert_eq!(e.kind(), Kind::Config, "{field}");
        assert!(e.to_string().contains(field), "{field}: {e}");
    }
    for c in [ProtocolConfig::q3(0, GENESIS), ProtocolConfig::q3(NETWORK, [0; 32])] {
        assert_eq!(
            c.validate().expect_err("network and genesis are required").kind(),
            Kind::Config
        );
    }
}

#[test]
fn the_body_decodes_validates_and_re_encodes() {
    let v = load();
    let raw = unhex(&v.body_encoding);
    let b = BodyV3::decode(&raw).expect("the Go body decodes and validates");
    assert_eq!(hex(&b.encode()), v.body_encoding);
    assert_eq!(hex(&b.identity()), v.body_identity);
    assert_eq!((b.network, b.epoch, b.earliest_activation, b.root_threshold), (NETWORK, 2, 20, 7));
    assert_eq!(
        b.members.iter().map(|m| m.weight).collect::<Vec<_>>(),
        [6, 1, 1, 1],
        "W=9, threshold 7"
    );
    assert_eq!(b.config, ProtocolConfig::q3(NETWORK, GENESIS));
    // the predecessor hash is the first-V3 tagged hash over a V1 prior
    assert_eq!(hex(&b.predecessor_hash), v.predecessor_from_v1);
}

#[test]
fn the_predecessor_rule() {
    let v = load();
    let hash = |version| {
        Prior { network: NETWORK, epoch: 1, body_version: version, identity: PRIOR_ID.to_vec() }
            .hash()
    };
    assert_eq!(hex(&hash(1).expect("v1")), v.predecessor_from_v1);
    assert_eq!(hex(&hash(2).expect("v2")), v.predecessor_from_v2);
    assert_eq!(hash(3).expect("v3"), PRIOR_ID, "a V3 prior is named by its identity directly");
    for bad in [
        Prior { network: 0, epoch: 1, body_version: 1, identity: PRIOR_ID.to_vec() },
        Prior { network: NETWORK, epoch: 0, body_version: 1, identity: PRIOR_ID.to_vec() },
        Prior { network: NETWORK, epoch: 1, body_version: 0, identity: PRIOR_ID.to_vec() },
        Prior { network: NETWORK, epoch: 1, body_version: 4, identity: PRIOR_ID.to_vec() },
        Prior { network: NETWORK, epoch: 1, body_version: 1, identity: vec![0; 31] },
    ] {
        assert_eq!(bad.hash().expect_err("refused").kind(), Kind::Prior);
    }
}

#[test]
fn the_readiness_message() {
    let v = load();
    let b = BodyV3::decode(&unhex(&v.body_encoding)).expect("body");
    let ctx = ReceiptContext::for_body(&b, 3, [0x44; 32]);
    assert_eq!(ctx.predecessor.as_slice(), unhex(&v.predecessor_from_v1).as_slice());
    let msg = ctx.message("n1");
    assert_eq!(hex(&msg), v.receipt_message);
    assert_eq!(hex(&votesig::digest(&msg)), v.receipt_message_hash);
    assert_ne!(ctx.message("n2"), msg, "the message names the member");
}

#[test]
fn the_envelope_decodes_to_the_vector_fields() {
    let v = load();
    let e = Envelope::decode(&unhex(&v.envelope)).expect("the Go envelope decodes");
    assert_eq!(e.root_input, [1; 8]);
    assert_eq!(e.transitions, [b"t1".to_vec(), b"t2".to_vec()]);
    assert_eq!(e.target_parent, [0x88; 32]);
    assert_eq!(e.block_id, None);
    assert_eq!(e.links.len(), 1);
    let l = &e.links[0];
    assert_eq!(hex(&l.body.identity()), v.body_identity);
    assert_eq!((l.claim.epoch, l.claim.start, l.claim.prior_version), (2, 25, 1));
    assert_eq!(l.claim.body_id, array32(&v.body_identity));
    assert_eq!(l.claim.commit_id, [0x99; 32]);
    assert_eq!(l.claim.prior_id, PRIOR_ID);
    assert_eq!(
        (l.evidence.summary.as_slice(), l.evidence.frozen_parent.as_slice()),
        (&[0x55u8; 32][..], &[0x66u8; 32][..])
    );
    assert_eq!(l.evidence.candidate_digest, [0x44; 32]);
    assert_eq!(l.proof, [0xab; 16], "the proof is carried as opaque bytes until verified");
    assert!(l.receipts.is_empty());
}
