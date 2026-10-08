//! The pair-binding wire format and its gate.
//!
//! `testdata/pair-binding-vectors.json` is produced by `generate-pair-binding-vectors.py`, whose
//! CBOR encoder shares no code with this crate, from the Go-produced `ordinary_successful` root
//! input in `v2-vectors.json`. Step 3 of `testdata/b1-vectors.json` is the Go-produced root input
//! that carries one acknowledged transition. Every negative below changes exactly one field
//! of an otherwise accepted binding and asserts the one variant that field's comparison raises.

use alloy_consensus::Header;
use alloy_primitives::{hex, Address, B256};
use reth_primitives_traits::SealedHeader;
use reth_unicity_execution::{
    pairing::{
        attributes_digest, header_attributes_digest, transitions_hash, verify_pair_binding,
        ExpectedSubject, PairBinding, PairBindingError, PairContext, PairPins, PairSubject,
        MAX_PAIR_BINDING_BYTES, PAIR_BINDING_VERSION, SUBJECT_BUILD, SUBJECT_IMPORT,
    },
    wire::CanonicalCborError,
    RootInputV2,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/pair-binding-vectors.json");
const B1: &str = include_str!("../testdata/b1-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn raw(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn word(value: &Value) -> B256 {
    B256::from_slice(&raw(value))
}

/// The fixture a binding is checked against: pins, genesis, a parent, a root input.
struct World {
    pins: PairPins,
    genesis: B256,
    parent: SealedHeader<Header>,
    root: RootInputV2,
    block_hash: B256,
    digest: B256,
}

fn parent_with(hash: B256, number: u64) -> SealedHeader<Header> {
    SealedHeader::new(Header { number, ..Default::default() }, hash)
}

/// The Go-produced ordinary root input with the vector's parent, pins and subjects.
fn world() -> (World, Value) {
    let v = vectors();
    let f = &v["fields"];
    let root = RootInputV2::from_canonical_cbor(&raw(&v["rootInput"])).unwrap();
    let world = World {
        pins: PairPins {
            network_id: f["networkId"].as_u64().unwrap(),
            root_genesis_id: word(&f["rootGenesisId"]),
        },
        genesis: word(&f["executionGenesisHash"]),
        parent: parent_with(word(&f["parentHash"]), f["parentNumber"].as_u64().unwrap()),
        root,
        block_hash: word(&v["blockHash"]),
        digest: word(&v["attributes"]["digest"]),
    };
    (world, v)
}

impl World {
    const fn context(&self, subject: ExpectedSubject) -> PairContext<'_> {
        PairContext {
            pins: self.pins,
            execution_genesis_hash: self.genesis,
            parent: &self.parent,
            root: &self.root,
            subject,
        }
    }

    const fn import(&self) -> ExpectedSubject {
        ExpectedSubject::Import { block_hash: self.block_hash }
    }

    const fn build(&self) -> ExpectedSubject {
        ExpectedSubject::Build { attributes_digest: self.digest }
    }
}

fn import_binding() -> PairBinding {
    let (_, v) = world();
    PairBinding::from_canonical_cbor(&raw(&v["import"])).unwrap()
}

#[test]
fn the_independent_vectors_reproduce_byte_for_byte_and_verify() {
    let (w, v) = world();
    let binding = PairBinding::from_canonical_cbor(&raw(&v["import"])).unwrap();
    assert_eq!(binding.canonical_cbor(), raw(&v["import"]));
    assert_eq!(binding.subject, PairSubject::Import { block_hash: w.block_hash });
    assert_eq!(verify_pair_binding(&raw(&v["import"]), &w.context(w.import())).unwrap(), binding);

    let build = PairBinding::from_canonical_cbor(&raw(&v["build"])).unwrap();
    assert_eq!(build.canonical_cbor(), raw(&v["build"]));
    assert_eq!(build.subject, PairSubject::Build { attributes_digest: w.digest });
    assert_eq!(verify_pair_binding(&raw(&v["build"]), &w.context(w.build())).unwrap(), build);
    assert!(raw(&v["build"]).len() <= MAX_PAIR_BINDING_BYTES);
}

#[test]
fn the_vector_hashes_are_the_ones_the_gate_derives() {
    let (w, v) = world();
    let binding = import_binding();
    assert_eq!(binding.root_input_hash, w.root.input_commitment().unwrap());
    assert_eq!(binding.transitions_hash, transitions_hash(&[]));
    assert_eq!(word(&v["emptyTransitionsHash"]), transitions_hash(&[]));
    assert_eq!(word(&v["oneTransitionHash"]), transitions_hash(&[raw(&v["transition"])]));
    let a = &v["attributes"];
    assert_eq!(
        attributes_digest(
            a["timestamp"].as_u64().unwrap(),
            word(&a["prevRandao"]),
            Address::from_slice(&raw(&a["suggestedFeeRecipient"])),
            word(&a["parentBeaconBlockRoot"]),
        ),
        word(&a["digest"])
    );
}

#[test]
fn a_built_blocks_header_implies_the_digest_the_build_named() {
    let (_, v) = world();
    let a = &v["attributes"];
    let header = Header {
        timestamp: a["timestamp"].as_u64().unwrap(),
        mix_hash: word(&a["prevRandao"]),
        beneficiary: Address::from_slice(&raw(&a["suggestedFeeRecipient"])),
        parent_beacon_block_root: Some(word(&a["parentBeaconBlockRoot"])),
        ..Default::default()
    };
    assert_eq!(header_attributes_digest(&header), Some(word(&a["digest"])));
    assert_eq!(header_attributes_digest(&Header::default()), None);
}

#[test]
fn every_malformed_encoding_is_a_named_refusal() {
    let (_, v) = world();
    let invalid = &v["invalid"];
    let get = |name: &str| raw(&invalid[name]);
    let decode = |name: &str| PairBinding::from_canonical_cbor(&get(name)).unwrap_err();

    assert_eq!(decode("empty"), PairBindingError::Missing);
    assert_eq!(
        decode("trailing_byte"),
        PairBindingError::Malformed(CanonicalCborError::TrailingBytes)
    );
    assert_eq!(decode("truncated"), PairBindingError::Malformed(CanonicalCborError::UnexpectedEof));
    assert_eq!(
        decode("indefinite_array"),
        PairBindingError::Malformed(CanonicalCborError::IndefiniteLength)
    );
    assert_eq!(
        decode("non_minimal_version"),
        PairBindingError::Malformed(CanonicalCborError::NonMinimalLength)
    );
    assert_eq!(decode("wrong_domain"), PairBindingError::WrongDomain);
    assert_eq!(decode("wrong_version"), PairBindingError::WrongVersion(2));
    assert_eq!(
        decode("arity_fourteen"),
        PairBindingError::Malformed(CanonicalCborError::WrongArity { expected: 15, found: 14 })
    );
    assert_eq!(decode("unknown_subject_kind"), PairBindingError::UnknownSubject(3));
    assert_eq!(decode("zero_parent"), PairBindingError::ZeroIdentity("parentHash"));
    assert_eq!(
        decode("short_word"),
        PairBindingError::Malformed(CanonicalCborError::WrongByteStringLength {
            expected: 32,
            found: 31
        })
    );
    assert_eq!(PAIR_BINDING_VERSION, 1);
    assert_eq!((SUBJECT_BUILD, SUBJECT_IMPORT), (1, 2));
}

#[test]
fn an_oversized_binding_is_refused_before_it_is_read() {
    let mut oversized = raw(&vectors()["import"]);
    oversized.resize(MAX_PAIR_BINDING_BYTES + 1, 0);
    assert_eq!(
        PairBinding::from_canonical_cbor(&oversized),
        Err(PairBindingError::TooLarge { len: MAX_PAIR_BINDING_BYTES + 1 })
    );
}

#[test]
fn each_zero_identity_is_refused_by_name() {
    let base = import_binding();
    let zero = B256::ZERO;
    let cases: [(&str, PairBinding); 8] = [
        ("rootGenesisId", PairBinding { root_genesis_id: zero, ..base }),
        ("executionGenesisHash", PairBinding { execution_genesis_hash: zero, ..base }),
        ("parentHash", PairBinding { parent_hash: zero, ..base }),
        ("configurationId", PairBinding { configuration_id: zero, ..base }),
        ("activationId", PairBinding { activation_id: zero, ..base }),
        ("rootInputHash", PairBinding { root_input_hash: zero, ..base }),
        ("transitionsHash", PairBinding { transitions_hash: zero, ..base }),
        ("subjectId", PairBinding { subject: PairSubject::Import { block_hash: zero }, ..base }),
    ];
    for (name, binding) in cases {
        assert_eq!(
            PairBinding::from_canonical_cbor(&binding.canonical_cbor()),
            Err(PairBindingError::ZeroIdentity(name)),
            "{name}"
        );
    }
}

/// Re-encodes the vector binding with `change` applied and runs the gate on it.
fn refused(change: impl FnOnce(&mut PairBinding)) -> PairBindingError {
    let (w, _) = world();
    let mut binding = import_binding();
    change(&mut binding);
    verify_pair_binding(&binding.canonical_cbor(), &w.context(w.import())).unwrap_err()
}

#[test]
fn each_single_field_mismatch_raises_exactly_its_own_variant() {
    let flip = |word: B256| B256::from(word.0.map(|byte| byte ^ 0xff));
    assert_eq!(refused(|b| b.network_id += 1), PairBindingError::NetworkMismatch);
    assert_eq!(
        refused(|b| b.root_genesis_id = flip(b.root_genesis_id)),
        PairBindingError::RootGenesisMismatch
    );
    assert_eq!(
        refused(|b| b.execution_genesis_hash = flip(b.execution_genesis_hash)),
        PairBindingError::ExecutionGenesisMismatch
    );
    assert_eq!(
        refused(|b| b.parent_hash = flip(b.parent_hash)),
        PairBindingError::ParentHashMismatch
    );
    assert_eq!(refused(|b| b.parent_number += 1), PairBindingError::ParentNumberMismatch);
    assert_eq!(refused(|b| b.origin_root_epoch += 1), PairBindingError::OriginEpochMismatch);
    assert_eq!(refused(|b| b.origin_root_round += 1), PairBindingError::OriginRoundMismatch);
    assert_eq!(
        refused(|b| b.configuration_id = flip(b.configuration_id)),
        PairBindingError::ConfigurationMismatch
    );
    assert_eq!(
        refused(|b| b.root_input_hash = flip(b.root_input_hash)),
        PairBindingError::RootInputMismatch
    );
    assert_eq!(
        refused(|b| b.transitions_hash = flip(b.transitions_hash)),
        PairBindingError::TransitionsMismatch
    );
    assert_eq!(
        refused(|b| b.subject = PairSubject::Import { block_hash: flip(b.root_input_hash) }),
        PairBindingError::BlockMismatch
    );
}

#[test]
fn the_activation_is_free_without_a_transition_and_pinned_with_one() {
    // No transition: the activation is carried, so any nonzero value passes.
    let (w, _) = world();
    let mut binding = import_binding();
    binding.activation_id = B256::repeat_byte(0x99);
    assert!(verify_pair_binding(&binding.canonical_cbor(), &w.context(w.import())).is_ok());

    // One acknowledged transition: the activation must be that transition's commit id.
    let b1: Value = serde_json::from_str(B1).unwrap();
    let step = &b1["steps"][2];
    let root = RootInputV2::from_canonical_cbor(&raw(&step["rootInput"])).unwrap();
    assert_eq!(root.transitions.len(), 1);
    let parent_number = step["parentNumber"].as_u64().unwrap();
    let parent = parent_with(root.parent_hash, parent_number);
    let pins = PairPins { network_id: root.network_id, root_genesis_id: B256::repeat_byte(0x51) };
    let genesis = parent.hash();
    let subject = ExpectedSubject::Import { block_hash: B256::repeat_byte(0x63) };
    let context = PairContext {
        pins,
        execution_genesis_hash: genesis,
        parent: &parent,
        root: &root,
        subject,
    };
    let good = PairBinding {
        network_id: root.network_id,
        root_genesis_id: pins.root_genesis_id,
        execution_genesis_hash: genesis,
        parent_hash: parent.hash(),
        parent_number,
        origin_root_epoch: root.origin.root_epoch,
        origin_root_round: root.origin.root_round,
        configuration_id: root.origin.shard_conf_hash,
        activation_id: B256::ZERO,
        root_input_hash: root.input_commitment().unwrap(),
        transitions_hash: transitions_hash(&root.transitions),
        subject: PairSubject::Import { block_hash: B256::repeat_byte(0x63) },
    };
    // The all-zero value is refused as an identity before it can be compared.
    assert_eq!(
        verify_pair_binding(&good.canonical_cbor(), &context),
        Err(PairBindingError::ZeroIdentity("activationId"))
    );
    let wrong = PairBinding { activation_id: B256::repeat_byte(0x99), ..good };
    assert_eq!(
        verify_pair_binding(&wrong.canonical_cbor(), &context),
        Err(PairBindingError::ActivationMismatch)
    );
    let commit_id = reference_commit_id(&root);
    let right = PairBinding { activation_id: commit_id, ..good };
    assert_eq!(verify_pair_binding(&right.canonical_cbor(), &context), Ok(right));
}

/// The acknowledgement's `commitId`, read from the transition body's wrapped ack (bytes 0x58 0x..)
/// by position: the last byte string of the outer array wraps the ack, whose fifth element is it.
fn reference_commit_id(root: &RootInputV2) -> B256 {
    let transition = &root.transitions[0];
    // Outer array of 13; the final element is the byte string holding the acknowledgement.
    // Locate the ack by its domain text rather than by a fixed offset.
    let marker = b"UNICITY_HANDOFF_ACK";
    let at = transition.windows(marker.len()).position(|w| w == marker).unwrap();
    // After the domain: version (1 byte), frozenId (34 bytes), then commitId (34 bytes).
    let start = at + marker.len() + 1 + 34 + 2;
    B256::from_slice(&transition[start..start + 32])
}

#[test]
fn an_input_for_another_network_is_refused_even_under_a_matching_binding() {
    let (mut w, v) = world();
    w.root.network_id += 1;
    assert_eq!(
        verify_pair_binding(&raw(&v["import"]), &w.context(w.import())),
        Err(PairBindingError::InputNetworkMismatch)
    );
}

#[test]
fn the_subject_kind_must_match_the_flow() {
    let (w, v) = world();
    assert_eq!(
        verify_pair_binding(&raw(&v["build"]), &w.context(w.import())),
        Err(PairBindingError::WrongSubjectKind { expected: SUBJECT_IMPORT, found: SUBJECT_BUILD })
    );
    assert_eq!(
        verify_pair_binding(&raw(&v["import"]), &w.context(w.build())),
        Err(PairBindingError::WrongSubjectKind { expected: SUBJECT_BUILD, found: SUBJECT_IMPORT })
    );
    // The right kind with another job or block is its own variant.
    assert_eq!(
        verify_pair_binding(
            &raw(&v["build"]),
            &w.context(ExpectedSubject::Build { attributes_digest: B256::repeat_byte(1) })
        ),
        Err(PairBindingError::JobMismatch)
    );
    assert_eq!(
        verify_pair_binding(
            &raw(&v["import"]),
            &w.context(ExpectedSubject::Import { block_hash: B256::repeat_byte(1) })
        ),
        Err(PairBindingError::BlockMismatch)
    );
}

#[test]
fn a_missing_binding_is_never_a_pass() {
    let (w, _) = world();
    assert_eq!(verify_pair_binding(&[], &w.context(w.import())), Err(PairBindingError::Missing));
}

#[test]
fn every_single_bit_flip_is_refused_except_the_unconstrained_activation() {
    let (w, v) = world();
    let good = raw(&v["import"]);
    let reference = import_binding();
    let mut activation_flips = 0;
    for at in 0..good.len() {
        for bit in 0..8 {
            let mut mutated = good.clone();
            mutated[at] ^= 1 << bit;
            match verify_pair_binding(&mutated, &w.context(w.import())) {
                Err(_) => {}
                Ok(binding) => {
                    // The one field with nothing to compare against when no transition is
                    // carried; it must still be the only difference.
                    assert_eq!(
                        PairBinding { activation_id: reference.activation_id, ..binding },
                        reference,
                        "flipping bit {bit} of byte {at} verified and changed more than activationId"
                    );
                    assert_ne!(binding.activation_id, reference.activation_id);
                    activation_flips += 1;
                }
            }
        }
    }
    assert_eq!(activation_flips, 32 * 8, "exactly the 32 activation bytes are unconstrained");
}
