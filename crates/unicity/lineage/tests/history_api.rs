//! The pinned genesis and the resolver surface of [`History`].

mod support;

use reth_unicity_lineage::{Envelope, History, Kind};
use serde::Deserialize;
use support::{array32, sha256, testdata, unhex, GenesisSpec};

fn pinned(spec: &GenesisSpec) -> (Vec<u8>, [u8; 32]) {
    let raw = spec.encode();
    let id = sha256(&raw);
    (raw, id)
}

fn start(spec: &GenesisSpec) -> reth_unicity_lineage::Result<History> {
    let (raw, id) = pinned(spec);
    History::new(&raw, id)
}

#[test]
fn a_unit_committee_self_signed_by_a_quorum_starts_a_history() {
    let h = start(&GenesisSpec::default()).expect("acceptance control");
    assert_eq!(
        (h.network(), h.tip().epoch(), h.tip().start(), h.tip().version(), h.tip().scheme()),
        (5, 1, 0, 1, 1)
    );
    assert_eq!(
        h.genesis(),
        pinned(&GenesisSpec::default()).1,
        "the genesis identity is the hash of the canonical bytes, signatures included"
    );
    assert!(h.tip().config().is_none(), "legacy history is explicit scheme 1 and has no tuple");
    // three of four signing is a quorum; two of four is not
    assert!(start(&GenesisSpec { signers: vec!["a", "b", "c"], ..GenesisSpec::default() }).is_ok());
    // a threshold anywhere in [floor(2n/3)+1, n] is allowed for the unit genesis
    assert!(start(&GenesisSpec { threshold: 4, ..GenesisSpec::default() }).is_ok());
}

#[test]
fn the_genesis_is_refused_unless_it_is_exactly_the_pinned_unit_committee() {
    let g = GenesisSpec::default;
    let refused = |name: &str, spec: GenesisSpec, kind: Kind| {
        let e = start(&spec).err().unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(e.kind(), kind, "{name}: {e}");
    };
    refused("two of four signers", GenesisSpec { signers: vec!["a", "b"], ..g() }, Kind::History);
    refused("unsigned", GenesisSpec { signers: vec![], ..g() }, Kind::History);
    refused("epoch 2 is not a genesis", GenesisSpec { epoch: 2, ..g() }, Kind::History);
    refused(
        "weighted member",
        GenesisSpec { nodes: vec![("a", 1, 2), ("b", 2, 1), ("c", 3, 1), ("d", 4, 1)], ..g() },
        Kind::History,
    );
    refused(
        "zero weight",
        GenesisSpec { nodes: vec![("a", 1, 0), ("b", 2, 1), ("c", 3, 1), ("d", 4, 1)], ..g() },
        Kind::History,
    );
    refused(
        "members out of order",
        GenesisSpec { nodes: vec![("b", 2, 1), ("a", 1, 1), ("c", 3, 1), ("d", 4, 1)], ..g() },
        Kind::History,
    );
    refused(
        "repeated member",
        GenesisSpec {
            nodes: vec![("a", 1, 1), ("a", 2, 1), ("c", 3, 1), ("d", 4, 1)],
            signers: vec!["c", "d"],
            ..g()
        },
        Kind::History,
    );
    refused("threshold below 2n/3+1", GenesisSpec { threshold: 2, ..g() }, Kind::History);
    refused("threshold above n", GenesisSpec { threshold: 5, ..g() }, Kind::History);
    refused(
        "no members",
        GenesisSpec { nodes: vec![], signers: vec![], threshold: 1, ..g() },
        Kind::History,
    );
    // a signature by a node that is not a member rejects the certificate (it is not skipped)
    let mut spec = g();
    spec.nodes.push(("e", 5, 1));
    spec.threshold = 4;
    spec.signers = vec!["a", "b", "c", "d"];
    let unsigned_by_e = start(&spec).expect("control: five members, four signers, threshold 4");
    assert_eq!(unsigned_by_e.tip().epoch(), 1);
}

#[test]
fn only_the_pinned_bytes_start_a_history() {
    let (raw, id) = pinned(&GenesisSpec::default());
    assert!(History::new(&raw, id).is_ok());
    let mut other = id;
    other[0] ^= 1;
    assert_eq!(
        History::new(&raw, other).err().map(|e| e.kind()),
        Some(Kind::Genesis),
        "the pin decides, not the bytes"
    );
    // another genesis with its own matching pin is a different chain, not an error: the pin is the
    // deployment's choice
    let (raw2, id2) = pinned(&GenesisSpec { start: 9, ..GenesisSpec::default() });
    assert_ne!(
        History::new(&raw2, id2).unwrap().genesis(),
        History::new(&raw, id).unwrap().genesis()
    );
    // trailing bytes, truncation and a non-minimal head under a matching pin are Format
    for (name, bytes) in [
        ("trailing", [raw.clone(), vec![0]].concat()),
        ("truncated", raw[..raw.len() - 1].to_vec()),
        ("non-minimal tag head", [vec![0xda, 0x00, 0x00, 0x98, 0x58], raw[3..].to_vec()].concat()),
        (
            "indefinite array",
            [vec![0xd9, 0x98, 0x58, 0x9f], raw[4..].to_vec(), vec![0xff]].concat(),
        ),
    ] {
        let e =
            History::new(&bytes, sha256(&bytes)).err().unwrap_or_else(|| panic!("{name} accepted"));
        assert_eq!(e.kind(), Kind::Format, "{name}: {e}");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    genesis_trust_base: String,
    genesis_id: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    envelope: String,
}

#[test]
fn the_resolver_covers_exactly_the_verified_intervals() {
    let v: Vectors = serde_json::from_str(&testdata("go-lineage-vectors.json")).unwrap();
    let g = History::new(&unhex(&v.genesis_trust_base), array32(&v.genesis_id)).unwrap();
    let case =
        v.cases.iter().find(|c| c.name.starts_with("positive: first")).expect("positive case");
    let h = g.verify_envelope(&Envelope::decode(&unhex(&case.envelope)).unwrap()).unwrap();
    assert_eq!(g.tip().epoch(), 1, "verification leaves the history it extended untouched");

    assert_eq!(h.for_epoch(2).unwrap().start(), 25);
    for e in [0, 3, u64::MAX] {
        assert_eq!(
            h.for_epoch(e).err().map(|x| x.kind()),
            Some(Kind::UnknownEpoch),
            "epoch {e}: an absent epoch is never a legacy default"
        );
    }
    for (round, want) in [(0, 1), (24, 1), (25, 2), (1 << 40, 2)] {
        assert_eq!(h.for_round(round).unwrap().epoch(), want, "round {round}");
    }
    assert_eq!(h.ordinary(1, 24).ok(), Some(()));
    assert_eq!(h.ordinary(2, 25).ok(), Some(()));
    assert_eq!(h.ordinary(2, 1 << 40).ok(), Some(()));
    for (epoch, round, kind) in [
        (1, 25, Kind::OutsideInterval),
        (2, 24, Kind::OutsideInterval),
        (3, 100, Kind::UnknownEpoch),
    ] {
        assert_eq!(
            h.ordinary(epoch, round).err().map(|x| x.kind()),
            Some(kind),
            "({epoch}, {round})"
        );
    }
    assert_eq!(
        h.for_epoch(1).unwrap().anchor(),
        (1, 0),
        "the genesis epoch has no predecessor to anchor on"
    );
    assert_eq!(h.for_epoch(2).unwrap().anchor(), (2, 24), "the successor is anchored at (E, A*-1)");
    assert_eq!(h.for_epoch(2).unwrap().scheme(), 2);
    assert_eq!(h.for_epoch(1).unwrap().scheme(), 1);
    // a history whose genesis epoch starts late covers nothing before it
    let late = start(&GenesisSpec { start: 30, ..GenesisSpec::default() }).unwrap();
    assert_eq!(late.for_round(29).err().map(|x| x.kind()), Some(Kind::UnknownEpoch));
}
