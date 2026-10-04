//! Guards that a decoded envelope cannot reach (the decoder refuses first) or whose refusal shares
//! a [`Kind`] with a neighbouring check. Each case drives the public API directly and asserts the
//! refusal's own detail text, so disabling that one guard fails exactly one assertion.

mod support;

use reth_unicity_lineage::{BodyV3, Envelope, History, Kind, Link};
use serde::Deserialize;
use support::{array32, testdata, unhex};

#[derive(Deserialize)]
struct File {
    worlds: Vec<World>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct World {
    name: String,
    genesis_trust_base: String,
    genesis_id: String,
    cases: Vec<Case>,
}

fn world(name: &str) -> World {
    let f: File = serde_json::from_str(&testdata("go-lineage-vectors.json")).unwrap();
    f.worlds.into_iter().find(|w| w.name == name).unwrap_or_else(|| panic!("world {name}"))
}

#[derive(Deserialize)]
struct Case {
    name: String,
    envelope: String,
}

fn setup() -> (History, Link) {
    let v = world("genesis-start-0");
    let g = History::new(&unhex(&v.genesis_trust_base), array32(&v.genesis_id)).unwrap();
    let c = v.cases.iter().find(|c| c.name.starts_with("positive: first")).unwrap();
    let link = Envelope::decode(&unhex(&c.envelope)).unwrap().links.remove(0);
    g.with_v3(&link).expect("acceptance control");
    (g, link)
}

fn refused(h: &History, l: &Link, kind: Kind, detail: &str) {
    let e = h.with_v3(l).err().unwrap_or_else(|| panic!("accepted, wanted {detail:?}"));
    assert_eq!(e.kind(), kind, "{e}");
    assert!(e.to_string().contains(detail), "wanted {detail:?}, got {e}");
}

#[test]
fn evidence_must_be_complete_and_bounded() {
    let (g, ok) = setup();
    let change = |f: fn(&mut Link)| {
        let mut l = ok.clone();
        f(&mut l);
        l
    };
    let d = "incomplete or oversize evidence";
    refused(&g, &change(|l| l.evidence.candidate_digest.truncate(31)), Kind::Binding, d);
    refused(&g, &change(|l| l.evidence.candidate_digest.push(0)), Kind::Binding, d);
    refused(&g, &change(|l| l.evidence.summary.clear()), Kind::Binding, d);
    refused(&g, &change(|l| l.evidence.frozen_parent.clear()), Kind::Binding, d);
    refused(&g, &change(|l| l.evidence.summary = vec![1; 65]), Kind::Binding, d);
    refused(&g, &change(|l| l.evidence.frozen_parent = vec![1; 65]), Kind::Binding, d);
}

#[test]
fn a_link_for_an_epoch_that_does_not_follow_the_tip_is_history_not_a_gap() {
    let (g, ok) = setup();
    let h = g.with_v3(&ok).unwrap();
    // the tip is epoch 2: a body for epoch 2 (a repeat) is neither a gap nor a successor
    refused(&h, &ok, Kind::History, "does not follow");
    let mut gap = ok;
    gap.body.epoch = 4;
    refused(&h, &gap, Kind::MissingHistory, "after");
}

#[test]
fn the_body_rules_hold_on_the_struct_not_only_through_decode() {
    let (_, ok) = setup();
    let b = ok.body;
    let bad = |f: &dyn Fn(&mut BodyV3), detail: &str| {
        let mut x = b.clone();
        f(&mut x);
        let e = x.validate().expect_err(detail);
        assert!(e.to_string().contains(detail), "wanted {detail:?}, got {e}");
    };
    assert!(b.validate().is_ok());
    bad(&|x| x.members.clear(), "empty member set");
    let m = b.members[0].clone();
    bad(&|x| x.members = (0..65).map(|_| m.clone()).collect(), "65 members");
    // weight rules, each with the threshold made consistent so that only the weight rule can refuse
    bad(
        &|x| {
            x.members[0].weight = 0;
            x.root_threshold = 2 * 3 / 3 + 1;
        },
        "weight 0 out of",
    );
    bad(
        &|x| {
            x.members[0].weight = (1 << 40) + 1;
            x.root_threshold = 2 * ((1 << 40) + 3) / 3 + 1;
        },
        "out of [1, 2^40]",
    );
    bad(&|x| x.config.network = 0, "required");
    bad(&|x| x.config.genesis = [0; 32], "required");
}

fn history_of(w: &World) -> History {
    History::new(&unhex(&w.genesis_trust_base), array32(&w.genesis_id)).expect("genesis")
}

fn first_link(w: &World) -> Link {
    let c = w
        .cases
        .iter()
        .find(|c| c.name.starts_with("positive: first"))
        .expect("the first-link case");
    Envelope::decode(&unhex(&c.envelope)).unwrap().links.remove(0)
}

/// A* must follow the epoch start of the epoch it replaces. The same A* = 25 link, in three worlds
/// whose genesis epoch starts at 30, 25 and 24 (each its own authenticated committee), is refused
/// below and at the start and accepted above it.
#[test]
fn activation_must_follow_the_start_of_the_epoch_it_replaces() {
    for (name, accepted) in
        [("genesis-start-30", false), ("genesis-start-25", false), ("genesis-start-24", true)]
    {
        let w = world(name);
        let (h, l) = (history_of(&w), first_link(&w));
        assert_eq!(l.claim.start, 25, "{name}: every world activates at A* = 25");
        if accepted {
            let next =
                h.with_v3(&l).unwrap_or_else(|e| panic!("{name}: acceptance control refused: {e}"));
            assert_eq!(next.tip().start(), 25);
        } else {
            refused(&h, &l, Kind::Binding, "does not follow the epoch start");
        }
    }
}
