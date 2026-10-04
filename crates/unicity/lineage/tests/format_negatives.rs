//! Refusals of the wire formats and the body and receipt rules, each isolated from the others by
//! starting from a decoding control and changing one thing.

mod support;

use reth_unicity_lineage::{
    verify_receipts, BodyV3, Envelope, Kind, Member, Receipt, ReceiptContext,
};
use serde::Deserialize;
use support::{public_key, sign, testdata, unhex, Enc};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    body_encoding: String,
    envelope: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(&testdata("q3format-vectors.json")).expect("vectors parse")
}

fn body() -> BodyV3 {
    BodyV3::decode(&unhex(&vectors().body_encoding)).expect("the Go body")
}

fn envelope_kind(raw: &[u8]) -> Kind {
    Envelope::decode(raw).expect_err("refused").kind()
}

const DOMAIN_END: usize = 1 + 2 + 26; // the array head, the text head and the 26-byte domain; the version item follows

#[test]
fn the_control_envelope_decodes() {
    assert!(Envelope::decode(&unhex(&vectors().envelope)).is_ok());
}

#[test]
fn the_envelope_framing_is_strict() {
    let raw = unhex(&vectors().envelope);
    assert_eq!(raw[DOMAIN_END], 0x01, "the version item");
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut m = raw.clone();
        f(&mut m);
        m
    };
    assert_eq!(envelope_kind(&with(&|m| m.push(0))), Kind::Format, "trailing byte");
    assert_eq!(envelope_kind(&raw[..raw.len() - 1]), Kind::Format, "truncated");
    assert_eq!(envelope_kind(&[]), Kind::Format, "empty");
    assert_eq!(
        envelope_kind(&with(&|m| m.splice(DOMAIN_END..=DOMAIN_END, [0x18, 0x01]).for_each(drop))),
        Kind::Format,
        "non-minimal integer head"
    );
    assert_eq!(envelope_kind(&with(&|m| m[DOMAIN_END] = 0x02)), Kind::Version, "unknown version");
    assert_eq!(envelope_kind(&with(&|m| m[5] ^= 0x01)), Kind::Version, "another domain");
    // an indefinite-length outer array re-encodes as a definite one, so it is not canonical
    assert_eq!(
        envelope_kind(&with(&|m| {
            m[0] = 0x9f;
            m.push(0xff);
        })),
        Kind::Format,
        "indefinite length"
    );
    let mut big = raw.clone();
    big.resize(16 << 20 | 1, 0);
    assert_eq!(envelope_kind(&big), Kind::TooLarge, "above 16 MiB");
    // a hostile length is refused from the bytes that remain, before anything is allocated
    let mut bomb = Enc::default();
    bomb.array(7)
        .text("UNICITY_Q3_EXECUTION_PROOF")
        .uint(1)
        .bytes(&[])
        .raw(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(envelope_kind(&bomb.0), Kind::TooLarge | Kind::Format));
    let mut bytes_bomb = Enc::default();
    bytes_bomb
        .array(7)
        .text("UNICITY_Q3_EXECUTION_PROOF")
        .uint(1)
        .raw(&[0x5b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        envelope_kind(&bytes_bomb.0),
        Kind::Format,
        "a 1 TiB byte string in a 90-byte input is truncated, not allocated"
    );
    // nesting beyond the bound
    let mut deep = Enc::default();
    deep.array(7).text("UNICITY_Q3_EXECUTION_PROOF").uint(1).bytes(&[]);
    for _ in 0..12 {
        deep.array(1);
    }
    deep.uint(0);
    assert_eq!(envelope_kind(&deep.0), Kind::TooLarge, "nesting too deep");
}

#[test]
fn the_envelope_admits_only_unsigned_bytes_text_arrays_and_null() {
    let head = |e: &mut Enc| {
        e.array(7).text("UNICITY_Q3_EXECUTION_PROOF").uint(1);
    };
    for (name, item) in [
        ("negative integer", vec![0x20]),
        ("float", vec![0xf9, 0x3c, 0x00]),
        ("true", vec![0xf5]),
        ("undefined", vec![0xf7]),
        ("tag", vec![0xc1, 0x01]),
        ("map", vec![0xa0]),
        ("invalid utf-8 text", vec![0x61, 0xff]),
    ] {
        let mut e = Enc::default();
        head(&mut e);
        e.raw(&item).array(0).bytes(&[0; 32]).null().array(0);
        assert_eq!(envelope_kind(&e.0), Kind::Format, "{name} where the root input goes");
    }
    // the control for this construction: the same frame with a byte string is accepted
    let mut ok = Enc::default();
    head(&mut ok);
    ok.bytes(&[1]).array(0).bytes(&[0; 32]).null().array(0);
    assert!(Envelope::decode(&ok.0).is_ok());
}

fn link(b: &BodyV3, epoch: u64, receipts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = b.clone();
    b.epoch = epoch;
    let mut e = Enc::default();
    e.array(5)
        .bytes(&b.encode())
        .array(6)
        .uint(epoch)
        .uint(25)
        .bytes(&[1; 32])
        .bytes(&[2; 32])
        .uint(1)
        .bytes(&[3; 32]);
    e.array(3).bytes(&[4; 32]).bytes(&[5; 32]).bytes(&[6; 32]).bytes(&[7; 8]).array(receipts.len());
    for (id, sig) in receipts {
        e.array(2).text(id).bytes(sig);
    }
    e.0
}

fn envelope_of(links: &[Vec<u8>], transitions: usize) -> Vec<u8> {
    let mut e = Enc::default();
    e.array(7).text("UNICITY_Q3_EXECUTION_PROOF").uint(1).bytes(&[1]).array(transitions);
    for _ in 0..transitions {
        e.bytes(b"t");
    }
    e.bytes(&[8; 32]).null().array(links.len());
    for l in links {
        e.raw(l);
    }
    e.0
}

#[test]
fn links_are_bounded_and_strictly_consecutive() {
    let b = body();
    let l = |epoch| link(&b, epoch, &[]);
    assert_eq!(Envelope::decode(&envelope_of(&[l(2), l(3)], 1)).expect("control").links.len(), 2);
    assert_eq!(envelope_kind(&envelope_of(&[l(2), l(4)], 1)), Kind::Envelope, "a skipped epoch");
    assert_eq!(envelope_kind(&envelope_of(&[l(2), l(2)], 1)), Kind::Envelope, "a repeated epoch");
    assert_eq!(envelope_kind(&envelope_of(&[l(3), l(2)], 1)), Kind::Envelope, "descending epochs");
    let many: Vec<Vec<u8>> = (2..2 + 65).map(l).collect();
    assert_eq!(envelope_kind(&envelope_of(&many, 1)), Kind::TooLarge, "65 links");
    let sixty_four: Vec<Vec<u8>> = (2..2 + 64).map(l).collect();
    assert_eq!(Envelope::decode(&envelope_of(&sixty_four, 1)).expect("64 links").links.len(), 64);
    assert_eq!(envelope_kind(&envelope_of(&[l(2)], 65)), Kind::TooLarge, "65 transitions");
    assert!(Envelope::decode(&envelope_of(&[l(2)], 64)).is_ok());
}

#[test]
fn an_embedded_body_that_fails_its_own_checks_refuses_the_envelope() {
    let b = body();
    let mut bad = b.clone();
    bad.root_threshold = 8;
    assert_eq!(envelope_kind(&envelope_of(&[link(&bad, 2, &[])], 1)), Kind::Body);
    let mut tuple = b;
    tuple.config.signing_scheme = 1;
    assert_eq!(envelope_kind(&envelope_of(&[link(&tuple, 2, &[])], 1)), Kind::Config);
}

#[test]
fn receipts_are_strictly_ordered_and_bounded_in_the_envelope() {
    let b = body();
    let sig = [9u8; 64];
    let ok = envelope_of(&[link(&b, 2, &[("n1", &sig), ("n2", &sig)])], 1);
    assert_eq!(Envelope::decode(&ok).expect("control").links[0].receipts.len(), 2);
    assert_eq!(
        envelope_kind(&envelope_of(&[link(&b, 2, &[("n2", &sig), ("n1", &sig)])], 1)),
        Kind::Format,
        "unordered"
    );
    assert_eq!(
        envelope_kind(&envelope_of(&[link(&b, 2, &[("n1", &sig), ("n1", &sig)])], 1)),
        Kind::Format,
        "duplicate"
    );
    assert_eq!(
        envelope_kind(&envelope_of(&[link(&b, 2, &[("n1", &[0u8; 129])])], 1)),
        Kind::TooLarge,
        "oversize signature"
    );
}

fn recode(b: &BodyV3) -> reth_unicity_lineage::Result<BodyV3> {
    BodyV3::decode(&b.encode())
}

#[test]
fn the_body_rules_each_in_isolation() {
    let ok = body();
    assert!(recode(&ok).is_ok(), "acceptance control");
    type Change = Box<dyn Fn(&mut BodyV3)>;
    let cases: Vec<(&str, Change, Kind)> = vec![
        ("epoch below 2", Box::new(|b| b.epoch = 1), Kind::Body),
        ("A_min zero", Box::new(|b| b.earliest_activation = 0), Kind::Body),
        ("short predecessor", Box::new(|b| b.predecessor_hash = vec![1; 31]), Kind::Body),
        ("missing predecessor", Box::new(|b| b.predecessor_hash.clear()), Kind::Body),
        ("tuple network", Box::new(|b| b.config.network = 6), Kind::Body),
        ("tuple scheme", Box::new(|b| b.config.signing_scheme = 1), Kind::Config),
        ("threshold too low", Box::new(|b| b.root_threshold = 6), Kind::Body),
        ("threshold too high", Box::new(|b| b.root_threshold = 8), Kind::Body),
        ("zero weight", Box::new(|b| b.members[1].weight = 0), Kind::Body),
        ("weight above 2^40", Box::new(|b| b.members[0].weight = (1 << 40) + 1), Kind::Body),
        (
            "duplicate node id",
            Box::new(|b| b.members[2].node_id = b.members[1].node_id.clone()),
            Kind::Body,
        ),
        (
            "duplicate staking id",
            Box::new(|b| b.members[2].staking_id = b.members[1].staking_id.clone()),
            Kind::Body,
        ),
        (
            "duplicate consensus key",
            Box::new(|b| b.members[2].consensus_key = b.members[1].consensus_key.clone()),
            Kind::Body,
        ),
        (
            "key not on the curve",
            Box::new(|b| b.members[1].consensus_key = [vec![2], vec![0xff; 32]].concat()),
            Kind::Body,
        ),
        ("empty node id", Box::new(|b| b.members[1].node_id.clear()), Kind::Body),
        ("empty staking id", Box::new(|b| b.members[1].staking_id.clear()), Kind::Body),
        ("no members", Box::new(|b| b.members.clear()), Kind::Body),
    ];
    for (name, change, kind) in cases {
        let mut b = ok.clone();
        change(&mut b);
        let e = recode(&b).err().unwrap_or_else(|| panic!("{name} accepted"));
        assert_eq!(e.kind(), kind, "{name}: {e}");
    }
    // 65 members is above the assignment limit
    let mut many = ok;
    many.members = (0..65u8)
        .map(|i| Member {
            staking_id: format!("s{i:02}"),
            node_id: format!("n{i:02}"),
            consensus_key: public_key(i + 1),
            weight: 1,
        })
        .collect();
    many.root_threshold = 2 * 65 / 3 + 1;
    assert_eq!(recode(&many).expect_err("65 members").kind(), Kind::TooLarge);
    many.members.truncate(64);
    many.root_threshold = 2 * 64 / 3 + 1;
    assert!(recode(&many).is_ok(), "64 members is the limit");
}

#[test]
fn body_encodings_must_be_canonical_and_of_this_version() {
    let raw = unhex(&vectors().body_encoding);
    assert_eq!(
        BodyV3::decode(&[raw.clone(), vec![0]].concat()).expect_err("trailing").kind(),
        Kind::Format
    );
    assert_eq!(BodyV3::decode(&raw[..raw.len() - 1]).expect_err("truncated").kind(), Kind::Format);
    // a V2 body (the field array that starts with version 2) is a version refusal, not a format
    // error
    let mut v2 = Enc::default();
    v2.array(9).uint(2);
    for _ in 0..8 {
        v2.uint(0);
    }
    assert_eq!(BodyV3::decode(&v2.0).expect_err("v2").kind(), Kind::Version);
    // members out of node-id order are not the canonical encoding
    let mut b = body();
    b.members.swap(0, 3);
    let mut swapped = unhex(&vectors().body_encoding);
    let canonical = b.encode();
    assert_eq!(
        canonical, swapped,
        "encode sorts members, so the swapped struct encodes to the Go bytes"
    );
    // exchange two member records in the bytes: valid CBOR, wrong order
    let first = swapped.windows(4).position(|w| w == [0x84, 0x62, 0x73, 0x31]).expect("member 1");
    let second = swapped.windows(4).position(|w| w == [0x84, 0x62, 0x73, 0x32]).expect("member 2");
    let len = second - first;
    let a: Vec<u8> = swapped[first..first + len].to_vec();
    let c: Vec<u8> = swapped[second..second + len].to_vec();
    swapped.splice(first..first + len, c).for_each(drop);
    swapped.splice(second..second + len, a).for_each(drop);
    assert_eq!(BodyV3::decode(&swapped).expect_err("unordered members").kind(), Kind::Format);
    // an empty optional field is null, never an empty byte string
    let mut empty = unhex(&vectors().body_encoding);
    let p = empty.windows(2).position(|w| w == [0x58, 0x20]).expect("a 32-byte field");
    empty.splice(p..p + 2 + 32, [0x40]).for_each(drop);
    assert_eq!(
        BodyV3::decode(&empty).expect_err("empty bytes in place of a hash").kind(),
        Kind::Format
    );
}

fn members_of(b: &BodyV3) -> Vec<(String, u8)> {
    // test keys 1..=4 stand in for n1..n4: rebuild the body with keys the test can sign with
    b.members.iter().enumerate().map(|(i, m)| (m.node_id.clone(), i as u8 + 1)).collect()
}

fn signed_body() -> (BodyV3, Vec<(String, u8)>) {
    let mut b = body();
    for (i, m) in b.members.iter_mut().enumerate() {
        m.consensus_key = public_key(i as u8 + 1);
    }
    let keys = members_of(&b);
    (b, keys)
}

fn receipts(ctx: &ReceiptContext, keys: &[(String, u8)]) -> Vec<Receipt> {
    keys.iter()
        .map(|(id, k)| Receipt { node_id: id.clone(), signature: sign(*k, &ctx.message(id)) })
        .collect()
}

#[test]
fn readiness_receipts_need_exactly_one_valid_receipt_from_every_member() {
    let (b, keys) = signed_body();
    let ctx = ReceiptContext::for_body(&b, 3, [0x44; 32]);
    let good = receipts(&ctx, &keys);
    verify_receipts(&b, &ctx, &good).expect("acceptance control");

    let kind = |r: &[Receipt], ctx: &ReceiptContext| {
        verify_receipts(&b, ctx, r).expect_err("refused").kind()
    };
    assert_eq!(kind(&good[..3], &ctx), Kind::ReceiptMissing, "omitted");
    assert_eq!(
        kind(&[good.clone(), vec![good[0].clone()]].concat(), &ctx),
        Kind::ReceiptDuplicate,
        "duplicate"
    );
    let mut unknown = good.clone();
    unknown.push(Receipt { node_id: "zz".into(), signature: sign(9, &ctx.message("zz")) });
    assert_eq!(kind(&unknown, &ctx), Kind::ReceiptUnknown, "unknown signer");
    let mut other_key = good.clone();
    other_key[1].signature = sign(9, &ctx.message("n2"));
    assert_eq!(kind(&other_key, &ctx), Kind::ReceiptSignature, "another key");
    let mut swapped = good.clone();
    swapped[1].signature = good[0].signature.clone();
    assert_eq!(kind(&swapped, &ctx), Kind::ReceiptSignature, "another member's signature");
    let mut high_s_or_short = good.clone();
    high_s_or_short[0].signature.truncate(63);
    assert_eq!(kind(&high_s_or_short, &ctx), Kind::ReceiptSignature, "short signature");

    // a receipt is bound to network, genesis, predecessor, attempt, candidate, body and tuple
    for (name, other) in [
        ("attempt", ReceiptContext::for_body(&b, 4, [0x44; 32])),
        ("candidate", ReceiptContext::for_body(&b, 3, [0x45; 32])),
    ] {
        assert_eq!(
            kind(&good, &other),
            Kind::ReceiptSignature,
            "receipts replayed for another {name}"
        );
    }
    let skew = |f: fn(&mut ReceiptContext)| {
        let mut c = ctx.clone();
        f(&mut c);
        c
    };
    for (name, c) in [
        ("network", skew(|c| c.network = 6)),
        ("genesis", skew(|c| c.genesis[0] ^= 1)),
        ("predecessor", skew(|c| c.predecessor[0] ^= 1)),
        ("body", skew(|c| c.body_id[0] ^= 1)),
        ("tuple", skew(|c| c.config[0] ^= 1)),
    ] {
        assert_eq!(
            kind(&good, &c),
            Kind::ReceiptContext,
            "a context that is not the body's: {name}"
        );
    }
    // the receipts of another body do not carry over even with the same candidate and attempt
    let mut b2 = b.clone();
    b2.earliest_activation += 1;
    assert_eq!(
        verify_receipts(&b2, &ReceiptContext::for_body(&b2, 3, [0x44; 32]), &good)
            .expect_err("another body")
            .kind(),
        Kind::ReceiptSignature
    );
    // an invalid body is refused before any receipt is looked at
    let mut invalid = b.clone();
    invalid.root_threshold = 1;
    assert_eq!(
        verify_receipts(&invalid, &ctx, &good).expect_err("invalid body").kind(),
        Kind::Body
    );
}

/// Hostile input never panics or allocates by its claimed size: random garbage and heavily mutated
/// copies of a valid envelope, a body and a proof all come back as a typed refusal or a value,
/// within bounded work.
#[test]
fn hostile_bytes_are_refused_without_panicking() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let valid = unhex(&vectors().envelope);
    let body = unhex(&vectors().body_encoding);
    for round in 0..4000 {
        let mut e = valid.clone();
        let mut b = body.clone();
        for _ in 0..1 + round % 6 {
            let (i, j) = (next() as usize % e.len(), next() as usize % b.len());
            e[i] = next() as u8;
            b[j] = next() as u8;
        }
        if round % 5 == 0 {
            e.truncate(next() as usize % e.len());
            b.truncate(next() as usize % b.len());
        }
        drop(Envelope::decode(&e));
        drop(BodyV3::decode(&b));
    }
    for _ in 0..2000 {
        let n = next() as usize % 300;
        let junk: Vec<u8> = (0..n).map(|_| next() as u8).collect();
        drop(Envelope::decode(&junk));
        drop(BodyV3::decode(&junk));
        // junk that starts like an array of a hostile length
        let mut head = vec![0x9b];
        head.extend(next().to_be_bytes());
        head.extend(junk);
        drop(Envelope::decode(&head));
    }
}
