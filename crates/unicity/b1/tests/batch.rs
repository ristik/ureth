//! `CERT_BATCH_V2`: scan, canonical grouping, metering, epoch/seal/claim reuse and the registry
//! failure classes, over the signed certificates of the pinned Go vectors re-framed as version 2.
use alloy_primitives::U256;
use reth_unicity_b1::{
    batch::{self, Counters},
    entry_slot, fixed_slot, member_slot, Error, Malformed, Pins, RegistryRead,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[path = "support/uc.rs"]
mod uc;

const PINS: Pins = Pins {
    genesis_commitment: U256::from_limbs([1, 0, 0, 0]),
    profile_hash: U256::from_limbs([2, 0, 0, 0]),
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(id: &str) -> Value {
    let m: Value = serde_json::from_str(include_str!("testdata/go-b3reprice.json")).unwrap();
    m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap().clone()
}
/// The packed claims of a version 1 request.
fn claims(id: &str) -> Vec<Vec<u8>> {
    let req = hex(fixture(id)["request"].as_str().unwrap());
    let k = u16::from_be_bytes([req[2], req[3]]) as usize;
    let mut at = 4;
    let mut out = vec![];
    for _ in 0..k {
        let sl = u16::from_be_bytes([req[at + 4], req[at + 5]]) as usize;
        let head = at + 6 + sl + 96;
        let ul = u32::from_be_bytes(req[head..head + 4].try_into().unwrap()) as usize;
        out.push(req[at..head + 4 + ul].to_vec());
        at = head + 4 + ul;
    }
    assert_eq!(at, req.len());
    out
}
fn request(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![2, 0];
    v.extend((parts.len() as u16).to_be_bytes());
    for p in parts {
        v.extend(p);
    }
    v
}

#[derive(Clone, Default)]
struct State {
    words: BTreeMap<U256, U256>,
    reads: u64,
}
impl RegistryRead for State {
    type Error = ();
    fn sload(&mut self, key: U256) -> Result<U256, ()> {
        self.reads += 1;
        Ok(*self.words.get(&key).unwrap_or(&U256::ZERO))
    }
}
struct Member<'a> {
    id: &'a str,
    key: Vec<u8>,
    weight: u64,
}
fn members(id: &str) -> Vec<Member<'static>> {
    let v = fixture(id);
    v["preState"]["epochs"][0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| Member {
            id: Box::leak(m["nodeID"].as_str().unwrap().to_owned().into_boxed_str()),
            key: hex(m["key"].as_str().unwrap()),
            weight: m["weight"].as_u64().unwrap(),
        })
        .collect()
}
fn put_epoch(s: &mut State, epoch: u64, start: u64, end: u64, ms: &[Member<'_>]) {
    let total: u64 = ms.iter().map(|m| m.weight).sum();
    let fields = [1, 2, 0xb0d1, 3, start, end, u64::from(end != 0), 1, 4, ms.len() as u64, total];
    for (f, w) in fields.into_iter().enumerate() {
        s.words.insert(entry_slot(epoch, f as u64), U256::from(w));
    }
    for (j, m) in ms.iter().enumerate() {
        let mut words = [[0u8; 32]; 8];
        words[0] = U256::from(m.id.len()).to_be_bytes::<32>();
        for (i, b) in m.id.bytes().enumerate() {
            words[1 + i / 32][i % 32] = b;
        }
        words[5].copy_from_slice(&m.key[..32]);
        words[6][0] = m.key[32];
        words[7] = U256::from(m.weight).to_be_bytes::<32>();
        for (f, w) in words.into_iter().enumerate() {
            s.words.insert(member_slot(epoch, j as u64, f as u64), U256::from_be_bytes(w));
        }
    }
}
/// A ready registry: epochs `g..=u` imported, `u` open and usable, root round 1000.
fn registry(g: u64, u: u64, ms: &[Member<'_>]) -> State {
    let mut s = State::default();
    for (n, v) in [
        ("genesisCommitment", 1),
        ("phase", 2),
        ("b1.initialized", 1),
        ("b1.network", 3),
        ("b1.profileHash", 2),
        ("b1.format", 2),
        ("b1.genesisEpoch", g),
        ("b1.importedTipEpoch", u),
        ("b1.originReady", 1),
        ("clock.rootRound", 1000),
        ("origin.rootEpoch", u),
    ] {
        s.words.insert(fixed_slot(n), U256::from(v));
    }
    for e in g..=u {
        put_epoch(&mut s, e, 900 + e - g, if e == u { 0 } else { 900 + e - g + 1 }, ms);
    }
    s
}
fn go(parts: &[Vec<u8>], st: &mut State) -> (Result<batch::Output, Error<()>>, Counters) {
    let mut c = Counters::default();
    let r = batch::run(&request(parts), u64::MAX, &PINS, st, Some(&mut c));
    (r, c)
}
fn ok(parts: &[Vec<u8>], st: &mut State) -> (batch::Output, Counters) {
    let (r, c) = go(parts, st);
    (r.unwrap(), c)
}
fn verdict(o: &batch::Output) -> bool {
    assert_eq!(&o.bytes[..31], &[0u8; 31]);
    assert_eq!(o.bytes[31], 2);
    assert_eq!(&o.bytes[32..63], &[0u8; 31]);
    o.bytes[63] == 1
}
/// The state the signed vectors were made for: epoch 7, start 900, root round 1000.
fn base() -> State {
    registry(7, 7, &members("cert.single.ok"))
}

#[test]
fn a_single_claim_and_a_shared_batch_verify_with_the_exact_counters() {
    let one = claims("cert.single.ok");
    let (out, c) = ok(&one, &mut base());
    assert!(verdict(&out));
    let d = batch::dimensions(&request(&one)).unwrap();
    assert_eq!((d.k, d.e, d.s, d.a, d.q), (1, 1, 1, 1, 3));
    assert_eq!(out.gas, d.gas());
    assert_eq!(
        c,
        Counters {
            epoch_loads: 1,
            key_parses: 4,
            quorums: 1,
            signatures: 3,
            claims: 1,
            folds: 1,
            reads: 11 + 11 + 32
        }
    );

    let shared = claims("cert.shared.ok");
    assert_eq!(shared.len(), 4);
    let (out, c) = ok(&shared, &mut base());
    assert!(verdict(&out));
    let d = batch::dimensions(&request(&shared)).unwrap();
    assert_eq!((d.k, d.e, d.s, d.a, d.q), (4, 1, 1, 4, 3));
    assert_eq!(out.gas, d.gas());
    assert_eq!((c.epoch_loads, c.quorums, c.signatures, c.claims, c.folds), (1, 1, 3, 4, 4));
}

#[test]
fn the_charge_is_the_contract_formula() {
    let shared = claims("cert.shared.ok");
    let req = request(&shared);
    let d = batch::dimensions(&req).unwrap();
    let expected = 60_000 + 16 * d.c + 500 * d.k * (d.k - 1) // scan and grouping
        + 100 * 11 // common words
        + (16_000 + 100 * (11 + 8 * 16)) * d.e
        + 6_000 * d.q
        + 2_000 * d.a
        + 250 * d.p;
    assert_eq!(d.gas(), expected);
    assert_eq!(batch::scan_gas(d.c, d.k), 60_000 + 16 * d.c + 500 * d.k * (d.k - 1));
    // One epoch at the member ceiling is 29,900.
    assert_eq!(16_000 + 100 * (11 + 8 * 16), 29_900);
}

#[test]
fn order_and_exact_repeats_do_not_change_the_verdict_and_repeats_pay_only_bytes_and_grouping() {
    let shared = claims("cert.shared.ok");
    let mut reversed = shared.clone();
    reversed.reverse();
    let (a, _) = ok(&shared, &mut base());
    let (b, _) = ok(&reversed, &mut base());
    assert_eq!((verdict(&a), a.gas), (true, b.gas));
    assert!(verdict(&b));

    let one = claims("cert.single.ok");
    let twice = [one[0].clone(), one[0].clone()];
    let d1 = batch::dimensions(&request(&one)).unwrap();
    let d2 = batch::dimensions(&request(&twice)).unwrap();
    assert_eq!((d2.k, d2.a, d2.s, d2.e, d2.q, d2.p), (2, 1, 1, 1, d1.q, d1.p));
    let (out, c) = ok(&twice, &mut base());
    assert!(verdict(&out));
    assert_eq!(out.gas - d1.gas(), 16 * (d2.c - d1.c) + 500 * 2);
    assert_eq!((c.claims, c.folds, c.signatures, c.epoch_loads), (1, 1, 3, 1));
}

#[test]
fn distinct_seals_of_one_epoch_share_the_epoch_charge_but_not_the_quorum() {
    let a = claims("cert.single.ok");
    let b = claims("cert.repeat-ir.ok");
    let parts = [a[0].clone(), b[0].clone()];
    let d = batch::dimensions(&request(&parts)).unwrap();
    assert_eq!((d.k, d.e, d.s, d.a, d.q), (2, 1, 2, 2, 6));
    let (out, c) = ok(&parts, &mut base());
    assert!(verdict(&out));
    assert_eq!((c.epoch_loads, c.quorums, c.signatures), (1, 2, 6));
}

#[test]
fn a_claim_for_an_unusable_epoch_is_false_at_the_full_charge_without_loading_it() {
    let one = claims("cert.single.ok");
    // Usable range [5,5]: the claim declares epoch 7 > U.
    let mut s = registry(5, 5, &members("cert.single.ok"));
    let (out, c) = ok(&one, &mut s);
    assert!(!verdict(&out));
    assert_eq!(out.gas, batch::dimensions(&request(&one)).unwrap().gas());
    assert_eq!((c.epoch_loads, c.signatures, s.reads), (0, 0, 11));
    // Usable range [8,8]: the claim declares epoch 7 < g.
    let mut s = registry(8, 8, &members("cert.single.ok"));
    let (out, c) = ok(&one, &mut s);
    assert!(!verdict(&out));
    assert_eq!((c.epoch_loads, c.signatures), (0, 0));
}

#[test]
fn seal_interval_and_origin_round_gates_are_semantic() {
    let one = claims("cert.single.ok");
    // Seal round is 990. Closed before it: epoch 7 ends at 980 (and is not the tip).
    let ms = members("cert.single.ok");
    let mut s = registry(7, 8, &ms);
    put_epoch(&mut s, 7, 900, 980, &ms);
    assert!(!verdict(&ok(&one, &mut s).0));
    // The same epoch, ending after the round, verifies.
    put_epoch(&mut s, 7, 900, 995, &ms);
    assert!(verdict(&ok(&one, &mut s).0));
    // Round above the origin round.
    let mut s = base();
    s.words.insert(fixed_slot("clock.rootRound"), U256::from(985));
    assert!(!verdict(&ok(&one, &mut s).0));
    // Round before the epoch start (start 991 > 990).
    let mut s = base();
    put_epoch(&mut s, 7, 991, 0, &ms);
    assert!(!verdict(&ok(&one, &mut s).0));
    // Wrong network.
    let mut s = base();
    s.words.insert(fixed_slot("b1.network"), U256::from(4));
    assert!(!verdict(&ok(&one, &mut s).0));
}

#[test]
fn phase_one_and_not_ready_are_false_after_only_the_common_reads() {
    let one = claims("cert.single.ok");
    let mut s = base();
    s.words.insert(fixed_slot("phase"), U256::from(1));
    let (out, c) = ok(&one, &mut s);
    assert!(!verdict(&out));
    assert_eq!((c.epoch_loads, s.reads), (0, 11));
    let mut s = base();
    s.words.insert(fixed_slot("b1.originReady"), U256::ZERO);
    s.words.insert(fixed_slot("clock.rootRound"), U256::ZERO);
    s.words.insert(fixed_slot("origin.rootEpoch"), U256::ZERO);
    let (out, _) = ok(&one, &mut s);
    assert!(!verdict(&out));
    assert_eq!(s.reads, 11);
}

#[test]
fn a_bad_signature_or_an_unknown_extra_signer_fails_without_cutting_the_loop_short() {
    let one = claims("cert.single.ok");
    // Flip a bit of the first signature (all three still get verified).
    let mut bad = one[0].clone();
    let at = bad.windows(6).position(|w| w == b"node00").unwrap() + 6 + 2;
    bad[at] ^= 1;
    let (out, c) = ok(&[bad], &mut base());
    assert!(!verdict(&out));
    assert_eq!(c.signatures, 3);

    // node02 renamed node09 (still sorted last): unknown signer, though node00+node01 hold 20 of
    // 21 and the quorum is 15. The seal must fail, not pass on a quorum of the known ones.
    let mut ms = members("cert.single.ok");
    ms.truncate(3);
    ms[0].weight = 10;
    ms[1].weight = 10;
    ms[2].weight = 1;
    let mut s = registry(7, 7, &ms);
    // Baseline: the three real signers hold all 21 of 21.
    assert!(verdict(&ok(&[one[0].clone()], &mut s).0));
    let mut renamed = one[0].clone();
    let p = renamed.windows(6).rposition(|w| w == b"node02").unwrap();
    renamed[p + 5] = b'9';
    let (out, _) = ok(&[renamed], &mut registry(7, 7, &ms));
    assert!(!verdict(&out));
}

#[test]
fn structural_failures_halt_before_any_state_is_read() {
    let one = claims("cert.single.ok");
    let good = request(&one);
    let mut s = base();
    let mut run = |req: &[u8], gas: u64| {
        let mut c = Counters::default();
        let r = batch::run(req, gas, &PINS, &mut s, Some(&mut c));
        (r, c)
    };
    for (mutate, want) in [
        (&|r: &mut Vec<u8>| r[0] = 1, Malformed::Version),
        (&|r: &mut Vec<u8>| r[1] = 1, Malformed::Flags),
        (&|r: &mut Vec<u8>| r[3] = 0, Malformed::Count),
        (&|r: &mut Vec<u8>| r[3] = 17, Malformed::Count),
        (&|r: &mut Vec<u8>| r.push(0), Malformed::Trailing),
        (&|r: &mut Vec<u8>| r.truncate(r.len() - 1), Malformed::Truncated),
    ] as [(&dyn Fn(&mut Vec<u8>), Malformed); 6]
    {
        let mut r = good.clone();
        mutate(&mut r);
        let (res, c) = run(&r, u64::MAX);
        assert_eq!(res, Err(Error::Malformed(want)));
        assert_eq!(c, Counters::default());
    }
    let (res, _) = run(&vec![0; batch::MAX_BYTES + 1], u64::MAX);
    assert_eq!(res, Err(Error::Malformed(Malformed::Limit)));
    // Gas: exactly the charge passes, one less is out of gas, and neither reads before the debit.
    let gas = batch::dimensions(&good).unwrap().gas();
    assert!(run(&good, gas).0.is_ok());
    let mut fresh = base();
    let mut c = Counters::default();
    assert_eq!(batch::run(&good, gas - 1, &PINS, &mut fresh, Some(&mut c)), Err(Error::OutOfGas));
    assert_eq!((fresh.reads, c), (0, Counters::default()));
    assert_eq!(batch::run(&good, 59_999, &PINS, &mut fresh, None), Err(Error::OutOfGas));
    assert_eq!(fresh.reads, 0);
}

#[test]
fn impossible_registry_state_is_an_infrastructure_error_never_a_verdict() {
    let one = claims("cert.single.ok");
    let ms = members("cert.single.ok");
    let cases: Vec<(&str, State)> = {
        let mut v = vec![];
        let mut s = base();
        s.words.insert(fixed_slot("genesisCommitment"), U256::from(9));
        v.push(("wrong genesis pin", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.profileHash"), U256::from(9));
        v.push(("wrong profile pin", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.format"), U256::from(1));
        v.push(("format", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.network"), U256::ZERO);
        v.push(("zero network", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.importedTipEpoch"), U256::from(8));
        v.push(("tip above the usable epoch while ready", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.originReady"), U256::from(2));
        v.push(("ready not a boolean", s));
        let mut s = base();
        s.words.insert(fixed_slot("b1.genesisEpoch"), U256::from(8));
        v.push(("genesis above tip", s));
        let mut s = base();
        s.words.insert(fixed_slot("clock.rootRound"), U256::MAX);
        v.push(("wide word", s));
        let mut s = base();
        put_epoch(&mut s, 7, 900, 1000, &ms);
        v.push(("closed usable tip", s));
        let mut s = base();
        put_epoch(&mut s, 7, 1001, 0, &ms);
        v.push(("start after the origin round", s));
        let mut s = base();
        s.words.insert(entry_slot(7, 0), U256::ZERO);
        v.push(("requested epoch missing", s));
        let mut s = base();
        s.words.insert(entry_slot(7, 9), U256::from(17));
        v.push(("more than sixteen members", s));
        let mut s = base();
        s.words.insert(entry_slot(7, 7), U256::from(3));
        v.push(("scheme 3", s));
        v
    };
    for (name, mut s) in cases {
        assert_eq!(go(&one, &mut s).0, Err(Error::Registry), "{name}");
    }
    // An old epoch left open is impossible too, but only a requested one is loaded: corruption
    // of an unrequested epoch is not read.
    let mut s = registry(6, 7, &ms);
    s.words.insert(entry_slot(6, 0), U256::ZERO);
    assert!(verdict(&ok(&one, &mut s).0));
    // A host failure propagates.
    struct Down;
    impl RegistryRead for Down {
        type Error = &'static str;
        fn sload(&mut self, _: U256) -> Result<U256, &'static str> {
            Err("down")
        }
    }
    assert_eq!(
        batch::run(&request(&one), u64::MAX, &PINS, &mut Down, None),
        Err(Error::Host("down"))
    );
}

#[test]
fn a_mixed_batch_checks_the_required_entries_for_corruption_before_any_false() {
    let a = claims("cert.single.ok");
    let ms = members("cert.single.ok");
    // Epoch 7 is requested and usable; the unusable-epoch claim is false, but a corrupt
    // requested entry still surfaces as the infrastructure error.
    let mut s = registry(7, 7, &ms);
    s.words.insert(member_slot(7, 0, 7), U256::ZERO);
    assert_eq!(go(&a, &mut s).0, Err(Error::Registry));
}

/// Registry epochs `g..=u` of `n` members each (ids `mNN`, keys of `uc::Signer`), epoch `e` live
/// from `900 + 10*(e-g)`, the last open, root round `round`.
fn own_registry(g: u64, u: u64, signers: &[uc::Signer], round: u64) -> State {
    let ms: Vec<Member<'_>> = signers
        .iter()
        .map(|s| Member {
            id: Box::leak(s.id.clone().into_boxed_str()),
            key: s.public().to_vec(),
            weight: 1,
        })
        .collect();
    let mut st = registry(g, u, &ms[..1]);
    for e in g..=u {
        let start = 900 + 10 * (e - g);
        put_epoch(&mut st, e, start, if e == u { 0 } else { start + 10 }, &ms);
    }
    st.words.insert(fixed_slot("clock.rootRound"), U256::from(round));
    st
}
fn signers(n: usize) -> Vec<uc::Signer> {
    (0..n).map(|i| uc::Signer::new(&format!("m{i:02}"), i as u64 + 1)).collect()
}

#[test]
fn certificates_of_many_epochs_verify_in_one_call_with_one_load_per_epoch() {
    let base = claims("cert.single.ok").remove(0);
    let sg = signers(4);
    let all: Vec<&uc::Signer> = sg.iter().collect();
    // Epochs 5, 6 and 7 (7 open): rounds 905, 915 and 985.
    let parts: Vec<Vec<u8>> = [(5, 905), (6, 915), (7, 985)]
        .iter()
        .map(|&(e, r)| uc::reseal(&base, e, r, &all, |_| {}))
        .collect();
    let d = batch::dimensions(&request(&parts)).unwrap();
    assert_eq!((d.k, d.e, d.s, d.a, d.q), (3, 3, 3, 3, 12));
    let mut st = own_registry(5, 7, &sg, 1000);
    let (out, c) = ok(&parts, &mut st);
    assert!(verdict(&out));
    assert_eq!(out.gas, d.gas());
    assert_eq!((c.epoch_loads, c.key_parses, c.quorums, c.signatures, c.claims), (3, 12, 3, 12, 3));
    // The order of the occurrences changes nothing.
    let mut shuffled = parts.clone();
    shuffled.swap(0, 2);
    let (again, _) = ok(&shuffled, &mut own_registry(5, 7, &sg, 1000));
    assert_eq!((verdict(&again), again.gas), (true, out.gas));
    // An epoch below genesis among them: false, still the full charge, the required entries read.
    let mut st = own_registry(6, 7, &sg, 1000);
    let (out2, c2) = ok(&parts, &mut st);
    assert!(!verdict(&out2));
    assert_eq!(out2.gas, out.gas);
    assert_eq!(c2.epoch_loads, 2);
    // A missing installed epoch inside [g,U] that a claim names is an infrastructure error.
    let mut st = own_registry(5, 7, &sg, 1000);
    st.words.insert(entry_slot(6, 0), U256::ZERO);
    assert_eq!(go(&parts, &mut st).0, Err(Error::Registry));
}

#[test]
fn a_seal_outside_its_epochs_interval_or_with_a_short_quorum_is_false_at_the_same_charge() {
    let base = claims("cert.single.ok").remove(0);
    let sg = signers(4);
    let all: Vec<&uc::Signer> = sg.iter().collect();
    let good = uc::reseal(&base, 5, 905, &all, |_| {});
    let (ok_out, _) = ok(std::slice::from_ref(&good), &mut own_registry(5, 6, &sg, 1000));
    assert!(verdict(&ok_out));
    // Round 912 is past epoch 5's end (910).
    let late = uc::reseal(&base, 5, 912, &all, |_| {});
    let (o, _) = ok(&[late], &mut own_registry(5, 6, &sg, 1000));
    assert!(!verdict(&o));
    // Two of four signers: below the quorum of three.
    let two = uc::reseal(&base, 5, 905, &all[..2], |_| {});
    let (o, c) = ok(&[two], &mut own_registry(5, 6, &sg, 1000));
    assert!(!verdict(&o));
    assert_eq!(c.signatures, 2);
    // One damaged signature among four valid ones: the seal fails though three would be a quorum.
    let bad = uc::reseal(&base, 5, 905, &all, |s| s[3][10] ^= 1);
    let (o, c) = ok(&[bad], &mut own_registry(5, 6, &sg, 1000));
    assert!(!verdict(&o));
    assert_eq!(c.signatures, 4);
}
