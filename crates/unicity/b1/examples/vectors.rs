//! Independent Rust construction. No oracle/manifest input is read here.
//! Run with `cargo run -p reth-unicity-b1 --example vectors`.
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[path = "vectors/rsmt.rs"]
mod rsmt;

const SEED: &str = "b1-oracle-v1";
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn head(m: u8, n: u64) -> Vec<u8> {
    let (ai, bytes) = if n < 24 {
        return vec![(m << 5) | n as u8];
    } else if n <= 255 {
        (24, 1)
    } else if n <= 65535 {
        (25, 2)
    } else if n <= u64::from(u32::MAX) {
        (26, 4)
    } else {
        (27, 8)
    };
    let mut v = vec![(m << 5) | ai];
    v.extend_from_slice(&n.to_be_bytes()[8 - bytes..]);
    v
}
fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
fn blob(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
fn text(b: &str) -> Vec<u8> {
    [head(3, b.len() as u64), b.as_bytes().to_vec()].concat()
}
fn array(v: &[Vec<u8>]) -> Vec<u8> {
    [head(4, v.len() as u64), v.concat()].concat()
}
fn tagged(tag: u64, v: &[Vec<u8>]) -> Vec<u8> {
    [head(6, tag), array(v)].concat()
}
struct Stream {
    key: [u8; 32],
    counter: u64,
}
impl Stream {
    fn new(label: &str) -> Self {
        Self::seeded(SEED, label)
    }
    fn seeded(seed: &str, label: &str) -> Self {
        Self { key: hash(&[format!("b1gen/v1|{seed}|{label}").as_bytes()]), counter: 0 }
    }
    fn next(&mut self) -> [u8; 32] {
        let h = hash(&[&self.key, &self.counter.to_be_bytes()]);
        self.counter += 1;
        h
    }
}
fn secret(id: &str) -> SecretKey {
    secret_seeded(SEED, id)
}
fn secret_seeded(seed: &str, id: &str) -> SecretKey {
    SecretKey::from_byte_array(&hash(&[format!("b1gen/v1|{seed}|key|{id}").as_bytes()])).unwrap()
}
fn bits(s: &str) -> Vec<u8> {
    let mut v = vec![0; s.len() / 8 + 1];
    for (i, b) in s.bytes().enumerate() {
        if b == b'1' {
            v[i / 8] |= 0x80 >> (i % 8);
        }
    }
    v[s.len() / 8] |= 0x80 >> (s.len() % 8);
    v
}
fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    hash(&[&blob(l), &blob(r)])
}
#[derive(Clone)]
struct Seal {
    seed: String,
    round: u64,
    epoch: u64,
    network: u64,
    timestamp: u64,
    prev: [u8; 32],
    root: [u8; 32],
    signers: Vec<String>,
    suffix: Option<u8>,
}
impl Seal {
    fn fields(&self, sigs: Vec<u8>) -> Vec<u8> {
        tagged(
            39005,
            &[
                uint(1),
                uint(self.network),
                uint(self.round),
                uint(self.epoch),
                uint(self.timestamp),
                blob(&self.prev),
                blob(&self.root),
                sigs,
            ],
        )
    }
    fn preimage(&self) -> Vec<u8> {
        self.fields(vec![0xf6])
    }
    fn wire(&self) -> Vec<u8> {
        let digest = hash(&[&self.preimage()]);
        let secp = Secp256k1::new();
        let mut sigs = BTreeMap::new();
        for id in &self.signers {
            let sig = secp.sign_ecdsa_recoverable(
                &Message::from_digest(digest),
                &secret_seeded(&self.seed, id),
            );
            let (rec, sig) = sig.serialize_compact();
            let mut sig = sig.to_vec();
            if let Some(v) = self.suffix {
                sig.push(if v == 255 { i32::from(rec) as u8 } else { v });
            }
            sigs.insert(text(id), blob(&sig));
        }
        let mut map = head(5, sigs.len() as u64);
        for (k, v) in sigs {
            map.extend(k);
            map.extend(v);
        }
        self.fields(map)
    }
}
#[derive(Clone)]
struct Uc {
    part: u32,
    shard: String,
    ir: Vec<u8>,
    state: [u8; 32],
    tr: [u8; 32],
    conf: [u8; 32],
    siblings: Vec<[u8; 32]>,
    steps: Vec<(u32, [u8; 32])>,
    seal: Seal,
}
impl Uc {
    fn leaf(&self) -> [u8; 32] {
        hash(&[&self.ir, &blob(&self.tr), &blob(&self.conf)])
    }
    fn wire(&self) -> Vec<u8> {
        tagged(
            39001,
            &[
                uint(1),
                self.ir.clone(),
                blob(&self.tr),
                blob(&self.conf),
                tagged(
                    39003,
                    &[
                        uint(1),
                        blob(&bits(&self.shard)),
                        array(&self.siblings.iter().map(|s| blob(s)).collect::<Vec<_>>()),
                    ],
                ),
                tagged(
                    39004,
                    &[
                        uint(1),
                        uint(u64::from(self.part)),
                        array(
                            &self
                                .steps
                                .iter()
                                .map(|(k, h)| array(&[uint(u64::from(*k)), blob(h)]))
                                .collect::<Vec<_>>(),
                        ),
                    ],
                ),
                self.seal.wire(),
            ],
        )
    }
    fn claim(&self) -> Vec<u8> {
        let sh = bits(&self.shard);
        let uc = self.wire();
        [
            self.part.to_be_bytes().to_vec(),
            (sh.len() as u16).to_be_bytes().to_vec(),
            sh,
            self.conf.to_vec(),
            self.state.to_vec(),
            hash(&[&self.ir]).to_vec(),
            (uc.len() as u32).to_be_bytes().to_vec(),
            uc,
        ]
        .concat()
    }
}
#[derive(Clone)]
struct Imt {
    hash: [u8; 32],
    key: u32,
    left: Option<Box<Self>>,
    right: Option<Box<Self>>,
}
impl Imt {
    fn build(leaves: &[(u32, [u8; 32])]) -> Self {
        if leaves.len() == 1 {
            let (k, d) = leaves[0];
            return Self {
                hash: hash(&[&blob(&[1]), &blob(&k.to_be_bytes()), &blob(&d)]),
                key: k,
                left: None,
                right: None,
            };
        }
        let split = leaves.len().div_ceil(2);
        let l = Self::build(&leaves[..split]);
        let r = Self::build(&leaves[split..]);
        let k = leaves[split - 1].0;
        Self {
            hash: hash(&[&blob(&[0]), &blob(&k.to_be_bytes()), &blob(&l.hash), &blob(&r.hash)]),
            key: k,
            left: Some(Box::new(l)),
            right: Some(Box::new(r)),
        }
    }
    fn path(&self, key: u32) -> Vec<(u32, [u8; 32])> {
        let (Some(l), Some(r)) = (&self.left, &self.right) else {
            return vec![];
        };
        let (mut p, sib) =
            if key > self.key { (r.path(key), l.hash) } else { (l.path(key), r.hash) };
        p.push((self.key, sib));
        p
    }
}
fn build(variant: &str, round: u64, signers: Vec<String>) -> BTreeMap<(u32, String), Uc> {
    build_seeded(SEED, variant, round, signers)
}
fn build_seeded(
    seed: &str,
    variant: &str,
    round: u64,
    signers: Vec<String>,
) -> BTreeMap<(u32, String), Uc> {
    let mut ucs = BTreeMap::new();
    let mut leaves = Vec::new();
    for part in 1..=7 {
        let shards = if part == 2 { vec!["0", "1"] } else { vec![""] };
        let mut roots = Vec::new();
        for sh in shards {
            let mut rng = Stream::seeded(seed, &format!("ir/{variant}/{part}/{sh}"));
            let prev = rng.next();
            let state = rng.next();
            let summary = rng.next();
            let block = rng.next();
            let et = rng.next();
            let ir = tagged(
                39002,
                &[
                    uint(1),
                    uint(5),
                    uint(1),
                    blob(&prev),
                    blob(&state),
                    blob(&summary[..8]),
                    uint(1681972084),
                    blob(&block),
                    uint(12),
                    blob(&et),
                ],
            );
            let tr = rng.next();
            let conf = rng.next();
            let uc = Uc {
                part,
                shard: sh.into(),
                ir,
                state,
                tr,
                conf,
                siblings: vec![],
                steps: vec![],
                seal: Seal {
                    seed: seed.to_owned(),
                    round,
                    epoch: 7,
                    network: 3,
                    timestamp: 1681971084 + 5000 + round,
                    prev: Stream::seeded(seed, &format!("prev/{variant}")).next(),
                    root: [0; 32],
                    signers: signers.clone(),
                    suffix: None,
                },
            };
            roots.push(uc.leaf());
            ucs.insert((part, sh.into()), uc);
        }
        let root = if part == 2 {
            ucs.get_mut(&(part, "0".into())).unwrap().siblings = vec![roots[1]];
            ucs.get_mut(&(part, "1".into())).unwrap().siblings = vec![roots[0]];
            node(&roots[0], &roots[1])
        } else {
            roots[0]
        };
        leaves.push((part, hash(&[&blob(&root)])));
    }
    let imt = Imt::build(&leaves);
    for uc in ucs.values_mut() {
        uc.steps = imt.path(uc.part);
        uc.seal.root = imt.hash;
    }
    ucs
}
fn request(ucs: &[Uc]) -> Vec<u8> {
    let mut r = vec![1, 0, 0, ucs.len() as u8];
    for u in ucs {
        r.extend(u.claim());
    }
    r
}
fn prestate(weights: &[u64]) -> Value {
    prestate_seeded(SEED, weights)
}
fn prestate_seeded(seed: &str, weights: &[u64]) -> Value {
    let secp = Secp256k1::new();
    let members:Vec<_>=weights.iter().enumerate().map(|(i,w)|{let id=format!("node{i:02}");json!({"nodeID":id,"key":hex(&PublicKey::from_secret_key(&secp,&secret_seeded(seed,&id)).serialize()),"weight":w})}).collect();
    json!({"network":3,"wCert":50,"origin":7,"clockRound":1000,"epochs":[{"epoch":7,"members":members,"bodyID":hex(&Stream::seeded(seed,"body").next()),"start":900,"end":0}]})
}
fn add(out: &mut Vec<Value>, id: &str, ucs: &[Uc], valid: bool, weights: &[u64]) {
    let req = request(ucs);
    let sigs = ucs.iter().map(|u| u.seal.signers.len()).max().unwrap();
    let steps: usize = ucs.iter().map(|u| u.siblings.len() + u.steps.len()).sum();
    let gas =
        60000 + 16 * req.len() + 64000 + 6000 * sigs + 2000 * ucs.len() + 250 * steps + 1117700;
    let mut ret = [0; 64];
    ret[31] = 1;
    ret[63] = u8::from(valid);
    let preimage = ucs[0].seal.preimage();
    out.push(json!({"id":id,"op":if ucs.len()==1{"UC_V1"}else{"SHARED_SEAL_V1"},"preState":prestate(weights),"request":hex(&req),"sealSigBytes":hex(&preimage),"sealDigest":hex(&hash(&[&preimage])),"expected":{"status":"ok","valid":valid,"output":hex(&ret),"gas":gas}}));
}
/// Construct from explicit records and deterministic scalars, without reading
/// either implementation's manifests or invoking the verification kernel.
pub(crate) fn generate() -> Value {
    let mut out = Vec::new();
    let q: Vec<_> = (0..3).map(|i| format!("node{i:02}")).collect();
    let cs = build("a", 990, q.clone());
    let one = cs[&(1, String::new())].clone();
    let sh = cs[&(2, "1".into())].clone();
    add(&mut out, "cert.single.ok", std::slice::from_ref(&one), true, &[1; 4]);
    add(
        &mut out,
        "cert.shared.ok",
        &[one.clone(), cs[&(2, "0".into())].clone(), sh.clone(), cs[&(3, String::new())].clone()],
        true,
        &[1; 4],
    );
    add(&mut out, "cert.uc.shard.ok", &[sh], true, &[1; 4]);
    add(
        &mut out,
        "cert.repeat-ir.ok",
        &[build("a", 993, q.clone())[&(1, String::new())].clone()],
        true,
        &[1; 4],
    );
    add(&mut out, "cert.subset-a.ok", std::slice::from_ref(&one), true, &[1; 4]);
    add(
        &mut out,
        "cert.subset-b.ok",
        &[build("a", 990, (1..4).map(|i| format!("node{i:02}")).collect())[&(1, String::new())]
            .clone()],
        true,
        &[1; 4],
    );
    for (id, weights) in [
        ("weighted.below", [4, 2, 2, 2]),
        ("weighted.at", [4, 3, 2, 1]),
        ("weighted.above", [4, 4, 1, 1]),
    ] {
        add(
            &mut out,
            id,
            &[build("a", 990, q[..2].to_vec())[&(1, String::new())].clone()],
            id != "weighted.below",
            &weights,
        );
    }
    let k = Stream::new("rsmt").next();
    for (id, value) in [
        ("rsmt.single-leaf.ok", b"only".to_vec()),
        ("rsmt.empty-value.ok", vec![]),
        ("rsmt.value-4096.ok", vec![0xab; 4096]),
    ] {
        let root = hash(&[&[0], &k, &value]);
        let req = [
            vec![1, 0, 0, 1],
            root.to_vec(),
            k.to_vec(),
            (value.len() as u32).to_be_bytes().to_vec(),
            value,
            vec![0; 32],
        ]
        .concat();
        let mut ret = [0; 64];
        ret[31] = 1;
        ret[63] = 1;
        out.push(json!({"id":id,"op":"RSMT_MEMBER_V1","request":hex(&req),"expected":{"status":"ok","valid":true,"output":hex(&ret),"gas":2000+16*req.len()+250}}));
    }
    supplemental(&mut out);
    rsmt::generate(&mut out);
    json!({"seed":SEED,"construction":"independent Rust CBOR, trees and RFC6979 signatures","vectors":out})
}

fn replaced(raw: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let positions: Vec<_> =
        raw.windows(old.len()).enumerate().filter(|(_, w)| *w == old).map(|(i, _)| i).collect();
    assert_eq!(positions.len(), 1);
    let i = positions[0];
    [raw[..i].to_vec(), new.to_vec(), raw[i + old.len()..].to_vec()].concat()
}
fn raw_claim(u: &Uc, uc: Vec<u8>) -> Vec<u8> {
    let sh = bits(&u.shard);
    [
        u.part.to_be_bytes().to_vec(),
        (sh.len() as u16).to_be_bytes().to_vec(),
        sh,
        u.conf.to_vec(),
        u.state.to_vec(),
        hash(&[&u.ir]).to_vec(),
        (uc.len() as u32).to_be_bytes().to_vec(),
        uc,
    ]
    .concat()
}
fn raw_request(claims: &[Vec<u8>]) -> Vec<u8> {
    [vec![1, 0, 0, claims.len() as u8], claims.concat()].concat()
}
#[expect(clippy::too_many_arguments, reason = "explicit vector operation and gas counters")]
fn emit(
    out: &mut Vec<Value>,
    id: &str,
    req: Vec<u8>,
    valid: Option<bool>,
    sigs: usize,
    n: usize,
    paths: usize,
    op: &str,
) {
    let expected = match valid {
        Some(valid) => {
            let mut ret = [0; 64];
            ret[31] = 1;
            ret[63] = u8::from(valid);
            json!({"status":"ok","valid":valid,"output":hex(&ret),"gas":60000+16*req.len()+64000+6000*sigs+2000*n+250*paths+1117700})
        }
        None => json!({"status":"error"}),
    };
    out.push(json!({"id":id,"op":op,"preState":prestate(&[1;4]),"request":hex(&req),"expected":expected}));
}
fn sign(id: &str, msg: &[u8]) -> Vec<u8> {
    Secp256k1::new()
        .sign_ecdsa(&Message::from_digest(hash(&[msg])), &secret(id))
        .serialize_compact()
        .to_vec()
}
fn sigmap(entries: &[(String, Vec<u8>)], sort: bool) -> Vec<u8> {
    let mut e: Vec<_> = entries.iter().map(|(id, sig)| (text(id), blob(sig))).collect();
    if sort {
        e.sort_by(|a, b| a.0.cmp(&b.0));
    }
    let mut map = head(5, e.len() as u64);
    for (k, v) in e {
        map.extend(k);
        map.extend(v);
    }
    map
}
fn custom(depth: usize, path_count: usize) -> Uc {
    let sh = "1".repeat(depth);
    let mut rng = Stream::new(&format!("custom/9/{sh}/{depth}/{path_count}"));
    let prev = rng.next();
    let state = rng.next();
    let summary = rng.next();
    let block = rng.next();
    let ir = tagged(
        39002,
        &[
            uint(1),
            uint(5),
            uint(1),
            blob(&prev),
            blob(&state),
            blob(&summary[..8]),
            uint(1681972084),
            blob(&block),
            uint(3),
            vec![0xf6],
        ],
    );
    let tr = rng.next();
    let conf = rng.next();
    let mut r = Stream::new("sibs");
    let siblings: Vec<_> = (0..depth).map(|_| r.next()).collect();
    let mut r = Stream::new("steps");
    let steps: Vec<_> = (0..path_count).map(|i| (10 + i as u32 * 7, r.next())).collect();
    let prev = rng.next();
    let mut h = hash(&[&ir, &blob(&tr), &blob(&conf)]);
    for sib in &siblings {
        h = node(sib, &h);
    }
    let data = hash(&[&blob(&h)]);
    h = hash(&[&blob(&[1]), &blob(&9u32.to_be_bytes()), &blob(&data)]);
    for (k, sib) in &steps {
        h = hash(&[&blob(&[0]), &blob(&k.to_be_bytes()), &blob(&h), &blob(sib)]);
    }
    Uc {
        part: 9,
        shard: sh,
        ir,
        state,
        tr,
        conf,
        siblings,
        steps,
        seal: Seal {
            seed: SEED.to_owned(),
            round: 990,
            epoch: 7,
            network: 3,
            timestamp: 1681977084,
            prev,
            root: h,
            signers: (0..3).map(|i| format!("node{i:02}")).collect(),
            suffix: None,
        },
    }
}
fn native_validity(out: &mut Vec<Value>) {
    // Rebuild the leaf/root and signatures for each invalid native object so
    // validity cannot be accidentally enforced by a stale hash or signature.
    for (name, summary, timestamp, previous_same, block_present, round) in [
        ("rust.native-null-summary", false, 1681972084, false, true, 990),
        ("rust.native-zero-ir-time", true, 0, false, true, 990),
        ("rust.native-unchanged-with-block", true, 1681972084, true, true, 990),
        ("rust.native-changed-without-block", true, 1681972084, false, false, 990),
        ("rust.native-zero-seal-round", true, 1681972084, false, true, 0),
    ] {
        let mut u = custom(0, 0);
        u.ir = tagged(
            39002,
            &[
                uint(1),
                uint(5),
                uint(1),
                blob(if previous_same { &u.state } else { &[0x42; 32] }),
                blob(&u.state),
                if summary { blob(&[1; 8]) } else { vec![0xf6] },
                uint(timestamp),
                if block_present { blob(&[2; 32]) } else { vec![0xf6] },
                uint(3),
                vec![0xf6],
            ],
        );
        let data = hash(&[&blob(&u.leaf())]);
        u.seal.root = hash(&[&blob(&[1]), &blob(&u.part.to_be_bytes()), &blob(&data)]);
        u.seal.round = round;
        add(out, name, &[u], false, &[1; 4]);
        if round == 0 {
            let state = &mut out.last_mut().unwrap()["preState"];
            state["clockRound"] = json!(0);
            state["epochs"][0]["start"] = json!(0);
        }
    }
}

fn supplemental(out: &mut Vec<Value>) {
    native_validity(out);
    for (id, n) in [("quorum.max.exact", 43), ("quorum.max.short", 42), ("quorum.max.all", 64)] {
        let seed = format!("{SEED}/64");
        let uc = build_seeded(&seed, "a", 990, (0..n).map(|i| format!("node{i:02}")).collect())
            [&(1, String::new())]
            .clone();
        add(out, id, &[uc], n >= 43, &[1; 64]);
        out.last_mut().unwrap()["preState"] = prestate_seeded(&seed, &[1; 64]);
    }
    let q: Vec<_> = (0..3).map(|i| format!("node{i:02}")).collect();
    let cs = build("a", 990, q.clone());
    let u = cs[&(1, String::new())].clone();
    let all: Vec<_> = cs.values().cloned().collect();
    add(out, "cert.shared.max-8.ok", &all, true, &[1; 4]);
    add(out, "cert.shared.order", &[all[1].clone(), all[0].clone()], false, &[1; 4]);
    add(out, "cert.shared.order-shard", &[all[2].clone(), all[1].clone()], false, &[1; 4]);
    add(out, "cert.shared.duplicate", &[u.clone(), u.clone()], false, &[1; 4]);
    add(
        out,
        "quorum.short",
        &[build("a", 990, q[..2].to_vec())[&(1, String::new())].clone()],
        false,
        &[1; 4],
    );
    for (d, p, id) in [
        (255, 0, "paths.shard-depth-255.ok"),
        (256, 0, "paths.shard-depth-256.ok"),
        (0, 32, "paths.unicity-steps-32.ok"),
    ] {
        add(out, id, &[custom(d, p)], true, &[1; 4]);
    }
    let mut with_v = u.clone();
    with_v.seal.suffix = Some(255);
    add(out, "quorum.sig.v-present", &[with_v], true, &[1; 4]);
    let mut x = u.clone();
    x.seal.network = 4;
    add(out, "cert.neg.network", &[x], false, &[1; 4]);
    let mut x = u.clone();
    x.seal.epoch = 6;
    add(out, "cert.neg.epoch", &[x], false, &[1; 4]);
    let mut x = u.clone();
    x.tr[0] ^= 1;
    add(out, "cert.neg.trhash", &[x], false, &[1; 4]);
    let mut root = u.seal.root;
    root[0] ^= 1;
    let seal = replaced(&u.seal.wire(), &blob(&u.seal.root), &blob(&root));
    emit(
        out,
        "cert.neg.root",
        raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
        Some(false),
        3,
        1,
        u.steps.len(),
        "UC_V1",
    );
    let mut x = u.clone();
    x.seal.timestamp = 1681971083;
    add(out, "cert.neg.seal-timestamp", &[x], false, &[1; 4]);
    // Caller-only claim mutations leave the native object unchanged.
    for (id, offset) in [
        ("cert.neg.partition", 3),
        ("cert.neg.config", 7),
        ("cert.neg.expected-state", 39),
        ("cert.neg.expected-ir", 71),
    ] {
        let mut claim = u.claim();
        claim[offset] ^= 1;
        // partition 1 -> 2, rather than the generic bit flip to zero.
        if id == "cert.neg.partition" {
            claim[3] = 2;
        }
        emit(out, id, raw_request(&[claim]), Some(false), 3, 1, u.steps.len(), "UC_V1");
    }
    let mut entries: Vec<_> =
        q.iter().map(|id| (id.clone(), sign(id, &u.seal.preimage()))).collect();
    let original = entries.clone();
    for (id, len) in [
        ("frozen.signature-length-0", 0),
        ("frozen.signature-length-63", 63),
        ("frozen.signature-length-66", 66),
    ] {
        entries = original.clone();
        entries[0].1 = vec![0; len];
        let seal = u.seal.fields(sigmap(&entries, true));
        let uc = replaced(&u.wire(), &u.seal.wire(), &seal);
        emit(out, id, raw_request(&[raw_claim(&u, uc)]), None, 0, 1, 0, "UC_V1");
    }
    for (id, suffix) in [("quorum.sig.v2", 2), ("quorum.sig.v255", 255)] {
        entries = original.clone();
        entries[0].1.push(suffix);
        let seal = u.seal.fields(sigmap(&entries, true));
        emit(
            out,
            id,
            raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
            None,
            0,
            1,
            0,
            "UC_V1",
        );
    }
    for (id, zero_start) in [("quorum.sig.r-zero", 0), ("quorum.sig.s-zero", 32)] {
        entries = original.clone();
        entries[0].1[zero_start..zero_start + 32].fill(0);
        let seal = u.seal.fields(sigmap(&entries, true));
        emit(
            out,
            id,
            raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
            Some(false),
            3,
            1,
            u.steps.len(),
            "UC_V1",
        );
    }
    entries = original.clone();
    entries.push(("mallory".into(), sign("mallory", &u.seal.preimage())));
    let seal = u.seal.fields(sigmap(&entries, true));
    emit(
        out,
        "quorum.unknown-signer",
        raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
        Some(false),
        4,
        1,
        u.steps.len(),
        "UC_V1",
    );
    entries = original.clone();
    entries.push(("node03".into(), sign("node03", b"not the seal")));
    let seal = u.seal.fields(sigmap(&entries, true));
    emit(
        out,
        "quorum.bad-extra",
        raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
        Some(false),
        4,
        1,
        u.steps.len(),
        "UC_V1",
    );
    for (id, map) in [("seal.sigs-null", vec![0xf6]), ("seal.sigs-empty", vec![0xa0])] {
        let seal = u.seal.fields(map);
        emit(
            out,
            id,
            raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
            Some(false),
            0,
            1,
            u.steps.len(),
            "UC_V1",
        );
    }
    entries = vec![original[0].clone(), original[1].clone(), original[1].clone()];
    let seal = u.seal.fields(sigmap(&entries, false));
    emit(
        out,
        "quorum.dup-map-key",
        raw_request(&[raw_claim(&u, replaced(&u.wire(), &u.seal.wire(), &seal))]),
        None,
        0,
        1,
        0,
        "UC_V1",
    );
    let mut false_first = u.claim();
    false_first[39] ^= 1;
    let last = raw_claim(&cs[&(3, String::new())], vec![0xf6]);
    emit(
        out,
        "frozen.malformed-last",
        raw_request(&[false_first.clone(), last.clone()]),
        None,
        0,
        2,
        0,
        "SHARED_SEAL_V1",
    );
    emit(
        out,
        "frozen.unsorted-malformed-last",
        raw_request(&[cs[&(2, "0".into())].claim(), false_first, last]),
        None,
        0,
        3,
        0,
        "SHARED_SEAL_V1",
    );
    // Native null positions and zero-step collection representations.
    let simple = custom(0, 0);
    for (id, old, new) in [
        (
            "frozen.null-shard",
            tagged(39003, &[uint(1), blob(&bits("")), array(&[])]),
            tagged(39003, &[uint(1), blob(&bits("")), vec![0xf6]]),
        ),
        (
            "frozen.null-unicity",
            tagged(39004, &[uint(1), uint(9), array(&[])]),
            tagged(39004, &[uint(1), uint(9), vec![0xf6]]),
        ),
    ] {
        emit(
            out,
            id,
            raw_request(&[raw_claim(&simple, replaced(&simple.wire(), &old, &new))]),
            Some(true),
            3,
            1,
            0,
            "UC_V1",
        );
    }
    // The full required-object null table, constructed without the Go output.
    for (tag, old) in [
        ("uc", u.wire()),
        ("ir", u.ir.clone()),
        ("seal", u.seal.wire()),
        ("shard", tagged(39003, &[uint(1), blob(&bits("")), array(&[])])),
        (
            "unicity",
            tagged(
                39004,
                &[
                    uint(1),
                    uint(1),
                    array(
                        &u.steps
                            .iter()
                            .map(|(k, h)| array(&[uint(u64::from(*k)), blob(h)]))
                            .collect::<Vec<_>>(),
                    ),
                ],
            ),
        ),
    ] {
        let uc = if tag == "uc" { vec![0xf6] } else { replaced(&u.wire(), &old, &[0xf6]) };
        emit(
            out,
            &format!("rust.null-required-{tag}"),
            raw_request(&[raw_claim(&u, uc)]),
            None,
            0,
            1,
            0,
            "UC_V1",
        );
    }
}
fn main() {
    println!("{}", serde_json::to_string_pretty(&generate()).unwrap());
}
