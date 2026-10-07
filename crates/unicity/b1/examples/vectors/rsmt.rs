//! Independent radix-tree construction, including every 255/256 junction.
use super::{hash, hex, json, Stream, Value};
#[derive(Clone)]
struct Leaf {
    key: [u8; 32],
    value: Vec<u8>,
}
struct Tree {
    hash: [u8; 32],
    key: [u8; 32],
    depth: usize,
    children: Option<(Box<Self>, Box<Self>)>,
}
const fn bit(k: &[u8; 32], d: usize) -> u8 {
    (k[d / 8] >> (7 - d % 8)) & 1
}
fn prefix(k: &[u8; 32], d: usize) -> [u8; 32] {
    let mut p = [0; 32];
    p[..d / 8].copy_from_slice(&k[..d / 8]);
    if !d.is_multiple_of(8) {
        p[d / 8] = k[d / 8] & (0xff << (8 - d % 8));
    }
    p
}
impl Tree {
    fn build(mut leaves: Vec<Leaf>) -> Self {
        leaves.sort_by_key(|l| l.key);
        Self::sorted(&leaves)
    }
    fn sorted(ls: &[Leaf]) -> Self {
        let first = &ls[0];
        if ls.len() == 1 {
            return Self {
                hash: hash(&[&[0], &first.key, &first.value]),
                key: first.key,
                depth: 0,
                children: None,
            };
        }
        let last = &ls[ls.len() - 1];
        let d = (0..256).find(|d| bit(&first.key, *d) != bit(&last.key, *d)).unwrap();
        let split = ls.partition_point(|l| bit(&l.key, d) == 0);
        let l = Self::sorted(&ls[..split]);
        let r = Self::sorted(&ls[split..]);
        Self {
            hash: hash(&[&[1, d as u8], &prefix(&first.key, d), &l.hash, &r.hash]),
            key: first.key,
            depth: d,
            children: Some((Box::new(l), Box::new(r))),
        }
    }
    fn proof(&self, key: &[u8; 32]) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut bm = [0; 32];
        let mut siblings = Vec::new();
        let mut node = self;
        while let Some((l, r)) = &node.children {
            bm[node.depth / 8] |= 0x80 >> (node.depth % 8);
            let (next, sib) = if bit(key, node.depth) == 0 { (l, r.hash) } else { (r, l.hash) };
            siblings.push(sib);
            node = next;
        }
        assert_eq!(&node.key, key);
        (bm, siblings)
    }
}
fn request(
    root: &[u8; 32],
    key: &[u8; 32],
    value: &[u8],
    bm: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Vec<u8> {
    let mut v = [
        vec![1, 0, 0, 1],
        root.to_vec(),
        key.to_vec(),
        (value.len() as u32).to_be_bytes().to_vec(),
        value.to_vec(),
        bm.to_vec(),
    ]
    .concat();
    for s in siblings {
        v.extend(s);
    }
    v
}
fn emit(out: &mut Vec<Value>, id: &str, request: Vec<u8>, valid: Option<bool>, bm: &[u8; 32]) {
    let expected = match valid {
        Some(valid) => {
            let mut ret = [0; 64];
            ret[31] = 1;
            ret[63] = u8::from(valid);
            let pop: u32 = bm.iter().map(|b| b.count_ones()).sum();
            json!({"status":"ok","valid":valid,"output":hex(&ret),"gas":2000+16*request.len()as u64+250*(1+u64::from(pop))})
        }
        None => json!({"status":"error"}),
    };
    out.push(json!({"id":id,"op":"RSMT_MEMBER_V1","request":hex(&request),"expected":expected}));
}
pub(super) fn generate(out: &mut Vec<Value>) {
    let mut rng = Stream::new("rsmt");
    let k0 = rng.next();
    // Single-leaf cases are emitted by the parent; consume their common key.
    let leaves: Vec<_> = (0..9)
        .map(|i| Leaf { key: rng.next(), value: format!("value-{i}").into_bytes() })
        .collect();
    let tree = Tree::build(leaves.clone());
    let target = &leaves[4];
    let (bm, siblings) = tree.proof(&target.key);
    let good = request(&tree.hash, &target.key, &target.value, &bm, &siblings);
    emit(out, "rsmt.small.ok", good.clone(), Some(true), &bm);
    for i in [0, 4, 8] {
        let l = &leaves[i];
        let (b, s) = tree.proof(&l.key);
        emit(
            out,
            &format!("rsmt.small.leaf{i}.ok"),
            request(&tree.hash, &l.key, &l.value, &b, &s),
            Some(true),
            &b,
        );
    }
    let mut k = target.key;
    k[31] ^= 1;
    emit(
        out,
        "rsmt.neg.key",
        request(&tree.hash, &k, &target.value, &bm, &siblings),
        Some(false),
        &bm,
    );
    emit(
        out,
        "rsmt.neg.value",
        request(&tree.hash, &target.key, b"other", &bm, &siblings),
        Some(false),
        &bm,
    );
    let mut root = tree.hash;
    root[0] ^= 1;
    emit(
        out,
        "rsmt.neg.root",
        request(&root, &target.key, &target.value, &bm, &siblings),
        Some(false),
        &bm,
    );
    emit(
        out,
        "rsmt.neg.zero-root",
        request(&[0; 32], &target.key, &target.value, &bm, &siblings),
        Some(false),
        &bm,
    );
    let mut s = siblings.clone();
    s.swap(0, 1);
    emit(
        out,
        "rsmt.neg.sibling-order",
        request(&tree.hash, &target.key, &target.value, &bm, &s),
        Some(false),
        &bm,
    );
    let mut s = siblings.clone();
    s.last_mut().unwrap()[0] ^= 1;
    emit(
        out,
        "rsmt.neg.sibling-value",
        request(&tree.hash, &target.key, &target.value, &bm, &s),
        Some(false),
        &bm,
    );
    let mut mv = bm;
    let d = (0..256).find(|d| bit(&bm, *d) == 1).unwrap();
    let e = (0..256).rev().find(|d| bit(&bm, *d) == 0).unwrap();
    mv[d / 8] &= !(0x80 >> (d % 8));
    mv[e / 8] |= 0x80 >> (e % 8);
    emit(
        out,
        "rsmt.neg.bitmap-bit",
        request(&tree.hash, &target.key, &target.value, &mv, &siblings),
        Some(false),
        &mv,
    );
    let mut h = hash(&[&[0], &target.key, &target.value]);
    let mut idx = siblings.len();
    for d in (0..256).rev() {
        if bit(&bm, d) == 0 {
            continue;
        }
        idx -= 1;
        let (l, r) = if bit(&target.key, d) == 0 { (h, siblings[idx]) } else { (siblings[idx], h) };
        h = hash(&[&[1, d as u8], &l, &r]);
    }
    emit(
        out,
        "rsmt.neg.no-region",
        request(&h, &target.key, &target.value, &bm, &siblings),
        Some(false),
        &bm,
    );
    for (id, bytes) in [
        ("rsmt.neg.truncated-sibling", good[..good.len() - 32].to_vec()),
        ("rsmt.neg.extra-sibling", [good.clone(), vec![0; 32]].concat()),
        ("rsmt.neg.partial-sibling", good[..good.len() - 1].to_vec()),
        ("rsmt.neg.short-header", good[..3].to_vec()),
        ("rsmt.neg.truncated-value", good[..74].to_vec()),
    ] {
        emit(out, id, bytes, None, &bm);
    }
    for (id, index, value) in
        [("rsmt.neg.version", 0, 2), ("rsmt.neg.flags", 1, 1), ("rsmt.neg.count-2", 3, 2)]
    {
        let mut r = good.clone();
        r[index] = value;
        emit(out, id, r, None, &bm);
    }
    let mut r = good;
    r[68..72].fill(255);
    emit(out, "rsmt.neg.value-length-u32max", r, None, &bm);
    let big = vec![0; 4097];
    let root = hash(&[&[0], &k0, &big]);
    emit(out, "rsmt.neg.value-4097", request(&root, &k0, &big, &[0; 32], &[]), None, &[0; 32]);
    emit(out, "rsmt.neg.too-large", vec![0; 12393], None, &[0; 32]);
    for depth in [255, 256] {
        let tk = rng.next();
        let mut leaves = vec![Leaf { key: tk, value: b"deep".to_vec() }];
        for d in 0..depth {
            let mut other = prefix(&tk, d);
            if bit(&tk, d) == 0 {
                other[d / 8] |= 0x80 >> (d % 8);
            }
            let rest = rng.next();
            for b in d + 1..256 {
                if bit(&rest, b) == 1 {
                    other[b / 8] |= 0x80 >> (b % 8);
                }
            }
            leaves.push(Leaf { key: other, value: vec![d as u8] });
        }
        let t = Tree::build(leaves);
        let (b, s) = t.proof(&tk);
        emit(
            out,
            &format!("rsmt.depth-{depth}.ok"),
            request(&t.hash, &tk, b"deep", &b, &s),
            Some(true),
            &b,
        );
        if depth == 256 {
            let mut s = s;
            s[255][0] ^= 1;
            emit(
                out,
                "rsmt.depth-256.neg.sibling",
                request(&t.hash, &tk, b"deep", &b, &s),
                Some(false),
                &b,
            );
        }
    }
}
