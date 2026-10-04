//! Shared helpers of the conformance suites.
#![allow(dead_code, unreachable_pub, missing_docs, clippy::use_self)]

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn array32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

pub fn testdata(name: &str) -> String {
    std::fs::read_to_string(format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR")))
        .expect("testdata file")
}

/// A minimal CBOR value for the test-side reading and writing of wire bytes (independent of the
/// crate's decoder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    U(u64),
    B(Vec<u8>),
    T(String),
    A(Vec<Val>),
    M(Vec<(Val, Val)>),
    Tag(u64, Box<Val>),
    Null,
}

pub fn dec(raw: &[u8]) -> Val {
    let (v, n) = dec_at(raw, 0);
    assert_eq!(n, raw.len(), "trailing bytes");
    v
}

fn dec_at(raw: &[u8], mut p: usize) -> (Val, usize) {
    let head = raw[p];
    p += 1;
    let (major, info) = (head >> 5, head & 0x1f);
    let arg = |p: &mut usize| -> u64 {
        match info {
            0..=23 => u64::from(info),
            24 => {
                *p += 1;
                u64::from(raw[*p - 1])
            }
            25 => {
                *p += 2;
                u64::from(u16::from_be_bytes(raw[*p - 2..*p].try_into().unwrap()))
            }
            26 => {
                *p += 4;
                u64::from(u32::from_be_bytes(raw[*p - 4..*p].try_into().unwrap()))
            }
            27 => {
                *p += 8;
                u64::from_be_bytes(raw[*p - 8..*p].try_into().unwrap())
            }
            _ => panic!("unsupported head"),
        }
    };
    match major {
        0 => {
            let n = arg(&mut p);
            (Val::U(n), p)
        }
        2 | 3 => {
            let n = arg(&mut p) as usize;
            let s = raw[p..p + n].to_vec();
            (if major == 2 { Val::B(s) } else { Val::T(String::from_utf8(s).unwrap()) }, p + n)
        }
        4 => {
            let n = arg(&mut p);
            let mut v = Vec::new();
            for _ in 0..n {
                let (x, q) = dec_at(raw, p);
                v.push(x);
                p = q;
            }
            (Val::A(v), p)
        }
        5 => {
            let n = arg(&mut p);
            let mut v = Vec::new();
            for _ in 0..n {
                let (k, q) = dec_at(raw, p);
                let (x, q) = dec_at(raw, q);
                v.push((k, x));
                p = q;
            }
            (Val::M(v), p)
        }
        6 => {
            let t = arg(&mut p);
            let (x, q) = dec_at(raw, p);
            (Val::Tag(t, Box::new(x)), q)
        }
        7 if info == 22 => (Val::Null, p),
        _ => panic!("unsupported item {head:#x}"),
    }
}

impl Val {
    pub fn arr(&self) -> &[Val] {
        match self {
            Val::A(a) => a,
            v => panic!("not an array: {v:?}"),
        }
    }
    pub fn uint(&self) -> u64 {
        match self {
            Val::U(n) => *n,
            v => panic!("not a uint: {v:?}"),
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Val::B(b) => b,
            v => panic!("not bytes: {v:?}"),
        }
    }
    pub fn text(&self) -> &str {
        match self {
            Val::T(t) => t,
            v => panic!("not text: {v:?}"),
        }
    }
    pub fn tagged(&self, tag: u64) -> &Val {
        match self {
            Val::Tag(t, v) if *t == tag => v,
            v => panic!("not tag {tag}: {v:?}"),
        }
    }
    pub fn map(&self) -> &[(Val, Val)] {
        match self {
            Val::M(m) => m,
            v => panic!("not a map: {v:?}"),
        }
    }
    pub fn diag(&self, indent: usize) -> String {
        let p = " ".repeat(indent);
        match self {
            Val::U(n) => format!("{p}{n}\n"),
            Val::B(b) => format!("{p}h'{}'\n", hex(&b[..b.len().min(24)])),
            Val::T(t) => format!("{p}{t:?}\n"),
            Val::Null => format!("{p}null\n"),
            Val::A(a) => {
                format!("{p}[\n{}{p}]\n", a.iter().map(|x| x.diag(indent + 2)).collect::<String>())
            }
            Val::M(m) => format!(
                "{p}{{\n{}{p}}}\n",
                m.iter()
                    .map(|(k, v)| format!("{}{}", k.diag(indent + 2), v.diag(indent + 4)))
                    .collect::<String>()
            ),
            Val::Tag(t, v) => format!("{p}tag {t}:\n{}", v.diag(indent + 2)),
        }
    }
}

/// A minimal canonical writer for test-built wire bytes.
#[derive(Default)]
pub struct Enc(pub Vec<u8>);

impl Enc {
    fn head(&mut self, major: u8, n: u64) -> &mut Self {
        let m = major << 5;
        if n < 24 {
            self.0.push(m | n as u8);
        } else if n < 0x100 {
            self.0.extend([m | 24, n as u8]);
        } else if n < 0x1_0000 {
            self.0.push(m | 25);
            self.0.extend((n as u16).to_be_bytes());
        } else if n < 0x1_0000_0000 {
            self.0.push(m | 26);
            self.0.extend((n as u32).to_be_bytes());
        } else {
            self.0.push(m | 27);
            self.0.extend(n.to_be_bytes());
        }
        self
    }
    pub fn array(&mut self, n: usize) -> &mut Self {
        self.head(4, n as u64)
    }
    pub fn uint(&mut self, n: u64) -> &mut Self {
        self.head(0, n)
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }
    pub fn text(&mut self, t: &str) -> &mut Self {
        self.head(3, t.len() as u64);
        self.0.extend_from_slice(t.as_bytes());
        self
    }
    pub fn null(&mut self) -> &mut Self {
        self.0.push(0xf6);
        self
    }
    pub fn tag(&mut self, n: u64) -> &mut Self {
        self.head(6, n)
    }
    pub fn map(&mut self, n: usize) -> &mut Self {
        self.head(5, n as u64)
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
}

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};

/// A deterministic test key: the 32-byte scalar `[n; 32]`.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).expect("a valid scalar")
}

/// The compressed public key of the test key `n`.
pub fn public_key(n: u8) -> Vec<u8> {
    signing_key(n).verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

/// A low-S 64-byte signature of SHA-256(`data`) by the test key `n`.
pub fn sign(n: u8, data: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(data).into();
    let sig: Signature = signing_key(n).sign_prehash(&digest).expect("signs");
    sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// What a test-built genesis trust base varies.
#[derive(Clone)]
pub struct GenesisSpec {
    pub network: u64,
    pub epoch: u64,
    pub start: u64,
    /// (node id, key index, stake)
    pub nodes: Vec<(&'static str, u8, u64)>,
    pub threshold: u64,
    /// ids that sign
    pub signers: Vec<&'static str>,
}

impl Default for GenesisSpec {
    fn default() -> Self {
        Self {
            network: 5,
            epoch: 1,
            start: 0,
            nodes: vec![("a", 1, 1), ("b", 2, 1), ("c", 3, 1), ("d", 4, 1)],
            threshold: 3,
            signers: vec!["a", "b", "c", "d"],
        }
    }
}

impl GenesisSpec {
    fn fields(&self, e: &mut Enc, sigs: Option<&[(&str, Vec<u8>)]>) {
        e.tag(39000)
            .array(10)
            .uint(1)
            .uint(self.network)
            .uint(self.epoch)
            .uint(self.start)
            .array(self.nodes.len());
        for (id, k, stake) in &self.nodes {
            e.array(3).text(id).bytes(&public_key(*k)).uint(*stake);
        }
        e.uint(self.threshold).null().null().null();
        match sigs {
            None => e.null(),
            Some(s) => {
                e.map(s.len());
                for (id, sig) in s {
                    e.text(id).bytes(sig);
                }
                e
            }
        };
    }

    /// The canonical signed encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut unsigned = Enc::default();
        self.fields(&mut unsigned, None);
        let mut sigs: Vec<(&str, Vec<u8>)> = self
            .nodes
            .iter()
            .filter(|(id, _, _)| self.signers.contains(id))
            .map(|(id, k, _)| (*id, sign(*k, &unsigned.0)))
            .collect();
        sigs.sort_by(|a, b| a.0.cmp(b.0)); // canonical map order
        let mut e = Enc::default();
        self.fields(&mut e, Some(&sigs));
        e.0
    }
}
