//! Re-sealing of signed vector certificates: the claim, IR and both Merkle folds are kept, the seal
//! is rebuilt with another epoch and round and signed by caller-owned registry keys. Shared by the
//! batch tests and the batch benchmark; it parses only the definite-length CBOR the vectors use.
#![allow(dead_code)]
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub fn head(major: u8, v: u64) -> Vec<u8> {
    let m = major << 5;
    match v {
        0..=23 => vec![m | v as u8],
        24..=0xff => vec![m | 24, v as u8],
        0x100..=0xffff => [vec![m | 25], (v as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (v as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], v.to_be_bytes().to_vec()].concat(),
    }
}
/// (major, argument, header length).
fn read_head(d: &[u8]) -> (u8, u64, usize) {
    let ai = d[0] & 31;
    let (n, len) = match ai {
        0..=23 => (u64::from(ai), 1),
        24 => (u64::from(d[1]), 2),
        25 => (u64::from(u16::from_be_bytes([d[1], d[2]])), 3),
        26 => (u64::from(u32::from_be_bytes(d[1..5].try_into().unwrap())), 5),
        _ => (u64::from_be_bytes(d[1..9].try_into().unwrap()), 9),
    };
    (d[0] >> 5, n, len)
}
/// Byte length of the first CBOR item of `d`.
pub fn skip(d: &[u8]) -> usize {
    let (m, n, h) = read_head(d);
    match m {
        0 | 1 | 7 => h,
        2 | 3 => h + n as usize,
        4 => (0..n).fold(h, |at, _| at + skip(&d[at..])),
        5 => (0..2 * n).fold(h, |at, _| at + skip(&d[at..])),
        _ => h + skip(&d[h..]),
    }
}
/// The items of the array that starts at `d` (after any tag), as byte ranges of `d`.
fn array_items(d: &[u8], mut at: usize) -> Vec<(usize, usize)> {
    let (m, n, h) = read_head(&d[at..]);
    assert_eq!(m, 4);
    at += h;
    (0..n)
        .map(|_| {
            let len = skip(&d[at..]);
            let r = (at, at + len);
            at += len;
            r
        })
        .collect()
}

pub struct Signer {
    pub id: String,
    pub secret: SecretKey,
}
impl Signer {
    pub fn new(id: &str, seed: u64) -> Self {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_be_bytes());
        s[31] = 1;
        let secret = SecretKey::from_slice(&Sha256::digest(s)).unwrap();
        Self { id: id.to_owned(), secret }
    }
    pub fn public(&self) -> [u8; 33] {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.secret).serialize()
    }
}

/// A claim re-sealed under `epoch` and `round`, signed by `signers` (sorted by id). `tamper`
/// receives the signatures to damage them after signing.
pub fn reseal(
    base: &[u8],
    epoch: u64,
    round: u64,
    signers: &[&Signer],
    tamper: impl FnOnce(&mut Vec<[u8; 64]>),
) -> Vec<u8> {
    let sl = u16::from_be_bytes([base[4], base[5]]) as usize;
    let prefix_len = 6 + sl + 96;
    let uc_len = u32::from_be_bytes(base[prefix_len..prefix_len + 4].try_into().unwrap()) as usize;
    let uc = &base[prefix_len + 4..prefix_len + 4 + uc_len];
    assert_eq!(prefix_len + 4 + uc_len, base.len());
    // uc = tag(39001) array[7]: version, ir, tr, conf, shard cert, tree cert, seal.
    let (_, _, tag_head) = read_head(uc);
    let items = array_items(uc, 0 + tag_head);
    let (seal_at, seal_end) = items[6];
    assert_eq!(seal_end, uc.len());
    let seal = &uc[seal_at..seal_end];
    let (_, _, seal_tag) = read_head(seal);
    let f = array_items(seal, seal_tag);
    let raw = |i: usize| &seal[f[i].0..f[i].1];
    let build = |sigs: &[u8]| {
        let mut s = seal[..seal_tag].to_vec();
        s.extend(head(4, 8));
        s.extend(raw(0));
        s.extend(raw(1));
        s.extend(head(0, round));
        s.extend(head(0, epoch));
        s.extend(raw(4));
        s.extend(raw(5));
        s.extend(raw(6));
        s.extend(sigs);
        s
    };
    let digest = Sha256::digest(build(&[0xf6]));
    let secp = Secp256k1::new();
    let mut sorted: Vec<&&Signer> = signers.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut sigs: Vec<[u8; 64]> = sorted
        .iter()
        .map(|s| {
            secp.sign_ecdsa(&Message::from_digest(digest.into()), &s.secret).serialize_compact()
        })
        .collect();
    tamper(&mut sigs);
    let mut map = head(5, sigs.len() as u64);
    for (s, sig) in sorted.iter().zip(&sigs) {
        map.extend(head(3, s.id.len() as u64));
        map.extend(s.id.as_bytes());
        map.extend(head(2, 64));
        map.extend(sig);
    }
    let new_seal = build(&map);
    let mut new_uc = uc[..seal_at].to_vec();
    new_uc.extend(&new_seal);
    let mut out = base[..prefix_len].to_vec();
    out.extend((new_uc.len() as u32).to_be_bytes());
    out.extend(new_uc);
    out
}
