//! Independent Rust fixture construction. No production parser/encoder or golden
//! bytes are used to construct Cfg, transactions, source states or signatures.
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn head(major: u8, n: u64) -> Vec<u8> {
    let (ai, width) = match n {
        0..=23 => (n as u8, 0),
        24..=255 => (24, 1),
        256..=65535 => (25, 2),
        65536..=4294967295 => (26, 4),
        _ => (27, 8),
    };
    let mut out = vec![(major << 5) | ai];
    out.extend_from_slice(&n.to_be_bytes()[8 - width..]);
    out
}
pub(crate) fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
pub(crate) fn blob(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
pub(crate) fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}
pub(crate) fn tag(t: u64, item: Vec<u8>) -> Vec<u8> {
    [head(6, t), item].concat()
}
pub(crate) fn word(n: usize) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}
pub(crate) fn abi(op: usize, cfg: &[u8], payload: &[u8]) -> Vec<u8> {
    let start = 128 + cfg.len().div_ceil(32) * 32;
    let mut out = [word(op), word(96), word(start), word(cfg.len())].concat();
    out.extend_from_slice(cfg);
    out.resize(start, 0);
    out.extend_from_slice(&word(payload.len()));
    out.extend_from_slice(payload);
    out.resize(out.len().div_ceil(32) * 32, 0);
    out
}
fn key(seed: &str) -> SecretKey {
    for i in 0u8..=255 {
        if let Ok(k) = SecretKey::from_byte_array(&hash(&[seed.as_bytes(), &[i]].concat())) {
            return k;
        }
    }
    panic!("seed has no scalar")
}
fn pk(key: &SecretKey) -> Vec<u8> {
    PublicKey::from_secret_key(SECP256K1, key).serialize().to_vec()
}
pub(crate) fn predicate(code: u8, params: &[u8]) -> Vec<u8> {
    tag(39032, array(&[uint(1), blob(&[code]), blob(params)]))
}
fn cd(key: &SecretKey, state: &[u8; 32], tx: &[u8]) -> Vec<u8> {
    let tx = hash(tx);
    let msg = hash(&array(&[blob(state), blob(&tx)]));
    let (id, sig) =
        SECP256K1.sign_ecdsa_recoverable(&Message::from_digest(msg), key).serialize_compact();
    let unlock = [sig.to_vec(), vec![i32::from(id) as u8]].concat();
    tag(39031, array(&[uint(1), predicate(1, &pk(key)), blob(state), blob(&tx), blob(&unlock)]))
}
fn state(source: &[u8; 32], mask: &[u8]) -> [u8; 32] {
    hash(&array(&[blob(&[&[0, 0][..], source].concat()), blob(mask)]))
}

#[derive(Debug)]
pub(crate) struct Fixture {
    pub(crate) cfg: Vec<u8>,
    pub(crate) ty: [u8; 32],
    pub(crate) aid: [u8; 32],
    pub(crate) vault: Vec<u8>,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let execution = hash(b"fixture-execution-genesis");
        let vault = hash(b"fixture-vault")[..20].to_vec();
        let ty =
            hash(&array(&[blob(b"UNICITY_NATIVE_WHOLE"), uint(3), blob(&execution), blob(&vault)]));
        let aid = hash(&array(&[blob(b"UNICITY_NATIVE_UCT"), uint(3), blob(&execution)]));
        let policy = array(&[
            blob(b"UNICITY_BR_AGG_ONE"),
            uint(11),
            blob(&[0x80]),
            blob(&hash(b"fixture-agg-conf")),
        ]);
        let cfg = array(&[
            blob(b"UNICITY_BR_CFG"),
            uint(3),
            blob(&hash(b"fixture-root-genesis")),
            uint(31337),
            blob(&execution),
            uint(7),
            blob(&[0x80]),
            blob(&vault),
            blob(&[0; 20]),
            blob(&ty),
            blob(&aid),
            blob(&hash(b"fixture-semantic-profile")),
            blob(&hash(b"fixture-verifier")[..20]),
            blob(&hash(b"fixture-verifier-code")),
            blob(&hash(b"fixture-b1-profile")),
            blob(&hash(&policy)),
        ]);
        Self { cfg, ty, aid, vault }
    }
    pub(crate) fn prepare(&self, n: u64, amount: &[u8]) -> Vec<u8> {
        array(&[uint(n), blob(amount), predicate(1, &pk(&key("vh-0")))])
    }
    // ordinary transfers followed by one terminal burn; None builds a mint.
    pub(crate) fn history(&self, n: u64, amount: &[u8], ordinary: Option<usize>) -> Vec<u8> {
        let salt = hash(&array(&[blob(b"UNICITY_BR_SALT"), blob(&hash(&self.cfg)), uint(n)]));
        let id = hash(&array(&[blob(&salt), uint(3)]));
        let minter = SecretKey::from_byte_array(&hash(&array(&[
            blob(b"I_AM_UNIVERSAL_MINTER_FOR_"),
            blob(&id),
        ])))
        .unwrap();
        let h0 = hash(&array(&[blob(&id), blob(&hash(b"TOKENID"))]));
        let mint = tag(
            39041,
            array(&[
                uint(1),
                uint(3),
                predicate(1, &pk(&key("vh-0"))),
                blob(&salt),
                blob(&self.ty),
                blob(&tag(
                    39049,
                    array(&[uint(1), uint(31337), blob(&self.vault), blob(&[0; 20]), uint(n)]),
                )),
                blob(&array(&[blob(&self.aid), blob(amount)])),
            ]),
        );
        let first = array(&[mint.clone(), cd(&minter, &h0, &mint)]);
        let mut pairs = Vec::new();
        let mut st = state(&h0, &id);
        if let Some(count) = ordinary {
            for i in 1..=count + 1 {
                let burn = i == count + 1;
                let owner = key(&format!("vh-{}", i - 1));
                let (pred, data) = if burn {
                    let mut to = [0; 20];
                    to[0] = 0xaa;
                    to[19] = 1;
                    let reason = tag(
                        39048,
                        array(&[
                            uint(1),
                            uint(31337),
                            blob(&self.vault),
                            blob(&[0; 20]),
                            blob(&self.ty),
                            blob(&self.aid),
                            blob(&to),
                            blob(amount),
                            blob(&[0; 20]),
                            blob(&[]),
                            uint(0),
                        ]),
                    );
                    (predicate(2, &hash(&reason)), blob(&reason))
                } else {
                    (predicate(1, &pk(&key(&format!("vh-{i}")))), vec![0xf6])
                };
                let mask = hash(
                    &[b"mask".as_slice(), &salt, &uint(if burn { 1000 } else { i as u64 })]
                        .concat(),
                );
                let tx = tag(39045, array(&[uint(1), pred, blob(&mask), data]));
                pairs.push(array(&[tx.clone(), cd(&owner, &st, &tx)]));
                st = state(&st, &mask);
            }
        }
        array(&[first, array(&pairs)])
    }
}

impl Fixture {
    // Build a full accepted token whose terminal unlock uses the rare ID 2/3.
    // The transfer's source state is independent of the mint recipient. Choose
    // the transfer first, derive Q from its digest and R, then mint to Q.
    fn high_history(&self, recovery: u8, flipped: bool) -> Vec<u8> {
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        let amount = [1];
        let salt = hash(&array(&[blob(b"UNICITY_BR_SALT"), blob(&hash(&self.cfg)), uint(5)]));
        let id = hash(&array(&[blob(&salt), uint(3)]));
        let h0 = hash(&array(&[blob(&id), blob(&hash(b"TOKENID"))]));
        let source = state(&h0, &id);
        let reason = tag(
            39048,
            array(&[
                uint(1),
                uint(31337),
                blob(&self.vault),
                blob(&[0; 20]),
                blob(&self.ty),
                blob(&self.aid),
                blob(&[0xaa; 20]),
                blob(&amount),
                blob(&[0; 20]),
                blob(&[]),
                uint(0),
            ]),
        );
        let tx = tag(
            39045,
            array(&[
                uint(1),
                predicate(2, &hash(&reason)),
                blob(&hash(b"high-recovery-mask")),
                blob(&reason),
            ]),
        );
        let tx_hash = hash(&tx);
        let digest = Message::from_digest(hash(&array(&[blob(&source), blob(&tx_hash)])));
        let (mut unlock, key) = (1u8..=255)
            .find_map(|r| {
                let mut bytes = [0; 65];
                bytes[31] = r;
                bytes[63] = 1;
                bytes[64] = recovery;
                let sig = RecoverableSignature::from_compact(
                    &bytes[..64],
                    RecoveryId::try_from(i32::from(recovery)).unwrap(),
                )
                .unwrap();
                SECP256K1.recover_ecdsa(&digest, &sig).ok().map(|key| (bytes, key))
            })
            .unwrap();
        let recipient = predicate(1, &key.serialize());
        let mint = tag(
            39041,
            array(&[
                uint(1),
                uint(3),
                recipient.clone(),
                blob(&salt),
                blob(&self.ty),
                blob(&tag(
                    39049,
                    array(&[uint(1), uint(31337), blob(&self.vault), blob(&[0; 20]), uint(5)]),
                )),
                blob(&array(&[blob(&self.aid), blob(&amount)])),
            ]),
        );
        let minter = SecretKey::from_byte_array(&hash(&array(&[
            blob(b"I_AM_UNIVERSAL_MINTER_FOR_"),
            blob(&id),
        ])))
        .unwrap();
        if flipped {
            unlock[64] ^= 1;
        }
        let transfer_cd =
            tag(39031, array(&[uint(1), recipient, blob(&source), blob(&tx_hash), blob(&unlock)]));
        array(&[
            array(&[mint.clone(), cd(&minter, &h0, &mint)]),
            array(&[array(&[tx, transfer_cd])]),
        ])
    }
}

/// Independent inputs, evaluated by the native kernel for comparison to Go.
pub(crate) fn vectors() -> Value {
    let f = Fixture::new();
    let mut vectors = Vec::new();
    let mut add = |id: String, op: usize, payload: Vec<u8>| {
        let request = abi(op, &f.cfg, &payload);
        let out = reth_unicity_b2::run(&request, u64::MAX);
        let (output, reason, gas) = match out {
            Ok(o) => (hex(&o.bytes), o.reason.map(|e| e.name()).unwrap_or(""), o.gas),
            Err(
                reth_unicity_b2::Error::Malformed(e) | reth_unicity_b2::Error::BudgetExceeded(e),
            ) => (String::new(), e.name(), 0),
            Err(e) => panic!("unexpected {e:?}"),
        };
        vectors.push(json!({"id":id,"operation":op,"cfg":hex(&f.cfg),"payload":hex(&payload),"request":hex(&request),"output":output,"reason":reason,"gas":gas}));
    };
    for n in [1, 5, u64::MAX] {
        add(format!("prepare-{n}"), 0, f.prepare(n, &[0x3b, 0x9a, 0xca, 7]));
        add(format!("mint-{n}"), 1, f.history(n, &[0x3b, 0x9a, 0xca, 7], None));
        for count in [0, 1, 2, 16, 63] {
            add(
                format!("return-{n}-{count}"),
                2,
                f.history(n, &[0x3b, 0x9a, 0xca, 7], Some(count)),
            );
        }
    }
    for id in [2, 3] {
        add(format!("high-recovery-{id}-match"), 2, f.high_history(id, false));
        add(format!("high-recovery-{id}-flipped"), 2, f.high_history(id, true));
    }
    // Boundary-positive uint256 amounts and a 65-transfer cap violation.
    for amount in [vec![1], vec![0xff; 32]] {
        add(format!("prepare-amount-{}", amount.len()), 0, f.prepare(5, &amount));
        add(format!("return-amount-{}", amount.len()), 2, f.history(5, &amount, Some(0)));
    }
    add("prepare-zero-nonce".into(), 0, f.prepare(0, &[1]));
    add("prepare-zero-amount".into(), 0, f.prepare(1, &[]));
    add("return-no-burn".into(), 2, f.history(5, &[1], None));
    add("mint-transfers".into(), 1, f.history(5, &[1], Some(0)));
    add("return-65-transfers".into(), 2, f.history(5, &[1], Some(64)));
    json!({"oracle":"9136c66146e56e1c5dc02c51e810a8df7f6b4fe4","vectors":vectors})
}
