use super::*;
use cbor::{array as a, bytes as b, tag, uint as u};
use k256::ecdsa::SigningKey;

fn pred(k: &SigningKey) -> Vec<u8> {
    tag(39032, &a(&[&u(1), &b(&[1]), &b(k.verifying_key().to_encoded_point(true).as_bytes())]))
}
fn ha(parts: &[&[u8]]) -> [u8; 32] {
    hash(&a(parts))
}
fn config() -> Vec<u8> {
    let d = format!("1:{}:{}:1337:{}", "11".repeat(32), "22".repeat(32), "00".repeat(20));
    let ty = hash(format!("unicity-bridge:unicity-native:{d}").as_bytes());
    let aid = hash(format!("unicity-bridge-coin:unicity-native:{d}").as_bytes());
    a(&[
        &b(b"UNICITY_BR_CFG"),
        &u(1),
        &b(&[0x11; 32]),
        &u(1337),
        &b(&[0x22; 32]),
        &u(7),
        &b(&[0x80]),
        &b(&[0x33; 20]),
        &b(&[0; 20]),
        &b(&ty),
        &b(&aid),
        &b(&[0x44; 32]),
        &b(&[0x55; 20]),
        &b(&[0x66; 32]),
        &b(&[0x77; 32]),
        &b(&[0x88; 32]),
    ])
}
fn fields(data: &[u8]) -> Vec<Vec<u8>> {
    let it = cbor::one(data, &mut 0).unwrap();
    let it = if it.major == 6 { cbor::one(it.data, &mut 0).unwrap() } else { it };
    it.children().map(|v| v.raw.to_vec()).collect()
}
fn field(data: &[u8], n: usize) -> Vec<u8> {
    fields(data)[n].clone()
}
fn blob(data: &[u8]) -> &[u8] {
    cbor::one(data, &mut 0).unwrap().data
}
fn rebuild(data: &[u8], parts: &[Vec<u8>]) -> Vec<u8> {
    let it = cbor::one(data, &mut 0).unwrap();
    let refs: Vec<_> = parts.iter().map(Vec::as_slice).collect();
    if it.major == 6 {
        tag(it.arg, &a(&refs))
    } else {
        a(&refs)
    }
}
fn edit(data: &[u8], path: &[usize], value: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return value.to_vec();
    }
    let mut f = fields(data);
    f[path[0]] = edit(&f[path[0]], &path[1..], value);
    rebuild(data, &f)
}
fn cd(k: &SigningKey, owner: &[u8], source: &[u8], tx: &[u8], e: &[u8]) -> Vec<u8> {
    let th = hash(tx);
    let msg = ha(&[&b(source), &b(&th)]);
    let (sig, rid) = k.sign_prehash_recoverable(&msg).unwrap();
    let mut sig = sig.to_bytes().to_vec();
    sig.push(rid.to_byte());
    tag(39031, &a(&[&u(2), owner, &b(source), &b(&th), e, &b(&sig)]))
}
fn state(source: &[u8], mask: &[u8]) -> [u8; 32] {
    let mut imprint = vec![0, 0];
    imprint.extend_from_slice(source);
    ha(&[&b(&imprint), &b(mask)])
}
struct Fixture {
    cfg: Vec<u8>,
    history: Vec<u8>,
    p0: Vec<u8>,
    id: [u8; 32],
    owner: SigningKey,
}
impl Fixture {
    fn new(transfers: usize, e: Option<u64>, t: u64) -> Self {
        let cfg = config();
        let owner = SigningKey::from_slice(&[9; 32]).unwrap();
        let p0 = pred(&owner);
        let salt = ha(&[&b(b"UNICITY_BR_SALT"), &b(&hash(&cfg)), &u(1)]);
        let id = ha(&[&b(&salt), &u(1)]);
        let lock = a(&[
            &u(1),
            &b(&hash(&cfg)),
            &b(&[0x99; 32]),
            &b(&[0x80]),
            &b(&[0x80]),
            &b(&[0xc0]),
            &a(&[&b(&[0xc0])]),
            &a(&[&b(&[0xc0])]),
        ]);
        let j = tag(39049, &a(&[&u(2), &u(1337), &b(&[0x33; 20]), &b(&[0; 20]), &u(1), &lock]));
        let data = tag(39050, &a(&[&u(1), &a(&[&a(&[&field(&cfg, 10), &b(&[7])])]), &[0xf6]]));
        let e = e.map_or_else(|| vec![0xf6], u);
        let mint =
            tag(39041, &a(&[&u(2), &u(1), &p0, &b(&salt), &field(&cfg, 9), &b(&j), &b(&data), &e]));
        let reason = tag(
            39048,
            &a(&[
                &u(1),
                &u(1337),
                &b(&[0x33; 20]),
                &b(&[0; 20]),
                &field(&cfg, 9),
                &field(&cfg, 10),
                &b(&[0xaa; 20]),
                &b(&[7]),
                &b(&[0; 20]),
                &b(&[]),
                &u(0),
            ]),
        );
        let burn = tag(39032, &a(&[&u(1), &b(&[2]), &b(&hash(&reason))]));
        let mut steps = Vec::new();
        for i in 0..transfers {
            let last = i + 1 == transfers;
            let data = if last { b(&reason) } else { vec![0xf6] };
            let tx = tag(
                39045,
                &a(&[&u(2), if last { &burn } else { &p0 }, &b(&[i as u8; 32]), &data, &e]),
            );
            steps.push(a(&[&tx, &[0xf6], &u(t)]));
        }
        let refs: Vec<_> = steps.iter().map(Vec::as_slice).collect();
        let history = a(&[&a(&[&mint, &[0xf6], &u(t)]), &a(&refs)]);
        let mut f = Self { cfg, history, p0, id, owner };
        f.resign();
        f
    }
    fn resign(&mut self) {
        let mut h = fields(&self.history);
        let mut genesis = fields(&h[0]);
        let secret = ha(&[&b(b"I_AM_UNIVERSAL_MINTER_FOR_"), &b(&self.id)]);
        let minter = SigningKey::from_slice(&secret).unwrap();
        let source = ha(&[&b(&self.id), &b(&hash(b"TOKENID"))]);
        genesis[1] = cd(&minter, &pred(&minter), &source, &genesis[0], &field(&genesis[0], 7));
        let mut owner = field(&genesis[0], 2);
        let mut source = state(&source, &self.id);
        let mut steps = fields(&h[1]);
        for step in &mut steps {
            let mut tuple = fields(step);
            let tx = tuple[0].clone();
            tuple[1] = cd(&self.owner, &owner, &source, &tx, &field(&tx, 4));
            owner = field(&tx, 1);
            source = state(&source, blob(&field(&tx, 2)));
            *step = rebuild(step, &tuple);
        }
        h[0] = rebuild(&h[0], &genesis);
        h[1] = rebuild(&h[1], &steps);
        self.history = rebuild(&self.history, &h);
    }
    fn mutate_tx(&mut self, path: &[usize], value: &[u8]) {
        self.history = edit(&self.history, path, value);
        self.resign();
    }
    fn mutate_reason(&mut self, index: usize, value: &[u8]) {
        let data = field(&field(&field(&self.history, 1), 0), 0);
        let r = blob(&field(&data, 3)).to_vec();
        let r = edit(&r, &[index], value);
        let burn = tag(39032, &a(&[&u(1), &b(&[2]), &b(&hash(&r))]));
        self.history = edit(&self.history, &[1, 0, 0, 1], &burn);
        self.mutate_tx(&[1, 0, 0, 3], &b(&r));
    }
    fn request(&self, op: u64) -> Vec<u8> {
        request(op, &self.cfg, &self.history)
    }
}
fn request(op: u64, cfg: &[u8], payload: &[u8]) -> Vec<u8> {
    fn enc(b: &[u8]) -> Vec<u8> {
        let mut out = abi::word(b.len() as u64).to_vec();
        out.extend_from_slice(b);
        out.resize(out.len().div_ceil(32) * 32, 0);
        out
    }
    let c = enc(cfg);
    let p = enc(payload);
    [abi::word(op).as_slice(), &abi::word(96), &abi::word((96 + c.len()) as u64), &c, &p].concat()
}
fn rejection(f: &Fixture, op: u64, expected: E) {
    let out = run(&f.request(op), u64::MAX);
    if expected.is_invalid() {
        let out = out.unwrap();
        assert_eq!(out.invalid, Some(expected));
        assert_eq!(out.bytes, abi::encode(false, &Outcome::default()));
        let valid_charge = 26000 +
            20 * f.request(op).len() as u64 +
            14000 * if op == 0 { 0 } else { 1 + fields(&field(&f.history, 1)).len() as u64 };
        assert_eq!(out.gas, valid_charge);
    } else {
        assert_eq!(out, Err(expected));
    }
}
use Error as E;

#[test]
fn signed_sdk3_histories_and_exact_abi() {
    for count in [0, 1, 16, 64] {
        for e in [None, Some(101)] {
            let f = Fixture::new(count, e, 100);
            let input = f.request(if count == 0 { 1 } else { 2 });
            let out = run(&input, u64::MAX).unwrap();
            assert_eq!(out.invalid, None);
            assert_eq!(out.bytes.len(), 448 + 128 * (count + 1));
            assert_eq!(&out.bytes[..23], b"UNICITY_TOKEN_SEMANTICS");
            assert_eq!(out.bytes[63], 1);
            assert_eq!(&out.bytes[64..96], &abi::word(96));
            assert_eq!(&out.bytes[96..128], &hash(&f.cfg));
            assert_eq!(&out.bytes[128..160], &abi::word(1));
            assert_eq!(&out.bytes[160..192], &abi::word(7));
            assert_eq!(&out.bytes[192..224], &f.id);
            assert_eq!(&out.bytes[384..416], &abi::word(320));
            assert_eq!(&out.bytes[416..448], &abi::word((count + 1) as u64));
            assert_eq!(&out.bytes[512..544], &abi::word(100));
            let th = hash(&field(&field(&f.history, 0), 0));
            assert_eq!(&out.bytes[480..512], &th);
            assert_eq!(&out.bytes[544..576], &ha(&[&b(&th), &u(100)]));
            assert_ne!(&out.bytes[544..576], &th);
            assert_eq!(run(&input, out.gas), Ok(out));
            assert_eq!(run(&input, 26000 + 20 * input.len() as u64 - 1), Err(E::OutOfGas));
            let charge = 26000 + 20 * input.len() as u64 + 14000 * (count + 1) as u64;
            assert_eq!(run(&input, charge - 1), Err(E::OutOfGas));
        }
    }
}
#[test]
fn prepare_matches_mint_and_zero_release_fields() {
    let f = Fixture::new(0, None, 100);
    let p = a(&[&u(1), &b(&[7]), &f.p0]);
    let out = run(&request(0, &f.cfg, &p), u64::MAX).unwrap();
    let mint = run(&f.request(1), u64::MAX).unwrap();
    assert_eq!(out.invalid, None);
    assert_eq!(out.bytes.len(), 448);
    assert_eq!(&out.bytes[96..320], &mint.bytes[96..320]);
    assert_eq!(&out.bytes[320..384], &[0; 64]);
    assert_eq!(&out.bytes[416..448], &[0; 32]);
    assert_eq!(out.gas, 26000 + 20 * request(0, &f.cfg, &p).len() as u64);
}
macro_rules! negative {
    ($name:ident, $count:expr, $error:ident, |$f:ident| $body:block) => {
        #[test] fn $name() {
            let mut $f=Fixture::new($count,None,100); $body
            rejection(&$f,if $count==0 {1} else {2},E::$error);
        }
    };
}
negative!(cfg_type_recomputed, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[9], &b(&[1; 32]));
});
negative!(cfg_coin_recomputed, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[10], &b(&[1; 32]));
});
negative!(cfg_domain, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[0], &b(b"wrong"));
});
negative!(cfg_nonzero_vault, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[7], &b(&[0; 20]));
});
negative!(cfg_native_asset, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[8], &b(&[1; 20]));
});
negative!(cfg_empty_shard, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[6], &b(&[]));
});
negative!(cfg_zero_terminated_shard, 0, CfgMismatch, |f| {
    f.cfg = edit(&f.cfg, &[6], &b(&[0]));
});
negative!(mint_network, 0, MintShape, |f| {
    f.mutate_tx(&[0, 0, 1], &u(2));
});
negative!(mint_type, 0, MintType, |f| {
    f.mutate_tx(&[0, 0, 4], &b(&[1; 32]));
});
negative!(mint_salt, 0, MintSalt, |f| {
    f.mutate_tx(&[0, 0, 3], &b(&[1; 32]));
});
negative!(mint_cd_owner, 0, CDMismatch, |f| {
    f.history = edit(&f.history, &[0, 1, 1], &f.p0);
});
negative!(mint_cd_source, 0, CDMismatch, |f| {
    f.history = edit(&f.history, &[0, 1, 2], &b(&[1; 32]));
});
negative!(mint_cd_hash, 0, CDMismatch, |f| {
    f.history = edit(&f.history, &[0, 1, 3], &b(&[1; 32]));
});
negative!(mint_cd_deadline, 0, DeadlineMismatch, |f| {
    f.history = edit(&f.history, &[0, 1, 4], &u(101));
});
negative!(mint_old_version, 0, Version, |f| {
    f.mutate_tx(&[0, 0, 0], &u(1));
});
negative!(mint_deadline_zero, 0, Deadline, |f| {
    f.mutate_tx(&[0, 0, 7], &u(0));
});
negative!(mint_missing_justification, 0, MintJustif, |f| {
    f.mutate_tx(&[0, 0, 5], &[0xf6]);
});
negative!(mint_missing_data, 0, MintData, |f| {
    f.mutate_tx(&[0, 0, 6], &[0xf6]);
});
negative!(unlock_short, 0, UnlockLength, |f| {
    f.history = edit(&f.history, &[0, 1, 5], &b(&[1; 64]));
});
negative!(unlock_zero_r_s, 0, UnlockScalars, |f| {
    f.history = edit(&f.history, &[0, 1, 5], &b(&[0; 65]));
});
negative!(unlock_id_four, 0, UnlockRecovery, |f| {
    let mut sig = blob(&field(&field(&field(&f.history, 0), 1), 5)).to_vec();
    sig[64] = 4;
    f.history = edit(&f.history, &[0, 1, 5], &b(&sig));
});
negative!(unlock_flipped_parity, 0, UnlockKey, |f| {
    let mut sig = blob(&field(&field(&field(&f.history, 0), 1), 5)).to_vec();
    sig[64] ^= 1;
    f.history = edit(&f.history, &[0, 1, 5], &b(&sig));
});
negative!(unlock_recovery_two, 0, UnlockKey, |f| {
    let mut sig = blob(&field(&field(&field(&f.history, 0), 1), 5)).to_vec();
    sig[64] = 2;
    f.history = edit(&f.history, &[0, 1, 5], &b(&sig));
});
negative!(unlock_recovery_three, 0, UnlockKey, |f| {
    let mut sig = blob(&field(&field(&field(&f.history, 0), 1), 5)).to_vec();
    sig[64] = 3;
    f.history = edit(&f.history, &[0, 1, 5], &b(&sig));
});
negative!(return_whole_amount, 1, ReturnAmount, |f| {
    f.mutate_reason(7, &b(&[6]));
});
negative!(return_chain, 1, ReturnData, |f| {
    f.mutate_reason(1, &u(1338));
});
negative!(return_vault, 1, ReturnData, |f| {
    f.mutate_reason(2, &b(&[2; 20]));
});
negative!(return_asset, 1, ReturnData, |f| {
    f.mutate_reason(3, &b(&[2; 20]));
});
negative!(return_type, 1, ReturnData, |f| {
    f.mutate_reason(4, &b(&[2; 32]));
});
negative!(return_coin, 1, ReturnData, |f| {
    f.mutate_reason(5, &b(&[2; 32]));
});
negative!(return_fee_asset, 1, ReturnData, |f| {
    f.mutate_reason(8, &b(&[2; 20]));
});
negative!(return_fee, 1, ReturnData, |f| {
    f.mutate_reason(9, &b(&[1]));
});
negative!(return_fee_deadline, 1, ReturnData, |f| {
    f.mutate_reason(10, &u(1));
});
negative!(return_zero_recipient, 1, ReturnRecip, |f| {
    f.mutate_reason(6, &b(&[0; 20]));
});
negative!(return_vault_recipient, 1, ReturnRecip, |f| {
    f.mutate_reason(6, &b(&[0x33; 20]));
});
negative!(return_reason_hash, 1, BurnReason, |f| {
    f.mutate_tx(&[1, 0, 0, 1, 2], &b(&[1; 32]));
});
negative!(return_missing_data, 1, ReturnData, |f| {
    f.mutate_tx(&[1, 0, 0, 3], &[0xf6]);
});
negative!(return_signature_owner, 1, NotBurn, |f| {
    let p = f.p0.clone();
    f.mutate_tx(&[1, 0, 0, 1], &p);
});
negative!(burn_not_terminal, 2, BurnNotFinal, |f| {
    let burn = field(&field(&field(&field(&f.history, 1), 1), 0), 1);
    f.mutate_tx(&[1, 0, 0, 1], &burn);
});
negative!(intermediate_data, 2, TransferData, |f| {
    f.mutate_tx(&[1, 0, 0, 3], &b(&[0]));
});
negative!(transfer_cd_source, 1, CDMismatch, |f| {
    f.history = edit(&f.history, &[1, 0, 1, 2], &b(&[1; 32]));
});
negative!(transfer_cd_deadline, 1, DeadlineMismatch, |f| {
    f.history = edit(&f.history, &[1, 0, 1, 4], &u(101));
});
negative!(transfer_cd_owner, 1, CDMismatch, |f| {
    let other = SigningKey::from_slice(&[8; 32]).unwrap();
    f.history = edit(&f.history, &[1, 0, 1, 1], &pred(&other));
});
negative!(transfer_cd_hash, 1, CDMismatch, |f| {
    f.history = edit(&f.history, &[1, 0, 1, 3], &b(&[1; 32]));
});
negative!(malformed_last, 2, Shape, |f| {
    f.history = edit(&f.history, &[1, 1], &a(&[&u(1)]));
});
#[test]
fn deadlines_are_original_times_and_strict() {
    for count in [0, 1] {
        for t in [99, 100, 101] {
            let f = Fixture::new(count, Some(100), t);
            if t < 100 {
                assert_eq!(
                    run(&f.request(if count == 0 { 1 } else { 2 }), u64::MAX).unwrap().invalid,
                    None
                );
            } else {
                rejection(&f, if count == 0 { 1 } else { 2 }, E::DeadlineExpired);
            }
        }
    }
    let f = Fixture::new(1, None, u64::MAX);
    assert_eq!(run(&f.request(2), u64::MAX).unwrap().invalid, None);
}
#[test]
fn operation_cardinality() {
    let f = Fixture::new(0, None, 100);
    rejection(&f, 2, E::NoTransfers);
    let f = Fixture::new(1, None, 100);
    rejection(&f, 1, E::HasTransfers);
    assert_eq!(run(&f.request(3), u64::MAX), Err(E::BadOperation));
    let f = Fixture::new(65, None, 100);
    rejection(&f, 2, E::TooManyTx);
}
#[test]
fn abi_offsets_padding_aliases_trailing_and_high_bits() {
    let f = Fixture::new(0, None, 100);
    let input = f.request(1);
    for offset in [0, 32, 64, 96] {
        let mut i = input.clone();
        i[offset] = 1;
        assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    }
    let mut i = input.clone();
    i[63] = 64;
    assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    let mut i = input.clone();
    i[64..96].copy_from_slice(&abi::word(96));
    assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    let mut i = input.clone();
    i.push(0);
    assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    let mut i = input.clone();
    i[128 + f.cfg.len()] = 1;
    assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    let mut i = input.clone();
    let last = i.len() - 1;
    i[last] = 1;
    assert_eq!(run(&i, u64::MAX), Err(E::ABIFraming));
    for n in [0, 1, 31, 32, 64, 95, 96, 127, input.len() - 1] {
        assert_eq!(run(&input[..n], u64::MAX), Err(E::ABIFraming));
    }
    assert_eq!(run(&vec![0; MAX_INPUT + 1], 0), Err(E::InputTooLarge));
    assert_eq!(
        run(&request(0, &f.cfg, &vec![0; MAX_HISTORY + 1]), u64::MAX),
        Err(E::InputTooLarge)
    );
    assert_eq!(run(&request(0, &vec![0; 1025], &[0]), u64::MAX), Err(E::InputTooLarge));
}
#[test]
fn canonical_scanner_limits_and_errors() {
    for (input, e) in [
        (&[0x18, 0x17][..], E::NonCanonical),
        (&[0x19, 0, 255], E::NonCanonical),
        (&[0x1a, 0, 0, 255, 255], E::NonCanonical),
        (&[0x1b, 0, 0, 0, 0, 255, 255, 255, 255], E::NonCanonical),
        (&[0x9f, 0xff], E::ForbiddenCBOR),
        (&[0x20], E::ForbiddenCBOR),
        (&[0x60], E::ForbiddenCBOR),
        (&[0xa0], E::ForbiddenCBOR),
        (&[0xf5], E::ForbiddenCBOR),
        (&[0xf9, 0, 0], E::ForbiddenCBOR),
        (&[0x58, 255], E::Truncated),
        (&[0], E::Shape),
    ] {
        let e = if input == [0] {
            cbor::one(input, &mut 0).unwrap().array::<2>().unwrap_err()
        } else {
            assert_eq!(cbor::one(input, &mut 0).unwrap_err(), e);
            e
        };
        assert!(matches!(e, E::NonCanonical | E::ForbiddenCBOR | E::Truncated | E::Shape));
    }
    assert_eq!(cbor::one(&[0, 0], &mut 0).unwrap_err(), E::Trailing);
    assert_eq!(cbor::one(&[0], &mut 32768).unwrap_err(), E::TooManyItems);
    assert_eq!(cbor::one(&[vec![0x81; 17], vec![0]].concat(), &mut 0).unwrap_err(), E::TooDeep);
    assert!(cbor::one(&[vec![0x81; 16], vec![0]].concat(), &mut 0).is_ok());
}

impl Fixture {
    fn mutate_j(&mut self, path: &[usize], value: &[u8]) {
        let m = field(&field(&self.history, 0), 0);
        let j = edit(blob(&field(&m, 5)), path, value);
        self.mutate_tx(&[0, 0, 5], &b(&j));
    }
    fn mutate_data(&mut self, path: &[usize], value: &[u8]) {
        let m = field(&field(&self.history, 0), 0);
        let data = edit(blob(&field(&m, 6)), path, value);
        self.mutate_tx(&[0, 0, 6], &b(&data));
    }
}
negative!(justification_chain, 0, MintJustif, |f| {
    f.mutate_j(&[1], &u(2));
});
negative!(justification_vault, 0, MintJustif, |f| {
    f.mutate_j(&[2], &b(&[1; 20]));
});
negative!(justification_native_asset, 0, MintJustif, |f| {
    f.mutate_j(&[3], &b(&[1; 20]));
});
negative!(justification_nonce_zero, 0, MintJustif, |f| {
    f.mutate_j(&[4], &u(0));
});
negative!(justification_old_version, 0, MintJustif, |f| {
    f.mutate_j(&[0], &u(1));
});
negative!(lock_proof_wrong_cfg, 0, LockProofCfg, |f| {
    f.mutate_j(&[5, 1], &b(&[1; 32]));
});
negative!(lock_proof_wrong_version, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 0], &u(2));
});
negative!(lock_proof_trust_id_width, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 2], &b(&[1; 31]));
});
negative!(lock_proof_empty_pdr, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 3], &b(&[]));
});
negative!(lock_proof_empty_nodes, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 6], &a(&[]));
});
negative!(lock_proof_empty_node, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 6, 0], &b(&[]));
});
negative!(lock_proof_empty_uc, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 4], &b(&[]));
});
negative!(lock_proof_empty_header, 0, LockProofShape, |f| {
    f.mutate_j(&[5, 5], &b(&[]));
});
negative!(mint_foreign_coin, 0, MintData, |f| {
    f.mutate_data(&[1, 0, 0], &b(&[1; 32]));
});
negative!(mint_zero_amount, 0, MintData, |f| {
    f.mutate_data(&[1, 0, 1], &b(&[0]));
});
negative!(mint_nonminimal_amount, 0, MintData, |f| {
    f.mutate_data(&[1, 0, 1], &b(&[0, 7]));
});
negative!(mint_empty_amount, 0, MintData, |f| {
    f.mutate_data(&[1, 0, 1], &b(&[]));
});
negative!(mint_large_amount, 0, MintData, |f| {
    f.mutate_data(&[1, 0, 1], &b(&[1; 33]));
});
negative!(mint_memo, 0, MintData, |f| {
    f.mutate_data(&[2], &b(&[]));
});
negative!(mint_value_version, 0, MintData, |f| {
    f.mutate_data(&[0], &u(2));
});
negative!(mint_multiple_assets, 0, MintData, |f| {
    let entry = a(&[&field(&f.cfg, 10), &b(&[7])]);
    f.mutate_data(&[1], &a(&[&entry, &entry]));
});
negative!(mint_burn_recipient, 0, Predicate, |f| {
    let p = tag(39032, &a(&[&u(1), &b(&[2]), &b(&[0; 32])]));
    f.mutate_tx(&[0, 0, 2], &p);
});
negative!(predicate_unknown_code, 0, Predicate, |f| {
    f.mutate_tx(&[0, 0, 2, 1], &b(&[3]));
});
negative!(predicate_invalid_point, 0, Predicate, |f| {
    let mut point = [255; 33];
    point[0] = 2;
    f.mutate_tx(&[0, 0, 2, 2], &b(&point));
});
#[test]
fn embedded_proof_size_boundaries() {
    for (index, max) in [(3, 16384), (4, 16384), (5, 2048)] {
        let mut f = Fixture::new(0, None, 100);
        f.mutate_j(&[5, index], &b(&vec![1; max]));
        assert_eq!(run(&f.request(1), u64::MAX).unwrap().invalid, None);
        f.mutate_j(&[5, index], &b(&vec![1; max + 1]));
        rejection(&f, 1, E::LockProofTooLarge);
    }
    let mut f = Fixture::new(0, None, 100);
    f.mutate_j(&[5, 6, 0], &b(&vec![1; 1024]));
    assert_eq!(run(&f.request(1), u64::MAX).unwrap().invalid, None);
    f.mutate_j(&[5, 6, 0], &b(&vec![1; 1025]));
    rejection(&f, 1, E::LockProofTooLarge);
    let node = b(&[1]);
    let mut f = Fixture::new(0, None, 100);
    f.mutate_j(&[5, 6], &a(&vec![node.as_slice(); 65]));
    assert_eq!(run(&f.request(1), u64::MAX).unwrap().invalid, None);
    f.mutate_j(&[5, 6], &a(&vec![node.as_slice(); 66]));
    rejection(&f, 1, E::LockProofTooLarge);
    let node = b(&vec![1; 1024]);
    let mut f = Fixture::new(0, None, 100);
    for i in [6, 7] {
        f.mutate_j(&[5, i], &a(&vec![node.as_slice(); 12]));
    }
    assert_eq!(run(&f.request(1), u64::MAX).unwrap().invalid, None);
    let mut nodes = vec![node.as_slice(); 12];
    let extra = b(&[1]);
    nodes.push(&extra);
    f.mutate_j(&[5, 7], &a(&nodes));
    rejection(&f, 1, E::LockProofTooLarge);
    let mut f = Fixture::new(0, None, 100);
    f.mutate_tx(&[0, 0, 5], &b(&vec![0; 65537]));
    rejection(&f, 1, E::JustificationTooLarge);
}
#[test]
fn prepare_nonce_amount_and_signature_profile() {
    let f = Fixture::new(0, None, 100);
    for (n, amount, e) in [
        (0, b(&[1]), E::LockInput),
        (1, b(&[0]), E::IntRange),
        (1, b(&[]), E::IntRange),
        (1, b(&[0, 1]), E::IntRange),
        (1, b(&[1; 33]), E::IntRange),
    ] {
        let r = run(&request(0, &f.cfg, &a(&[&u(n), &amount, &f.p0])), u64::MAX);
        if e.is_invalid() {
            assert_eq!(r.unwrap().invalid, Some(e));
        } else {
            assert_eq!(r, Err(e));
        }
    }
    let p = a(&[&u(u64::MAX), &b(&[255; 32]), &f.p0]);
    let out = run(&request(0, &f.cfg, &p), u64::MAX).unwrap();
    assert_eq!(out.invalid, None);
    assert_eq!(&out.bytes[128..160], &abi::word(u64::MAX));
    assert_eq!(&out.bytes[160..192], &[255; 32]);
}
#[test]
fn sdk_pre3_shapes_and_wrong_projection_arity_reject() {
    let f = Fixture::new(0, None, 100);
    for path in [&[0, 0][..], &[0, 1], &[0]] {
        let mut target = f.history.clone();
        for p in path {
            target = field(&target, *p);
        }
        let mut parts = fields(&target);
        parts.pop();
        let h = edit(&f.history, path, &rebuild(&target, &parts));
        assert_eq!(run(&request(1, &f.cfg, &h), u64::MAX), Err(E::Shape));
    }
    let f = Fixture::new(1, None, 100);
    for path in [&[1, 0, 0][..], &[1, 0, 1], &[1, 0]] {
        let mut target = f.history.clone();
        for p in path {
            target = field(&target, *p);
        }
        let mut parts = fields(&target);
        parts.pop();
        let h = edit(&f.history, path, &rebuild(&target, &parts));
        assert_eq!(run(&request(2, &f.cfg, &h), u64::MAX), Err(E::Shape));
    }
}
#[test]
fn reference_time_changes_leaf_but_never_nullifier() {
    let f = Fixture::new(1, None, 100);
    let first = run(&f.request(2), u64::MAX).unwrap();
    let mut f = f;
    f.history = edit(&f.history, &[0, 2], &u(101));
    f.history = edit(&f.history, &[1, 0, 2], &u(102));
    let second = run(&f.request(2), u64::MAX).unwrap();
    assert_eq!(second.invalid, None);
    assert_eq!(&first.bytes[96..448], &second.bytes[96..448]);
    for off in [448, 576] {
        assert_eq!(&first.bytes[off..off + 64], &second.bytes[off..off + 64]);
        assert_ne!(&first.bytes[off + 96..off + 128], &second.bytes[off + 96..off + 128]);
    }
}

#[test]
fn provider_status_and_cache_preserve_exact_gas_and_bytes() {
    use alloy_evm::{
        eth::EthEvmContext,
        precompiles::{Precompile, PrecompileInput},
        EvmInternals,
    };
    use alloy_primitives::{Address, U256};
    use revm::{
        database::InMemoryDB, handler::precompile_output_to_interpreter_result,
        interpreter::InstructionResult,
    };
    let pc = provider::B2Precompile::default();
    assert!(pc.supports_caching());
    assert!(provider::B2Precompile::default().into_dyn().supports_caching());
    assert_eq!(ADDRESS, alloy_primitives::address!("0000000000000000000000000000000000000104"));
    let f = Fixture::new(1, None, 100);
    let good = f.request(2);
    let out = run(&good, u64::MAX).unwrap();
    let mut bad = f;
    bad.history = edit(&bad.history, &[0, 1, 3], &b(&[1; 32]));
    let bad = bad.request(2);
    let mut ctx = EthEvmContext::new(InMemoryDB::default(), Default::default());
    for (data, gas, expected, halt) in [
        (&good[..], out.gas, Some(out.bytes.clone()), None),
        (&good[..], out.gas - 1, None, Some(InstructionResult::PrecompileOOG)),
        (&bad[..], u64::MAX, Some(abi::encode(false, &Outcome::default())), None),
        (&[0][..], u64::MAX, None, Some(InstructionResult::PrecompileError)),
    ] {
        let result = pc
            .call(PrecompileInput {
                data,
                gas,
                reservoir: 0,
                caller: Address::ZERO,
                value: U256::ZERO,
                is_static: true,
                internals: EvmInternals::from_context(&mut ctx),
                target_address: ADDRESS,
                bytecode_address: ADDRESS,
            })
            .unwrap();
        if let Some(bytes) = expected {
            assert_eq!(result.bytes.as_ref(), bytes.as_slice());
            assert_eq!(result.gas_used, out.gas);
        } else {
            let converted = precompile_output_to_interpreter_result(result, gas);
            assert_eq!(converted.result, halt.unwrap());
            assert!(converted.output.is_empty());
        }
    }
}

#[test]
#[ignore = "native timing experiment; run explicitly in release mode"]
fn benchmark_native_kernel() {
    use std::time::Instant;
    let iterations =
        std::env::var("NBP4_ITERATIONS").ok().map(|v| v.parse::<usize>().unwrap()).unwrap_or(10000);
    let warmup =
        std::env::var("NBP4_WARMUP").ok().map(|v| v.parse::<usize>().unwrap()).unwrap_or(1000);
    for count in [0, 1, 16, 64] {
        let f = Fixture::new(count, Some(1001), 1000);
        let input = f.request(if count == 0 { 1 } else { 2 });
        for _ in 0..warmup {
            std::hint::black_box(run(&input, u64::MAX).unwrap());
        }
        let mut samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let now = Instant::now();
            std::hint::black_box(run(&input, u64::MAX).unwrap());
            samples.push(now.elapsed().as_nanos() as u64);
        }
        samples.sort_unstable();
        println!("BENCH transfers={count} bytes={} gas={} iterations={iterations} warmup={warmup} p99_ns={} max_ns={}",
            input.len(),run(&input,u64::MAX).unwrap().gas,samples[iterations*99/100],samples[iterations-1]);
    }
}
#[test]
#[ignore = "independent constructor export for the pinned Go differential runner"]
fn export_independent_constructor_cases() {
    fn hx(b: &[u8]) -> String {
        b.iter().map(|v| format!("{v:02x}")).collect()
    }
    let mut cases = Vec::new();
    for count in [0, 1, 16, 64] {
        for e in [None, Some(101)] {
            let f = Fixture::new(count, e, 100);
            let input = f.request(if count == 0 { 1 } else { 2 });
            let out = run(&input, u64::MAX).unwrap();
            cases.push(serde_json::json!({"name":format!("rust_{count}_{e:?}"),"input":hx(&input),"output":hx(&out.bytes)}));
        }
    }
    let f = Fixture::new(0, None, 100);
    let input = request(0, &f.cfg, &a(&[&u(1), &b(&[7]), &f.p0]));
    cases.push(serde_json::json!({"name":"rust_prepare","input":hx(&input),"output":hx(&run(&input,u64::MAX).unwrap().bytes)}));
    let dest = std::env::var("NBP4_EXPORT").expect("NBP4_EXPORT file path required");
    std::fs::write(dest, serde_json::to_vec_pretty(&cases).unwrap()).unwrap();
}
#[test]
fn scanner_schema_guard_errors() {
    let it = |b| cbor::one(b, &mut 0).unwrap();
    assert_eq!(it(&[0]).uint(0), Ok(0));
    assert_eq!(it(&[1]).uint(0), Err(E::IntRange));
    assert_eq!(it(&[0x40]).uint(0), Err(E::Shape));
    assert_eq!(it(&[0]).bytes(0), Err(E::Shape));
    assert_eq!(it(&[0x40]).bytes(1), Err(E::Length));
    assert_eq!(it(&[0]).blob(0), Err(E::Shape));
    assert_eq!(it(&[0x41, 0]).blob(0), Err(E::ProofTooLarge));
    assert_eq!(it(&[0]).count(0), Err(E::Shape));
    assert_eq!(it(&[0x81, 0]).count(0), Err(E::TooManyTx));
    assert_eq!(it(&[0]).array::<0>().unwrap_err(), E::Shape);
    assert_eq!(it(&[0x80]).array::<1>().unwrap_err(), E::Shape);
    assert_eq!(it(&[0]).tagged::<1>(39032, 1).unwrap_err(), E::Tag);
    let tagged = tag(39032, &a(&[&u(1)]));
    assert_eq!(it(&tagged).tagged::<1>(39033, 1).unwrap_err(), E::Tag);
    assert_eq!(it(&tagged).tagged::<1>(39032, 2).unwrap_err(), E::Version);
    assert_eq!(cbor::one(&[0x82, 0], &mut 0).unwrap_err(), E::Truncated);
    assert_eq!(cbor::one(&[], &mut 0).unwrap_err(), E::Truncated);
    assert_eq!(cbor::one(&[0x18], &mut 0).unwrap_err(), E::Truncated);
    let f = Fixture::new(0, None, 100);
    assert_eq!(run(&f.request(256), u64::MAX), Err(E::ABIFraming));
}
#[test]
fn base_gas_precedes_framing() {
    let malformed = [1u8; 100];
    let base = 26000 + 20 * malformed.len() as u64;
    assert_eq!(run(&malformed, base - 1), Err(E::OutOfGas));
    assert_ne!(run(&malformed, base), Err(E::OutOfGas));
}
