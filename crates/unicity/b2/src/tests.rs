//! Pinned oracle conformance, including exact named errors and ABI results.
use super::*;
use crate::encode::{encode_array as a, encode_byte_string as b, encode_uint as u};
use serde_json::Value;

fn hx(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn manifest() -> Value {
    serde_json::from_str(include_str!("../tests/testdata/go-9136c661.json")).unwrap()
}
fn word(n: usize) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}
fn abi(op: usize, cfg: &[u8], payload: &[u8]) -> Vec<u8> {
    let padded = cfg.len().div_ceil(32) * 32;
    let mut out = [word(op), word(96), word(128 + padded), word(cfg.len())].concat();
    out.extend_from_slice(cfg);
    out.resize(128 + padded, 0);
    out.extend_from_slice(&word(payload.len()));
    out.extend_from_slice(payload);
    out.resize(out.len().div_ceil(32) * 32, 0);
    out
}
fn expected_bytes(r: &Value) -> Vec<u8> {
    let mut marker = [0; 32];
    marker[..23].copy_from_slice(b"UNICITY_TOKEN_SEMANTICS");
    let mut out = [marker, word(1), word(96)].concat();
    for key in [
        "cfg",
        "nonce",
        "amount",
        "tokenId",
        "salt",
        "firstPredicateHash",
        "lockDigest",
        "releaseTo",
        "nullifier",
    ] {
        let v = if key == "nonce" {
            word(r[key].as_u64().unwrap() as usize).to_vec()
        } else {
            hx(r[key].as_str().unwrap())
        };
        assert!(v.len() <= 32);
        out.extend_from_slice(&vec![0; 32 - v.len()]);
        out.extend_from_slice(&v);
    }
    out.extend_from_slice(&word(320));
    let leaves = r["leaves"].as_array().unwrap();
    out.extend_from_slice(&word(leaves.len()));
    for leaf in leaves {
        out.extend_from_slice(&hx(leaf.as_str().unwrap()));
    }
    out
}
fn check(id: &str) {
    let m = manifest();
    let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
    let input = hx(v["input"].as_str().unwrap());
    let expected = &v["expected"];
    let op = v["op"].as_str().unwrap();
    if op == "unlock" {
        let source = input[..32].try_into().unwrap();
        let tx = input[32..64].try_into().unwrap();
        let result = unlock::parse_key(&hx(v["extra"].as_str().unwrap()))
            .and_then(|k| unlock::verify_unlock(&k, &source, &tx, &input[64..]));
        if expected["status"] == "ok" {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result.unwrap_err().name(), expected["reason"].as_str().unwrap());
        }
        return;
    }
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let (operation, payload) = match op {
        "prepareLock" => {
            let (n, amount) = v["extra"].as_str().unwrap().split_once(':').unwrap();
            (0, a(&[&u(n.parse().unwrap()), &b(&hx(amount)), &input]))
        }
        "mint" => (1, input),
        "return" => (2, input),
        _ => panic!("unsupported vector"),
    };
    let request = abi(operation, &cfg, &payload);
    let result = run(&request, u64::MAX);
    if expected["status"] == "ok" {
        let out = result.unwrap();
        assert_eq!(out.reason, None);
        assert_eq!(out.bytes, expected_bytes(&expected["result"]));
        let leaf_count = expected["result"]["leaves"].as_array().unwrap().len() as u64;
        assert_eq!(out.gas, 26000 + 16 * request.len() as u64 + 13000 * leaf_count);
        assert_eq!(run(&request, out.gas), Ok(out));
        assert_eq!(
            run(&request, 26000 + 16 * request.len() as u64 + 13000 * leaf_count - 1),
            Err(Error::OutOfGas)
        );
    } else {
        let reason = expected["reason"].as_str().unwrap();
        match result {
            Ok(out) => {
                assert_eq!(out.reason.unwrap().name(), reason);
                assert_eq!(&out.bytes[32..64], &[0; 32]);
                assert_eq!(out.bytes.len(), 448);
                assert!(out.bytes[96..384].iter().all(|b| *b == 0));
                let exact = out.gas;
                assert_eq!(run(&request, exact), Ok(out));
                assert_eq!(run(&request, exact - 1), Err(Error::OutOfGas));
            }
            Err(Error::Malformed(e) | Error::BudgetExceeded(e)) => assert_eq!(e.name(), reason),
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
}

#[test]
fn vector_unlock_valid() {
    check("unlock-valid");
}

#[test]
fn vector_unlock_flipped_parity() {
    check("unlock-flipped-parity");
}

#[test]
fn vector_unlock_id2() {
    check("unlock-id2");
}

#[test]
fn vector_unlock_id3() {
    check("unlock-id3");
}

#[test]
fn vector_unlock_id4() {
    check("unlock-id4");
}

#[test]
fn vector_unlock_id255() {
    check("unlock-id255");
}

#[test]
fn vector_unlock_short() {
    check("unlock-short");
}

#[test]
fn vector_unlock_high_s() {
    check("unlock-high-s");
}

#[test]
fn vector_unlock_r_zero() {
    check("unlock-r-zero");
}

#[test]
fn vector_unlock_s_zero() {
    check("unlock-s-zero");
}

#[test]
fn vector_unlock_r_n() {
    check("unlock-r-n");
}

#[test]
fn vector_unlock_other_key() {
    check("unlock-other-key");
}

#[test]
fn vector_unlock_high_recovery_match() {
    check("unlock-high-recovery-match");
}

#[test]
fn vector_unlock_high_recovery_flipped() {
    check("unlock-high-recovery-flipped");
}

#[test]
fn vector_unlock_high_recovery_id0() {
    check("unlock-high-recovery-id0");
}

#[test]
fn vector_unlock_regression_00() {
    check("unlock-regression-00");
}

#[test]
fn vector_unlock_regression_01() {
    check("unlock-regression-01");
}

#[test]
fn vector_return_negative_integer() {
    check("return-negative-integer");
}

#[test]
fn vector_return_negative_integer_nonminimal() {
    check("return-negative-integer-nonminimal");
}

#[test]
fn vector_prepare_valid() {
    check("prepare-valid");
}

#[test]
fn vector_prepare_max_nonce() {
    check("prepare-max-nonce");
}

#[test]
fn vector_prepare_zero_nonce() {
    check("prepare-zero-nonce");
}

#[test]
fn vector_prepare_zero_amount() {
    check("prepare-zero-amount");
}

#[test]
fn vector_prepare_burn_p0() {
    check("prepare-burn-p0");
}

#[test]
fn vector_mint_valid() {
    check("mint-valid");
}

#[test]
fn vector_return_valid_0() {
    check("return-valid-0");
}

#[test]
fn vector_return_valid_1() {
    check("return-valid-1");
}

#[test]
fn vector_return_valid_2() {
    check("return-valid-2");
}

#[test]
fn vector_return_valid_16() {
    check("return-valid-16");
}

#[test]
fn vector_mint_for_return_op() {
    check("mint-for-return-op");
}

#[test]
fn vector_return_for_mint_op() {
    check("return-for-mint-op");
}

#[test]
fn vector_mint_wrong_network() {
    check("mint-wrong-network");
}

#[test]
fn vector_mint_burn_recipient() {
    check("mint-burn-recipient");
}

#[test]
fn vector_mint_wrong_type() {
    check("mint-wrong-type");
}

#[test]
fn vector_mint_null_justification() {
    check("mint-null-justification");
}

#[test]
fn vector_mint_external_backing() {
    check("mint-external-backing");
}

#[test]
fn vector_mint_wrong_chain() {
    check("mint-wrong-chain");
}

#[test]
fn vector_mint_zero_nonce() {
    check("mint-zero-nonce");
}

#[test]
fn vector_mint_other_nonce() {
    check("mint-other-nonce");
}

#[test]
fn vector_mint_salt_changed() {
    check("mint-salt-changed");
}

#[test]
fn vector_mint_null_data() {
    check("mint-null-data");
}

#[test]
fn vector_mint_wrong_asset() {
    check("mint-wrong-asset");
}

#[test]
fn vector_mint_leading_zero_amount() {
    check("mint-leading-zero-amount");
}

#[test]
fn vector_transfer_data() {
    check("transfer-data");
}

#[test]
fn vector_transfer_empty_data() {
    check("transfer-empty-data");
}

#[test]
fn vector_burn_before_final() {
    check("burn-before-final");
}

#[test]
fn vector_final_not_burn() {
    check("final-not-burn");
}

#[test]
fn vector_burn_reason_mismatch() {
    check("burn-reason-mismatch");
}

#[test]
fn vector_return_null_data() {
    check("return-null-data");
}

#[test]
fn vector_cd_source_owner() {
    check("cd-source-owner");
}

#[test]
fn vector_cd_source_hash() {
    check("cd-source-hash");
}

#[test]
fn vector_cd_tx_hash() {
    check("cd-tx-hash");
}

#[test]
fn vector_history_removed_predecessor() {
    check("history-removed-predecessor");
}

#[test]
fn vector_history_reordered() {
    check("history-reordered");
}

#[test]
fn vector_unlock_wrong_signer() {
    check("unlock-wrong-signer");
}

#[test]
fn vector_unlock_minter_public_key() {
    check("unlock-minter-public-key");
}

#[test]
fn vector_hist_unlock_flipped_parity() {
    check("hist-unlock-flipped-parity");
}

#[test]
fn vector_hist_unlock_id4() {
    check("hist-unlock-id4");
}

#[test]
fn vector_hist_unlock_short() {
    check("hist-unlock-short");
}

#[test]
fn vector_return_partial_amount() {
    check("return-partial-amount");
}

#[test]
fn vector_return_zero_recipient() {
    check("return-zero-recipient");
}

#[test]
fn vector_return_vault_recipient() {
    check("return-vault-recipient");
}

#[test]
fn vector_return_fee_token() {
    check("return-fee-token");
}

#[test]
fn vector_return_fee_amount() {
    check("return-fee-amount");
}

#[test]
fn vector_return_deadline() {
    check("return-deadline");
}

#[test]
fn vector_return_wrong_asset() {
    check("return-wrong-asset");
}

#[test]
fn vector_wire_trailing() {
    check("wire-trailing");
}

#[test]
fn vector_wire_truncated() {
    check("wire-truncated");
}

#[test]
fn vector_wire_indefinite() {
    check("wire-indefinite");
}

#[test]
fn vector_wire_nonminimal_head() {
    check("wire-nonminimal-head");
}

#[test]
fn vector_wire_transfer_version() {
    check("wire-transfer-version");
}

#[test]
fn vector_wire_transfer_extra_field() {
    check("wire-transfer-extra-field");
}

#[test]
fn vector_wire_transfer_tag() {
    check("wire-transfer-tag");
}

#[test]
fn vector_wire_transfer_short_mask() {
    check("wire-transfer-short-mask");
}

#[test]
fn vector_wire_predicate_engine() {
    check("wire-predicate-engine");
}

#[test]
fn vector_wire_predicate_text_code() {
    check("wire-predicate-text-code");
}

#[test]
fn vector_wire_predicate_nonminimal_code() {
    check("wire-predicate-nonminimal-code");
}

#[test]
fn vector_wire_predicate_uncompressed() {
    check("wire-predicate-uncompressed");
}

#[test]
fn abi_rejects_alias_offsets_padding_and_trailing() {
    let cfg = hx(manifest()["fixtures"][0]["cfg"].as_str().unwrap());
    let good = abi(0, &cfg, &[0x83, 1, 0x41, 1, 0]);
    for offset in [0usize, 32, 64, 96] {
        let mut bad = good.clone();
        bad[offset] = 1;
        assert_eq!(run(&bad, u64::MAX), Err(Error::Malformed(BridgeError::ABIFraming)));
    }
    let mut alias = good.clone();
    alias[64..96].copy_from_slice(&word(96));
    assert_eq!(run(&alias, u64::MAX), Err(Error::Malformed(BridgeError::ABIFraming)));
    let mut padding = good.clone();
    *padding.last_mut().unwrap() = 1;
    assert_eq!(run(&padding, u64::MAX), Err(Error::Malformed(BridgeError::ABIFraming)));
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0; 32]);
    assert_eq!(run(&trailing, u64::MAX), Err(Error::Malformed(BridgeError::ABIFraming)));
    let mut op = good;
    op[31] = 3;
    assert_eq!(run(&op, u64::MAX), Err(Error::Malformed(BridgeError::BadOperation)));
    assert_eq!(run(&[], u64::MAX), Err(Error::Malformed(BridgeError::ABIFraming)));
}

#[test]
fn initial_debit_precedes_malformed_scan() {
    let malformed = abi(0, &[0xff], &[0xff]);
    assert_eq!(run(&malformed, 20000 + 16 * malformed.len() as u64 - 1), Err(Error::OutOfGas));
    assert_eq!(run(&malformed, u64::MAX), Err(Error::Malformed(BridgeError::ForbiddenCBOR)));
}

#[test]
fn malformed_last_wins_over_false_mint() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let v =
        m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "mint-wrong-network").unwrap();
    let mut payload = hx(v["input"].as_str().unwrap());
    assert_eq!(
        run(&abi(2, &cfg, &payload), u64::MAX).unwrap().reason,
        Some(BridgeError::MintShape)
    );
    payload.pop();
    assert_eq!(
        run(&abi(2, &cfg, &payload), u64::MAX),
        Err(Error::Malformed(BridgeError::Truncated))
    );
}

#[test]
fn semantic_byte_ceiling_exact_and_over() {
    let mut size = 65000;
    let exact = loop {
        let request = abi(0, &[0], &b(&vec![0; size]));
        match request.len().cmp(&65536) {
            core::cmp::Ordering::Less => size += 1,
            core::cmp::Ordering::Equal => break request,
            core::cmp::Ordering::Greater => panic!("skipped exact limit"),
        }
    };
    assert_eq!(run(&exact, u64::MAX), Err(Error::Malformed(BridgeError::Shape)));
    let mut over = exact;
    over.push(0);
    assert_eq!(run(&over, u64::MAX), Err(Error::BudgetExceeded(BridgeError::InputTooLarge)));
}

#[test]
fn depth_and_shared_item_ceilings_exact_and_over() {
    let make = |depth| [vec![0x81; depth], vec![0]].concat();
    assert_eq!(run(&abi(0, &[0], &make(16)), u64::MAX), Err(Error::Malformed(BridgeError::Shape)));
    assert_eq!(
        run(&abi(0, &[0], &make(17)), u64::MAX),
        Err(Error::BudgetExceeded(BridgeError::TooDeep))
    );
    for (n, err) in [
        (32766, Error::Malformed(BridgeError::Shape)),
        (32767, Error::BudgetExceeded(BridgeError::TooManyItems)),
    ] {
        let mut payload = vec![0x99, (n >> 8) as u8, n as u8];
        payload.extend_from_slice(&vec![0; n]);
        assert_eq!(run(&abi(0, &[0], &payload), u64::MAX), Err(err));
    }
}

#[test]
fn cfg_and_prepare_shape_errors_are_exact() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    for payload in [&[0x80][..], &[0x83, 0xf6, 0x41, 1, 0], &[0x83, 1, 1, 0]] {
        assert_eq!(
            run(&abi(0, &cfg, payload), u64::MAX),
            Err(Error::Malformed(BridgeError::Shape))
        );
    }
    assert_eq!(
        run(&abi(0, &[0], &[0x83, 1, 0x41, 1, 0]), u64::MAX),
        Err(Error::Malformed(BridgeError::Shape))
    );
    assert_eq!(address()[18..], [1, 4]);
}

#[test]
fn embedded_caps_precede_relation_and_share_item_budget() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "mint-valid").unwrap();
    let base = hx(v["input"].as_str().unwrap());
    let [head, list] = scan::scan_one(&base).unwrap().array::<2>().unwrap();
    let [mint, cd] = head.array::<2>().unwrap();
    let fields = mint.tag_content(39041).unwrap().array::<7>().unwrap();
    let replace = |data: &[u8]| {
        let mut raw: Vec<Vec<u8>> = fields.iter().map(|f| f.raw(&base).to_vec()).collect();
        raw[6] = b(data);
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        let mint = encode::encode_tag(39041, &a(&refs));
        a(&[&a(&[&mint, cd.raw(&base)]), list.raw(&base)])
    };
    let deep = [vec![0x81; 17], vec![0]].concat();
    assert_eq!(
        run(&abi(1, &cfg, &replace(&deep)), u64::MAX),
        Err(Error::BudgetExceeded(BridgeError::TooDeep))
    );
    let mut outer = 0;
    scan::scan_shared(&cfg, &mut outer).unwrap();
    scan::scan_shared(&base, &mut outer).unwrap();
    scan::scan_shared(fields[5].bytes().unwrap(), &mut outer).unwrap();
    // Only embedded mint-data is replaced. The whole outer tree has identical
    // item cardinality; exactly one additional root belongs to embedded data.
    let exact = 32768 - outer - 1;
    for (n, expected) in
        [(exact, None), (exact + 1, Some(Error::BudgetExceeded(BridgeError::TooManyItems)))]
    {
        let mut data = vec![0x99, (n >> 8) as u8, n as u8];
        data.extend_from_slice(&vec![0; n]);
        let result = run(&abi(1, &cfg, &replace(&data)), u64::MAX);
        if let Some(expected) = expected {
            assert_eq!(result, Err(expected));
        } else {
            assert_eq!(result.unwrap().reason, Some(BridgeError::MintData));
        }
    }
}

#[test]
fn high_recovery_ids_both_require_actual_matching_recovery() {
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, SECP256K1,
    };
    let source = [1; 32];
    let tx = [2; 32];
    let digest = Message::from_digest(unlock::unlock_message(&source, &tx));
    for id in [2u8, 3] {
        let (signature, key) = (1u8..=255)
            .find_map(|r| {
                let mut bytes = [0; 65];
                bytes[31] = r;
                bytes[63] = 1;
                bytes[64] = id;
                let sig = RecoverableSignature::from_compact(
                    &bytes[..64],
                    RecoveryId::try_from(i32::from(id)).unwrap(),
                )
                .unwrap();
                SECP256K1.recover_ecdsa(&digest, &sig).ok().map(|key| (bytes, key))
            })
            .unwrap();
        assert_eq!(unlock::verify_unlock(&key, &source, &tx, &signature), Ok(()));
        let mut flipped = signature;
        flipped[64] ^= 1;
        assert_eq!(
            unlock::verify_unlock(&key, &source, &tx, &flipped),
            Err(BridgeError::UnlockKey)
        );
    }
}

#[test]
fn borrowed_schema_views_assert_exact_errors() {
    use BridgeError as E;
    let uint = scan::scan_one(&[0x18, 24]).unwrap();
    let bytes = scan::scan_one(&[0x40]).unwrap();
    assert_eq!(uint.array::<1>().unwrap_err(), E::Shape);
    assert_eq!(uint.any_array().unwrap_err(), E::Shape);
    assert_eq!(uint.bytes(), Err(E::Shape));
    assert_eq!(uint.bytes_n(1), Err(E::Shape));
    assert_eq!(bytes.bytes_n(1), Err(E::Length));
    assert_eq!(uint.tag_content(39032).unwrap_err(), E::Shape);
    let tag = scan::scan_one(&[0xd9, 0x98, 0x78, 0x80]).unwrap();
    assert_eq!(tag.tag_content(39033).unwrap_err(), E::Tag);
    assert_eq!(bytes.uint_max(0), Err(E::Shape));
    assert_eq!(uint.uint_max(23), Err(E::IntRange));
    assert_eq!(uint.version(), Err(E::Version));
    for data in [
        &[0x40][..],
        &[0x41, 0],
        &[
            0x58, 33, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1,
        ],
    ] {
        assert_eq!(scan::scan_one(data).unwrap().amount(), Err(E::IntRange));
    }
}

#[test]
fn cfg_domain_widths_and_integer_bounds() {
    let cfg = hx(manifest()["fixtures"][0]["cfg"].as_str().unwrap());
    let items = scan::scan_one(&cfg).unwrap().array::<16>().unwrap();
    for (index, value, expected) in [
        (0, b(b"OTHER"), BridgeError::Shape),
        (1, u(65536), BridgeError::IntRange),
        (2, b(&[0; 31]), BridgeError::Length),
        (3, b(&[]), BridgeError::Shape),
        (5, u(u64::MAX), BridgeError::IntRange),
        (7, b(&[0; 19]), BridgeError::Length),
    ] {
        let mut fields: Vec<&[u8]> = items.iter().map(|i| i.raw(&cfg)).collect();
        fields[index] = &value;
        assert_eq!(
            run(&abi(0, &a(&fields), &[0x83, 1, 0x41, 1, 0]), u64::MAX),
            Err(Error::Malformed(expected))
        );
    }
}

#[test]
fn transfer_cap_checks_actual_count_before_relation() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "return-valid-0").unwrap();
    let raw = hx(v["input"].as_str().unwrap());
    let fields = scan::scan_one(&raw).unwrap().array::<2>().unwrap();
    let pairs = fields[1].any_array().unwrap().next().unwrap().raw;
    for (count, expected) in [(64, None), (65, Some(Error::BudgetExceeded(BridgeError::TooManyTx)))]
    {
        let payload = a(&[fields[0].raw(&raw), &a(&vec![pairs; count])]);
        let result = run(&abi(2, &cfg, &payload), u64::MAX);
        if let Some(expected) = expected {
            assert_eq!(result, Err(expected));
        } else {
            assert_eq!(result.unwrap().reason, Some(BridgeError::BurnNotFinal));
        }
    }
}

#[test]
fn preflight_schema_errors_precede_second_debit() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "mint-valid").unwrap();
    let raw = hx(v["input"].as_str().unwrap());
    let fields = scan::scan_one(&raw).unwrap().array::<2>().unwrap();
    for (op, payload) in
        [(0, vec![0x80]), (1, a(&[fields[0].raw(&raw), &[0xf6]])), (1, a(&[&[0x80], &[0x80]]))]
    {
        let request = abi(op, &cfg, &payload);
        let base = 20000 + 16 * request.len() as u64;
        assert_eq!(run(&request, base), Err(Error::Malformed(BridgeError::Shape)));
    }
}

#[test]
fn embedded_return_cap_is_checked_before_cd_mismatch() {
    let m = manifest();
    let cfg = hx(m["fixtures"][0]["cfg"].as_str().unwrap());
    let v = m["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "return-valid-0").unwrap();
    let raw = hx(v["input"].as_str().unwrap());
    let [head, list] = scan::scan_one(&raw).unwrap().array::<2>().unwrap();
    let pair = scan::Item(list.any_array().unwrap().next().unwrap()).array::<2>().unwrap();
    let fields = pair[0].tag_content(39045).unwrap().array::<4>().unwrap();
    let deep = [vec![0x81; 17], vec![0]].concat();
    let tx = encode::encode_tag(
        39045,
        &a(&[fields[0].raw(&raw), fields[1].raw(&raw), fields[2].raw(&raw), &b(&deep)]),
    );
    let payload = a(&[head.raw(&raw), &a(&[&a(&[&tx, pair[1].raw(&raw)])])]);
    assert_eq!(
        run(&abi(2, &cfg, &payload), u64::MAX),
        Err(Error::BudgetExceeded(BridgeError::TooDeep))
    );
}
