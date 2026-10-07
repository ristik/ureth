//! Actual STATICCALL callers of the B1 precompiles through the real EVM.
//!
//! Every request of bft-core's pinned conformance manifest (`go-4ba487e`, shared with the native
//! kernel's tests) is sent by a contract executing `STATICCALL`, against an EVM created by
//! [`UnicityEvmFactory`], with the manifest's registry pre-state written into the registry
//! account's storage. The caller returns `success ++ returndata`, so the test sees exactly what a
//! Solidity consumer would: the success flag, the 64-byte `(version, valid)` answer, and the gas it
//! paid.
//!
//! The pre-state is an injected simulation of authenticated state (the manifest says so too); the
//! authenticated admission path that produces such state is covered by the registry tests.

use alloy_evm::{precompiles::Precompile, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use reth_unicity_b1::{entry_slot, fixed_slot, member_slot, Operation, REGISTRY};
use reth_unicity_execution::evm_factory::{b1_precompiles, UnicityEvmFactory};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::ExecutionResult,
    database::{CacheDB, EmptyDB},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use serde_json::Value;

const MANIFEST: &str = include_str!("../../b1/tests/testdata/go-4ba487e.json");
const SENDER: Address = address!("1000000000000000000000000000000000000001");
const CALLER: Address = address!("2000000000000000000000000000000000000002");
const INTRINSIC: u64 = 21_000;

fn hex(s: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(s).unwrap()
}

/// A contract that forwards its calldata with `STATICCALL` to `target` and returns
/// `success(32) ++ returndata`. With `forward`, exactly that much gas is passed on; without it,
/// all gas is.
fn caller_code(target: Address, forward: Option<u64>) -> Bytes {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37]; // CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY
    code.extend_from_slice(&[0x5f, 0x5f, 0x36, 0x5f]); // retSize retOffset argsSize argsOffset
    code.push(0x61); // PUSH2 address
    code.extend_from_slice(&target.0[18..20]);
    match forward {
        None => code.push(0x5a), // GAS
        Some(gas) => {
            code.push(0x63); // PUSH4 gas
            code.extend_from_slice(&u32::try_from(gas).unwrap().to_be_bytes());
        }
    }
    code.push(0xfa); // STATICCALL
    code.extend_from_slice(&[0x5f, 0x52]); // MSTORE(0, success)
    code.extend_from_slice(&[0x3d, 0x5f, 0x60, 0x20, 0x3e]); // RETURNDATACOPY(32, 0, size)
    code.extend_from_slice(&[0x3d, 0x60, 0x20, 0x01, 0x5f, 0xf3]); // RETURN(0, 32 + size)
    code.into()
}

/// The registry words a manifest pre-state describes, as the native kernel's tests build them.
fn words(pre: &Value) -> Vec<(U256, U256)> {
    let mut out = Vec::new();
    for (name, value) in
        [("genesisCommitment", 1u64), ("phase", 2), ("b1.initialized", 1), ("b1.profileHash", 2)]
    {
        out.push((fixed_slot(name), U256::from(value)));
    }
    for (name, field) in [
        ("b1.network", "network"),
        ("b1.wCert", "wCert"),
        ("clock.rootRound", "clockRound"),
        ("origin.rootEpoch", "origin"),
    ] {
        out.push((fixed_slot(name), U256::from(pre[field].as_u64().unwrap_or(0))));
    }
    for e in pre["epochs"].as_array().into_iter().flatten() {
        let epoch = e["epoch"].as_u64().unwrap();
        let members = e["members"].as_array().unwrap();
        let total: u64 = members.iter().map(|m| m["weight"].as_u64().unwrap()).sum();
        let end = e["end"].as_u64().unwrap();
        let fields = [
            U256::from(1),
            U256::from(2),
            U256::from_be_slice(&hex(e["bodyID"].as_str().unwrap())),
            U256::from(3),
            U256::from(e["start"].as_u64().unwrap()),
            U256::from(end),
            U256::from(u64::from(end != 0)),
            U256::from(1),
            U256::from(4),
            U256::from(members.len()),
            U256::from(total),
        ];
        for (f, w) in fields.into_iter().enumerate() {
            out.push((entry_slot(epoch, f as u64), w));
        }
        for (j, m) in members.iter().enumerate() {
            let id = m["nodeID"].as_str().unwrap().as_bytes();
            let key = hex(m["key"].as_str().unwrap());
            let mut word = [[0u8; 32]; 8];
            word[0] = U256::from(id.len()).to_be_bytes::<32>();
            for (i, b) in id.iter().enumerate() {
                word[1 + i / 32][i % 32] = *b;
            }
            word[5].copy_from_slice(&key[..32]);
            word[6][0] = key[32];
            word[7] = U256::from(m["weight"].as_u64().unwrap()).to_be_bytes::<32>();
            for (f, w) in word.into_iter().enumerate() {
                out.push((member_slot(epoch, j as u64, f as u64), U256::from_be_bytes(w)));
            }
        }
    }
    out
}

fn database(pre: Option<&Value>, code: Bytes) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        SENDER,
        AccountInfo { balance: U256::from(10).pow(U256::from(20)), ..Default::default() },
    );
    db.insert_account_info(
        CALLER,
        AccountInfo {
            code_hash: Bytecode::new_raw(code.clone()).hash_slow(),
            code: Some(Bytecode::new_raw(code)),
            ..Default::default()
        },
    );
    db.insert_account_info(REGISTRY, AccountInfo::default());
    for (slot, value) in pre.map(words).unwrap_or_default() {
        db.insert_account_storage(REGISTRY, slot, value).unwrap();
    }
    db
}

struct Outcome {
    success: bool,
    returndata: Vec<u8>,
    gas_used: u64,
}

fn call(db: CacheDB<EmptyDB>, request: &[u8], gas_limit: u64) -> Outcome {
    let cfg = CfgEnv::new_with_spec(SpecId::CANCUN);
    let block = BlockEnv { gas_limit: 100_000_000, ..Default::default() };
    let mut evm = UnicityEvmFactory::default().create_evm(db, EvmEnv::new(cfg, block));
    let tx = TxEnv {
        caller: SENDER,
        kind: TxKind::Call(CALLER),
        data: request.to_vec().into(),
        gas_limit,
        ..Default::default()
    };
    let result = evm.transact_raw(tx).expect("the EVM executes the transaction").result;
    let ExecutionResult::Success { output, .. } = &result else {
        panic!("the caller contract itself must not fail: {result:?}");
    };
    let bytes = output.data().to_vec();
    Outcome {
        success: bytes[31] == 1 && bytes[..31].iter().all(|b| *b == 0),
        returndata: bytes[32..].to_vec(),
        gas_used: result.gas().total_gas_spent(),
    }
}

fn address_of(op: &str) -> Address {
    match op {
        "UC_V1" => Operation::Uc,
        "SHARED_SEAL_V1" => Operation::Shared,
        _ => Operation::Member,
    }
    .address()
}

fn intrinsic(request: &[u8]) -> u64 {
    INTRINSIC + request.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum::<u64>()
}

#[test]
fn every_manifest_request_is_decided_and_priced_identically_through_a_real_staticcall() {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    let mut checked = 0;
    for v in manifest["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let request = hex(v["request"].as_str().unwrap());
        let target = address_of(v["op"].as_str().unwrap());
        let expected = &v["expected"];
        let pre = v.get("preState");
        let unlimited = call(database(pre, caller_code(target, None)), &request, 60_000_000);
        if expected["status"] == "error" {
            // Malformed: an exceptional halt, success 0, empty returndata, all forwarded gas burnt.
            assert!(!unlimited.success, "{id}: malformed must fail the STATICCALL");
            assert!(unlimited.returndata.is_empty(), "{id}: no returndata");
            assert!(
                unlimited.gas_used > 59_000_000,
                "{id}: a halt consumes all forwarded gas, used {}",
                unlimited.gas_used
            );
        } else {
            let charge = expected["gas"].as_u64().unwrap();
            assert!(unlimited.success, "{id}: the STATICCALL succeeds");
            assert_eq!(unlimited.returndata, hex(expected["output"].as_str().unwrap()), "{id}");
            // The paid gas is the intrinsic cost, the precompile's candidate charge and the
            // caller's own work: copying the request into memory (3 gas per word plus the memory
            // expansion `3w + w^2/512`) and a constant for the opcodes and the warm call.
            let overhead = unlimited.gas_used - intrinsic(&request) - charge;
            let words = (request.len() as u64).div_ceil(32);
            let copy = 3 * words + 3 * words + words * words / 512;
            assert!(overhead >= copy && overhead < copy + 400, "{id}: caller overhead {overhead}");
            // Exactly the charge succeeds; one less is an exceptional halt that burns what was
            // passed.
            let exact =
                call(database(pre, caller_code(target, Some(charge))), &request, 60_000_000);
            assert!(exact.success, "{id}: exact gas {charge}");
            assert_eq!(exact.returndata, unlimited.returndata, "{id}");
            let short =
                call(database(pre, caller_code(target, Some(charge - 1))), &request, 60_000_000);
            assert!(!short.success, "{id}: gas-1 must fail");
            assert!(short.returndata.is_empty(), "{id}");
            assert!(short.gas_used >= intrinsic(&request) + charge - 1, "{id}: OOG burns the pass");
        }
        checked += 1;
    }
    assert_eq!(checked, manifest["vectors"].as_array().unwrap().len());
}

#[test]
fn an_unregistered_address_answers_with_empty_success_that_a_checking_caller_rejects() {
    // 0x0103 (S1) stays inactive: the STATICCALL succeeds with no returndata, which fails the
    // callers' length, version and boolean checks.
    let outcome = call(
        database(None, caller_code(address!("0000000000000000000000000000000000000103"), None)),
        b"x",
        1_000_000,
    );
    assert!(outcome.success);
    assert!(outcome.returndata.is_empty());
}

#[test]
fn repeated_calls_in_one_transaction_pay_the_same_flat_charge() {
    // Warm slots must not discount the flat source allowance: the second call costs the same as the
    // first apart from the caller's own opcodes.
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    let v = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "cert.single.ok")
        .unwrap();
    let request = hex(v["request"].as_str().unwrap());
    let charge = v["expected"]["gas"].as_u64().unwrap();
    let target = address_of("UC_V1");
    let single = call(database(v.get("preState"), caller_code(target, None)), &request, 60_000_000);
    // A caller that makes the call twice (code of one call, executed twice) is built by running two
    // transactions' worth of the same STATICCALL in one frame.
    let doubled = {
        let one = caller_code(target, None).to_vec();
        // Drop the return epilogue of the first copy: everything up to and including
        // MSTORE(0, success) stays and the second copy starts with CALLDATACOPY again.
        let body = &one[..one.len() - 11];
        let mut code = body.to_vec();
        code.extend_from_slice(&one);
        Bytes::from(code)
    };
    let double = call(database(v.get("preState"), doubled), &request, 60_000_000);
    assert!(double.success);
    let extra = double.gas_used - single.gas_used;
    assert!(
        (charge..charge + 400).contains(&extra),
        "second call paid {extra}, flat charge {charge}"
    );
}

#[test]
fn stateful_providers_are_never_result_cached_and_the_stateless_one_may_be() {
    let caching: Vec<(Address, bool)> =
        b1_precompiles().into_iter().map(|(a, p)| (a, p.supports_caching())).collect();
    assert_eq!(
        caching,
        vec![
            (Operation::Uc.address(), false),
            (Operation::Shared.address(), false),
            (Operation::Member.address(), true)
        ]
    );
}
