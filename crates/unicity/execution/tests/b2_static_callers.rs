//! Actual STATICCALL callers of the B2 precompile at `0x0104` through the real EVM.
//!
//! The sealed corpus's raw kernel requests (the cases whose input is the complete ABI request) are
//! sent by a contract executing `STATICCALL` against an EVM created by [`UnicityEvmFactory`]. Each
//! must give the library's verdict, returndata and charge, and exactly that charge must succeed
//! while one gas less is an exceptional halt.

use alloy_evm::{precompiles::Precompile, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use reth_unicity_execution::evm_factory::{b2_precompile, UnicityEvmFactory};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::ExecutionResult,
    database::{CacheDB, EmptyDB},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use serde_json::Value;
use std::collections::BTreeMap;

const SENDER: Address = address!("1000000000000000000000000000000000000001");
const CALLER: Address = address!("2000000000000000000000000000000000000002");
const TARGET: Address = address!("0000000000000000000000000000000000000104");
const FAMILIES: [(&str, &str); 2] = [
    ("config", include_str!("../../b2/protocol/vectors/config/cases.json")),
    ("wire", include_str!("../../b2/protocol/vectors/wire/cases.json")),
];
const EXPECTATIONS: &str = include_str!("../../b2/protocol/kernel-expectations.json");

fn hex(v: &Value) -> Vec<u8> {
    alloy_primitives::hex::decode(v.as_str().unwrap()).unwrap()
}

/// Forwards calldata by `STATICCALL` to `TARGET` and returns `success(32) ++ returndata`.
fn caller_code(forward: Option<u64>) -> Bytes {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x61, 0x01, 0x04];
    match forward {
        None => code.push(0x5a),
        Some(gas) => {
            code.push(0x63);
            code.extend_from_slice(&u32::try_from(gas).unwrap().to_be_bytes());
        }
    }
    code.push(0xfa);
    code.extend_from_slice(&[
        0x5f, 0x52, 0x3d, 0x5f, 0x60, 0x20, 0x3e, 0x3d, 0x60, 0x20, 0x01, 0x5f,
    ]);
    code.push(0xf3);
    code.into()
}

struct Outcome {
    success: bool,
    returndata: Vec<u8>,
    gas_used: u64,
}

fn call(request: &[u8], forward: Option<u64>, gas_limit: u64) -> Outcome {
    let code = caller_code(forward);
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

#[test]
fn every_sealed_kernel_request_is_decided_and_priced_like_the_library_through_a_real_staticcall() {
    let expected: BTreeMap<String, Value> = serde_json::from_str::<Vec<Value>>(EXPECTATIONS)
        .unwrap()
        .into_iter()
        .map(|c| (c["id"].as_str().unwrap().to_string(), c["expected"].clone()))
        .collect();
    let (mut accepted, mut halted) = (0, 0);
    for (family, text) in FAMILIES {
        let cases: Value = serde_json::from_str(text).unwrap();
        for c in cases["cases"].as_array().unwrap().iter().filter(|c| c["op"] == "kernel") {
            let id = c["id"].as_str().unwrap();
            let want = &expected[id];
            let request = hex(&c["input"]);
            let unlimited = call(&request, None, 60_000_000);
            if want["status"] == "error" {
                assert!(!unlimited.success, "{family}/{id}: malformed must fail the STATICCALL");
                assert!(unlimited.returndata.is_empty(), "{family}/{id}");
                assert!(unlimited.gas_used > 59_000_000, "{family}/{id}: a halt burns the pass");
                halted += 1;
            } else {
                let library = reth_unicity_b2::run(&request, u64::MAX).unwrap();
                assert_eq!(library.bytes, hex(&want["output"]), "{family}/{id}: library");
                assert!(unlimited.success, "{family}/{id}");
                assert_eq!(unlimited.returndata, library.bytes, "{family}/{id}");
                let exact = call(&request, Some(library.gas), 60_000_000);
                assert!(exact.success, "{family}/{id}: exact gas {}", library.gas);
                assert_eq!(exact.returndata, library.bytes, "{family}/{id}");
                let short = call(&request, Some(library.gas - 1), 60_000_000);
                assert!(!short.success, "{family}/{id}: gas-1 must fail");
                assert!(short.returndata.is_empty(), "{family}/{id}");
                accepted += 1;
            }
        }
    }
    assert_eq!((accepted, halted), (9, 10));
}

#[test]
fn the_b2_provider_is_registered_at_0104_and_may_be_result_cached() {
    let (address, provider) = b2_precompile();
    assert_eq!(address, TARGET);
    assert_eq!(address, reth_unicity_b2::ADDRESS);
    assert!(provider.supports_caching());
}
