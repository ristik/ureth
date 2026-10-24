//! Actual STATICCALL callers of `BRIDGE_COMPOSE_V2` at `0x0105` through the real EVM.
//!
//! The oracle's `native-compose-v2` cases (the split corpus) whose status is
//! decided before the anchor table's batch (so independent of the registry) are sent by a contract
//! executing `STATICCALL` against an EVM created by [`UnicityEvmFactory`]: each returns the
//! oracle's 480 bytes, exactly its metered gas succeeds and one gas less is an exceptional halt.
//! The non-canonical input halts.

use alloy_evm::{precompiles::Precompile, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use reth_unicity_execution::evm_factory::{bridge_precompile, UnicityEvmFactory};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::ExecutionResult,
    database::{CacheDB, EmptyDB},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use serde_json::Value;

const SENDER: Address = address!("1000000000000000000000000000000000000001");
const CALLER: Address = address!("2000000000000000000000000000000000000002");
const TARGET: Address = address!("0000000000000000000000000000000000000105");
const CASES: &str = include_str!("../../bridge/testdata/split-v2.json");
/// Statuses decided before the batch verdict: they do not depend on the registry.
const BEFORE_BATCH: [&str; 13] = [
    "ErrPolicyLeafCount",
    "ErrMintData",
    "ErrMintJustif",
    "ErrMintSalt",
    "ErrMintShape",
    "ErrMintType",
    "ErrSplitBurn",
    "ErrSplitManifest",
    "ErrSplitProof",
    "ErrSplitSum",
    "ErrReturnAmount",
    "ErrUnlockKey",
    "ErrRepeatedSID",
];

/// Forwards calldata by `STATICCALL` to `TARGET` and returns `success(32) ++ returndata`.
fn caller_code(forward: Option<u64>) -> Bytes {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x61, 0x01, 0x05];
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

fn call(request: &[u8], forward: Option<u64>) -> (bool, Vec<u8>) {
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
    let mut evm = UnicityEvmFactory::new(reth_unicity_b1::Pins {
        genesis_commitment: Default::default(),
        profile_hash: Default::default(),
    })
    .create_evm(db, EvmEnv::new(cfg, block));
    let tx = TxEnv {
        caller: SENDER,
        kind: TxKind::Call(CALLER),
        data: request.to_vec().into(),
        gas_limit: 60_000_000,
        ..Default::default()
    };
    let result = evm.transact_raw(tx).expect("the EVM executes the transaction").result;
    let ExecutionResult::Success { output, .. } = &result else {
        panic!("the caller contract itself must not fail: {result:?}");
    };
    let bytes = output.data().to_vec();
    (bytes[31] == 1 && bytes[..31].iter().all(|b| *b == 0), bytes[32..].to_vec())
}

fn hex(v: &Value) -> Vec<u8> {
    alloy_primitives::hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn registry_independent_compose_cases_return_the_oracles_bytes_at_exactly_the_metered_gas() {
    let corpus: Value = serde_json::from_str(CASES).unwrap();
    let mut decided = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let want = &case["expected"];
        let input = hex(&case["input"]);
        match want["status"].as_str().unwrap() {
            "halt" if want["values"]["halt"] == "abi" => {
                let (ok, data) = call(&input, None);
                assert!(!ok && data.is_empty(), "{id}: a non-canonical input halts");
            }
            "ok" if BEFORE_BATCH.contains(&want["values"]["statusName"].as_str().unwrap()) => {
                let gas: u64 = want["values"]["gas"].as_str().unwrap().parse().unwrap();
                let (ok, data) = call(&input, Some(gas));
                assert!(ok, "{id}: exact gas {gas}");
                assert_eq!(data, hex(&want["output"]), "{id}");
                let (ok, data) = call(&input, Some(gas - 1));
                assert!(!ok && data.is_empty(), "{id}: gas-1 must halt");
                decided += 1;
            }
            _ => {}
        }
    }
    assert_eq!(decided, 23, "registry-independent cases of split-v2.json");
}

#[test]
fn the_compose_provider_is_registered_at_0105_and_never_result_cached() {
    let pins = reth_unicity_b1::Pins {
        genesis_commitment: Default::default(),
        profile_hash: Default::default(),
    };
    let (address, provider) = bridge_precompile(pins);
    assert_eq!(address, TARGET);
    assert_eq!(address, reth_unicity_bridge::ADDRESS);
    assert!(!provider.supports_caching());
}
