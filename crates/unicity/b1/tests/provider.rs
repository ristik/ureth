//! The `CERT_BATCH_V2` provider inside a real EVM context: journal values, warmth, revert, status
//! conversion, host failures and a STATICCALL from a contract. Inputs are the any-age corpus's
//! single-claim vector.
use alloy_evm::{
    eth::{EthEvmBuilder, EthEvmContext},
    precompiles::{Precompile, PrecompileInput},
    Database as EvmDatabase, Evm, EvmEnv, EvmInternals,
};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use reth_unicity_b1::{
    batch, entry_slot, fixed_slot, provider::CertBatchPrecompile, Pins, REGISTRY,
};
use revm::{
    context::{JournalTr, TxEnv},
    database::InMemoryDB,
    database_interface::{DBErrorMarker, Database},
    handler::precompile_output_to_interpreter_result,
    interpreter::InstructionResult,
    state::{AccountInfo, Bytecode},
};
use serde_json::Value;
use std::collections::BTreeMap;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn word(s: &str) -> U256 {
    U256::from_be_slice(&hex(s))
}
/// The request, the registry words and the pins of a corpus vector.
fn vector(id: &str) -> (Vec<u8>, BTreeMap<U256, U256>, Pins) {
    let corpus: Value =
        serde_json::from_str(include_str!("testdata/b1-vectors-anyage.json")).unwrap();
    let v = corpus["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
    let pre = &v["preState"];
    let words = pre["storage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (word(w["slot"].as_str().unwrap()), word(w["value"].as_str().unwrap())))
        .collect();
    let pins = Pins {
        genesis_commitment: word(pre["pinnedGenesisCommitment"].as_str().unwrap()),
        profile_hash: word(pre["pinnedProfileHash"].as_str().unwrap()),
    };
    (hex(v["request"].as_str().unwrap()), words, pins)
}

fn call<DB: EvmDatabase>(
    pc: &CertBatchPrecompile,
    ctx: &mut EthEvmContext<DB>,
    data: &[u8],
    gas: u64,
) -> revm::precompile::PrecompileResult {
    pc.call(PrecompileInput {
        data,
        gas,
        reservoir: 0,
        caller: Address::ZERO,
        value: U256::ZERO,
        is_static: true,
        internals: EvmInternals::from_context(ctx),
        target_address: Address::ZERO,
        bytecode_address: Address::ZERO,
    })
}

#[test]
fn journal_values_warmth_revert_and_status_conversion() {
    let (input, words, pins) = vector("cert.single.ok");
    let mut db = InMemoryDB::default();
    for (k, val) in &words {
        db.insert_account_storage(REGISTRY, *k, *val).unwrap();
    }
    let mut ctx = EthEvmContext::new(db, Default::default());
    let pc = CertBatchPrecompile::new(pins);
    assert!(!pc.supports_caching());
    assert!(!CertBatchPrecompile::new(pins).into_dyn().supports_caching());
    let checkpoint = ctx.journaled_state.checkpoint();
    let cold = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(cold.bytes[31], 2);
    assert_eq!(cold.bytes[63], 1);
    // The registry reads warm the journal exactly as ordinary SLOADs do.
    let key = fixed_slot("b1.network");
    assert!(!EvmInternals::from_context(&mut ctx).sload(REGISTRY, key).unwrap().is_cold);
    assert_eq!(call(&pc, &mut ctx, &input, u64::MAX).unwrap(), cold);
    ctx.journaled_state.checkpoint_revert(checkpoint);
    assert!(EvmInternals::from_context(&mut ctx).sload(REGISTRY, key).unwrap().is_cold);
    // The backing database says network 3; the current journal value 4 wins and the charge is the
    // same.
    let cp = ctx.journaled_state.checkpoint();
    EvmInternals::from_context(&mut ctx).sstore(REGISTRY, key, U256::from(4)).unwrap();
    let changed = call(&pc, &mut ctx, &input, u64::MAX).unwrap();
    assert_eq!(changed.bytes[63], 0);
    assert_eq!(changed.gas_used, cold.gas_used);
    assert!(
        !EvmInternals::from_context(&mut ctx).sload(REGISTRY, entry_slot(7, 10)).unwrap().is_cold
    );
    ctx.journaled_state.checkpoint_revert(cp);
    assert_eq!(call(&pc, &mut ctx, &input, u64::MAX).unwrap().bytes[63], 1);
    // Malformed and underfunded calls consume the whole forwarded gas and return nothing.
    for (data, gas, want) in [
        (vec![2, 0, 0, 1], 123_456, InstructionResult::PrecompileError),
        (input.clone(), cold.gas_used - 1, InstructionResult::PrecompileOOG),
    ] {
        let out = call(&pc, &mut ctx, &data, gas).unwrap();
        let result = precompile_output_to_interpreter_result(out, gas);
        assert_eq!(result.result, want);
        assert!(result.output.is_empty());
        assert_eq!(result.gas.remaining(), 0);
    }
    // An impossible admitted registry is a host failure, never a caller halt.
    EvmInternals::from_context(&mut ctx)
        .sstore(REGISTRY, fixed_slot("b1.initialized"), U256::ZERO)
        .unwrap();
    assert!(matches!(
        call(&pc, &mut ctx, &input, u64::MAX),
        Err(revm::precompile::PrecompileError::Fatal(ref msg)) if msg == "impossible admitted B1 registry"
    ));
}

#[test]
fn a_wrong_deployment_pin_is_a_registry_failure_not_a_verdict() {
    let (input, words, mut pins) = vector("cert.single.ok");
    pins.profile_hash ^= U256::from(1);
    let mut db = InMemoryDB::default();
    for (k, val) in &words {
        db.insert_account_storage(REGISTRY, *k, *val).unwrap();
    }
    let mut ctx = EthEvmContext::new(db, Default::default());
    assert!(matches!(
        call(&CertBatchPrecompile::new(pins), &mut ctx, &input, u64::MAX),
        Err(revm::precompile::PrecompileError::Fatal(_))
    ));
}

#[test]
fn database_failure_aborts_execution() {
    #[derive(Debug)]
    struct Unavailable;
    impl std::fmt::Display for Unavailable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("historical storage unavailable")
        }
    }
    impl std::error::Error for Unavailable {}
    impl DBErrorMarker for Unavailable {}
    #[derive(Debug)]
    struct Fail;
    impl Database for Fail {
        type Error = Unavailable;
        fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Unavailable> {
            Ok(Some(AccountInfo::default()))
        }
        fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Unavailable> {
            Err(Unavailable)
        }
        fn storage(&mut self, _: Address, _: U256) -> Result<U256, Unavailable> {
            Err(Unavailable)
        }
        fn block_hash(&mut self, _: u64) -> Result<B256, Unavailable> {
            Err(Unavailable)
        }
    }
    let (input, _, pins) = vector("cert.single.ok");
    let mut ctx = EthEvmContext::new(Fail, Default::default());
    assert!(matches!(
        call(&CertBatchPrecompile::new(pins), &mut ctx, &input, u64::MAX),
        Err(revm::precompile::PrecompileError::Fatal(ref msg)) if msg == "historical storage unavailable"
    ));
}

#[test]
fn an_actual_staticcall_warms_the_downstream_sload() {
    let (input, words, pins) = vector("cert.single.ok");
    let caller = Address::repeat_byte(0x11);
    assert_eq!(
        batch::ADDRESS,
        alloy_primitives::address!("0000000000000000000000000000000000000100")
    );
    for (invoke, network, want) in [(false, 3, 2107), (true, 3, 107), (true, 4, 107)] {
        let mut db = InMemoryDB::default();
        for (k, val) in &words {
            db.insert_account_storage(REGISTRY, *k, *val).unwrap();
        }
        db.insert_account_storage(REGISTRY, fixed_slot("b1.network"), U256::from(network)).unwrap();
        let mut code = Vec::new();
        if invoke {
            // Copy calldata, STATICCALL 0x0100 and discard the success flag: a false verdict
            // warms exactly the storage a true one does.
            code.extend([
                0x36, 0x5f, 0x5f, 0x37, 0x60, 0x40, 0x5f, 0x36, 0x5f, 0x61, 0x01, 0x00, 0x5a, 0xfa,
                0x50,
            ]);
        }
        code.extend([0x5a, 0x7f]);
        code.extend(fixed_slot("b1.network").to_be_bytes::<32>());
        code.extend([0x54, 0x50, 0x5a, 0x90, 0x03, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        db.insert_account_info(
            REGISTRY,
            AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
        );
        db.insert_account_info(caller, AccountInfo { balance: U256::MAX, ..Default::default() });
        let mut env = EvmEnv::default();
        env.cfg_env.spec = revm::primitives::hardfork::SpecId::CANCUN;
        let mut evm = EthEvmBuilder::new(db, env).build();
        assert!(evm.precompiles_mut().get(&batch::ADDRESS).is_none());
        evm.precompiles_mut()
            .apply_precompile(&batch::ADDRESS, |_| Some(CertBatchPrecompile::new(pins).into_dyn()));
        let result = evm
            .transact(TxEnv {
                caller,
                kind: TxKind::Call(REGISTRY),
                gas_limit: 10_000_000,
                data: Bytes::copy_from_slice(&input),
                ..Default::default()
            })
            .unwrap()
            .result;
        assert!(result.is_success(), "{result:?}");
        assert_eq!(
            U256::from_be_slice(result.output().unwrap()),
            U256::from(want),
            "invoke={invoke} network={network}"
        );
    }
}
