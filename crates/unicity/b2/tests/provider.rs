//! Explicit provider installation and real Cancun STATICCALL semantics.
mod common;
use alloy_evm::{eth::EthEvmBuilder, Evm, EvmEnv};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use reth_unicity_b2::provider::B2Precompile;
use revm::{
    context::TxEnv,
    database::InMemoryDB,
    state::{AccountInfo, Bytecode},
};

#[test]
fn actual_staticcall_requires_explicit_installation_and_preserves_output() {
    let f = common::Fixture::new();
    let payload = f.history(5, &[1], None);
    let input = common::abi(1, &f.cfg, &payload);
    let expected = reth_unicity_b2::run(&input, u64::MAX).unwrap();
    let caller = Address::repeat_byte(0x11);
    let target = Address::repeat_byte(0x44);
    for install in [false, true] {
        let mut db = InMemoryDB::default();
        // Copy calldata; STATICCALL 0x0104; return its entire returndata.
        let code = vec![
            0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x61, 0x01, 0x04, 0x5a, 0xfa, 0x50,
            0x3d, 0x5f, 0x5f, 0x3e, 0x3d, 0x5f, 0xf3,
        ];
        db.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
        );
        db.insert_account_info(caller, AccountInfo { balance: U256::MAX, ..Default::default() });
        let mut env = EvmEnv::default();
        env.cfg_env.spec = revm::primitives::hardfork::SpecId::CANCUN;
        let mut evm = EthEvmBuilder::new(db, env).build();
        let address = Address::new(reth_unicity_b2::address());
        assert!(evm.precompiles_mut().get(&address).is_none());
        if install {
            evm.precompiles_mut()
                .apply_precompile(&address, |_| Some(B2Precompile::default().into_dyn()));
        }
        let result = evm
            .transact(TxEnv {
                caller,
                kind: TxKind::Call(target),
                gas_limit: 2_000_000,
                data: Bytes::copy_from_slice(&input),
                ..Default::default()
            })
            .unwrap()
            .result;
        assert!(result.is_success(), "{result:?}");
        assert_eq!(
            result.output().unwrap().as_ref(),
            if install { expected.bytes.as_slice() } else { &[] }
        );
    }
    assert_eq!(common::vectors()["vectors"].as_array().unwrap().len(), 34);
}

#[test]
fn provider_maps_false_malformed_budget_and_oog() {
    use alloy_evm::{
        eth::EthEvmContext,
        precompiles::{Precompile, PrecompileInput},
        EvmInternals,
    };
    use revm::{handler::precompile_output_to_interpreter_result, interpreter::InstructionResult};
    let f = common::Fixture::new();
    let payload = f.prepare(0, &[1]);
    let input = common::abi(0, &f.cfg, &payload);
    let mut ctx = EthEvmContext::new(InMemoryDB::default(), Default::default());
    let pc = B2Precompile::default();
    let mut call = |data: &[u8], gas| {
        pc.call(PrecompileInput {
            data,
            gas,
            reservoir: 0,
            caller: Address::ZERO,
            value: U256::ZERO,
            is_static: true,
            internals: EvmInternals::from_context(&mut ctx),
            target_address: Address::new(reth_unicity_b2::address()),
            bytecode_address: Address::new(reth_unicity_b2::address()),
        })
        .unwrap()
    };
    let out = call(&input, u64::MAX);
    assert_eq!(out.bytes, reth_unicity_b2::run(&input, u64::MAX).unwrap().bytes);
    assert_eq!(
        precompile_output_to_interpreter_result(out, u64::MAX).result,
        InstructionResult::Return
    );
    let out = call(&input, 0);
    assert_eq!(
        precompile_output_to_interpreter_result(out, 0).result,
        InstructionResult::PrecompileOOG
    );
    for data in [vec![0; 65537], vec![0]] {
        let out = call(&data, u64::MAX);
        let result = precompile_output_to_interpreter_result(out, u64::MAX);
        assert_eq!(result.result, InstructionResult::PrecompileError);
        assert!(result.output.is_empty());
        assert_eq!(result.gas.remaining(), 0);
    }
}
