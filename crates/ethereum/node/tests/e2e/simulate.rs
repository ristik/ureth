use crate::utils::{eth_payload_attributes, eth_payload_attributes_amsterdam};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{bytes, hex, Address, TxKind, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::{
    simulate::{SimBlock, SimulatePayload, SimulatedBlock},
    state::{AccountOverride, StateOverride, StateOverridesBuilder},
    BlockOverrides, TransactionRequest, TransactionTrait as _,
};
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};
use reth_e2e_test_utils::{setup, setup_engine, transaction::TransactionTestContext};
use reth_node_ethereum::EthereumNode;
use reth_provider::BlockReader;
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::test]
async fn pending_simulation_replays_ethereum_pool_transactions() -> eyre::Result<()> {
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json"))?)
            .cancun_activated()
            .build(),
    );
    let (mut nodes, wallet) =
        setup::<EthereumNode>(1, chain_spec, false, eth_payload_attributes).await?;
    let node = nodes.pop().unwrap();
    let client = node.rpc_client().unwrap();
    let recipient = Address::repeat_byte(0x43);
    let amount = U256::from(100);
    let tx = TransactionRequest {
        to: Some(TxKind::Call(recipient)),
        value: Some(amount),
        chain_id: Some(1),
        nonce: Some(0),
        gas: Some(21_000),
        gas_price: Some(20_000_000_000),
        ..Default::default()
    };
    let tx = TransactionTestContext::sign_tx(wallet.inner, tx).await;
    let tx_hash = node.rpc.inject_tx(tx.encoded_2718().into()).await?;
    assert!(node.inner.provider.pending_block()?.is_none());
    let pending: Value = client.request("eth_getBlockByNumber", ("pending", false)).await?;
    assert_eq!(pending["number"], "0x1");
    assert_eq!(pending["transactions"], json!([tx_hash]));

    // Return the block number and the transfer recipient's balance.
    let to = Address::repeat_byte(0x42);
    let code = format!("0x4360005273{}3160205260406000f3", hex::encode(recipient));
    let overrides = json!({ (format!("{to:#x}")): { "code": code } });
    let call = json!({ "to": to });
    let bundles = json!([{ "transactions": [call.clone()] }]);
    let expected = |balance: U256| format!("0x{:064x}{balance:064x}", 1);
    let full: Value = client
        .request(
            "eth_callMany",
            rpc_params![bundles.clone(), json!({ "blockNumber": "pending" }), overrides.clone()],
        )
        .await?;
    assert_eq!(full[0][0]["value"], expected(amount));

    let traces: Value = client
        .request(
            "debug_traceCallMany",
            rpc_params![
                bundles,
                json!({ "blockNumber": "pending", "transactionIndex": 0 }),
                json!({ "stateOverrides": overrides.clone() })
            ],
        )
        .await?;
    let indexed: Value = client
        .request(
            "debug_traceCall",
            rpc_params![call, "pending", json!({ "stateOverrides": overrides, "txIndex": "0x0" })],
        )
        .await?;
    for trace in [&traces[0][0], &indexed] {
        assert_eq!(trace["failed"], false);
        assert_eq!(trace["returnValue"], expected(U256::ZERO));
    }
    Ok(())
}

#[tokio::test]
async fn test_simulate_v1_explicit_gas_uses_remaining_block_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec,
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let tx = TransactionRequest::default().to(Address::ZERO).gas_limit(3_000_000);
    let sim_block = SimBlock::default().call(tx.clone()).call(tx);
    let payload = SimulatePayload::default().extend(sim_block);

    let result: Vec<SimulatedBlock> =
        provider.raw_request("eth_simulateV1".into(), (&payload, "latest")).await?;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].calls.len(), 2);
    assert!(result[0].calls.iter().all(|call| call.status));

    Ok(())
}

#[tokio::test]
async fn test_simulate_v1_no_fields_call_defaults_to_remaining_block_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec,
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let first_tx_gas_limit = 21_000;
    let sim_block = SimBlock::default()
        .call(TransactionRequest::default().to(Address::ZERO).gas_limit(first_tx_gas_limit))
        .call(TransactionRequest::default());
    let payload = SimulatePayload::default().with_full_transactions().extend(sim_block);

    let result: Vec<SimulatedBlock> =
        provider.raw_request("eth_simulateV1".into(), (&payload, "latest")).await?;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].calls.len(), 2);
    assert!(result[0].calls.iter().all(|call| call.status));

    let block = &result[0].inner;
    let txs = block.transactions.as_transactions().expect("expected full transactions");
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0].gas_limit(), first_tx_gas_limit);

    let expected_remaining_gas = block.header.inner.gas_limit - result[0].calls[0].gas_used;
    assert_eq!(txs[1].gas_limit(), expected_remaining_gas);

    Ok(())
}

async fn assert_validation_uses_remaining_gas(
    chain_spec: Arc<ChainSpec>,
    payload_attributes: fn(u64) -> PayloadAttributes,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut nodes, wallet) =
        setup_engine::<EthereumNode>(1, chain_spec, false, Default::default(), payload_attributes)
            .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let from: Address = "0xc000000000000000000000000000000000000000".parse()?;
    let state_overrides =
        StateOverridesBuilder::default().with_balance(from, U256::from(1_000_000_000u64)).build();
    let tx = TransactionRequest::default()
        .from(from)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .nonce(0)
        // Create an empty contract so Amsterdam exercises the state-gas reservoir.
        .input(bytes!("0x60006000f3").into());
    let sim_block = SimBlock::default()
        .with_block_overrides(BlockOverrides {
            gas_limit: Some(30_000_000),
            base_fee: Some(U256::ZERO),
            ..Default::default()
        })
        .with_state_overrides(state_overrides)
        .call(tx);
    let payload =
        SimulatePayload::default().with_validation().with_full_transactions().extend(sim_block);

    let result: Vec<SimulatedBlock> =
        provider.raw_request("eth_simulateV1".into(), (&payload, "latest")).await?;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].calls.len(), 1);
    assert!(result[0].calls[0].status);
    let txs = result[0].inner.transactions.as_transactions().expect("expected full transactions");
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].gas_limit(), 30_000_000);
    assert!(txs[0].gas_limit() > (1 << 24));

    Ok(())
}

#[tokio::test]
async fn test_simulate_v1_validation_omitted_gas_uses_remaining_gas_osaka() -> eyre::Result<()> {
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .osaka_activated()
            .build(),
    );
    assert_validation_uses_remaining_gas(chain_spec, eth_payload_attributes).await
}

#[tokio::test]
async fn test_simulate_v1_validation_omitted_gas_uses_remaining_gas_amsterdam() -> eyre::Result<()>
{
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .amsterdam_activated()
            .build(),
    );
    assert_validation_uses_remaining_gas(chain_spec, eth_payload_attributes_amsterdam).await
}

#[tokio::test]
async fn test_simulate_v1_blockhash_reads_prior_simulated_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec,
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let contract = Address::with_last_byte(0x42);
    let mut state_overrides = StateOverride::default();
    state_overrides.insert(
        contract,
        AccountOverride::default().with_code(bytes!("0x6004354303405f5260205ff3")),
    );
    let input =
        bytes!("0xee82ac5e000000000000000000000000000000000000000000000000000000000000000f").into();

    let payload = SimulatePayload::default().extend(SimBlock::default()).extend(
        SimBlock::default()
            .with_block_overrides(BlockOverrides {
                number: Some(U256::from(16)),
                ..Default::default()
            })
            .with_state_overrides(state_overrides)
            .call(TransactionRequest::default().to(contract).input(input)),
    );

    let result: Vec<SimulatedBlock> =
        provider.raw_request("eth_simulateV1".into(), (&payload, "latest")).await?;

    assert_eq!(result.len(), 16);
    assert_eq!(result[15].calls.len(), 1);
    assert!(result[15].calls[0].status);
    assert_eq!(result[15].calls[0].return_data.as_ref(), result[0].inner.header.hash.as_slice());

    Ok(())
}

#[tokio::test]
async fn test_simulate_v1_explicit_gas_over_remaining_block_gas_errors() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec,
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let sim_block = SimBlock::default()
        .with_block_overrides(BlockOverrides { gas_limit: Some(50_000), ..Default::default() })
        .call(TransactionRequest::default().to(Address::ZERO))
        .call(TransactionRequest::default().to(Address::ZERO).gas_limit(30_000));
    let payload = SimulatePayload::default().extend(sim_block);

    let err = provider
        .raw_request::<_, Vec<SimulatedBlock>>("eth_simulateV1".into(), (&payload, "latest"))
        .await
        .unwrap_err();
    let err = err.as_error_resp().expect("expected JSON-RPC error response");

    assert_eq!(err.code, -38015);
    assert_eq!(err.message, "Block gas limit exceeded by the block's transactions");

    Ok(())
}

/// Tests that `eth_simulateV1` handles a transaction with `maxFeePerBlobGas` set but no
/// `blob_versioned_hashes` or sidecar. The transaction should be treated as EIP-1559, not
/// EIP-4844.
///
/// Reproduces <https://github.com/paradigmxyz/reth/issues/21809>
#[tokio::test]
async fn test_simulate_v1_with_max_fee_per_blob_gas_only() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec.clone(),
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let mut node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let _ = provider.send_transaction(TransactionRequest::default().to(Address::ZERO)).await?;
    node.advance_block().await?;

    let from: Address = "0xc000000000000000000000000000000000000000".parse()?;
    let to: Address = "0xc100000000000000000000000000000000000000".parse()?;

    let tx = TransactionRequest::default()
        .from(from)
        .to(to)
        .gas_limit(0x52080)
        .max_fee_per_gas(0)
        .max_priority_fee_per_gas(0)
        .max_fee_per_blob_gas(0)
        .value(U256::ZERO)
        .nonce(0)
        .input(Default::default());

    let state_overrides =
        StateOverridesBuilder::default().with_balance(from, U256::from(0x334500u64)).build();

    let sim_block = SimBlock::default()
        .with_block_overrides(BlockOverrides { base_fee: Some(U256::ZERO), ..Default::default() })
        .with_state_overrides(state_overrides)
        .call(tx);

    let payload = SimulatePayload::default().with_validation().extend(sim_block);

    let result: Vec<SimulatedBlock> =
        provider.raw_request("eth_simulateV1".into(), (&payload, "latest")).await?;

    assert_eq!(result.len(), 1, "expected exactly 1 simulated block");
    assert_eq!(result[0].calls.len(), 1, "expected exactly 1 call result");
    let call = &result[0].calls[0];
    assert!(call.status, "expected call to succeed");
    assert!(call.error.is_none(), "expected no error");
    assert_eq!(call.max_used_gas, Some(call.gas_used), "expected maxUsedGas in call result");

    Ok(())
}

#[tokio::test]
async fn test_simulate_v1_too_many_blocks_error() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(serde_json::from_str(include_str!("../assets/genesis.json")).unwrap())
            .cancun_activated()
            .build(),
    );

    let (mut nodes, wallet) = setup_engine::<EthereumNode>(
        1,
        chain_spec,
        false,
        Default::default(),
        eth_payload_attributes,
    )
    .await?;
    let node = nodes.pop().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(wallet.wallet_gen().swap_remove(0)))
        .connect_http(node.rpc_url());

    let payload: SimulatePayload<TransactionRequest> =
        (0..257).fold(SimulatePayload::default(), |payload, _| payload.extend(SimBlock::default()));

    let err = provider
        .raw_request::<_, Vec<SimulatedBlock>>("eth_simulateV1".into(), (&payload, "latest"))
        .await
        .unwrap_err();
    let err = err.as_error_resp().expect("expected JSON-RPC error response");

    assert_eq!(err.code, -38026);
    assert_eq!(err.message, "too many blocks");

    Ok(())
}
