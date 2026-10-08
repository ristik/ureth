//! The B1 precompiles on the node's RPC execution routes.
//!
//! Block execution, `eth_call`, `eth_estimateGas` and tracing all build their EVM from the node's
//! `ConfigureEvm`, so one factory serves every route. This launches a real Unicity node whose
//! genesis carries a STATICCALL caller contract and a registry pre-state taken from bft-core's
//! pinned conformance manifest (an injected simulation of authenticated state, as in the kernel
//! tests), then asks the node over HTTP: the result matches the manifest, an explicit state
//! override can change it (a simulation, never canonical authority), the estimate covers the
//! manifest charge, and a call trace shows the precompile frame.

use alloy_genesis::Genesis;
use alloy_primitives::{address, Address, Bytes, B256, U256};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{NetworkArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_rpc_server_types::RpcModuleSelection;
use reth_tasks::Runtime;
use reth_unicity_b1::{entry_slot, fixed_slot, member_slot, Operation, REGISTRY};
use reth_unicity_execution::{
    block::BlockProfile,
    pairing::PairPins,
    testing::{b1_context, world},
};
use reth_unicity_payload::{SealJobRegistry, UnicityNode, UnicitySealConfig};
use serde_json::{json, Value};
use std::sync::Arc;

const MANIFEST: &str = include_str!("../../b1/tests/testdata/go-4ba487e.json");
const GENESIS: &str = include_str!("../testdata/signed-beacon-genesis.json");
const CALLER: Address = address!("2000000000000000000000000000000000000002");

fn hex(s: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(s).unwrap()
}

fn word_hex(v: U256) -> String {
    format!("0x{}", alloy_primitives::hex::encode(v.to_be_bytes::<32>()))
}

/// Forwards its calldata with `STATICCALL` to the address in its first two bytes of immediate and
/// returns `success ++ returndata`.
fn caller_code(target: Address) -> String {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x61];
    code.extend_from_slice(&target.0[18..20]);
    code.extend_from_slice(&[0x5a, 0xfa, 0x5f, 0x52, 0x3d, 0x5f, 0x60, 0x20, 0x3e]);
    code.extend_from_slice(&[0x3d, 0x60, 0x20, 0x01, 0x5f, 0xf3]);
    format!("0x{}", alloy_primitives::hex::encode(code))
}

/// The registry words a manifest pre-state describes.
fn registry_words(pre: &Value) -> Vec<(U256, U256)> {
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

#[tokio::test]
async fn rpc_routes_run_the_same_precompiles_over_the_same_registry_state() -> eyre::Result<()> {
    let manifest: Value = serde_json::from_str(MANIFEST)?;
    let vector = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "cert.single.ok")
        .unwrap()
        .clone();
    let request = hex(vector["request"].as_str().unwrap());
    let charge = vector["expected"]["gas"].as_u64().unwrap();
    let expected_output = vector["expected"]["output"].as_str().unwrap().to_owned();

    // Genesis: the B1 world with the manifest's registry words overlaid and a caller contract.
    let mut doc: Value = serde_json::from_str(GENESIS)?;
    let registry_key = format!("{REGISTRY:#x}");
    let storage: &mut Value = &mut doc["alloc"][registry_key.as_str()]["storage"];
    *storage = json!({});
    for (slot, value) in registry_words(&vector["preState"]) {
        storage[word_hex(slot)] = json!(word_hex(value));
    }
    doc["alloc"][format!("{CALLER:#x}")] =
        json!({ "balance": "0x0", "code": caller_code(Operation::Uc.address()) });
    let genesis: Genesis = serde_json::from_value(doc)?;
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(genesis)
            .cancun_activated()
            .build(),
    );

    let mut network = NetworkArgs::default().with_unused_ports();
    network.discovery.disable_discovery = true;
    network.discovery.disable_dns_discovery = true;
    let node_config = NodeConfig::test()
        .with_chain(chain_spec)
        .with_network(network)
        .with_unused_ports()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        );
    let w = world();
    let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
        .testing_node(Runtime::test())
        .node(UnicityNode::new(
            SealJobRegistry::new(),
            UnicitySealConfig {
                profile: BlockProfile {
                    max_gas: w.max_gas,
                    system_gas: w.system_gas,
                    base_fee_floor: 7,
                    elasticity: 2,
                    change_denominator: 8,
                },
                fee_collector: Address::ZERO,
                pins: PairPins {
                    network_id: u64::from(w.network),
                    root_genesis_id: w.root_genesis_id,
                },
                b1: b1_context(),
            },
        ))
        .launch()
        .await?;
    let client = node
        .add_ons_handle
        .rpc_server_handles
        .rpc
        .http_client()
        .expect("http transport was enabled above");

    let call = |input: &[u8]| json!({ "to": format!("{CALLER:#x}"), "data": format!("0x{}", alloy_primitives::hex::encode(input)) });
    let params = |call: Value, extra: Vec<Value>| {
        let mut p = ArrayParams::new();
        p.insert(call).unwrap();
        for e in extra {
            p.insert(e).unwrap();
        }
        p
    };

    // eth_call: success flag 1, then the manifest's 64-byte answer.
    let out: Bytes =
        client.request("eth_call", params(call(&request), vec![json!("latest")])).await?;
    assert_eq!(out.len(), 32 + 64);
    assert_eq!(&out[..32], B256::with_last_byte(1).as_slice());
    assert_eq!(out[32..], hex(&expected_output)[..]);

    // eth_estimateGas covers the intrinsic cost, the precompile charge and the caller's work.
    let estimate: U256 =
        client.request("eth_estimateGas", params(call(&request), vec![json!("latest")])).await?;
    assert!(estimate > U256::from(21_000 + charge), "estimate {estimate} below the charge");

    // An explicit state override is a simulation: erasing the certificate's epoch makes the seal an
    // unknown epoch, so the answer is a well-formed false. It establishes no canonical authority.
    let seal_epoch = vector["preState"]["epochs"][0]["epoch"].as_u64().unwrap();
    // Every word of the entry is cleared: a half-erased entry is an impossible registry and an
    // infrastructure error, never a verdict.
    let erased: serde_json::Map<String, Value> = (0..11)
        .map(|f| (word_hex(entry_slot(seal_epoch, f)), json!(word_hex(U256::ZERO))))
        .collect();
    let overrides = json!({ format!("{REGISTRY:#x}"): { "stateDiff": erased } });
    let simulated: Bytes = client
        .request("eth_call", params(call(&request), vec![json!("latest"), overrides]))
        .await?;
    assert_eq!(&simulated[..32], B256::with_last_byte(1).as_slice(), "the call itself succeeds");
    assert_eq!(simulated[32 + 63], 0, "an unknown epoch is a false verdict");
    assert_ne!(simulated, out);

    // A half-erased entry is an impossible registry, which surfaces as an infrastructure error and
    // never as a false verdict.
    let half = json!({
        format!("{REGISTRY:#x}"): { "stateDiff": { word_hex(entry_slot(seal_epoch, 0)): word_hex(U256::ZERO) } }
    });
    let error = client
        .request::<Bytes, _>("eth_call", params(call(&request), vec![json!("latest"), half]))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("impossible admitted B1 registry"), "{error}");

    // The trace shows the precompile frame under the caller.
    let trace: Value = client
        .request(
            "debug_traceCall",
            params(call(&request), vec![json!("latest"), json!({ "tracer": "callTracer" })]),
        )
        .await?;
    let frames = trace["calls"].as_array().expect("the caller made one call");
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0]["to"].as_str().unwrap().to_lowercase(),
        format!("{:#x}", Operation::Uc.address())
    );
    assert_eq!(frames[0]["type"], "STATICCALL");
    // The traced frame ran the kernel: the manifest's answer at the manifest's charge, not the
    // empty success an unregistered address gives.
    assert_eq!(frames[0]["output"].as_str().unwrap(), format!("0x{expected_output}"));
    assert_eq!(
        u64::from_str_radix(frames[0]["gasUsed"].as_str().unwrap().trim_start_matches("0x"), 16)?,
        charge
    );
    Ok(())
}
