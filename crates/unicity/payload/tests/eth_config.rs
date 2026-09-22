//! `eth_config` (EIP-7910) must be served by the Unicity node.
//!
//! The stock node registers this handler inside `EthereumNode::launch_add_ons`
//! (`crates/ethereum/node/src/node.rs`). `UnicityNode` assembles its own add-ons and so does not
//! go through that function; when it silently lost the handler, the method was simply absent and
//! the node answered `-32601 Method not found`.
//!
//! That is not a cosmetic gap. A consensus client reads `eth_config` at startup to refuse an
//! execution client whose loaded chain spec is not the one it expects, and it requires `next` and
//! `last` to be *present and null* rather than omitted — an answer that leaves them out has not
//! said "nothing is scheduled". A Unicity node without this method is a node nothing will pair
//! with, so the check is asserted here against a really launched node rather than by reading the
//! builder chain.

use alloy_eips::eip7910::EthConfig;
use alloy_genesis::Genesis;
use alloy_primitives::Address;
use jsonrpsee::core::client::ClientT;
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{NetworkArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_tasks::Runtime;
use reth_unicity_execution::block::BlockProfile;
use reth_unicity_payload::{SealJobRegistry, UnicityNode, UnicitySealConfig};
use std::sync::Arc;

#[tokio::test]
async fn unicity_node_serves_eth_config() -> eyre::Result<()> {
    let genesis: Genesis = serde_json::from_str(include_str!("assets/genesis.json"))?;
    // Cancun and nothing after it: the fixed profile the bounded execution kernel pins, so the
    // node under test is configured the way a real shard node configures it.
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(genesis)
            .cancun_activated()
            .build(),
    );

    // Peer discovery is off: this node is only ever asked one RPC question, and leaving discovery
    // on makes the test depend on the host's DNS configuration.
    let mut network = NetworkArgs::default().with_unused_ports();
    network.discovery.disable_discovery = true;
    network.discovery.disable_dns_discovery = true;

    let node_config = NodeConfig::test()
        .with_chain(chain_spec)
        .with_network(network)
        .with_unused_ports()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
        .testing_node(Runtime::test())
        .node(UnicityNode::new(
            SealJobRegistry::new(),
            UnicitySealConfig {
                profile: BlockProfile {
                    max_gas: 30_000_000,
                    system_gas: 2_000_000,
                    base_fee_floor: 1_000_000,
                    elasticity: 2,
                    change_denominator: 8,
                },
                fee_collector: Address::ZERO,
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

    // Deserializing into EthConfig is itself part of the assertion: the consensus client decodes
    // the same shape, so a response that answers but omits a required key fails here too.
    let config: EthConfig =
        client.request("eth_config", jsonrpsee::core::params::ArrayParams::new()).await?;

    assert!(config.next.is_none(), "the pinned profile schedules no next fork");
    assert!(config.last.is_none(), "the pinned profile schedules no last fork");
    assert_eq!(config.current.activation_time, 0, "Cancun is active from genesis");

    Ok(())
}
