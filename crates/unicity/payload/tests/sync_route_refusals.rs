//! Ensure the Unicity node refuses the generic execution networking routes.

use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, B512};
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_eth_wire_types::snap::GetAccountRangeMessage;
use reth_network_api::{noop::NoopNetwork, BlockDownloaderProvider, NetworkInfo, Peers, PeersInfo};
use reth_network_p2p::{error::RequestError, snap::client::SnapClient};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{NetworkArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_tasks::Runtime;
use reth_unicity_execution::{block::BlockProfile, pairing::PairPins};
use reth_unicity_payload::{SealJobRegistry, UnicityNode, UnicitySealConfig};
use std::{net::SocketAddr, sync::Arc};

async fn launch_unicity_network() -> eyre::Result<NoopNetwork> {
    let genesis: Genesis = serde_json::from_str(include_str!("assets/genesis.json"))?;
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
                pins: PairPins { network_id: 3, root_genesis_id: B256::repeat_byte(0x5a) },
            },
        ))
        .launch()
        .await?;
    // The concrete return type makes this a production-builder assertion: changing the Unicity
    // node back to Reth's normal network builder makes this regression test stop compiling.
    Ok(node.network)
}

#[tokio::test]
async fn generic_el_p2p_sync_is_refused() -> eyre::Result<()> {
    let network = launch_unicity_network().await?;

    let peer = B512::repeat_byte(0x44);
    let address: SocketAddr = "127.0.0.1:30303".parse()?;
    network.add_peer(peer, address);
    network.connect_peer(peer, address);
    assert_eq!(network.num_connected_peers(), 0, "generic EL P2P cannot add a peer");
    assert!(network.get_all_peers().await?.is_empty());
    assert!(
        !network.is_initially_syncing(),
        "the generic execution pipeline has no network sync source"
    );
    assert!(!network.is_syncing());
    Ok(())
}

#[tokio::test]
async fn generic_el_snap_sync_is_refused() -> eyre::Result<()> {
    let network = launch_unicity_network().await?;
    let snap = network.fetch_client().await?;
    let result = snap
        .get_account_range(GetAccountRangeMessage {
            request_id: 1,
            root_hash: B256::ZERO,
            starting_hash: B256::ZERO,
            limit_hash: B256::repeat_byte(0xff),
            response_bytes: 1024,
        })
        .await;
    assert_eq!(result.unwrap_err(), RequestError::UnsupportedCapability);
    Ok(())
}
