//! Ensure the Unicity node refuses the generic execution networking routes.

use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, B512};
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_eth_wire_types::snap::GetAccountRangeMessage;
use reth_ethereum_primitives::{EthPrimitives, PooledTransactionVariant};
use reth_network::primitives::BasicNetworkPrimitives;
use reth_network_api::{BlockDownloaderProvider, NetworkInfo, Peers, PeersInfo};
use reth_network_p2p::{error::RequestError, snap::client::SnapClient};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{NetworkArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_tasks::Runtime;
use reth_unicity_execution::{block::BlockProfile, pairing::PairPins, update::B1Context};
use reth_unicity_payload::{SealJobRegistry, TxGossipNetwork, UnicityNode, UnicitySealConfig};
use std::{net::SocketAddr, sync::Arc};

type GossipNet = TxGossipNetwork<BasicNetworkPrimitives<EthPrimitives, PooledTransactionVariant>>;

async fn launch_unicity_network() -> eyre::Result<GossipNet> {
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
                b1: B1Context {
                    network: 3,
                    root_genesis_id: B256::repeat_byte(0x5a),
                    execution_chain_id: 1337,
                    profile_hash: B256::repeat_byte(2),
                    genesis_commitment: B256::repeat_byte(3),
                    max_epochs: 2,
                    hook: Default::default(),
                },
            },
        ))
        .launch()
        .await?;
    // The concrete return type makes this a production-builder assertion: changing the Unicity
    // node to Reth's normal network builder (or back to the no-op one) makes this regression test
    // stop compiling.
    Ok(node.network)
}

#[tokio::test]
async fn generic_el_p2p_sync_is_refused() -> eyre::Result<()> {
    let network = launch_unicity_network().await?;

    // Transaction gossip needs a real peer set, so a peer can now be added; nothing listens at
    // this address, so nothing connects, and what a connected peer could do is tested in
    // `tx_gossip.rs`.
    let peer = B512::repeat_byte(0x44);
    let address: SocketAddr = "127.0.0.1:30303".parse()?;
    network.add_peer(peer, address);
    network.connect_peer(peer, address);
    assert_eq!(network.num_connected_peers(), 0, "nothing listens at the peer's address");
    // Before any authenticated seal request the gate is closed: the network stays in its initial
    // syncing state, whatever the launcher reports, so no peer's transactions are imported.
    assert!(
        network.is_initially_syncing(),
        "the network reports Idle only after authenticated seal progress"
    );
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
