//! Transaction-only gossip among Unicity validators (ristik/ureth#34, bft-core #710).
//!
//! Each test launches real [`UnicityNode`]s in this process (real network, real pool, no block
//! sync) and wires them as trusted peers, the way the shard node wires a validator set. A
//! validator that receives a transaction it did not submit is the one that can include it when
//! its turn comes, so every scenario asks: did the transaction reach another validator's pool?

use alloy_consensus::{transaction::SignerRecoverable, SignableTransaction, TxLegacy};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, TxKind, B256, U256};
use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};
use reth_ethereum_primitives::{Transaction, TransactionSigned};
use reth_network_api::{Peers, PeersInfo};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{NetworkArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_primitives_traits::crypto::secp256k1::sign_message;
use reth_storage_api::BlockNumReader;
use reth_tasks::Runtime;
use reth_transaction_pool::{
    EthPooledTransaction, PoolTransaction, TransactionOrigin, TransactionPool,
};
use reth_unicity_execution::{block::BlockProfile, pairing::PairPins, update::B1Context};
use reth_unicity_payload::{GossipGate, SealJobRegistry, UnicityNode, UnicitySealConfig};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Hardhat account #1: funded in the test genesis.
const SENDER_KEY: [u8; 32] = [
    0x59, 0xc6, 0x99, 0x5e, 0x99, 0x8f, 0x97, 0xa5, 0xa0, 0x04, 0x49, 0x66, 0xf0, 0x94, 0x53, 0x89,
    0xdc, 0x9e, 0x86, 0xda, 0xe8, 0x8a, 0x7c, 0x84, 0x12, 0xf4, 0x60, 0x3b, 0x6b, 0x78, 0x69, 0x0d,
];

fn chain_spec() -> Arc<ChainSpec> {
    let genesis: Genesis = serde_json::from_str(include_str!("assets/genesis.json")).unwrap();
    Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(genesis)
            .cancun_activated()
            .build(),
    )
}

fn seal_config() -> UnicitySealConfig {
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
    }
}

/// Launches a Unicity node with its gate closed (`open == false`) or open. Expands to the launched
/// node, so that the node's concrete type is inferred rather than spelled out.
macro_rules! validator {
    ($open:expr) => {{
        let unicity = UnicityNode::new(SealJobRegistry::new(), seal_config());
        let gate: GossipGate = unicity.gossip_gate().clone();
        if $open {
            gate.open();
        }
        let mut network = NetworkArgs::default().with_unused_ports();
        network.discovery.disable_discovery = true;
        network.discovery.disable_dns_discovery = true;
        let config = NodeConfig::test()
            .with_chain(chain_spec())
            .with_network(network)
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());
        let NodeHandle { node, node_exit_future: _ } =
            NodeBuilder::new(config).testing_node(Runtime::test()).node(unicity).launch().await?;
        (node, gate)
    }};
}

fn transfer(nonce: u64, gas_price: u128, signer_key: [u8; 32]) -> TransactionSigned {
    let tx = TxLegacy {
        chain_id: Some(1),
        nonce,
        gas_price,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0xaa)),
        value: U256::from(1),
        input: Default::default(),
    };
    let tx = Transaction::Legacy(tx);
    let signature = sign_message(B256::from(signer_key), tx.signature_hash()).unwrap();
    TransactionSigned::new_unhashed(tx, signature)
}

fn pooled(tx: TransactionSigned) -> EthPooledTransaction {
    let recovered = tx.try_into_recovered().expect("valid signature");
    let len = alloy_eips::eip2718::Encodable2718::encode_2718_len(&recovered);
    EthPooledTransaction::new(recovered, len)
}

fn dial_address(record: reth_network_peers::NodeRecord) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), record.tcp_port)
}

/// Makes `a` and `b` trusted peers of each other, the way a validator set is configured.
macro_rules! trust_each_other {
    ($a:expr, $b:expr) => {{
        let ra = $a.network.local_node_record();
        let rb = $b.network.local_node_record();
        $a.network.add_trusted_peer(rb.id, dial_address(rb));
        $b.network.add_trusted_peer(ra.id, dial_address(ra));
    }};
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn stays_false(for_how_long: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + for_how_long;
    while tokio::time::Instant::now() < end {
        if condition() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_sent_to_a_non_proposer_reaches_the_ready_validator() -> eyre::Result<()> {
    // A: where the user submits. B: the next proposer, not yet caught up (gate closed).
    let (a, _gate_a) = validator!(true);
    let (b, gate_b) = validator!(false);
    trust_each_other!(a, b);
    eventually("A and B connect", || a.network.num_connected_peers() == 1).await;

    // Before B is ready (no authenticated seal progress yet) it imports nothing, even from a
    // trusted peer: sync readiness is what gates the transaction manager.
    let early = pooled(transfer(0, 10_000_000_000, SENDER_KEY));
    let early_hash = *early.hash();
    a.pool.add_transaction(TransactionOrigin::Local, early).await?;
    assert!(
        stays_false(Duration::from_secs(3), || b.pool.contains(&early_hash)).await,
        "a validator that has not caught up through the authenticated path imports no gossip"
    );

    // Authenticated progress opens B's gate; the next transaction reaches B's pool although it
    // was submitted to A only.
    gate_b.open();
    let tx = pooled(transfer(1, 10_000_000_000, SENDER_KEY));
    let hash = *tx.hash();
    a.pool.add_transaction(TransactionOrigin::Local, tx).await?;
    eventually("B's pool holds the transaction", || b.pool.contains(&hash)).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_transaction_stays_after_the_receiving_node_left() -> eyre::Result<()> {
    let (a, _) = validator!(true);
    let (b, _) = validator!(true);
    trust_each_other!(a, b);
    eventually("A and B connect", || a.network.num_connected_peers() == 1).await;

    let tx = pooled(transfer(0, 10_000_000_000, SENDER_KEY));
    let hash = *tx.hash();
    a.pool.add_transaction(TransactionOrigin::Local, tx).await?;
    eventually("B's pool holds the transaction", || b.pool.contains(&hash)).await;

    // The node that took the submission goes away (here: B removes and disconnects it): the
    // transaction is B's now and does not depend on A being reachable.
    let ra = a.network.local_node_record();
    b.network.remove_peer(ra.id, reth_network_types::PeerKind::Trusted);
    b.network.disconnect_peer(ra.id);
    eventually("B has no peers", || b.network.num_connected_peers() == 0).await;
    assert!(b.pool.contains(&hash), "the gossiped transaction survives the submitter");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_validator_that_connects_later_receives_the_pending_pool() -> eyre::Result<()> {
    let (b, _) = validator!(true);
    let tx = pooled(transfer(0, 10_000_000_000, SENDER_KEY));
    let hash = *tx.hash();
    b.pool.add_transaction(TransactionOrigin::Local, tx).await?;

    // C starts after the transaction was submitted and connects (a reconnect or a new member):
    // B announces its pending pool to the new session.
    let (c, _) = validator!(true);
    trust_each_other!(b, c);
    eventually("C's pool holds the transaction", || c.pool.contains(&hash)).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_follow_membership_changes() -> eyre::Result<()> {
    let (b, _) = validator!(true);
    let (d, _) = validator!(true);

    // D is not a member yet: nothing is shared.
    let first = pooled(transfer(0, 10_000_000_000, SENDER_KEY));
    let first_hash = *first.hash();
    b.pool.add_transaction(TransactionOrigin::Local, first).await?;
    assert!(stays_false(Duration::from_secs(2), || d.pool.contains(&first_hash)).await);

    // D joins the validator set: it receives B's pending pool and what follows.
    trust_each_other!(b, d);
    eventually("D joined", || b.network.num_connected_peers() == 1).await;
    eventually("D's pool holds the earlier transaction", || d.pool.contains(&first_hash)).await;

    // D leaves the set: a transaction submitted after that does not reach it.
    let rd = d.network.local_node_record();
    b.network.remove_peer(rd.id, reth_network_types::PeerKind::Trusted);
    b.network.disconnect_peer(rd.id);
    eventually("D left", || b.network.num_connected_peers() == 0).await;
    let rb = b.network.local_node_record();
    d.network.remove_peer(rb.id, reth_network_types::PeerKind::Trusted);
    let second = pooled(transfer(1, 10_000_000_000, SENDER_KEY));
    let second_hash = *second.hash();
    b.pool.add_transaction(TransactionOrigin::Local, second).await?;
    assert!(
        stays_false(Duration::from_secs(3), || d.pool.contains(&second_hash)).await,
        "a validator that is no longer a member receives nothing"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_is_not_a_transaction_peer() -> eyre::Result<()> {
    let (a, _) = validator!(true);
    let (stranger, _) = validator!(true);
    // The stranger trusts A and dials it; A has not added the stranger, so A refuses the session
    // (the network is built with trusted_nodes_only).
    let ra = a.network.local_node_record();
    stranger.network.add_trusted_peer(ra.id, dial_address(ra));
    assert!(
        stays_false(Duration::from_secs(3), || a.network.num_connected_peers() > 0).await,
        "an unconfigured peer is not connected"
    );
    let tx = pooled(transfer(0, 10_000_000_000, SENDER_KEY));
    let hash = *tx.hash();
    a.pool.add_transaction(TransactionOrigin::Local, tx).await?;
    assert!(stays_false(Duration::from_secs(2), || stranger.pool.contains(&hash)).await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_and_invalid_traffic_stays_bounded() -> eyre::Result<()> {
    let (a, _) = validator!(true);
    let (b, _) = validator!(true);
    trust_each_other!(a, b);
    eventually("A and B connect", || a.network.num_connected_peers() == 1).await;

    let tx = transfer(0, 10_000_000_000, SENDER_KEY);
    let hash = *tx.tx_hash();
    // The same transaction twice: the pool deduplicates, the second insertion is an error, and B
    // holds exactly one copy.
    a.pool.add_transaction(TransactionOrigin::Local, pooled(tx.clone())).await?;
    assert!(a.pool.add_transaction(TransactionOrigin::Local, pooled(tx)).await.is_err());
    eventually("B's pool holds the transaction", || b.pool.contains(&hash)).await;
    assert_eq!(b.pool.pool_size().total, 1);

    // A transaction that is invalid for this chain (underpriced, from the same sender) is
    // rejected by A's own validation before anything is gossiped; B never sees it.
    let invalid = transfer(1, 0, SENDER_KEY);
    let invalid_hash = *invalid.tx_hash();
    assert!(a.pool.add_transaction(TransactionOrigin::Local, pooled(invalid)).await.is_err());
    assert!(stays_false(Duration::from_secs(2), || b.pool.contains(&invalid_hash)).await);
    assert_eq!(
        a.network.num_connected_peers(),
        1,
        "invalid local traffic does not cost the session"
    );
    Ok(())
}

/// A trusted peer that is hostile: it announces blocks the node never asked for. Block and header
/// traffic from the network cannot advance the canonical head; only the authenticated seal
/// methods do.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_block_announcement_cannot_advance_the_head() -> eyre::Result<()> {
    use alloy_consensus::Header;
    use reth_ethereum_primitives::{Block, BlockBody};
    use reth_network::{EthNetworkPrimitives, NetworkConfig, NetworkManager};
    use reth_provider::test_utils::NoopProvider;

    let (a, _) = validator!(true);
    let head_before = a.provider.best_block_number()?;

    // A plain reth network (the hostile validator) on the same chain, configured as A's peer.
    let secret = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
    let config = NetworkConfig::<_, EthNetworkPrimitives>::builder(secret, Runtime::test())
        .listener_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .disable_discovery()
        .build(NoopProvider::eth(chain_spec()));
    let hostile = NetworkManager::new(config).await?;
    let hostile_handle = hostile.handle().clone();
    tokio::spawn(hostile);

    let ra = a.network.local_node_record();
    let rh = hostile_handle.local_node_record();
    a.network.add_trusted_peer(rh.id, dial_address(rh));
    hostile_handle.add_trusted_peer(ra.id, dial_address(ra));
    eventually("the hostile peer connects", || a.network.num_connected_peers() == 1).await;

    // It announces a block on top of genesis, with and without the body.
    let genesis_hash = chain_spec().genesis_hash();
    let header = Header { number: 1, parent_hash: genesis_hash, ..Default::default() };
    let block = Block { header, body: BlockBody::default() };
    let hash = block.header.hash_slow();
    hostile_handle.announce_block(
        reth_eth_wire_types::NewBlock { block, td: alloy_primitives::U128::from(1) }.into(),
        hash,
    );

    assert!(
        stays_false(Duration::from_secs(3), || a
            .provider
            .best_block_number()
            .map(|n| n != head_before)
            .unwrap_or(true))
        .await,
        "a block announced over the network does not move the canonical head"
    );
    // And nothing can be fetched from peers on behalf of the engine.
    use reth_network_api::BlockDownloaderProvider;
    use reth_network_p2p::headers::client::HeadersClient;
    let client = a.network.fetch_client().await?;
    assert_eq!(reth_network_p2p::download::DownloadClient::num_connected_peers(&client), 0);
    let _ = client.get_header(alloy_eips::BlockHashOrNumber::Number(1));
    Ok(())
}
