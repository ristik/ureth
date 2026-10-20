//! Transaction-only gossip among the EVM shard's validators (ristik/ureth#34).
//!
//! M1 installed `NoopNetworkBuilder`, which kept P2P from admitting blocks but also switched
//! transaction gossip off: a transaction was mined only when it reached the proposer's own pool.
//! This module builds the real reth network, so the stock `TransactionsManager` propagates pending
//! transactions with its validation, deduplication and bounded announce/fetch machinery, and wraps
//! the handle so that nothing can be downloaded from a peer:
//!
//! - [`TxGossipNetwork::fetch_client`] returns a client that fetches nothing, so neither the
//!   pipeline nor the engine's block downloader can obtain headers or bodies from the network (they
//!   take their client from `network.fetch_client()`); a downloaded block would have no
//!   authenticated seal input anyway. Blocks advance the chain only through the authenticated seal
//!   methods.
//! - The peer set is the configured one: the network is built with `trusted_nodes_only`, so only
//!   peers the operator (or the shard node, through `admin_addPeer` / `admin_removePeer` as
//!   validator membership changes) added are connected to; discovery stays whatever the node's
//!   network arguments say.
//! - Sync readiness: the transaction manager ignores gossip while the network reports
//!   `is_initially_syncing`, and the launcher moves the network to `Idle` on its own signals (a
//!   backfill, or a canonical head event). The wrapper does not forward those: `Idle` is passed on
//!   only once the [`GossipGate`] is open, and the gate is opened by the authenticated seal methods
//!   (an accepted seal import or an accepted seal build on an authenticated parent), i.e. when the
//!   node has caught up through the shard's authenticated path. `Syncing` is always forwarded.
//!
//! Serving headers and bodies to connected peers (the `eth` request handler) stays enabled. That is
//! a deliberate choice: serving is not admission, and a peer can only use what it fetches through
//! its own authenticated path.

use core::fmt;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use reth_chainspec::Hardforks;
use reth_eth_wire_types::{DisconnectReason, EthNetworkPrimitives, NetworkPrimitives};
use reth_ethereum_forks::Head;
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle};
use reth_network_api::{
    events::{NetworkPeersEvents, PeerEventStream},
    test_utils::{PeersHandle, PeersHandleProvider},
    BlockDownloaderProvider, CellCustody, DiscoveryEvent, NetworkError, NetworkEvent,
    NetworkEventListenerProvider, NetworkInfo, NetworkStatus, PeerId, PeerInfo, PeerRequest, Peers,
    PeersInfo,
};
use reth_network_p2p::{
    sync::{NetworkSyncUpdater, SyncState},
    NoopFullBlockClient,
};
use reth_network_peers::{NodeRecord, TrustedPeer};
use reth_network_types::{PeerKind, Reputation, ReputationChangeKind};
use reth_node_api::{PrimitivesTy, TxTy};
use reth_node_builder::{
    components::NetworkBuilder, node::FullNodeTypes, BuilderContext, NodeTypes,
};
use reth_tokio_util::EventStream;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnboundedReceiverStream;

/// The switch that lets the network report `Idle` to the transaction manager.
///
/// It starts closed. [`GossipGate::open`] is called by the authenticated seal methods; it is
/// idempotent and cheap after the first call. A gate shared by clones is one gate.
#[derive(Clone, Default)]
pub struct GossipGate {
    inner: Arc<GateInner>,
}

#[derive(Default)]
struct GateInner {
    open: AtomicBool,
    /// Called once, when the gate opens, to move the network to `Idle`.
    on_open: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl GossipGate {
    /// Creates a closed gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the gate and moves the network to `Idle`. Safe to call on every authenticated seal
    /// request; only the first call does anything.
    pub fn open(&self) {
        if self.inner.open.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(f) = self.inner.on_open.lock().expect("gossip gate lock").as_ref() {
            f();
        }
    }

    /// Whether the node has caught up through the authenticated path.
    pub fn is_open(&self) -> bool {
        self.inner.open.load(Ordering::Acquire)
    }

    /// Registers what the gate does when it opens (the builder registers the network's own
    /// `Idle` update). If the gate is already open, it runs at once.
    fn on_open(&self, f: impl Fn() + Send + Sync + 'static) {
        let mut slot = self.inner.on_open.lock().expect("gossip gate lock");
        if self.is_open() {
            f();
        }
        *slot = Some(Box::new(f));
    }
}

impl fmt::Debug for GossipGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GossipGate").field("open", &self.is_open()).finish()
    }
}

/// The real reth network with downloads switched off and sync readiness under a [`GossipGate`].
///
/// Everything delegates to the wrapped handle except [`BlockDownloaderProvider::fetch_client`]
/// (a client that fetches nothing) and [`NetworkSyncUpdater::update_sync_state`] (`Idle` only
/// through the gate).
#[derive(Debug, Clone)]
pub struct TxGossipNetwork<N: NetworkPrimitives = EthNetworkPrimitives> {
    inner: NetworkHandle<N>,
    gate: GossipGate,
}

impl<N: NetworkPrimitives> TxGossipNetwork<N> {
    /// Wraps `inner`; the gate decides when it reports `Idle`.
    pub fn new(inner: NetworkHandle<N>, gate: GossipGate) -> Self {
        let handle = inner.clone();
        gate.on_open(move || handle.update_sync_state(SyncState::Idle));
        Self { inner, gate }
    }

    /// The wrapped handle (for the node's own use, e.g. its enode record).
    pub const fn handle(&self) -> &NetworkHandle<N> {
        &self.inner
    }

    /// The gate this network reports `Idle` through.
    pub const fn gate(&self) -> &GossipGate {
        &self.gate
    }
}

impl<N: NetworkPrimitives> PeersInfo for TxGossipNetwork<N> {
    fn num_connected_peers(&self) -> usize {
        self.inner.num_connected_peers()
    }

    fn local_node_record(&self) -> NodeRecord {
        self.inner.local_node_record()
    }

    fn local_enr(&self) -> enr::Enr<enr::secp256k1::SecretKey> {
        self.inner.local_enr()
    }
}

impl<N: NetworkPrimitives> NetworkInfo for TxGossipNetwork<N> {
    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    async fn network_status(&self) -> Result<NetworkStatus, NetworkError> {
        self.inner.network_status().await
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn cell_custody(&self) -> &CellCustody {
        self.inner.cell_custody()
    }

    fn is_syncing(&self) -> bool {
        NetworkInfo::is_syncing(&self.inner)
    }

    fn is_initially_syncing(&self) -> bool {
        NetworkInfo::is_initially_syncing(&self.inner)
    }
}

impl<N: NetworkPrimitives> Peers for TxGossipNetwork<N> {
    fn add_trusted_peer_id(&self, peer: PeerId) {
        self.inner.add_trusted_peer_id(peer)
    }

    fn add_trusted_peer_node(&self, peer: TrustedPeer) {
        self.inner.add_trusted_peer_node(peer)
    }

    fn add_peer_kind(
        &self,
        peer: PeerId,
        kind: Option<PeerKind>,
        tcp_addr: SocketAddr,
        udp_addr: Option<SocketAddr>,
    ) {
        self.inner.add_peer_kind(peer, kind, tcp_addr, udp_addr)
    }

    async fn get_peers_by_kind(&self, kind: PeerKind) -> Result<Vec<PeerInfo>, NetworkError> {
        self.inner.get_peers_by_kind(kind).await
    }

    async fn get_all_peers(&self) -> Result<Vec<PeerInfo>, NetworkError> {
        self.inner.get_all_peers().await
    }

    async fn get_peer_by_id(&self, peer_id: PeerId) -> Result<Option<PeerInfo>, NetworkError> {
        self.inner.get_peer_by_id(peer_id).await
    }

    async fn get_peers_by_id(&self, peer_ids: Vec<PeerId>) -> Result<Vec<PeerInfo>, NetworkError> {
        self.inner.get_peers_by_id(peer_ids).await
    }

    fn remove_peer(&self, peer: PeerId, kind: PeerKind) {
        self.inner.remove_peer(peer, kind)
    }

    fn disconnect_peer(&self, peer: PeerId) {
        self.inner.disconnect_peer(peer)
    }

    fn disconnect_peer_with_reason(&self, peer: PeerId, reason: DisconnectReason) {
        self.inner.disconnect_peer_with_reason(peer, reason)
    }

    fn ban_peer(&self, peer: PeerId) {
        self.inner.ban_peer(peer)
    }

    fn unban_peer(&self, peer: PeerId) {
        self.inner.unban_peer(peer)
    }

    fn connect_peer_kind(
        &self,
        peer: PeerId,
        kind: PeerKind,
        tcp_addr: SocketAddr,
        udp_addr: Option<SocketAddr>,
    ) {
        self.inner.connect_peer_kind(peer, kind, tcp_addr, udp_addr)
    }

    fn reputation_change(&self, peer_id: PeerId, kind: ReputationChangeKind) {
        self.inner.reputation_change(peer_id, kind)
    }

    async fn reputation_by_id(&self, peer_id: PeerId) -> Result<Option<Reputation>, NetworkError> {
        self.inner.reputation_by_id(peer_id).await
    }
}

impl<N: NetworkPrimitives> PeersHandleProvider for TxGossipNetwork<N> {
    fn peers_handle(&self) -> &PeersHandle {
        self.inner.peers_handle()
    }
}

impl<N: NetworkPrimitives> NetworkPeersEvents for TxGossipNetwork<N> {
    fn peer_events(&self) -> PeerEventStream {
        self.inner.peer_events()
    }
}

impl<N: NetworkPrimitives> NetworkEventListenerProvider for TxGossipNetwork<N> {
    type Primitives = N;

    fn event_listener(&self) -> EventStream<NetworkEvent<PeerRequest<Self::Primitives>>> {
        self.inner.event_listener()
    }

    fn discovery_listener(&self) -> UnboundedReceiverStream<DiscoveryEvent> {
        self.inner.discovery_listener()
    }
}

impl<N: NetworkPrimitives> NetworkSyncUpdater for TxGossipNetwork<N> {
    fn update_sync_state(&self, state: SyncState) {
        match state {
            // The launcher says "syncing" after every restart: always honoured.
            SyncState::Syncing => self.inner.update_sync_state(SyncState::Syncing),
            // Its own reasons for "idle" (a finished backfill, a canonical head event, the
            // startup flag) are not the reason that matters here: only the gate moves the
            // network to Idle.
            SyncState::Idle => {
                if self.gate.is_open() {
                    self.inner.update_sync_state(SyncState::Idle)
                }
            }
        }
    }

    fn update_status(&self, head: Head) {
        self.inner.update_status(head)
    }

    fn update_block_range(&self, update: reth_eth_wire_types::BlockRangeUpdate) {
        self.inner.update_block_range(update)
    }
}

impl<N: NetworkPrimitives> BlockDownloaderProvider for TxGossipNetwork<N> {
    type Client = NoopFullBlockClient<N>;

    /// A client that fetches nothing. The pipeline and the engine's block downloader take their
    /// client from here, so no header or body can be obtained from a peer.
    async fn fetch_client(&self) -> Result<Self::Client, oneshot::error::RecvError> {
        Ok(NoopFullBlockClient::<N>::default())
    }
}

/// Builds the transaction-gossip network of the Unicity node: the real network over the pool,
/// restricted to the configured peers, wrapped as [`TxGossipNetwork`].
#[derive(Debug, Clone, Default)]
pub struct UnicityNetworkBuilder {
    gate: GossipGate,
}

impl UnicityNetworkBuilder {
    /// Creates the builder over the node's gate.
    pub const fn new(gate: GossipGate) -> Self {
        Self { gate }
    }
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for UnicityNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        TxGossipNetwork<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let mut config = ctx.network_config()?;
        // Only the peers that were added (the validator set) are connected to; a stranger that
        // dials in or is discovered is not a transaction peer.
        config.peers_config.trusted_nodes_only = true;
        let network = reth_network::NetworkManager::builder(config).await?;
        let handle = ctx.start_network(network, pool);
        tracing::info!(target: "unicity::gossip", enode = %handle.local_node_record(), "transaction-only P2P initialized (block and header downloads refused)");
        Ok(TxGossipNetwork::new(handle, self.gate))
    }
}
