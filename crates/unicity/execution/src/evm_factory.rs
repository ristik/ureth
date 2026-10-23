//! The one EVM factory every Unicity execution route builds its EVM from.
//!
//! Block execution (build, import, replay and recovery), `eth_call`, `estimateGas` and tracing all
//! create their EVM through the node's `ConfigureEvm`, whose block-executor factory owns an
//! [`EvmFactory`]. Giving that factory the B1 precompiles is therefore what makes every route see
//! the same native certificate and membership kernels, with the same journal-aware registry reads:
//! there is no second construction path to forget. The stateless B2 relation is installed the same
//! way at `0x0104`, and the composed bridge relation (`BRIDGE_COMPOSE_V2`, protocol 6: lineage
//! through repeated splits) at `0x0105`. `0x0103` (S1) stays unregistered until its authority
//! source is accepted.
//!
//! The UC, shared-seal and composition providers are stateful (their verdict depends on the
//! registry words in the selected block's journal), so they are never result-cached; only the
//! stateless RSMT membership check and the stateless B2 relation may be.

use crate::update::B1Context;
use alloy_evm::{
    eth::EthEvmFactory,
    precompiles::{DynPrecompile, PrecompilesMap},
    Database, Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::Address;
use reth_chainspec::ChainSpec;
use reth_evm_ethereum::EthEvmConfig;
use reth_unicity_b1::{
    provider::{CertBatchPrecompile, MembershipPrecompile},
    Operation, Pins,
};
use reth_unicity_b2::provider::B2Precompile;
use reth_unicity_bridge::provider::ComposePrecompile;
use revm::{inspector::NoOpInspector, Inspector};
use std::sync::Arc;

/// The B1 precompile set, keyed by its reserved addresses: `CERT_BATCH_V2` at `0x0100` (the sole
/// certificate operation; `0x0101` stays unregistered) checked against the deployment `pins`, and
/// the stateless RSMT membership check at `0x0102`.
pub fn b1_precompiles(pins: Pins) -> [(Address, DynPrecompile); 2] {
    [
        (Operation::CertBatch.address(), CertBatchPrecompile::new(pins).into_dyn()),
        (Operation::Member.address(), MembershipPrecompile::default().into_dyn()),
    ]
}

/// The B2 (SDK 3.0.1 native bridge relation) precompile, keyed by its reserved address.
pub fn b2_precompile() -> (Address, DynPrecompile) {
    (reth_unicity_b2::ADDRESS, B2Precompile::default().into_dyn())
}

/// The composed bridge relation (`BRIDGE_COMPOSE_V2`, protocol 6), keyed by its reserved address;
/// its batch evaluation compares the registry with the deployment `pins`, as `CERT_BATCH_V2` does.
/// A protocol 5 deployment is replaced, not upgraded, so the V1 provider
/// ([`ComposePrecompile::new`]) is not registered here.
pub fn bridge_precompile(pins: Pins) -> (Address, DynPrecompile) {
    (reth_unicity_bridge::ADDRESS, ComposePrecompile::new_v2(pins).into_dyn())
}

/// [`EthEvmFactory`] with the B1, B2 and bridge precompiles installed in every EVM it creates.
#[derive(Clone, Copy, Debug)]
pub struct UnicityEvmFactory {
    inner: EthEvmFactory,
    pins: Pins,
}

impl UnicityEvmFactory {
    /// A factory whose certificate batch compares the registry with `pins`.
    pub fn new(pins: Pins) -> Self {
        Self { inner: EthEvmFactory::default(), pins }
    }
}

impl EvmFactory for UnicityEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> =
        <EthEvmFactory as EvmFactory>::Evm<DB, I>;
    type Context<DB: Database> = <EthEvmFactory as EvmFactory>::Context<DB>;
    type Tx = <EthEvmFactory as EvmFactory>::Tx;
    type Error<DBError: revm::context::DBErrorMarker> =
        <EthEvmFactory as EvmFactory>::Error<DBError>;
    type HaltReason = <EthEvmFactory as EvmFactory>::HaltReason;
    type Spec = <EthEvmFactory as EvmFactory>::Spec;
    type BlockEnv = <EthEvmFactory as EvmFactory>::BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let mut evm = self.inner.create_evm(db, input);
        evm.precompiles_mut().extend_precompiles(b1_precompiles(self.pins));
        evm.precompiles_mut().extend_precompiles([b2_precompile(), bridge_precompile(self.pins)]);
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.inner.create_evm_with_inspector(db, input, inspector);
        evm.precompiles_mut().extend_precompiles(b1_precompiles(self.pins));
        evm.precompiles_mut().extend_precompiles([b2_precompile(), bridge_precompile(self.pins)]);
        evm
    }
}

/// The Ethereum EVM configuration every Unicity route starts from.
pub type UnicityInnerEvmConfig = EthEvmConfig<ChainSpec, UnicityEvmFactory>;

/// Builds [`UnicityInnerEvmConfig`] for `chain_spec`; the certificate batch checks the registry
/// against the pins `b1` carries.
pub fn unicity_eth_config(chain_spec: Arc<ChainSpec>, b1: &B1Context) -> UnicityInnerEvmConfig {
    EthEvmConfig::new_with_evm_factory(chain_spec, UnicityEvmFactory::new(b1.cert_batch_pins()))
}
