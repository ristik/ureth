//! The one EVM factory every Unicity execution route builds its EVM from.
//!
//! Block execution (build, import, replay and recovery), `eth_call`, `estimateGas` and tracing all
//! create their EVM through the node's `ConfigureEvm`, whose block-executor factory owns an
//! [`EvmFactory`]. Giving that factory the B1 precompiles is therefore what makes every route see
//! the same native certificate and membership kernels, with the same journal-aware registry reads:
//! there is no second construction path to forget. The stateless B2 relation is installed the same
//! way at `0x0104`. `0x0103` (S1) stays unregistered until its authority source is accepted.
//!
//! The UC and shared-seal providers are stateful (their verdict depends on the registry words in
//! the selected block's journal), so they are never result-cached; only the stateless RSMT
//! membership check and the stateless B2 relation may be.

use alloy_evm::{
    eth::EthEvmFactory,
    precompiles::{DynPrecompile, PrecompilesMap},
    Database, Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::Address;
use reth_chainspec::ChainSpec;
use reth_evm_ethereum::EthEvmConfig;
use reth_unicity_b1::{provider::B1Precompile, Operation};
use reth_unicity_b2::provider::B2Precompile;
use revm::{inspector::NoOpInspector, Inspector};
use std::sync::Arc;

/// The B1 precompile set, keyed by its reserved addresses.
pub fn b1_precompiles() -> [(Address, DynPrecompile); 3] {
    [Operation::Uc, Operation::Shared, Operation::Member]
        .map(|op| (op.address(), B1Precompile::new(op).into_dyn()))
}

/// The B2 (SDK 3.0.1 native bridge relation) precompile, keyed by its reserved address.
pub fn b2_precompile() -> (Address, DynPrecompile) {
    (reth_unicity_b2::ADDRESS, B2Precompile::default().into_dyn())
}

/// [`EthEvmFactory`] with the B1 and B2 precompiles installed in every EVM it creates.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnicityEvmFactory(EthEvmFactory);

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
        let mut evm = self.0.create_evm(db, input);
        evm.precompiles_mut().extend_precompiles(b1_precompiles());
        evm.precompiles_mut().extend_precompiles([b2_precompile()]);
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.0.create_evm_with_inspector(db, input, inspector);
        evm.precompiles_mut().extend_precompiles(b1_precompiles());
        evm.precompiles_mut().extend_precompiles([b2_precompile()]);
        evm
    }
}

/// The Ethereum EVM configuration every Unicity route starts from.
pub type UnicityInnerEvmConfig = EthEvmConfig<ChainSpec, UnicityEvmFactory>;

/// Builds [`UnicityInnerEvmConfig`] for `chain_spec`.
pub fn unicity_eth_config(chain_spec: Arc<ChainSpec>) -> UnicityInnerEvmConfig {
    EthEvmConfig::new_with_evm_factory(chain_spec, UnicityEvmFactory::default())
}
