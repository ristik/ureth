//! The precompile provider. It evaluates the anchor table's batch against the registry through the
//! current journal under the deployment pins, so it is never result-cached.
use crate::{run, Halt, Verdict};
use alloy_evm::{
    precompiles::{DynPrecompile, Precompile, PrecompileInput},
    EvmInternals, EvmInternalsError,
};
use alloy_primitives::U256;
use reth_unicity_b1::{batch, Pins, RegistryRead, REGISTRY};
use revm::precompile::{
    PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult,
};

/// Native provider for [`crate::ADDRESS`].
#[derive(Debug)]
pub struct ComposePrecompile {
    pins: Pins,
    id: PrecompileId,
}
impl ComposePrecompile {
    /// A provider whose batch evaluation compares the registry with `pins`.
    pub fn new(pins: Pins) -> Self {
        Self { pins, id: PrecompileId::Custom("unicity-bridge-compose-v1".into()) }
    }
    /// Wrap for an explicitly supplied map. The result is stateful: no result cache.
    pub fn into_dyn(self) -> DynPrecompile {
        let id = self.id.clone();
        DynPrecompile::new_stateful(id, move |input| self.call(input))
    }
}

struct Journal<'a, 'b>(&'a mut EvmInternals<'b>);
impl RegistryRead for Journal<'_, '_> {
    type Error = EvmInternalsError;
    fn sload(&mut self, key: U256) -> Result<U256, Self::Error> {
        self.0.sload(REGISTRY, key).map(|v| v.data)
    }
}

struct Registry<'a, 'b, 'c> {
    pins: &'a Pins,
    journal: Journal<'b, 'c>,
}
impl Verdict for Registry<'_, '_, '_> {
    type Error = EvmInternalsError;
    fn batch(&mut self, request: &[u8]) -> Result<bool, Halt<Self::Error>> {
        // The composition pays the batch by its own schedule; the B1 charge is not applied twice.
        match batch::run(request, u64::MAX, self.pins, &mut self.journal, None) {
            Ok(out) => Ok(out.bytes[63] == 1),
            // The request passed the same scan already (its dimensions); B1 would refuse it.
            Err(reth_unicity_b1::Error::Malformed(_)) => Ok(false),
            Err(reth_unicity_b1::Error::OutOfGas) => Err(Halt::OutOfGas),
            Err(reth_unicity_b1::Error::Host(e)) => Err(Halt::Host(e)),
            Err(reth_unicity_b1::Error::Registry) => Err(Halt::Registry),
        }
    }
}

impl Precompile for ComposePrecompile {
    fn precompile_id(&self) -> &PrecompileId {
        &self.id
    }
    fn supports_caching(&self) -> bool {
        false
    }
    fn call(&self, mut input: PrecompileInput<'_>) -> PrecompileResult {
        let mut registry = Registry { pins: &self.pins, journal: Journal(&mut input.internals) };
        match run(input.data, input.gas, &mut registry) {
            Ok(out) => {
                Ok(PrecompileOutput::new(out.gas, out.bytes.to_vec().into(), input.reservoir))
            }
            Err(Halt::OutOfGas) => {
                Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir))
            }
            Err(Halt::Malformed) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("malformed bridge compose input".into()),
                input.reservoir,
            )),
            Err(Halt::Host(e)) => Err(PrecompileError::Fatal(e.to_string())),
            Err(Halt::Registry) => {
                Err(PrecompileError::Fatal("impossible admitted B1 registry".into()))
            }
        }
    }
}
