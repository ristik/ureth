//! Provider objects for the B1 precompiles. The node factory installs them; the certificate batch
//! is never result-cached.
use crate::{batch, membership, Error, Pins, RegistryRead, REGISTRY};
use alloy_evm::{
    precompiles::{DynPrecompile, Precompile, PrecompileInput},
    EvmInternals,
};
use alloy_primitives::U256;
use revm::precompile::{
    PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult,
};

/// Native provider for the stateless RSMT membership check. Its verdict depends on the request
/// alone, so it may be result-cached.
#[derive(Debug)]
pub struct MembershipPrecompile {
    id: PrecompileId,
}
impl Default for MembershipPrecompile {
    fn default() -> Self {
        Self { id: PrecompileId::Custom("unicity-b1-membership".into()) }
    }
}
impl MembershipPrecompile {
    /// Wrap for an explicitly supplied map.
    pub fn into_dyn(self) -> DynPrecompile {
        let id = self.id.clone();
        DynPrecompile::new(id, move |input| self.call(input))
    }
}
struct Journal<'a, 'b>(&'a mut EvmInternals<'b>);
impl RegistryRead for Journal<'_, '_> {
    type Error = alloy_evm::EvmInternalsError;
    fn sload(&mut self, key: U256) -> Result<U256, Self::Error> {
        self.0.sload(REGISTRY, key).map(|v| v.data)
    }
}
impl Precompile for MembershipPrecompile {
    fn precompile_id(&self) -> &PrecompileId {
        &self.id
    }
    fn supports_caching(&self) -> bool {
        true
    }
    fn call(&self, input: PrecompileInput<'_>) -> PrecompileResult {
        match membership::<core::convert::Infallible>(input.data, input.gas) {
            Ok(out) => {
                Ok(PrecompileOutput::new(out.gas, out.bytes.to_vec().into(), input.reservoir))
            }
            Err(Error::OutOfGas) => {
                Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir))
            }
            Err(_) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("malformed B1 request".into()),
                input.reservoir,
            )),
        }
    }
}

/// Native provider for `CERT_BATCH_V2` at [`batch::ADDRESS`]. It reads the registry through the
/// current journal, is never result-cached and carries the deployment pins it compares against.
#[derive(Debug)]
pub struct CertBatchPrecompile {
    pins: Pins,
    id: PrecompileId,
}
impl CertBatchPrecompile {
    /// Construct a provider; installing it in a precompile map is the integration's decision.
    pub fn new(pins: Pins) -> Self {
        Self { pins, id: PrecompileId::Custom("unicity-b1-cert-batch-v2".into()) }
    }
    /// Wrap for an explicitly supplied map. The result is stateful: no result cache.
    pub fn into_dyn(self) -> DynPrecompile {
        let id = self.id.clone();
        DynPrecompile::new_stateful(id, move |input| self.call(input))
    }
}
impl Precompile for CertBatchPrecompile {
    fn precompile_id(&self) -> &PrecompileId {
        &self.id
    }
    fn supports_caching(&self) -> bool {
        false
    }
    fn call(&self, mut input: PrecompileInput<'_>) -> PrecompileResult {
        let result =
            batch::run(input.data, input.gas, &self.pins, &mut Journal(&mut input.internals), None);
        match result {
            Ok(out) => {
                Ok(PrecompileOutput::new(out.gas, out.bytes.to_vec().into(), input.reservoir))
            }
            Err(Error::OutOfGas) => {
                Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir))
            }
            Err(Error::Malformed(_)) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("malformed B1 batch request".into()),
                input.reservoir,
            )),
            Err(Error::Host(e)) => Err(PrecompileError::Fatal(e.to_string())),
            Err(Error::Registry) => {
                Err(PrecompileError::Fatal("impossible admitted B1 registry".into()))
            }
        }
    }
}
