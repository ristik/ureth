//! Explicit native provider for tests and later integration. Constructing this
//! object never installs it in a factory or changes a fork's precompile map.
use crate::{run, Error};
use alloy_evm::precompiles::{DynPrecompile, Precompile, PrecompileInput};
use revm::precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult};

/// Pure native semantics provider; no host or storage access.
#[derive(Debug)]
pub struct B2Precompile {
    id: PrecompileId,
}
impl Default for B2Precompile {
    fn default() -> Self {
        Self { id: PrecompileId::Custom("unicity-b2".into()) }
    }
}
impl B2Precompile {
    /// Wrap an explicitly supplied provider. Production registration is deferred.
    pub fn into_dyn(self) -> DynPrecompile {
        DynPrecompile::new(self.id.clone(), move |input| self.call(input))
    }
}
impl Precompile for B2Precompile {
    fn precompile_id(&self) -> &PrecompileId {
        &self.id
    }
    fn supports_caching(&self) -> bool {
        true
    }
    fn call(&self, input: PrecompileInput<'_>) -> PrecompileResult {
        match run(input.data, input.gas) {
            Ok(out) => Ok(PrecompileOutput::new(out.gas, out.bytes.into(), input.reservoir)),
            Err(Error::OutOfGas) => {
                Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir))
            }
            Err(Error::Malformed(reason)) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other(format!("malformed B2: {reason}").into()),
                input.reservoir,
            )),
            Err(Error::BudgetExceeded(reason)) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other(format!("B2 budget exceeded: {reason}").into()),
                input.reservoir,
            )),
        }
    }
}
