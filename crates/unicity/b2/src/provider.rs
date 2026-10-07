//! Explicit opt-in provider object. No production map imports or installs it.
use crate::{run, Error};
use alloy_evm::precompiles::{DynPrecompile, Precompile, PrecompileInput};
use revm::precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult};

/// Stateless provider for the reserved 0x0104 address.
#[derive(Debug)]
pub struct B2Precompile {
    id: PrecompileId,
}
impl Default for B2Precompile {
    fn default() -> Self {
        Self { id: PrecompileId::Custom("unicity-b2-sdk3".into()) }
    }
}
impl B2Precompile {
    /// Construct for a caller-supplied map; does not install it anywhere.
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
            Err(_) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("malformed B2 request".into()),
                input.reservoir,
            )),
        }
    }
}
