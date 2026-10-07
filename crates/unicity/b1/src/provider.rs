//! Explicit provider objects for PR4 integration. No automatic registration,
//! fork activation, ambient authority, or stateful result cache.
use crate::{run, Error, Operation, RegistryRead, REGISTRY};
use alloy_evm::{
    precompiles::{DynPrecompile, Precompile, PrecompileInput},
    EvmInternals,
};
use alloy_primitives::U256;
use revm::precompile::{
    PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult,
};

/// Native provider for one reserved B1 operation. Merely constructing one does
/// not add it to any production factory or precompile map.
#[derive(Debug)]
pub struct B1Precompile {
    op: Operation,
    id: PrecompileId,
}
impl B1Precompile {
    /// Construct an inactive provider. Integration must separately install it
    /// under the accepted profile after all PR1–4 activation gates pass.
    pub fn new(op: Operation) -> Self {
        Self { op, id: PrecompileId::Custom(format!("unicity-b1-{op:?}").into()) }
    }
    /// Wrap for an explicitly supplied map, preserving the stateful cache ban.
    /// This method does not modify or install any production map.
    pub fn into_dyn(self) -> DynPrecompile {
        let id = self.id.clone();
        if self.op == Operation::Member {
            DynPrecompile::new(id, move |input| self.call(input))
        } else {
            DynPrecompile::new_stateful(id, move |input| self.call(input))
        }
    }
}
struct Journal<'a, 'b>(&'a mut EvmInternals<'b>);
impl RegistryRead for Journal<'_, '_> {
    type Error = alloy_evm::EvmInternalsError;
    fn sload(&mut self, key: U256) -> Result<U256, Self::Error> {
        self.0.sload(REGISTRY, key).map(|v| v.data)
    }
}
impl Precompile for B1Precompile {
    fn precompile_id(&self) -> &PrecompileId {
        &self.id
    }
    fn supports_caching(&self) -> bool {
        self.op == Operation::Member
    }
    fn call(&self, mut input: PrecompileInput<'_>) -> PrecompileResult {
        let result = run(self.op, input.data, input.gas, &mut Journal(&mut input.internals));
        match result {
            Ok(out) => {
                Ok(PrecompileOutput::new(out.gas, out.bytes.to_vec().into(), input.reservoir))
            }
            Err(Error::OutOfGas) => {
                Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir))
            }
            Err(Error::Malformed(_)) => Ok(PrecompileOutput::halt(
                PrecompileHalt::Other("malformed B1 request".into()),
                input.reservoir,
            )),
            Err(Error::Host(e)) => Err(PrecompileError::Fatal(e.to_string())),
            Err(Error::Registry) => {
                Err(PrecompileError::Fatal("impossible admitted B1 registry".into()))
            }
        }
    }
}
