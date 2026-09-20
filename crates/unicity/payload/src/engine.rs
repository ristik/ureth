//! Unicity Engine API types.
//!
//! The only difference from the stock Ethereum engine types is that the payload attributes carry
//! the per-payload commitment, so a build started through these types resolves to an immutable
//! [`UnicityEvmConfig`](reth_unicity_execution::block_executor::UnicityEvmConfig) instead of the
//! stock EVM configuration. The execution payload shape and its envelopes are unchanged, because
//! the seal methods are additive and versioned siblings of the standard `engine_*` methods, never
//! a change to the standard ones.
//!
//! Nothing here advertises a seal method. The type exists so a node can carry the Unicity payload
//! attributes end to end before U3c to U3f attach the `engine_*WithSealV1` methods.

use alloy_primitives::Bytes;
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3,
    ExecutionPayloadEnvelopeV4, ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6,
    ExecutionPayloadV1,
};
use reth_engine_primitives::EngineTypes;
use reth_payload_builder::EthBuiltPayload;
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, SealedBlock};
use serde::{Deserialize, Serialize};

use crate::UnicityPayloadAttributes;

/// The Engine API types used by a Unicity node.
///
/// [`PayloadTypes::PayloadAttributes`] is [`UnicityPayloadAttributes`], so the payload id binds the
/// commitment and the payload service resolves each build job through the node's
/// [`SealJobRegistry`](crate::SealJobRegistry). [`PayloadTypes::BuiltPayload`] is the stock
/// [`EthBuiltPayload`], so every `engine_getPayloadV*` response keeps the ordinary Ethereum shape.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UnicityEngineTypes;

impl PayloadTypes for UnicityEngineTypes {
    type ExecutionData = ExecutionData;
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = UnicityPayloadAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
        bal: Option<Bytes>,
    ) -> Self::ExecutionData {
        // Same conversion as `EthPayloadTypes::block_to_payload`: the block access list, when
        // present, travels in the sidecar rather than in the payload body. Keeping this identical
        // is what lets the standard `engine_getPayloadV*` methods return Unicity blocks unchanged.
        let (payload, sidecar) = ExecutionPayload::from_block_unchecked_with_extras(
            block.hash(),
            &block.into_block(),
            bal,
        );
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for UnicityEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
    type ExecutionPayloadEnvelopeV6 = ExecutionPayloadEnvelopeV6;
}
