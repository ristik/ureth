//! Unicity parent-fee validation with the stock Ethereum checks preserved elsewhere.

use std::{fmt::Debug, sync::Arc};

use alloy_consensus::Header;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_gas_limit,
    validate_against_parent_hash_number, validate_against_parent_timestamp,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_primitives::{Block, EthPrimitives, Receipt};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{GotExpected, RecoveredBlock, SealedBlock, SealedHeader};
use reth_unicity_execution::{block::BlockProfile, block_executor::CompletedParent};

use crate::registry::{
    ParentAccountingResolver, ParentAccountingUnavailable, UnicityParentAccountings,
};

/// Ethereum consensus with only the parent base-fee rule replaced by Unicity's ordinary-gas rule.
#[derive(Clone, Debug)]
pub struct UnicityConsensus<R = UnicityParentAccountings> {
    inner: EthBeaconConsensus<ChainSpec>,
    chain_spec: Arc<ChainSpec>,
    profile: BlockProfile,
    resolver: R,
}

impl<R> UnicityConsensus<R> {
    /// Constructs the fee validator over the same chain and accounting source used by seal paths.
    pub fn new(chain_spec: Arc<ChainSpec>, profile: BlockProfile, resolver: R) -> Self {
        Self { inner: EthBeaconConsensus::new(chain_spec.clone()), chain_spec, profile, resolver }
    }
}

impl<R> HeaderValidator<Header> for UnicityConsensus<R>
where
    R: ParentAccountingResolver + Clone + Debug,
{
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;
        validate_against_parent_timestamp(header.header(), parent.header())?;
        validate_against_parent_gas_limit(header, parent, &self.chain_spec)?;

        let expected = if parent.number == 0 && parent.hash() == self.chain_spec.genesis_hash() {
            CompletedParent::genesis_next_base_fee(
                parent,
                self.chain_spec.genesis_hash(),
                self.profile,
            )
            .map_err(|_| ConsensusError::other(ParentAccountingUnavailable(parent.hash())))?
        } else {
            self.resolver
                .resolve(parent, &self.chain_spec, self.profile)
                .map_err(ConsensusError::other)?
                .next_fee()
        };
        let got = header.base_fee_per_gas.ok_or(ConsensusError::BaseFeeMissing)?;
        if got != expected {
            return Err(ConsensusError::BaseFeeDiff(GotExpected { got, expected }));
        }

        if let Some(blob_params) = self.chain_spec.blob_params_at_timestamp(header.timestamp) {
            validate_against_parent_4844(header.header(), parent.header(), blob_params)?;
        }
        Ok(())
    }
}

impl<R> Consensus<Block> for UnicityConsensus<R>
where
    R: ParentAccountingResolver + Clone + Debug,
{
    fn is_validation_unavailable(&self, error: &ConsensusError) -> bool {
        matches!(error, ConsensusError::Other(inner) if inner.as_ref().downcast_ref::<ParentAccountingUnavailable>().is_some())
    }

    fn validate_body_against_header(
        &self,
        body: &<Block as reth_primitives_traits::Block>::Body,
        header: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<ChainSpec> as Consensus<Block>>::validate_body_against_header(
            &self.inner,
            body,
            header,
        )
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<Block>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution(block)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<Block>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution_with_tx_root(block, transaction_root)
    }

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        matches!(error, ConsensusError::Other(inner) if inner.as_ref().downcast_ref::<ParentAccountingUnavailable>().is_some())
    }
}

impl<R> FullConsensus<EthPrimitives> for UnicityConsensus<R>
where
    R: ParentAccountingResolver + Clone + Debug,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<Block>,
        result: &BlockExecutionResult<Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<alloy_primitives::B256>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<ChainSpec> as FullConsensus<EthPrimitives>>::validate_block_post_execution(
            &self.inner,
            block,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}
