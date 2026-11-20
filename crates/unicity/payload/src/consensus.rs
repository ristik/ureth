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
use reth_unicity_execution::{
    block::{BlockProfile, MAX_BASE_FEE},
    block_executor::CompletedParent,
};

use crate::{
    fees::FeeReader,
    registry::{ParentAccountingResolver, ParentAccountingUnavailable, UnicityParentAccountings},
};

/// Ethereum consensus with only the parent base-fee rule replaced by Unicity's ordinary-gas rule.
#[derive(Clone, Debug)]
pub struct UnicityConsensus<R = UnicityParentAccountings> {
    inner: EthBeaconConsensus<ChainSpec>,
    chain_spec: Arc<ChainSpec>,
    profile: BlockProfile,
    resolver: R,
    fees: Option<FeeReader>,
}

impl<R> UnicityConsensus<R> {
    /// Constructs the fee validator over the same chain and accounting source used by seal paths.
    pub fn new(chain_spec: Arc<ChainSpec>, profile: BlockProfile, resolver: R) -> Self {
        Self {
            inner: EthBeaconConsensus::new(chain_spec.clone()),
            chain_spec,
            profile,
            resolver,
            fees: None,
        }
    }

    pub(crate) fn with_fees(mut self, fees: Option<FeeReader>) -> Self {
        self.fees = fees;
        self
    }
}

impl<R> HeaderValidator<Header> for UnicityConsensus<R>
where
    R: ParentAccountingResolver + Clone + Debug,
{
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)?;
        if header.base_fee_per_gas.is_some_and(|fee| fee > MAX_BASE_FEE) {
            return Err(ConsensusError::other(std::io::Error::other(
                "Unicity base fee exceeds its bound",
            )));
        }
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;
        validate_against_parent_timestamp(header.header(), parent.header())?;
        validate_against_parent_gas_limit(header, parent, &self.chain_spec)?;

        let unavailable = || ConsensusError::other(ParentAccountingUnavailable(parent.hash()));
        let (parent_profile, child_profile) = if let Some(reader) = &self.fees {
            let state = reader.at(parent.hash()).map_err(|_| unavailable())?;
            let child_fees = state.for_block(header.number);
            if header.beneficiary != child_fees.collector {
                return Err(ConsensusError::other(std::io::Error::other(
                    "invalid VR fee collector",
                )));
            }
            (state.for_block(parent.number).profile, child_fees.profile)
        } else {
            (self.profile, self.profile)
        };
        let expected = if parent.number == 0 && parent.hash() == self.chain_spec.genesis_hash() {
            CompletedParent::genesis_next_base_fee(
                parent,
                self.chain_spec.genesis_hash(),
                child_profile,
            )
            .map_err(|_| unavailable())?
        } else {
            self.resolver
                .resolve(parent, &self.chain_spec, parent_profile)
                .map_err(ConsensusError::other)?
                .token()
                .checked_next_base_fee_for_child(parent, parent_profile, child_profile)
                .map_err(|_| unavailable())?
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
