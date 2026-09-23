//! Canonical-only hydration of durable parent accounting at node startup.

use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::Block as _;
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{BlockNumReader, BlockReader, HeaderProvider, StateProviderFactory};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{replay_complete, UnicityEvmConfig},
    wire::{bind_completed_parent, bind_validated_genesis},
};
use reth_unicity_store::{CompanionStore, Lookup};
use std::sync::Arc;

use crate::registry::{ParentAccountingResolver, UnicityParentAccountings};

/// Number of nearby canonical tokens loaded around both the visible and persisted tips.
pub const ACCOUNTING_WINDOW: u64 = 16;
/// Maximum historical blocks a repair may replay from a verified anchor.
pub const DEFAULT_REPAIR_LIMIT: u64 = 64;

/// Loads only hashes confirmed against the canonical chain, including the persisted DB frontier.
pub fn hydrate_accounting<P>(
    provider: &P,
    tokens: &UnicityParentAccountings,
    profile: BlockProfile,
) -> eyre::Result<()>
where
    P: BlockNumReader + HeaderProvider<Header = Header> + ChainSpecProvider<ChainSpec = ChainSpec>,
{
    let head = provider.best_block_number()?;
    let persisted = provider.last_block_number()?;
    let chain = provider.chain_spec();
    for tip in [persisted, head] {
        for number in tip.saturating_sub(ACCOUNTING_WINDOW.saturating_sub(1))..=tip {
            if number == 0 {
                continue;
            }
            let Some(hash) = provider.block_hash(number)? else {
                continue;
            };
            let Some(header) = provider.sealed_header_by_hash(hash)? else {
                continue;
            };
            tokens.restore_exact(&header, chain.chain().id(), chain.genesis_hash(), profile)?;
        }
    }
    Ok(())
}

/// Repairs a missing canonical head from the nearest verified token within `limit` blocks.
/// Missing historical bodies, companions, state, or an anchor are explicit refusals.
pub fn repair_accounting<P>(
    provider: &P,
    store: &CompanionStore,
    tokens: &UnicityParentAccountings,
    profile: BlockProfile,
    fee_collector: Address,
    target: u64,
    limit: u64,
) -> eyre::Result<()>
where
    P: BlockReader<Block = Block, Header = Header, Transaction = TransactionSigned>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + StateProviderFactory,
{
    if target == 0 {
        return Ok(());
    }
    let chain = provider.chain_spec();
    let genesis = chain.genesis_hash();
    let target_hash = canonical_hash(provider, target)?;
    let earliest = target.saturating_sub(limit);
    let mut anchor = None;
    for number in (earliest.max(1)..=target).rev() {
        let hash = canonical_hash(provider, number)?;
        let header = canonical_header(provider, hash)?;
        if tokens.restore_exact(&header, chain.chain().id(), genesis, profile)?.is_some() {
            anchor = Some(number);
            break;
        }
    }
    // The configured genesis is the verified zero-system-gas anchor for B1. No disk token for B0
    // exists, so a one-block repair must be able to start here.
    if anchor.is_none() && earliest == 0 {
        let genesis_header = canonical_header(provider, canonical_hash(provider, 0)?)?;
        reth_unicity_execution::block_executor::CompletedParent::genesis_next_base_fee(
            &genesis_header,
            genesis,
            profile,
        )
        .map_err(|error| eyre::eyre!("invalid configured genesis anchor: {error:?}"))?;
        anchor = Some(0);
    }
    let anchor = anchor.ok_or_else(|| {
        eyre::eyre!(
            "parent accounting unavailable: no verified token within {limit} blocks of {target}"
        )
    })?;
    for number in anchor + 1..=target {
        let hash = canonical_hash(provider, number)?;
        let parent_hash = canonical_hash(provider, number - 1)?;
        let parent = canonical_header(provider, parent_hash)?;
        let companion = match store.get(hash)? {
            Lookup::Found(companion) => companion,
            _ => {
                return Err(eyre::eyre!(
                    "parent accounting unavailable: companion missing for block {number}"
                ))
            }
        };
        let root = companion.decode_root_input()?;
        let bound = if number == 1 {
            bind_validated_genesis(root, profile, &parent, genesis, fee_collector)
        } else {
            let token = tokens
                .resolve(&parent, &chain, profile)
                .map_err(|_| eyre::eyre!("missing predecessor token for block {number}"))?;
            bind_completed_parent(root, profile, &parent, token.token(), fee_collector)
        }
        .map_err(|error| eyre::eyre!("parent accounting binding failed at {number}: {error:?}"))?;
        let block = provider
            .block_by_hash(hash)?
            .ok_or_else(|| {
                eyre::eyre!("parent accounting unavailable: body missing for block {number}")
            })?
            .try_into_recovered()
            .map_err(|error| eyre::eyre!("sender recovery failed at {number}: {error:?}"))?;
        if block.hash() != hash || block.header().parent_hash != parent_hash {
            eyre::bail!(
                "parent accounting unavailable: historical block identity mismatch at {number}"
            );
        }
        let state = provider.state_by_block_hash(parent_hash)?;
        let config = UnicityEvmConfig::new(EthEvmConfig::new(chain.clone()), Arc::new(bound));
        let replay =
            replay_complete(&config, StateProviderDatabase::new(state.as_ref()), &state, &block)
                .map_err(|error| eyre::eyre!("accounting replay failed at {number}: {error}"))?;
        tokens.publish(hash, number, chain.chain().id(), genesis, replay.parent)?;
    }
    if canonical_hash(provider, target)? != target_hash {
        eyre::bail!("parent accounting unavailable: canonical head changed during repair");
    }
    Ok(())
}

fn canonical_hash<P: BlockNumReader>(provider: &P, number: u64) -> eyre::Result<B256> {
    provider.block_hash(number)?.ok_or_else(|| {
        eyre::eyre!("parent accounting unavailable: canonical hash missing at block {number}")
    })
}

fn canonical_header<P: HeaderProvider<Header = Header>>(
    provider: &P,
    hash: B256,
) -> eyre::Result<reth_primitives_traits::SealedHeader<Header>> {
    provider.sealed_header_by_hash(hash)?.ok_or_else(|| {
        eyre::eyre!("parent accounting unavailable: canonical header missing for {hash}")
    })
}
