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
    let anchor = select_repair_anchor(
        provider,
        tokens,
        profile,
        chain.chain().id(),
        genesis,
        target,
        limit,
    )?;
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

fn select_repair_anchor<P>(
    provider: &P,
    tokens: &UnicityParentAccountings,
    profile: BlockProfile,
    chain_id: u64,
    genesis: B256,
    target: u64,
    limit: u64,
) -> eyre::Result<u64>
where
    P: BlockNumReader + HeaderProvider<Header = Header>,
{
    let earliest = target.saturating_sub(limit);
    let mut anchor = None;
    for number in (earliest.max(1)..=target).rev() {
        let hash = canonical_hash(provider, number)?;
        let header = canonical_header(provider, hash)?;
        if tokens.restore_exact(&header, chain_id, genesis, profile)?.is_some() {
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
    anchor.ok_or_else(|| {
        eyre::eyre!(
            "parent accounting unavailable: no verified token within {limit} blocks of {target}"
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use reth_provider::test_utils::MockEthProvider;
    use reth_unicity_execution::block_executor::{CompletedParent, LocalParentAccounting};

    const PROFILE: BlockProfile = BlockProfile {
        max_gas: 30_000_001,
        system_gas: 500_001,
        base_fee_floor: 7,
        elasticity: 2,
        change_denominator: 8,
    };

    fn header(number: u64, marker: u8) -> Header {
        Header {
            number,
            extra_data: vec![marker].into(),
            gas_limit: PROFILE.max_gas,
            gas_used: 0,
            base_fee_per_gas: Some(PROFILE.base_fee_floor),
            ..Default::default()
        }
    }

    #[test]
    fn anchor_selection_is_bounded_and_ignores_orphan_tokens() {
        let provider = MockEthProvider::default();
        let genesis = provider.chain_spec().genesis_hash();
        for number in 0..=3 {
            let canonical = header(number, 0);
            provider.add_header(canonical.hash_slow(), canonical);
        }
        let canonical_one = provider.sealed_header(1).unwrap().unwrap();
        let orphan = header(1, 1);
        let orphan_hash = orphan.hash_slow();
        let token = CompletedParent::from_local_storage(
            LocalParentAccounting {
                block_hash: orphan_hash,
                profile: PROFILE,
                header_gas: 0,
                system_gas: 0,
                ordinary_gas: 0,
                base_fee: PROFILE.base_fee_floor,
            },
            &reth_primitives_traits::SealedHeader::new(orphan, orphan_hash),
            PROFILE,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(reth_unicity_store::open(directory.path()).unwrap());
        let tokens = UnicityParentAccountings::new().require_durability();
        tokens.attach_store(store.clone());
        tokens.publish(orphan_hash, 1, 1, genesis, token).unwrap();

        let error =
            select_repair_anchor(&provider, &tokens, PROFILE, 1, genesis, 2, 1).unwrap_err();
        assert!(error.to_string().contains("no verified token"));
        assert!(tokens.get(&canonical_one.hash()).is_none());

        let canonical_token = CompletedParent::from_local_storage(
            LocalParentAccounting { block_hash: canonical_one.hash(), ..token.for_local_storage() },
            &canonical_one,
            PROFILE,
        )
        .unwrap();
        tokens.publish(canonical_one.hash(), 1, 1, genesis, canonical_token).unwrap();
        assert_eq!(select_repair_anchor(&provider, &tokens, PROFILE, 1, genesis, 2, 1).unwrap(), 1);
        let missing_companion =
            repair_accounting(&provider, &store, &tokens, PROFILE, Address::ZERO, 2, 1)
                .unwrap_err();
        assert!(missing_companion.to_string().contains("companion missing for block 2"));
        let error =
            select_repair_anchor(&provider, &tokens, PROFILE, 1, genesis, 3, 1).unwrap_err();
        assert!(error.to_string().contains("no verified token within 1 blocks of 3"));
    }
}
