//! Canonical-only hydration of durable parent accounting at node startup.

use alloy_consensus::Header;
use alloy_primitives::B256;
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{Block as _, SealedHeader};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{BlockNumReader, BlockReader, HeaderProvider, StateProviderFactory};
use reth_unicity_execution::{
    block::BlockProfile,
    block_executor::{replay_complete, UnicityEvmConfig},
    pairing::{
        header_attributes_digest, verify_pair_binding, ExpectedSubject, PairBinding,
        PairBindingError, PairContext, PairSubject,
    },
    wire::{bind_completed_parent, bind_validated_genesis, SealCompanion},
    RootInputV2,
};
use reth_unicity_store::{CompanionStore, Lookup};
use std::sync::Arc;

use crate::{
    node::UnicitySealConfig,
    registry::{ParentAccountingResolver, UnicityParentAccountings},
};

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

/// Typed causes of a refused recovery admission. They travel inside the `eyre::Report` the entry
/// points return, so a caller or a test recovers the exact cause with `downcast_ref` rather than
/// matching text.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// No companion is retained for the block, so its binding cannot be re-checked.
    #[error("parent accounting unavailable: companion missing for block {0}")]
    CompanionMissing(u64),
    /// The retained binding of the block is not a decodable binding (including an empty one).
    #[error("retained binding unusable at {number}: {source}")]
    RetainedUnusable {
        /// Block whose companion holds the binding.
        number: u64,
        /// Why it cannot be used.
        #[source]
        source: PairBindingError,
    },
    /// The retained binding no longer names the canonical block, parent, genesis or this pair.
    #[error("retained binding refused at {number}: {source}")]
    RetainedRefused {
        /// Block whose companion holds the binding.
        number: u64,
        /// The single comparison that failed.
        #[source]
        source: PairBindingError,
    },
    /// The binding the local Go side presented for the head is missing, malformed, or names
    /// something other than this node's canonical head.
    #[error("presented binding refused at {number}: {source}")]
    PresentedRefused {
        /// The head the Go side was asked to admit.
        number: u64,
        /// The single comparison that failed.
        #[source]
        source: PairBindingError,
    },
    /// The presented binding is valid for the head but differs from the retained one in something
    /// other than its subject: Go re-derived another parent context than the one that was stored.
    #[error("presented binding is not the retained one for block {0}")]
    PresentedDiffers(u64),
    /// A retained build binding needs the header's beacon root to recompute its job digest.
    #[error("retained build binding at {0}: header has no beacon root")]
    NoBeaconRoot(u64),
}

/// The block's retained companion, its decoded root input and the canonical headers, after the
/// retained binding was re-checked against the canonical chain, this node's pins and genesis.
struct RetainedBlock {
    hash: B256,
    companion: SealCompanion,
    root: RootInputV2,
    header: SealedHeader<Header>,
    parent: SealedHeader<Header>,
}

fn subject_for(
    number: u64,
    subject: PairSubject,
    hash: B256,
    header: &Header,
) -> Result<ExpectedSubject, RecoveryError> {
    Ok(match subject {
        PairSubject::Build { .. } => ExpectedSubject::Build {
            attributes_digest: header_attributes_digest(header)
                .ok_or(RecoveryError::NoBeaconRoot(number))?,
        },
        PairSubject::Import { .. } => ExpectedSubject::Import { block_hash: hash },
    })
}

/// Re-checks the binding retained with a canonical block's companion. A retained input that no
/// longer names this block, its parent, the genesis or this pair's pins is a refusal.
fn check_retained<P>(
    provider: &P,
    store: &CompanionStore,
    seal: UnicitySealConfig,
    genesis: B256,
    number: u64,
) -> eyre::Result<RetainedBlock>
where
    P: BlockNumReader + HeaderProvider<Header = Header>,
{
    let hash = canonical_hash(provider, number)?;
    let header = canonical_header(provider, hash)?;
    let parent = canonical_header(provider, canonical_hash(provider, number - 1)?)?;
    let Lookup::Found(companion) = store.get(hash)? else {
        return Err(RecoveryError::CompanionMissing(number).into());
    };
    let root = companion.decode_root_input()?;
    let retained = PairBinding::from_canonical_cbor(&companion.pair_binding)
        .map_err(|source| RecoveryError::RetainedUnusable { number, source })?;
    let subject = subject_for(number, retained.subject, hash, header.header())?;
    verify_pair_binding(
        &companion.pair_binding,
        &PairContext {
            pins: seal.pins,
            execution_genesis_hash: genesis,
            parent: &parent,
            root: &root,
            subject,
        },
    )
    .map_err(|source| RecoveryError::RetainedRefused { number, source })?;
    Ok(RetainedBlock { hash, companion, root, header, parent })
}

/// Recovery admission of the canonical head, the only way a token read back from the sidecar
/// becomes usable.
///
/// A cached accounting token is an optimization, never the authority. Whatever the sidecar holds,
/// this runs in full: the head's retained binding is re-checked against the canonical chain and
/// this node's pins; the binding the local Go side presents for the head, from its own
/// reauthentication of the named parent context, must itself verify for that head and must equal
/// the retained one in everything but its subject; only then is the head's token taken from the
/// cache or replayed, and admitted. Tokens of the recent window whose own retained binding still
/// checks are admitted with it; the rest stay unusable.
///
/// Missing companion, an empty or changed retained binding, another pair's pins and a presented
/// binding that names another parent context are each a distinct [`RecoveryError`].
pub fn admit_recovered_head<P>(
    provider: &P,
    store: &CompanionStore,
    tokens: &UnicityParentAccountings,
    seal: UnicitySealConfig,
    presented: &[u8],
    limit: u64,
) -> eyre::Result<()>
where
    P: BlockReader<Block = Block, Header = Header, Transaction = TransactionSigned>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + StateProviderFactory,
{
    let head = provider.best_block_number()?;
    if head == 0 {
        return Ok(());
    }
    let chain = provider.chain_spec();
    let genesis = chain.genesis_hash();
    let retained = check_retained(provider, store, seal, genesis, head)?;
    let presented_binding = PairBinding::from_canonical_cbor(presented)
        .map_err(|source| RecoveryError::PresentedRefused { number: head, source })?;
    let subject =
        subject_for(head, presented_binding.subject, retained.hash, retained.header.header())?;
    verify_pair_binding(
        presented,
        &PairContext {
            pins: seal.pins,
            execution_genesis_hash: genesis,
            parent: &retained.parent,
            root: &retained.root,
            subject,
        },
    )
    .map_err(|source| RecoveryError::PresentedRefused { number: head, source })?;
    let mut same_context = presented_binding;
    same_context.subject =
        PairBinding::from_canonical_cbor(&retained.companion.pair_binding)?.subject;
    if same_context != PairBinding::from_canonical_cbor(&retained.companion.pair_binding)? {
        return Err(RecoveryError::PresentedDiffers(head).into());
    }
    // Only now is any cached or replayed accounting consulted.
    let cached =
        tokens.restore_exact(&retained.header, chain.chain().id(), genesis, seal.profile)?;
    if cached.is_none() {
        repair_accounting(provider, store, tokens, seal, head, limit)?;
    }
    // The head's own token must outlive the restoration of the window behind it: every restore
    // inserts, and a store that already holds newer tokens (a build in flight) would evict the
    // head to make room for the older blocks.
    let Some(_head_pin) = tokens.pin(&retained.hash) else {
        eyre::bail!("parent accounting unavailable: no token for the admitted head {head}");
    };
    for number in head.saturating_sub(ACCOUNTING_WINDOW.saturating_sub(1)).max(1)..head {
        let hash = canonical_hash(provider, number)?;
        let header = canonical_header(provider, hash)?;
        if tokens.restore_exact(&header, chain.chain().id(), genesis, seal.profile)?.is_some() &&
            check_retained(provider, store, seal, genesis, number).is_ok()
        {
            tokens.admit(&hash);
        }
    }
    if !tokens.admit(&retained.hash) {
        eyre::bail!("parent accounting unavailable: no token for the admitted head {head}");
    }
    Ok(())
}

/// Replays a missing canonical head from the nearest cached token within `limit` blocks. The
/// anchor's own retained binding is re-checked first, and every replayed block's binding is
/// re-checked before its input is replayed. Missing historical bodies, companions, state, or an
/// anchor are explicit refusals. Reached only from [`admit_recovered_head`], after the presented
/// binding verified.
fn repair_accounting<P>(
    provider: &P,
    store: &CompanionStore,
    tokens: &UnicityParentAccountings,
    seal: UnicitySealConfig,
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
    let UnicitySealConfig { profile, fee_collector, .. } = seal;
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
    if anchor >= 1 {
        // A cached anchor is usable for the replay only once its own retained binding checks.
        let held = check_retained(provider, store, seal, genesis, anchor)?;
        tokens.admit(&held.hash);
    }
    for number in anchor + 1..=target {
        let RetainedBlock { hash, root, parent, .. } =
            check_retained(provider, store, seal, genesis, number)?;
        let parent_hash = parent.hash();
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
        let bound = if number == 1 {
            bind_validated_genesis(root, profile, &parent, genesis, fee_collector)
        } else {
            let token = tokens
                .resolve(&parent, &chain, profile)
                .map_err(|_| eyre::eyre!("missing predecessor token for block {number}"))?;
            bind_completed_parent(root, profile, &parent, token.token(), fee_collector)
        }
        .map_err(|error| eyre::eyre!("parent accounting binding failed at {number}: {error:?}"))?;
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
    use alloy_primitives::Address;
    use reth_provider::test_utils::MockEthProvider;
    use reth_unicity_execution::{
        block_executor::{CompletedParent, LocalParentAccounting},
        pairing::PairPins,
    };

    const PROFILE: BlockProfile = BlockProfile {
        max_gas: 30_000_001,
        system_gas: 500_001,
        base_fee_floor: 7,
        elasticity: 2,
        change_denominator: 8,
    };

    const PINS: PairPins = PairPins { network_id: 1, root_genesis_id: B256::repeat_byte(1) };

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
        let missing_companion = repair_accounting(
            &provider,
            &store,
            &tokens,
            UnicitySealConfig { profile: PROFILE, fee_collector: Address::ZERO, pins: PINS },
            2,
            1,
        )
        .unwrap_err();
        // The cached anchor's own retained binding is re-checked before anything replays.
        assert!(matches!(
            missing_companion.downcast_ref::<RecoveryError>(),
            Some(RecoveryError::CompanionMissing(1))
        ));
        let error =
            select_repair_anchor(&provider, &tokens, PROFILE, 1, genesis, 3, 1).unwrap_err();
        assert!(error.to_string().contains("no verified token within 1 blocks of 3"));
    }
}
