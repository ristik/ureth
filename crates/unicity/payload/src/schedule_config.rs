//! The Engine API profile and epoch-driven EVM configuration reported by `eth_config`.

use alloy_consensus::Header;
use alloy_eips::{
    eip7840::BlobParams,
    eip7910::{EthForkConfig, SystemContract},
};
use alloy_primitives::{Address, Bytes};
use jsonrpsee::{types::ErrorObjectOwned, RpcModule};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_evm::ConfigureEvm;
use reth_revm::{database::StateProviderDatabase, db::EmptyDB};
use reth_rpc_eth_api::helpers::config::{evm_to_precompiles_map, EthConfigHandler};
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use reth_unicity_execution::{
    node_evm::UnicityNodeEvmConfig,
    rules::{
        assigned_root_epoch, check_supported_spec, evaluate, read_schedule, EntryState, RuleError,
        UnicityRules, GENESIS_SPEC,
    },
    VALIDATOR_REGISTRY,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// The fixed Engine API profile is the adapter's pairing contract. Epoch-scoped changes to the
/// interpreter are reported alongside it. They have no scheduled Unix activation timestamp.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    current: EthForkConfig,
    next: Option<EpochFork>,
    last: Option<EpochFork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unicity_active: Option<EpochFork>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EpochFork {
    activation_time: Option<u64>,
    activation_root_epoch: u64,
    not_before_uc_time: u64,
    blob_schedule: BlobParams,
    chain_id: String,
    fork_id: Bytes,
    precompiles: BTreeMap<String, Address>,
    system_contracts: BTreeMap<SystemContract, Address>,
}

pub(crate) fn module<P>(
    provider: P,
    evm: UnicityNodeEvmConfig,
) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError>
where
    P: StateProviderFactory
        + BlockReaderIdExt<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + Clone
        + Sync
        + 'static,
{
    let mut module = RpcModule::new(());
    module.register_method("eth_config", move |_, _, _| {
        config(&provider, &evm)
            .map_err(|error| ErrorObjectOwned::owned(-32603, error.to_string(), None::<()>))
    })?;
    Ok(module)
}

fn config<P>(provider: &P, evm: &UnicityNodeEvmConfig) -> eyre::Result<Config>
where
    P: StateProviderFactory
        + BlockReaderIdExt<Header = Header>
        + ChainSpecProvider<ChainSpec = ChainSpec>
        + Clone
        + 'static,
{
    let header = provider.latest_header()?.ok_or_else(|| eyre::eyre!("no canonical head"))?;
    let mut db = StateProviderDatabase::new(provider.state_by_block_hash(header.hash())?);
    let rules = UnicityRules::global();
    let entries = read_schedule(&mut db, VALIDATOR_REGISTRY)?;
    let epoch = assigned_root_epoch(&mut db)?;
    let current = evaluate(&entries, rules.known_rules(), epoch);
    if let Some(refusal) = current.refusal {
        return Err(RuleError::UpgradeRequired(refusal).into());
    }
    check_supported_spec(current.spec)?;

    let base = EthConfigHandler::new(provider.clone(), evm.chain_evm_config().clone())
        .config_for_header(&header)?;
    eyre::ensure!(base.next.is_none() && base.last.is_none(), "unexpected timestamp fork");
    let mut output = Config { current: base.current, next: None, last: None, unicity_active: None };

    // Cancun and Prague are the only supported specs, so there is at most one change. Evaluate
    // the actual schedule in epoch order, stopping if there is a required upgrade before it.
    let effective: BTreeMap<_, _> = entries
        .iter()
        .filter(|entry| entry.state != EntryState::Superseded)
        .map(|entry| (entry.rule_id, entry))
        .collect();
    let mut candidates: Vec<_> = effective.into_values().collect();
    candidates.sort_by_key(|entry| (entry.root_epoch, entry.change_id));
    for entry in candidates {
        let resolution = evaluate(&entries, rules.known_rules(), entry.root_epoch);
        if resolution.refusal.is_some() {
            break;
        }
        if resolution.spec == GENESIS_SPEC {
            continue;
        }
        check_supported_spec(resolution.spec)?;
        // Several entries can share an epoch. Attribute the transition to the rule selecting it.
        let entry_spec =
            rules.known_rules().iter().find(|rule| rule.id == entry.rule_id).map(|rule| rule.spec);
        if entry_spec != Some(resolution.spec) {
            continue;
        }
        let env = evm.rpc_env_with_spec(&header, None, resolution.spec)?;
        let fork = EpochFork {
            activation_time: None,
            activation_root_epoch: entry.root_epoch,
            not_before_uc_time: entry.not_before_uc_time,
            blob_schedule: output.current.blob_schedule,
            chain_id: format!("{:#x}", output.current.chain_id),
            fork_id: output.current.fork_id.clone(),
            precompiles: evm_to_precompiles_map(evm.evm_with_env(EmptyDB::default(), env)),
            system_contracts: output.current.system_contracts.clone(),
        };
        if entry.root_epoch <= epoch {
            output.unicity_active = Some(fork);
        } else {
            output.last = Some(fork.clone());
            output.next = Some(fork);
        }
        break;
    }
    Ok(output)
}
