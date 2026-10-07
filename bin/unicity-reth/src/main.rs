//! A seal-capable Reth node binary.
//!
//! The node, its Engine API seal siblings and the `unicity` read methods all live in
//! `reth-unicity-payload`; this binary only turns operator configuration into the constructor
//! arguments of `UnicityNode`. Nothing about the block profile is compiled in.

#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

// Required for "override_allocator_on_supported_platforms".
#[cfg(all(feature = "jemalloc", unix))]
use reth_cli_util::allocator::tikv_jemalloc_sys as _;

#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

use alloy_primitives::{Address, B256};
use clap::{Args, Parser};
use reth_config::Config as RethConfig;
use reth_ethereum_cli::{chainspec::EthereumChainSpecParser, interface::Cli};
use reth_unicity_execution::{block::BlockProfile, pairing::PairPins};
use reth_unicity_payload::{
    recovery::ACCOUNTING_WINDOW, SealJobRegistry, UnicityNode, UnicityRetentionConfig,
    UnicitySealConfig,
};
use tracing::{info, warn};

/// Operator configuration for the Unicity node.
///
/// Every value the node pins comes from here; the defaults are the profile the bounded execution
/// kernel pins, not a binary-local choice. The fee collector has no sensible default — a zero
/// address would silently burn fees — so it is required.
#[derive(Debug, Clone, Args)]
struct UnicityArgs {
    /// Beneficiary every Unicity payload attributes must name.
    #[arg(long = "unicity.fee-collector", value_name = "ADDRESS")]
    fee_collector: Address,

    /// Root network identifier this pair is pinned to. Every pair binding must name it.
    #[arg(long = "unicity.network-id", value_name = "ID")]
    network_id: u64,

    /// Identity of the pinned root genesis this pair is pinned to. Every pair binding must name
    /// it.
    #[arg(long = "unicity.root-genesis-id", value_name = "HASH")]
    root_genesis_id: B256,

    /// Header gas limit (`g_max`), retained as the real EVM block gas limit.
    #[arg(long = "unicity.max-gas", default_value_t = 30_000_000)]
    max_gas: u64,

    /// Combined gross open/finalize reservation (`g_sys`).
    #[arg(long = "unicity.system-gas", default_value_t = 2_000_000)]
    system_gas: u64,

    /// Positive base-fee floor.
    #[arg(long = "unicity.base-fee-floor", default_value_t = 1_000_000)]
    base_fee_floor: u64,

    /// EIP-1559 elasticity denominator.
    #[arg(long = "unicity.elasticity", default_value_t = 2)]
    elasticity: u64,

    /// EIP-1559 base-fee change denominator.
    #[arg(long = "unicity.base-fee-change-denominator", default_value_t = 8)]
    base_fee_change_denominator: u64,

    /// Number of blocks of companions to retain behind the tip.
    ///
    /// Absent retains every companion indefinitely and publishes no horizon.
    #[arg(long = "unicity.companion-retention-depth", value_name = "BLOCKS")]
    companion_retention_depth: Option<u64>,

    /// Disable protection against pruning receipt, transaction and companion data needed for
    /// offline proof capture.
    #[arg(long = "unicity.no-proof-source")]
    no_proof_source: bool,

    /// Maximum historical blocks replayed from a durable parent-accounting token at startup.
    #[arg(long = "unicity.accounting-repair-limit", default_value_t = 64, value_name = "BLOCKS")]
    accounting_repair_limit: u64,
}

impl UnicityArgs {
    /// Validates the configured block profile before the node starts.
    ///
    /// The default values are the `PROFILE` constant in `crates/unicity/execution/src/block.rs`.
    /// A rejected profile names the `BlockAccountingError` variant, so the operator sees the
    /// reason instead of a later, more confusing failure.
    fn profile(&self) -> eyre::Result<BlockProfile> {
        let profile = BlockProfile {
            max_gas: self.max_gas,
            system_gas: self.system_gas,
            base_fee_floor: self.base_fee_floor,
            elasticity: self.elasticity,
            change_denominator: self.base_fee_change_denominator,
        };
        profile.validate().map_err(|err| eyre::eyre!("invalid --unicity profile: {err:?}"))
    }

    /// The companion retention policy this configuration selects.
    ///
    /// An absent depth maps to indefinite retention; a configured depth is a number of blocks
    /// behind the tip, not an absolute block number.
    const fn retention(&self) -> UnicityRetentionConfig {
        match self.companion_retention_depth {
            Some(depth) => UnicityRetentionConfig::retain_last(depth),
            None => UnicityRetentionConfig::retain_indefinitely(),
        }
    }

    /// Whether this validator protects data needed for offline proof capture.
    const fn proof_source_enabled(&self) -> bool {
        !self.no_proof_source
    }

    fn validate_retention(&self) -> eyre::Result<()> {
        let Some(depth) = self.companion_retention_depth else {
            return Ok(());
        };
        let required =
            ACCOUNTING_WINDOW.checked_add(self.accounting_repair_limit).ok_or_else(|| {
                eyre::eyre!("accounting repair limit is too large for companion retention")
            })?;
        eyre::ensure!(
            depth >= required,
            "--unicity.companion-retention-depth ({depth}) must be at least accounting window + repair limit ({required})"
        );
        Ok(())
    }

    /// Reject proof-source settings that could prune required data before services start.
    fn validate_proof_source(
        &self,
        cli_prune: Option<reth_config::PruneConfig>,
        toml_prune: reth_config::PruneConfig,
    ) -> eyre::Result<()> {
        if !self.proof_source_enabled() {
            return Ok(());
        }
        let effective = match cli_prune {
            Some(mut cli) => {
                cli.merge(toml_prune);
                cli
            }
            None => toml_prune,
        };
        reth_unicity_payload::prune::validate_proof_retention(
            &effective.segments,
            self.companion_retention_depth,
        )
    }
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) = Cli::<EthereumChainSpecParser, UnicityArgs>::parse().run(
        async move |builder, args: UnicityArgs| {
            let profile = args.profile()?;
            args.validate_retention()?;
            if args.proof_source_enabled() {
                // Validate before launch starts payload-building and other node services.
                // Keep the same CLI-over-TOML precedence as LaunchContext::prune_config.
                let node_config = builder.config();
                let config_path = node_config
                    .config
                    .clone()
                    .unwrap_or_else(|| node_config.datadir().config());
                let disk_config = RethConfig::from_path(config_path)?;
                args.validate_proof_source(node_config.prune_config(), disk_config.prune)?;
            } else {
                warn!(
                    target: "reth::unicity",
                    "proof-source retention protection is disabled; pruning may permanently remove data required for offline proof capture"
                );
            }
            let seal = UnicitySealConfig {
                profile,
                fee_collector: args.fee_collector,
                pins: PairPins {
                    network_id: args.network_id,
                    root_genesis_id: args.root_genesis_id,
                },
            };

            info!(target: "reth::cli", "Launching Unicity node");
            let handle = builder
                .node(
                    UnicityNode::new(SealJobRegistry::new(), seal)
                        .with_retention(args.retention())
                        .with_proof_source(args.proof_source_enabled())
                        .with_repair_limit(args.accounting_repair_limit),
                )
                .launch()
                .await?;

            handle.wait_for_node_exit().await
        },
    ) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use reth_prune_types::{PruneMode, ReceiptsLogPruneConfig};

    #[test]
    fn companion_retention_covers_accounting_repair() {
        let args = UnicityArgs {
            fee_collector: Address::ZERO,
            network_id: 1,
            root_genesis_id: B256::repeat_byte(1),
            max_gas: 30_000_000,
            system_gas: 2_000_000,
            base_fee_floor: 1_000_000,
            elasticity: 2,
            base_fee_change_denominator: 8,
            companion_retention_depth: Some(ACCOUNTING_WINDOW + 2 - 1),
            accounting_repair_limit: 2,
            no_proof_source: false,
        };
        assert!(args.validate_retention().is_err());
        let args = UnicityArgs { companion_retention_depth: Some(ACCOUNTING_WINDOW + 2), ..args };
        assert!(args.validate_retention().is_ok());
    }

    fn proof_args(enabled: bool, companion_retention_depth: Option<u64>) -> UnicityArgs {
        UnicityArgs {
            fee_collector: Address::ZERO,
            network_id: 1,
            root_genesis_id: B256::repeat_byte(1),
            max_gas: 30_000_000,
            system_gas: 2_000_000,
            base_fee_floor: 1_000_000,
            elasticity: 2,
            base_fee_change_denominator: 8,
            companion_retention_depth,
            no_proof_source: !enabled,
            accounting_repair_limit: 64,
        }
    }

    #[test]
    fn proof_source_refuses_every_pruning_combination_and_accepts_defaults() {
        let receipt_modes =
            [None, Some(PruneMode::Full), Some(PruneMode::Before(1)), Some(PruneMode::Distance(1))];
        let body_modes = receipt_modes;
        for receipt in receipt_modes {
            for filter_receipts in [false, true] {
                for bodies in body_modes {
                    for companion_depth in [None, Some(1)] {
                        let mut toml = RethConfig::default();
                        toml.prune.segments.receipts = receipt;
                        toml.prune.segments.bodies_history = bodies;
                        if filter_receipts {
                            toml.prune.segments.receipts_log_filter = ReceiptsLogPruneConfig(
                                [(Address::ZERO, PruneMode::Before(1))].into(),
                            );
                        }
                        let should_reject = receipt.is_some() ||
                            filter_receipts ||
                            bodies.is_some() ||
                            companion_depth.is_some();
                        assert_eq!(
                            proof_args(true, companion_depth)
                                .validate_proof_source(None, toml.prune)
                                .is_err(),
                            should_reject,
                            "receipt={receipt:?}, filtered={filter_receipts}, bodies={bodies:?}, companion={companion_depth:?}"
                        );
                    }
                }
            }
        }

        // Account/storage history and rebuildable indexes do not remove proof-source material.
        let mut allowed = RethConfig::default();
        allowed.prune.segments.account_history = Some(PruneMode::Distance(1));
        allowed.prune.segments.storage_history = Some(PruneMode::Distance(1));
        allowed.prune.segments.sender_recovery = Some(PruneMode::Full);
        allowed.prune.segments.transaction_lookup = Some(PruneMode::Full);
        assert!(proof_args(true, None).validate_proof_source(None, allowed.prune).is_ok());
        assert!(proof_args(true, None)
            .validate_proof_source(None, RethConfig::default().prune)
            .is_ok());
    }

    #[test]
    fn effective_pruning_includes_toml_and_cli_segments() {
        let mut toml = RethConfig::default().prune;
        toml.segments.receipts = Some(PruneMode::Full);
        let cli = reth_config::PruneConfig {
            segments: reth_prune_types::PruneModes {
                account_history: Some(PruneMode::Distance(1)),
                ..Default::default()
            },
            ..Default::default()
        };
        // A CLI override of one segment must not mask a destructive TOML segment.
        assert!(proof_args(true, None).validate_proof_source(Some(cli), toml.clone()).is_err());

        let cli = reth_config::PruneConfig {
            segments: reth_prune_types::PruneModes {
                bodies_history: Some(PruneMode::Distance(1)),
                ..Default::default()
            },
            ..Default::default()
        };
        toml.segments.receipts = None;
        assert!(proof_args(true, None).validate_proof_source(Some(cli), toml).is_err());

        // Explicitly opting out keeps existing pruning configurations accepted.
        let mut destructive = RethConfig::default().prune;
        destructive.segments.receipts = Some(PruneMode::Full);
        assert!(proof_args(false, None).validate_proof_source(None, destructive).is_ok());
    }

    #[test]
    fn proof_source_is_on_by_default_and_explicitly_opt_out() {
        use clap::FromArgMatches;

        let command = <UnicityArgs as clap::Args>::augment_args(clap::Command::new("unicity"));
        let matches = command
            .clone()
            .try_get_matches_from([
                "unicity",
                "--unicity.fee-collector=0x0000000000000000000000000000000000000000",
                "--unicity.network-id=1",
                "--unicity.root-genesis-id=0x0101010101010101010101010101010101010101010101010101010101010101",
            ])
            .unwrap();
        let defaults = UnicityArgs::from_arg_matches(&matches).unwrap();
        assert!(defaults.proof_source_enabled());

        let matches = command
            .try_get_matches_from([
                "unicity",
                "--unicity.fee-collector=0x0000000000000000000000000000000000000000",
                "--unicity.network-id=1",
                "--unicity.root-genesis-id=0x0101010101010101010101010101010101010101010101010101010101010101",
                "--unicity.no-proof-source",
            ])
            .unwrap();
        let opt_out = UnicityArgs::from_arg_matches(&matches).unwrap();
        assert!(!opt_out.proof_source_enabled());
    }

    #[test]
    fn default_proof_source_mode_refuses_destructive_pruning() {
        use clap::FromArgMatches;

        let command = <UnicityArgs as clap::Args>::augment_args(clap::Command::new("unicity"));
        let matches = command
            .try_get_matches_from([
                "unicity",
                "--unicity.fee-collector=0x0000000000000000000000000000000000000000",
                "--unicity.network-id=1",
                "--unicity.root-genesis-id=0x0101010101010101010101010101010101010101010101010101010101010101",
            ])
            .unwrap();
        let args = UnicityArgs::from_arg_matches(&matches).unwrap();
        assert!(args.proof_source_enabled());
        let mut destructive = RethConfig::default().prune;
        destructive.segments.receipts = Some(PruneMode::Full);
        assert!(args.validate_proof_source(None, destructive).is_err());
    }
}
