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

use alloy_primitives::Address;
use clap::{Args, Parser};
use reth_ethereum_cli::{chainspec::EthereumChainSpecParser, interface::Cli};
use reth_unicity_execution::block::BlockProfile;
use reth_unicity_payload::{
    SealJobRegistry, UnicityNode, UnicityRetentionConfig, UnicitySealConfig,
};
use tracing::info;

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
            let seal = UnicitySealConfig { profile, fee_collector: args.fee_collector };

            info!(target: "reth::cli", "Launching Unicity node");
            let handle = builder
                .node(
                    UnicityNode::new(SealJobRegistry::new(), seal)
                        .with_retention(args.retention())
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
