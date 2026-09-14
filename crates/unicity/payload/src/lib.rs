//! Unicity per-payload `extraData` commitment provision (U2, bft-core #11).
//!
//! The stock Ethereum payload builder copies one per-process value, `EthereumBuilderConfig::extra_data`,
//! into every block it builds, and the stock payload id hashes only the standard attribute fields. This
//! crate adds, without editing any upstream crate:
//!
//! - [`UnicityPayloadAttributes`]: the standard attributes plus the 32-byte D1 commitment the block's
//!   header `extraData` must carry. The commitment has no default and is refused unless it is exactly 32
//!   bytes.
//! - A payload id that also covers the commitment, so two build jobs that differ only in their
//!   commitment are different jobs.
//! - [`UnicityPayloadBuilder`]: the stock `EthereumPayloadBuilder`, constructed for each job with that
//!   job's commitment as `extra_data`. Nothing is shared or mutated between jobs.
//!
//! INACTIVE. Nothing registers these types with an `EngineTypes`, a node, an RPC module or a capability,
//! so no Engine API method accepts them and normal node operation cannot reach them. This is provision
//! only: no system call, no import or validation hook, no companion data, and no `WithSealV1` semantics.
//! The commitment is copied verbatim; computing or checking it is not this crate's job.

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadId};
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_ethereum_payload_builder::{EthereumBuilderConfig, EthereumPayloadBuilder};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_payload_builder::EthBuiltPayload;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadAttributes;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation for the payload id: the stock id and the commitment are hashed under this tag, so
/// the result cannot equal a stock id computed from the same attributes.
pub const PAYLOAD_ID_DOMAIN: &[u8] = b"UNICITY_PAYLOAD_ID_EXTRADATA_COMMITMENT_V1";

/// Payload attributes with the per-payload header commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicityPayloadAttributes {
    /// The standard Engine API V3 attributes, unchanged.
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// The 32-byte value the built block's header `extraData` must carry. Required: deserialization
    /// refuses a missing field and any value that is not exactly 32 bytes of hex.
    pub commitment: B256,
}

impl UnicityPayloadAttributes {
    /// The payload id for these attributes on `parent`: the stock id, bound to the commitment.
    pub fn unicity_payload_id(&self, parent: &B256) -> PayloadId {
        let stock = PayloadAttributes::payload_id(&self.inner, parent);
        let mut hasher = Sha256::new();
        hasher.update(PAYLOAD_ID_DOMAIN);
        hasher.update(stock.0.as_slice());
        hasher.update(self.commitment.as_slice());
        let out = hasher.finalize();
        let mut id = [0u8; 8];
        id.copy_from_slice(&out[..8]);
        PayloadId::new(id)
    }
}

impl PayloadAttributes for UnicityPayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        self.unicity_payload_id(parent_hash)
    }

    fn timestamp(&self) -> u64 {
        PayloadAttributes::timestamp(&self.inner)
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        PayloadAttributes::withdrawals(&self.inner)
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        PayloadAttributes::parent_beacon_block_root(&self.inner)
    }

    fn slot_number(&self) -> Option<u64> {
        PayloadAttributes::slot_number(&self.inner)
    }

    fn target_gas_limit(&self) -> Option<u64> {
        PayloadAttributes::target_gas_limit(&self.inner)
    }
}

/// A payload builder that writes each job's commitment into its block's header `extraData`.
///
/// It holds the parts of a stock `EthereumPayloadBuilder` and constructs one per job, with that job's
/// commitment as `extra_data`. `base_config.extra_data` is therefore never used: every block built here
/// carries the commitment of the job that built it.
#[derive(Debug, Clone)]
pub struct UnicityPayloadBuilder<Pool, Client, EvmConfig> {
    client: Client,
    pool: Pool,
    evm_config: EvmConfig,
    base_config: EthereumBuilderConfig,
}

impl<Pool, Client, EvmConfig> UnicityPayloadBuilder<Pool, Client, EvmConfig> {
    /// `UnicityPayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        base_config: EthereumBuilderConfig,
    ) -> Self {
        Self { client, pool, evm_config, base_config }
    }
}

impl<Pool, Client, EvmConfig> UnicityPayloadBuilder<Pool, Client, EvmConfig>
where
    Pool: Clone,
    Client: Clone,
    EvmConfig: Clone,
{
    /// The stock builder for one job: the base configuration with this job's commitment as extraData.
    fn for_job(&self, commitment: B256) -> EthereumPayloadBuilder<Pool, Client, EvmConfig> {
        EthereumPayloadBuilder::new(
            self.client.clone(),
            self.pool.clone(),
            self.evm_config.clone(),
            self.base_config.clone().with_extra_data(commitment.0.to_vec().into()),
        )
    }
}

/// Splits Unicity build arguments into the job's commitment and stock build arguments.
fn split_args(
    args: BuildArguments<UnicityPayloadAttributes, EthBuiltPayload>,
) -> (B256, BuildArguments<EthPayloadAttributes, EthBuiltPayload>) {
    let BuildArguments {
        cached_reads,
        execution_cache,
        state_root_handle,
        config,
        cancel,
        best_payload,
    } = args;
    let (commitment, config) = split_config(config);
    (
        commitment,
        BuildArguments {
            cached_reads,
            execution_cache,
            state_root_handle,
            config,
            cancel,
            best_payload,
        },
    )
}

/// Splits a Unicity payload config into the job's commitment and a stock config. The payload id is
/// kept as computed from the Unicity attributes.
fn split_config(
    config: PayloadConfig<UnicityPayloadAttributes>,
) -> (B256, PayloadConfig<EthPayloadAttributes>) {
    let PayloadConfig { parent_header, parent_block_info, attributes, payload_id } = config;
    (
        attributes.commitment,
        PayloadConfig {
            parent_header,
            parent_block_info,
            attributes: attributes.inner,
            payload_id,
        },
    )
}

impl<Pool, Client, EvmConfig> PayloadBuilder for UnicityPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = UnicityPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let (commitment, args) = split_args(args);
        self.for_job(commitment).try_build(args)
    }

    fn on_missing_payload(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        let (commitment, args) = split_args(args);
        self.for_job(commitment).on_missing_payload(args)
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let (commitment, config) = split_config(config);
        self.for_job(commitment).build_empty_payload(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header};
    use alloy_primitives::{Address, Bytes};
    use reth_basic_payload_builder::BuildOutcome;
    use reth_chainspec::{ChainSpec, ChainSpecBuilder};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_primitives_traits::SealedHeader;
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::test_utils::{testing_pool, TestPool};
    use std::sync::Arc;

    type Provider = MockEthProvider<EthPrimitives, ChainSpec>;

    struct Fixture {
        provider: Provider,
        pool: TestPool,
        evm: EthEvmConfig,
        parent: Arc<SealedHeader>,
    }

    /// A post-Shanghai, pre-Cancun chain with one parent header, an empty pool and mock state. Cancun is
    /// left inactive so the test needs no parent beacon root or blob fields: extraData is all it checks.
    fn fixture() -> Fixture {
        let spec = ChainSpecBuilder::mainnet()
            .london_activated()
            .paris_activated()
            .shanghai_activated()
            .build();
        let provider = MockEthProvider::default().with_chain_spec(spec.clone());
        let header = Header {
            number: 1,
            gas_limit: 30_000_000,
            timestamp: 1_000,
            base_fee_per_gas: Some(1_000_000_000),
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(header.clone());
        provider.add_header(parent.hash(), header);
        Fixture {
            provider,
            pool: testing_pool(),
            evm: EthEvmConfig::new(Arc::new(spec)),
            parent: Arc::new(parent),
        }
    }

    fn inner() -> EthPayloadAttributes {
        EthPayloadAttributes {
            timestamp: 1_012,
            prev_randao: B256::repeat_byte(0x11),
            suggested_fee_recipient: Address::repeat_byte(0x22),
            withdrawals: Some(vec![]),
            parent_beacon_block_root: None,
            slot_number: None,
            target_gas_limit: None,
        }
    }

    fn attrs(commitment: B256) -> UnicityPayloadAttributes {
        UnicityPayloadAttributes { inner: inner(), commitment }
    }

    fn builder(f: &Fixture) -> UnicityPayloadBuilder<TestPool, Provider, EthEvmConfig> {
        UnicityPayloadBuilder::new(
            f.provider.clone(),
            f.pool.clone(),
            f.evm.clone(),
            // A base extraData that must never appear in a block this builder builds.
            EthereumBuilderConfig::new()
                .with_extra_data(Bytes::from_static(b"base-must-not-appear")),
        )
    }

    fn config(f: &Fixture, a: UnicityPayloadAttributes) -> PayloadConfig<UnicityPayloadAttributes> {
        let payload_id = a.payload_id(&f.parent.hash());
        PayloadConfig {
            parent_header: f.parent.clone(),
            parent_block_info: None,
            attributes: a,
            payload_id,
        }
    }

    fn extra_data_of(p: &EthBuiltPayload) -> Bytes {
        p.block().header().extra_data().clone()
    }

    fn build_full(
        b: &UnicityPayloadBuilder<TestPool, Provider, EthEvmConfig>,
        cfg: PayloadConfig<UnicityPayloadAttributes>,
    ) -> EthBuiltPayload {
        let args =
            BuildArguments::new(Default::default(), None, None, cfg, Default::default(), None);
        match b.try_build(args).expect("build") {
            BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) => payload,
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn different_commitments_are_different_jobs_and_reach_their_own_extra_data() {
        let f = fixture();
        let b = builder(&f);
        let (ca, cb) = (B256::repeat_byte(0xaa), B256::repeat_byte(0xbb));
        let (a, bb) = (attrs(ca), attrs(cb));

        let (ida, idb) = (a.payload_id(&f.parent.hash()), bb.payload_id(&f.parent.hash()));
        assert_ne!(ida, idb, "a commitment difference alone must change the payload id");

        // Interleaved: A empty, B full, A full, B empty. Each block carries its own job's commitment.
        let a_empty = b.build_empty_payload(config(&f, a.clone())).expect("a empty");
        let b_full = build_full(&b, config(&f, bb.clone()));
        let a_full = build_full(&b, config(&f, a));
        let b_empty = b.build_empty_payload(config(&f, bb)).expect("b empty");

        assert_eq!(extra_data_of(&a_empty).as_ref(), ca.as_slice());
        assert_eq!(extra_data_of(&a_full).as_ref(), ca.as_slice());
        assert_eq!(extra_data_of(&b_full).as_ref(), cb.as_slice());
        assert_eq!(extra_data_of(&b_empty).as_ref(), cb.as_slice());
    }

    #[test]
    fn the_same_commitment_is_the_same_job() {
        let f = fixture();
        let c = B256::repeat_byte(0x33);
        assert_eq!(attrs(c).payload_id(&f.parent.hash()), attrs(c).payload_id(&f.parent.hash()));
    }

    #[test]
    fn the_unicity_id_is_domain_separated_from_the_stock_id() {
        let f = fixture();
        let a = attrs(B256::ZERO);
        assert_ne!(
            a.payload_id(&f.parent.hash()),
            PayloadAttributes::payload_id(&a.inner, &f.parent.hash()),
            "even a zero commitment must not reproduce the stock id"
        );
    }

    #[test]
    fn the_payload_id_is_the_documented_derivation() {
        let f = fixture();
        let c = B256::repeat_byte(0x5a);
        let a = attrs(c);
        let stock = PayloadAttributes::payload_id(&a.inner, &f.parent.hash());
        // The domain tag is written out rather than taken from the constant, so changing either fails here.
        let mut h = Sha256::new();
        h.update(b"UNICITY_PAYLOAD_ID_EXTRADATA_COMMITMENT_V1");
        h.update(stock.0.as_slice());
        h.update(c.as_slice());
        let out = h.finalize();
        let mut want = [0u8; 8];
        want.copy_from_slice(&out[..8]);
        assert_eq!(a.payload_id(&f.parent.hash()), PayloadId::new(want));
    }

    #[test]
    fn missing_or_malformed_commitments_are_refused() {
        let base = serde_json::json!({
            "timestamp": "0x3f4",
            "prevRandao": format!("{:#x}", B256::repeat_byte(0x11)),
            "suggestedFeeRecipient": format!("{:#x}", Address::repeat_byte(0x22)),
            "withdrawals": []
        });

        let mut good = base.clone();
        good["commitment"] = serde_json::json!(format!("{:#x}", B256::repeat_byte(0x44)));
        let parsed: UnicityPayloadAttributes =
            serde_json::from_value(good).expect("premise: well-formed");
        assert_eq!(parsed.commitment, B256::repeat_byte(0x44));
        assert_eq!(parsed.inner.timestamp, 0x3f4);

        let cases = [
            ("missing", None),
            ("31 bytes", Some(format!("0x{}", "44".repeat(31)))),
            ("33 bytes", Some(format!("0x{}", "44".repeat(33)))),
            ("not hex", Some(format!("0x{}", "zz".repeat(32)))),
            ("empty", Some("0x".to_string())),
        ];
        for (name, value) in cases {
            let mut v = base.clone();
            if let Some(value) = value {
                v["commitment"] = serde_json::json!(value);
            }
            assert!(
                serde_json::from_value::<UnicityPayloadAttributes>(v).is_err(),
                "{name} commitment must be refused"
            );
        }
    }

    #[test]
    fn the_stock_builder_and_stock_id_are_unchanged() {
        let f = fixture();
        let stock = EthereumPayloadBuilder::new(
            f.provider.clone(),
            f.pool.clone(),
            f.evm.clone(),
            EthereumBuilderConfig::new().with_extra_data(Bytes::from_static(b"stock-extra")),
        );
        let a = inner();
        let payload_id = PayloadAttributes::payload_id(&a, &f.parent.hash());
        assert_eq!(
            payload_id,
            reth_payload_primitives::payload_id(&f.parent.hash(), &a),
            "the stock id is still the stock function"
        );
        let cfg = PayloadConfig {
            parent_header: f.parent,
            parent_block_info: None,
            attributes: a,
            payload_id,
        };
        let p = stock.build_empty_payload(cfg).expect("stock empty");
        assert_eq!(extra_data_of(&p).as_ref(), b"stock-extra");
    }
}
