//! Resolve per-block fees from the parent state and the generation's fixed gas profile.

use std::{fmt, sync::Arc};

use alloy_consensus::Header;
use alloy_primitives::{address, b256, keccak256, Address, B256};
use reth_chainspec::ChainSpec;
use reth_primitives_traits::SealedHeader;
use reth_storage_api::StateProviderFactory;
use reth_unicity_execution::block::BlockProfile;

use crate::node::UnicitySealConfig;

// Validator-registry schema v1, V+11 through V+15.
const REGISTRY: Address = address!("ff00000000000000000000000000000000000003");
const PREVIOUS: B256 = b256!("2015195c564edf8b5942ad7bb1fe48e96d190815eb762db2ddff1d85ce73f90b");

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fees {
    pub(crate) profile: BlockProfile,
    pub(crate) collector: Address,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FeeState {
    previous: Fees,
    current: Fees,
    pub(crate) effective_block: u64,
}

impl FeeState {
    pub(crate) const fn for_block(self, number: u64) -> Fees {
        if number >= self.effective_block {
            self.current
        } else {
            self.previous
        }
    }

    fn decode(words: [[u8; 32]; 5], profile: BlockProfile) -> eyre::Result<Self> {
        let fee_set = |packed: [u8; 32], collector: [u8; 32]| {
            eyre::ensure!(packed[..16] == [0; 16], "noncanonical VR fee word");
            eyre::ensure!(collector[..12] == [0; 12], "noncanonical VR collector word");
            let collector = Address::from_slice(&collector[12..]);
            eyre::ensure!(!collector.is_zero(), "zero VR fee collector");
            let profile = BlockProfile {
                base_fee_floor: u64::from_be_bytes(packed[24..].try_into()?),
                change_denominator: u64::from_be_bytes(packed[16..24].try_into()?),
                ..profile
            };
            profile.validate().map_err(|err| eyre::eyre!("invalid VR fee profile: {err:?}"))?;
            Ok::<_, eyre::Report>(Fees { profile, collector })
        };
        eyre::ensure!(words[4][..24] == [0; 24], "noncanonical VR fee effective block");
        Ok(Self {
            previous: fee_set(words[0], words[1])?,
            current: fee_set(words[2], words[3])?,
            effective_block: u64::from_be_bytes(words[4][24..].try_into()?),
        })
    }
}

pub(crate) fn has_registry(chain: &ChainSpec) -> bool {
    registry_code(chain).is_some()
}

fn registry_code(chain: &ChainSpec) -> Option<B256> {
    chain
        .genesis()
        .alloc
        .get(&REGISTRY)?
        .code
        .as_ref()
        .filter(|code| !code.is_empty())
        .map(keccak256)
}

fn fee_slot(i: usize) -> B256 {
    let mut key = PREVIOUS;
    key[31] += i as u8;
    key
}

pub(crate) fn validate_genesis(chain: &ChainSpec, seal: UnicitySealConfig) -> eyre::Result<()> {
    if has_registry(chain) {
        let account = &chain.genesis().alloc[&REGISTRY];
        let words = std::array::from_fn(|i| {
            account
                .storage
                .as_ref()
                .and_then(|storage| storage.get(&fee_slot(i)))
                .copied()
                .unwrap_or_default()
                .0
        });
        let genesis = FeeState::decode(words, seal.profile)?;
        let profiles_match =
            [genesis.previous, genesis.current].iter().all(|fees| fees.profile == seal.profile);
        let collectors_match = [genesis.previous, genesis.current]
            .iter()
            .all(|fees| fees.collector == seal.fee_collector);
        eyre::ensure!(
            genesis.effective_block == 0 && profiles_match && collectors_match,
            "configured fee parameters differ from validator registry genesis"
        );
    }
    Ok(())
}

fn read_vr_fees(
    provider: &impl StateProviderFactory,
    code_hash: B256,
    parent_hash: B256,
    profile: BlockProfile,
) -> eyre::Result<FeeState> {
    let state = provider.state_by_block_hash(parent_hash)?;
    eyre::ensure!(
        state.basic_account(&REGISTRY)?.and_then(|account| account.bytecode_hash) ==
            Some(code_hash),
        "parent state lacks the genesis-pinned validator registry"
    );
    let mut words = [[0; 32]; 5];
    for (i, word) in words.iter_mut().enumerate() {
        *word = state.storage(REGISTRY, fee_slot(i))?.unwrap_or_default().to_be_bytes();
    }
    FeeState::decode(words, profile)
}

pub(crate) fn fee_state(
    provider: &impl StateProviderFactory,
    chain: &ChainSpec,
    parent_hash: B256,
    seal: UnicitySealConfig,
) -> eyre::Result<FeeState> {
    if let Some(code_hash) = registry_code(chain) {
        return read_vr_fees(provider, code_hash, parent_hash, seal.profile);
    }
    let fees = Fees { profile: seal.profile, collector: seal.fee_collector };
    Ok(FeeState { previous: fees, current: fees, effective_block: 0 })
}

pub(crate) fn block_profile(
    provider: &impl StateProviderFactory,
    chain: &ChainSpec,
    block: &SealedHeader<Header>,
    profile: BlockProfile,
) -> eyre::Result<BlockProfile> {
    match registry_code(chain) {
        Some(code_hash) => Ok(read_vr_fees(provider, code_hash, block.parent_hash, profile)?
            .for_block(block.number)
            .profile),
        None => Ok(profile),
    }
}

#[derive(Clone)]
pub(crate) struct FeeReader(Arc<dyn Fn(B256) -> eyre::Result<FeeState> + Send + Sync>);

impl FeeReader {
    pub(crate) fn new(
        provider: impl StateProviderFactory + Sync + 'static,
        chain: &ChainSpec,
        seal: UnicitySealConfig,
    ) -> Option<Self> {
        let code_hash = registry_code(chain)?;
        Some(Self(Arc::new(move |parent| read_vr_fees(&provider, code_hash, parent, seal.profile))))
    }

    pub(crate) fn at(&self, hash: B256) -> eyre::Result<FeeState> {
        (self.0)(hash)
    }
}

impl fmt::Debug for FeeReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FeeReader")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn frozen_fee_transition_resolves_both_sides_from_parent_state() {
        let doc: Value = serde_json::from_str(include_str!(
            "../../execution/testdata/vr-schema-v1/arithmetic.json"
        ))
        .unwrap();
        let vector = doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["op"] == "fee.transition")
            .unwrap();
        let number = |x: &Value| x.as_u64().unwrap_or_else(|| x.as_str().unwrap().parse().unwrap());
        let floor = |f: &Value| number(&f["baseFeeFloor"]);
        let denom = |f: &Value| number(&f["changeDenominator"]);
        let collector = |f: &Value| f["feeCollector"].as_str().unwrap().parse::<Address>().unwrap();
        let b_ack = number(&vector["input"]["bAck"]);
        let effective = b_ack + 1;
        let profile = BlockProfile {
            max_gas: number(&vector["input"]["ordinaryCapacity"]) + 2_000_000,
            system_gas: 2_000_000,
            elasticity: 2,
            base_fee_floor: floor(&vector["input"]["previous"]),
            change_denominator: denom(&vector["input"]["previous"]),
        };
        let words = |current: &Value, at: u64| {
            let mut words = [[0; 32]; 5];
            for (i, f) in [&vector["input"]["previous"], current].into_iter().enumerate() {
                words[2 * i][24..].copy_from_slice(&floor(f).to_be_bytes());
                words[2 * i][16..24].copy_from_slice(&denom(f).to_be_bytes());
                words[2 * i + 1][12..].copy_from_slice(collector(f).as_slice());
            }
            words[4][24..].copy_from_slice(&at.to_be_bytes());
            words
        };
        let before = FeeState::decode(words(&vector["input"]["previous"], 0), profile).unwrap();
        let after = FeeState::decode(words(&vector["input"]["new"], effective), profile).unwrap();
        assert_eq!(after.effective_block, number(&vector["expect"]["effectiveBlock"]));
        for row in vector["expect"]["blocks"].as_array().unwrap() {
            let n = number(&row["block"]);
            let state = if n <= b_ack { before } else { after };
            for (height, expected) in [(n - 1, &row["fNminus1"]), (n, &row["fN"])] {
                let got = state.for_block(height);
                assert_eq!(got.profile.base_fee_floor, floor(expected));
                assert_eq!(got.profile.change_denominator, denom(expected));
                assert_eq!(got.collector, collector(expected));
            }
        }

        let mut invalid = words(&vector["input"]["new"], effective);
        invalid[0][24..]
            .copy_from_slice(&(reth_unicity_execution::block::MAX_BASE_FEE + 1).to_be_bytes());
        assert!(FeeState::decode(invalid, profile).is_err());
        invalid = words(&vector["input"]["new"], effective);
        invalid[3][0] = 1;
        assert!(FeeState::decode(invalid, profile).is_err());
    }

    #[test]
    fn genesis_checks_profile_and_collector_of_both_fee_sets() {
        use alloy_genesis::{Genesis, GenesisAccount};
        use alloy_primitives::{Bytes, U256};
        use reth_unicity_execution::{pairing::PairPins, update::B1Context};

        let seal = UnicitySealConfig {
            profile: BlockProfile {
                max_gas: 30_000_000,
                system_gas: 2_000_000,
                base_fee_floor: 1_000_000,
                change_denominator: 8,
                elasticity: 2,
            },
            fee_collector: Address::repeat_byte(1),
            pins: PairPins { network_id: 1, root_genesis_id: B256::ZERO },
            b1: B1Context {
                network: 1,
                root_genesis_id: B256::ZERO,
                execution_chain_id: 1,
                profile_hash: B256::ZERO,
                genesis_commitment: B256::ZERO,
                max_epochs: 2,
                hook: Default::default(),
            },
        };
        let packed: U256 = U256::from(seal.profile.change_denominator) << 64 |
            U256::from(seal.profile.base_fee_floor);
        let collector = B256::left_padding_from(seal.fee_collector.as_slice());
        let mut genesis = Genesis::default();
        genesis.alloc.insert(
            REGISTRY,
            GenesisAccount {
                code: Some(Bytes::from_static(&[0])),
                storage: Some(
                    [
                        (fee_slot(0), B256::from(packed.to_be_bytes::<32>())),
                        (fee_slot(1), collector),
                        (fee_slot(2), B256::from(packed.to_be_bytes::<32>())),
                        (fee_slot(3), collector),
                    ]
                    .into(),
                ),
                ..Default::default()
            },
        );
        validate_genesis(&ChainSpec::from_genesis(genesis.clone()), seal).unwrap();
        for i in 0..4 {
            let mut wrong = genesis.clone();
            let word = wrong
                .alloc
                .get_mut(&REGISTRY)
                .unwrap()
                .storage
                .as_mut()
                .unwrap()
                .get_mut(&fee_slot(i))
                .unwrap();
            word[31] ^= 2;
            assert!(validate_genesis(&ChainSpec::from_genesis(wrong), seal).is_err());
        }
    }
}
