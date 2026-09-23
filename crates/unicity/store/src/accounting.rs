//! Fixed local encoding for completed parent accounting; companion v1 bytes stay untouched.

use alloy_primitives::B256;
use reth_unicity_execution::{block::BlockProfile, block_executor::LocalParentAccounting};

use crate::StoreError;

const SCHEMA: u8 = 1;
/// Version of the execution rules that mint accounting tokens.
pub const RULE_VERSION: u8 = 1;
const RECORD_LEN: usize = 1 + 1 + 8 + 32 + 8 + 32 + 40 + 32;

/// Chain-bound accounting record read only from this node's local sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredAccounting {
    /// Ethereum chain identifier.
    pub chain_id: u64,
    /// Configured genesis hash.
    pub genesis_hash: B256,
    /// Number of the completed block.
    pub block_number: u64,
    /// Locally measured execution accounting.
    pub accounting: LocalParentAccounting,
}

pub(crate) fn encode(record: StoredAccounting) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_LEN);
    out.extend_from_slice(&[SCHEMA, RULE_VERSION]);
    out.extend_from_slice(&record.chain_id.to_be_bytes());
    out.extend_from_slice(record.genesis_hash.as_slice());
    out.extend_from_slice(&record.block_number.to_be_bytes());
    out.extend_from_slice(record.accounting.block_hash.as_slice());
    let profile = record.accounting.profile;
    for value in [
        profile.max_gas,
        profile.system_gas,
        profile.base_fee_floor,
        profile.elasticity,
        profile.change_denominator,
        record.accounting.header_gas,
        record.accounting.system_gas,
        record.accounting.ordinary_gas,
        record.accounting.base_fee,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

pub(crate) fn decode(bytes: &[u8]) -> Result<StoredAccounting, StoreError> {
    if bytes.len() != RECORD_LEN {
        return Err(StoreError::MalformedRecord("accounting record length"));
    }
    if bytes[0] != SCHEMA {
        return Err(StoreError::UnknownVersion(bytes[0]));
    }
    if bytes[1] != RULE_VERSION {
        return Err(StoreError::UnknownVersion(bytes[1]));
    }
    let number = |start: usize| u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    Ok(StoredAccounting {
        chain_id: number(2),
        genesis_hash: B256::from_slice(&bytes[10..42]),
        block_number: number(42),
        accounting: LocalParentAccounting {
            block_hash: B256::from_slice(&bytes[50..82]),
            profile: BlockProfile {
                max_gas: number(82),
                system_gas: number(90),
                base_fee_floor: number(98),
                elasticity: number(106),
                change_denominator: number(114),
            },
            header_gas: number(122),
            system_gas: number(130),
            ordinary_gas: number(138),
            base_fee: number(146),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_rule_versions_are_refused() {
        let record = StoredAccounting {
            chain_id: 1,
            genesis_hash: B256::ZERO,
            block_number: 1,
            accounting: LocalParentAccounting {
                block_hash: B256::repeat_byte(1),
                profile: BlockProfile {
                    max_gas: 30_000_000,
                    system_gas: 2_000_000,
                    base_fee_floor: 1_000_000,
                    elasticity: 2,
                    change_denominator: 8,
                },
                header_gas: 2,
                system_gas: 1,
                ordinary_gas: 1,
                base_fee: 1_000_000,
            },
        };
        let encoded = encode(record);
        assert_eq!(decode(&encoded).unwrap(), record);
        let mut wrong_schema = encoded.clone();
        wrong_schema[0] = 2;
        assert!(matches!(decode(&wrong_schema), Err(StoreError::UnknownVersion(2))));
        let mut wrong_rules = encoded;
        wrong_rules[1] = 2;
        assert!(matches!(decode(&wrong_rules), Err(StoreError::UnknownVersion(2))));
    }
}
