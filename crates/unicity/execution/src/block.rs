//! Shared block-accounting primitives used by build and replay adapters.
//!
//! This module does not activate a node path. A future adapter must construct
//! [`ParentExecutionOutcome`] from authenticated or locally re-executed parent data; accepting an
//! arbitrary caller-supplied ordinary-gas scalar is outside this API.

use alloy_primitives::B256;

/// Maximum base fee accepted by the bounded profile.
pub const MAX_BASE_FEE: u64 = 1 << 62;

/// Fixed gas and fee parameters for one deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockProfile {
    /// Header gas limit (`g_max`), retained as the real EVM block gas limit.
    pub max_gas: u64,
    /// Combined gross open/finalize reservation (`g_sys`).
    pub system_gas: u64,
    /// Positive base-fee floor.
    pub base_fee_floor: u64,
    /// EIP-1559 elasticity denominator.
    pub elasticity: u64,
    /// EIP-1559 change denominator.
    pub change_denominator: u64,
}

/// Profile or accounting rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAccountingError {
    /// A required positive configuration value was zero.
    ZeroParameter,
    /// Parameters are outside the single supported London profile.
    UnsupportedProfile,
    /// Reserved system gas leaves no ordinary capacity.
    NoOrdinaryCapacity,
    /// A gas sum or fee computation overflowed.
    Overflow,
    /// Derived work exceeds its fixed capacity.
    CapacityExceeded,
    /// Parent gross gas cannot be reconciled with its derived buckets.
    ParentGasMismatch,
    /// Parent base fee is absent or outside the bounded profile.
    InvalidParentBaseFee,
}

impl BlockProfile {
    /// Validates the bounded profile.
    pub const fn validate(self) -> Result<Self, BlockAccountingError> {
        if self.max_gas == 0 ||
            self.system_gas == 0 ||
            self.base_fee_floor == 0 ||
            self.elasticity == 0 ||
            self.change_denominator == 0
        {
            return Err(BlockAccountingError::ZeroParameter);
        }
        if self.system_gas >= self.max_gas {
            return Err(BlockAccountingError::NoOrdinaryCapacity);
        }
        if self.base_fee_floor > MAX_BASE_FEE {
            return Err(BlockAccountingError::InvalidParentBaseFee);
        }
        let ordinary_capacity = self.max_gas - self.system_gas;
        if self.elasticity != 2 || !ordinary_capacity.is_multiple_of(self.elasticity) {
            return Err(BlockAccountingError::UnsupportedProfile);
        }
        Ok(self)
    }

    /// Gas available to paid ordinary transactions. It never changes the EVM block gas limit.
    pub fn ordinary_capacity(self) -> Result<u64, BlockAccountingError> {
        self.validate()?;
        Ok(self.max_gas - self.system_gas)
    }
}

/// Reconciled gas result for a block with no forced-inclusion prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockGasAccounting {
    /// Gross pre-refund privileged work.
    pub system: u64,
    /// Standard receipt gas from paid ordinary transactions.
    pub ordinary: u64,
    /// Header gas used, equal to `system + ordinary`.
    pub header: u64,
}

impl BlockGasAccounting {
    /// Reconciles system and ordinary work against the fixed split.
    pub fn derive(
        profile: BlockProfile,
        system: u64,
        ordinary: u64,
    ) -> Result<Self, BlockAccountingError> {
        let ordinary_capacity = profile.ordinary_capacity()?;
        if system > profile.system_gas || ordinary > ordinary_capacity {
            return Err(BlockAccountingError::CapacityExceeded);
        }
        let header = system.checked_add(ordinary).ok_or(BlockAccountingError::Overflow)?;
        if header > profile.max_gas {
            return Err(BlockAccountingError::CapacityExceeded);
        }
        Ok(Self { system, ordinary, header })
    }
}

/// Parent execution accounting derived from authenticated or locally re-executed data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentExecutionOutcome {
    profile: BlockProfile,
    parent_hash: B256,
    gas: BlockGasAccounting,
    base_fee: u64,
}

impl ParentExecutionOutcome {
    /// Reconciles a parent's gross header gas with its independently derived system work.
    pub(crate) fn reconcile(
        profile: BlockProfile,
        parent_hash: B256,
        header_gas: u64,
        system_gas: u64,
        base_fee: u64,
    ) -> Result<Self, BlockAccountingError> {
        profile.validate()?;
        if base_fee < profile.base_fee_floor || base_fee > MAX_BASE_FEE {
            return Err(BlockAccountingError::InvalidParentBaseFee);
        }
        let ordinary =
            header_gas.checked_sub(system_gas).ok_or(BlockAccountingError::ParentGasMismatch)?;
        let gas = BlockGasAccounting::derive(profile, system_gas, ordinary)?;
        if gas.header != header_gas {
            return Err(BlockAccountingError::ParentGasMismatch);
        }
        Ok(Self { profile, parent_hash, gas, base_fee })
    }

    /// Derived paid-ordinary gas that alone feeds the next base fee.
    pub const fn ordinary_gas(self) -> u64 {
        self.gas.ordinary
    }

    /// Validated parent base fee.
    pub const fn base_fee(self) -> u64 {
        self.base_fee
    }

    /// Header hash whose successful execution produced this accounting.
    pub const fn parent_hash(self) -> B256 {
        self.parent_hash
    }

    pub(crate) const fn profile(self) -> BlockProfile {
        self.profile
    }

    pub(crate) const fn system_gas(self) -> u64 {
        self.gas.system
    }

    pub(crate) const fn header_gas(self) -> u64 {
        self.gas.header
    }
}

/// Computes the next base fee from reconciled parent ordinary gas using checked wide arithmetic.
pub fn next_base_fee(parent: ParentExecutionOutcome) -> Result<u64, BlockAccountingError> {
    let profile = parent.profile;
    let ordinary_capacity = profile.ordinary_capacity()?;
    let target = ordinary_capacity / profile.elasticity;
    if target == 0 {
        return Err(BlockAccountingError::NoOrdinaryCapacity);
    }
    let used = parent.ordinary_gas();
    let base = parent.base_fee();
    let next = if used == target {
        base
    } else {
        let numerator = used.abs_diff(target);
        let product = u128::from(base)
            .checked_mul(u128::from(numerator))
            .ok_or(BlockAccountingError::Overflow)?;
        let delta = product / u128::from(target) / u128::from(profile.change_denominator);
        let delta = u64::try_from(delta).map_err(|_| BlockAccountingError::Overflow)?;
        if used > target {
            base.checked_add(delta.max(1)).ok_or(BlockAccountingError::Overflow)?
        } else {
            base.saturating_sub(delta)
        }
    };
    Ok(next.clamp(profile.base_fee_floor, MAX_BASE_FEE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleFile {
        max_base_fee: u64,
        vectors: Vec<OracleVector>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleVector {
        parent_base_fee: u64,
        ordinary_gas_used: u64,
        ordinary_capacity: u64,
        base_fee_floor: u64,
        elasticity: u64,
        change_denominator: u64,
        next_base_fee: u64,
    }

    const PROFILE: BlockProfile = BlockProfile {
        max_gas: 30_000_000,
        system_gas: 2_000_000,
        base_fee_floor: 1_000_000,
        elasticity: 2,
        change_denominator: 8,
    };

    #[test]
    fn gross_header_and_ordinary_capacity_are_distinct() {
        let gas = BlockGasAccounting::derive(PROFILE, 1_800_000, 15_000_000).unwrap();
        assert_eq!(PROFILE.ordinary_capacity().unwrap(), 28_000_000);
        assert_eq!(gas.header, 16_800_000);
        assert!(BlockGasAccounting::derive(PROFILE, 1_800_000, 28_000_001).is_err());
    }

    #[test]
    fn parent_reconciliation_drives_ordinary_only_base_fee() {
        let at_target = ParentExecutionOutcome::reconcile(
            PROFILE,
            B256::ZERO,
            15_800_000,
            1_800_000,
            10_000_000,
        )
        .unwrap();
        assert_eq!(at_target.ordinary_gas(), 14_000_000);
        assert_eq!(next_base_fee(at_target).unwrap(), 10_000_000);

        let full = ParentExecutionOutcome::reconcile(
            PROFILE,
            B256::ZERO,
            29_800_000,
            1_800_000,
            10_000_000,
        )
        .unwrap();
        assert_eq!(next_base_fee(full).unwrap(), 11_250_000);
    }

    #[test]
    fn idle_blocks_stop_at_positive_floor() {
        let parent =
            ParentExecutionOutcome::reconcile(PROFILE, B256::ZERO, 1_800_000, 1_800_000, 1_000_001)
                .unwrap();
        assert_eq!(next_base_fee(parent).unwrap(), PROFILE.base_fee_floor);
    }

    #[test]
    fn wide_fee_product_does_not_truncate() {
        let profile = BlockProfile { base_fee_floor: 1, ..PROFILE };
        let parent = ParentExecutionOutcome::reconcile(
            profile,
            B256::ZERO,
            29_800_000,
            1_800_000,
            10_000_000_000_000,
        )
        .unwrap();
        assert_eq!(next_base_fee(parent).unwrap(), 11_250_000_000_000);
    }

    #[test]
    fn base_fee_matches_independent_python_oracle() {
        // Generated by testdata/generate-d2-basefee-vectors.py from the accepted D2 integer
        // formula.
        let oracle: OracleFile =
            serde_json::from_str(include_str!("../testdata/d2-basefee-vectors.json")).unwrap();
        assert_eq!(oracle.max_base_fee, MAX_BASE_FEE);
        for vector in oracle.vectors {
            let system_gas = 2_000_000;
            let profile = BlockProfile {
                max_gas: vector.ordinary_capacity + system_gas,
                system_gas,
                base_fee_floor: vector.base_fee_floor,
                elasticity: vector.elasticity,
                change_denominator: vector.change_denominator,
            };
            let parent = ParentExecutionOutcome::reconcile(
                profile,
                B256::ZERO,
                vector.ordinary_gas_used + system_gas,
                system_gas,
                vector.parent_base_fee,
            )
            .unwrap();
            assert_eq!(next_base_fee(parent).unwrap(), vector.next_base_fee);
        }
    }

    #[test]
    fn unsupported_odd_capacity_is_explicitly_refused() {
        assert_eq!(
            BlockProfile { max_gas: 30_000_001, ..PROFILE }.validate(),
            Err(BlockAccountingError::UnsupportedProfile)
        );
    }
}
