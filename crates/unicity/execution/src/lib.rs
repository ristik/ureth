//! Inactive bounded `SealRegistry` execution kernel.
//!
//! Authentication of the structured input is an external prerequisite. This crate deliberately
//! accepts no caller authentication verdict. It derives the input and origin commitments locally,
//! checks the technical-record hash against the structured record, and derives the ABI projection
//! before executing the two privileged calls. Certificate authentication, configuration binding,
//! and binding `parent_hash` to the supplied parent state remain caller prerequisites. This is not
//! a block-builder, import, replay, node, or RPC activation.

use alloy_primitives::{b256, Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use revm::{
    context::TxEnv,
    context_interface::{ContextSetters, ContextTr, JournalTr},
    database::{CacheDB, DatabaseRef},
    handler::{EvmTr, Handler, MainnetHandler, SystemCallTx},
    primitives::hardfork::SpecId,
    Context, Database, DatabaseCommit, MainBuilder, MainContext,
};
use sha2::{Digest, Sha256};

pub mod block;
pub mod block_executor;

sol! {
    function open(
        uint64 n, uint64 rootRound, uint64 rootEpoch, uint64 timestamp,
        bytes32 treeRoot, bytes32 originIdentity, bytes32 trHash, bytes32 shardConfHash,
        uint64 certifiedRound, uint64 certEpoch, uint64 authEpoch, bytes32 stateHash,
        bool hasBlockHash, bytes32 blockHash, bytes32 inputCommitment, uint64 transitionCount
    );
    function finalize(uint64 n, bytes32 sealRegistryCommitment);
}

/// Fixed privileged caller from the pinned profile.
pub const SYSTEM_CALLER: Address =
    Address::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
/// Fixed registry destination from the pinned profile.
pub const SEAL_REGISTRY: Address =
    Address::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
/// Keccak-256 of the pinned `SealRegistry` v1 runtime artifact.
pub const SEAL_REGISTRY_CODE_HASH: B256 =
    b256!("643b1b983696b0de1f67053daf65c33b55d304de79074b55ee6f8829715a267b");
const OUTCOMES_ROUND_SLOT: B256 =
    b256!("a6dfb02f4e0457f6dc0ca8f4fd82b31c4a0df5261e0214610377f2af855a5ee5");
const OUTCOMES_COMMITMENT_SLOT: B256 =
    b256!("435c00c3e0bb551759ef849ef59de7b0a62c300b5c1aa3011d4363b09ddef85a");
const PHASE_SLOT: B256 = b256!("2d5c30492e4b770265db26c3b2d89794cb0435f97f91a351ae818c18236222a7");
#[cfg(test)]
const CERTIFIED_ROUND_SLOT: B256 =
    b256!("47a3f86feb14af4a7e5a1a1fb3362c95b32dfbf03a7a3ca31717f8e829382b3c");
#[cfg(test)]
const CERTIFIED_STATE_SLOT: B256 =
    b256!("e39f0827feecb5f38ffbd452e7c3556ecd0ba586a94434c3f5a10f846cbbfcea");
#[cfg(test)]
const CERTIFIED_HAS_BLOCK_SLOT: B256 =
    b256!("1b118c38b50e4765caa320a933997b81ec1218283e0c260e18a4609340314deb");
#[cfg(test)]
const CERTIFIED_BLOCK_SLOT: B256 =
    b256!("80ce058bdccaa08590781edd25c9005041ebaba94b6a8941896d46eb60394931");

#[derive(Clone, Debug, PartialEq, Eq)]
/// Authenticated shard input record with nullable v2 state fields.
pub struct InputRecordV2 {
    /// Certified shard round, or zero for bootstrap.
    pub round: u64,
    /// Certified shard epoch.
    pub epoch: u64,
    /// Previous state hash; `None` has distinct canonical CBOR meaning.
    pub previous_hash: Option<B256>,
    /// Certified state hash.
    pub state_hash: Option<B256>,
    /// Input-record timestamp.
    pub timestamp: u64,
    /// Certified block hash when the state changed.
    pub block_hash: Option<B256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Root-chain origin embedded in the canonical v2 input.
pub struct RootOriginV2 {
    /// Network identifier.
    pub network_id: u64,
    /// Root-chain round.
    pub root_round: u64,
    /// Configured root epoch.
    pub root_epoch: u64,
    /// Root reference time.
    pub reference_time: u64,
    /// Unicity-tree root.
    pub tree_root: B256,
    /// Authenticated input-record version.
    pub input_record_version: u64,
    /// Authenticated shard input record.
    pub input_record: InputRecordV2,
    /// Claimed technical-record hash, checked from [`RootInputV2::technical`].
    pub tr_hash: B256,
    /// Authenticated shard-configuration hash.
    pub shard_conf_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Structured technical record used to derive `tr_hash`.
pub struct TechnicalRecordV2 {
    /// Authorized shard round.
    pub round: u64,
    /// Authorized shard epoch.
    pub epoch: u64,
    /// Leader identifier.
    pub leader: String,
    /// Statistics hash.
    pub stat_hash: B256,
    /// Fee hash.
    pub fee_hash: B256,
}

/// Canonical v2 input. Its certificate and transition bodies must already have been authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootInputV2 {
    /// Profile version; fixed to two.
    pub version: u64,
    /// Network identifier.
    pub network_id: u64,
    /// Partition identifier.
    pub partition_id: u64,
    /// Canonical shard identifier bytes.
    pub shard_id: Vec<u8>,
    /// Positive round authorized by the technical record.
    pub authorized_round: u64,
    /// Certified shard epoch.
    pub certified_epoch: u64,
    /// Authorized shard epoch.
    pub authorized_epoch: u64,
    /// Expected execution parent; binding it to `parent` is a caller prerequisite.
    pub parent_hash: B256,
    /// Authenticated root origin.
    pub origin: RootOriginV2,
    /// Structured technical record.
    pub technical: TechnicalRecordV2,
    /// Authenticated transition bodies; unsupported by this bounded kernel.
    pub transitions: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Origin class derived from nullable input-record fields.
pub enum OriginClass {
    /// Initial nil-state origin.
    Bootstrap,
    /// First certified state with no previous state.
    FirstCertified,
    /// Later quiet or state-changing origin.
    Ordinary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Fixed execution limits supplied by the surrounding profile.
pub struct ExecutionConfig {
    /// Combined gross gas cap for open and finalize.
    pub system_gas_limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Derived commitments and gross pre-refund gas accounting for a successful pair.
pub struct ExecutionResult {
    /// Gross open gas spent before refunds.
    pub open_gas_spent: u64,
    /// Open refund observed but not credited to the privileged gas budget.
    pub open_gas_refunded: u64,
    /// Gross finalize gas spent before refunds.
    pub finalize_gas_spent: u64,
    /// Finalize refund observed but not credited to the privileged gas budget.
    pub finalize_gas_refunded: u64,
    /// Checked sum of both gross gas values.
    pub total_gas_spent: u64,
    /// Locally derived root-input commitment.
    pub input_commitment: B256,
    /// Locally derived root-origin identity.
    pub origin_identity: B256,
    /// Locally derived technical-record hash.
    pub technical_record_hash: B256,
    /// Derived system-outcome commitment written by finalize.
    pub registry_commitment: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Failure that makes the candidate state unpublishable.
pub enum ExecutionError {
    /// Structured input or pinned-parent precondition failed.
    InvalidInput(&'static str),
    /// Parent database access failed.
    Database(String),
    /// Open errored, reverted, or halted.
    OpenFailed(String),
    /// Finalize errored, reverted, halted, or produced wrong storage.
    FinalizeFailed(String),
    /// Combined gross gas exceeded the configured cap.
    GasBudgetExceeded {
        /// Gross gas spent when the failure was detected.
        spent: u64,
        /// Configured combined system-gas limit.
        limit: u64,
    },
}

impl RootInputV2 {
    /// Validates the bounded v2 shape and derives its origin class.
    pub fn origin_class(&self) -> Result<OriginClass, ExecutionError> {
        let ir = &self.origin.input_record;
        if self.version != 2 {
            return Err(ExecutionError::InvalidInput("profile version must be 2"));
        }
        if self.origin.input_record_version != 1 {
            return Err(ExecutionError::InvalidInput("input record version must be 1"));
        }
        if self.authorized_round == 0 || self.technical.round != self.authorized_round {
            return Err(ExecutionError::InvalidInput(
                "authorized round must be positive and equal the technical-record round",
            ));
        }
        if self.certified_epoch != 0 ||
            self.authorized_epoch != 0 ||
            self.technical.epoch != 0 ||
            ir.epoch != 0
        {
            return Err(ExecutionError::InvalidInput("bounded profile requires shard epoch zero"));
        }
        if self.network_id != self.origin.network_id {
            return Err(ExecutionError::InvalidInput("network identity mismatch"));
        }
        if self.transitions.iter().any(Vec::is_empty) {
            return Err(ExecutionError::InvalidInput("empty transition body"));
        }
        if technical_record_hash(&self.technical) != self.origin.tr_hash {
            return Err(ExecutionError::InvalidInput("technical record hash mismatch"));
        }
        match (&ir.previous_hash, &ir.state_hash, &ir.block_hash, ir.round, ir.timestamp) {
            (None, None, None, 0, 0) => Ok(OriginClass::Bootstrap),
            (None, Some(_), Some(_), round, _) if round > 0 => Ok(OriginClass::FirstCertified),
            (Some(previous), Some(state), None, round, _) if round > 0 && previous == state => {
                Ok(OriginClass::Ordinary)
            }
            (Some(previous), Some(state), Some(_), round, _) if round > 0 && previous != state => {
                Ok(OriginClass::Ordinary)
            }
            _ => Err(ExecutionError::InvalidInput("invalid v2 origin shape")),
        }
    }

    /// Returns RFC 8949 deterministic CBOR in the fixed v2 tuple order.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, ExecutionError> {
        self.origin_class()?;
        let mut out = Vec::new();
        array(&mut out, 11);
        uint(&mut out, self.version);
        uint(&mut out, self.network_id);
        uint(&mut out, self.partition_id);
        bytes(&mut out, &self.shard_id);
        uint(&mut out, self.authorized_round);
        uint(&mut out, self.certified_epoch);
        uint(&mut out, self.authorized_epoch);
        bytes(&mut out, self.parent_hash.as_slice());
        encode_origin(&mut out, &self.origin);
        encode_technical(&mut out, &self.technical);
        array(&mut out, self.transitions.len() as u64);
        for transition in &self.transitions {
            bytes(&mut out, transition);
        }
        Ok(out)
    }

    /// Returns `SHA-256(CBOR(rootInput))` after validation.
    pub fn input_commitment(&self) -> Result<B256, ExecutionError> {
        Ok(sha256(&self.canonical_cbor()?))
    }
    /// Returns `SHA-256(CBOR(origin))` after validation.
    pub fn origin_identity(&self) -> Result<B256, ExecutionError> {
        self.origin_class()?;
        let mut out = Vec::new();
        encode_origin(&mut out, &self.origin);
        Ok(sha256(&out))
    }
}

/// Returns the canonical technical-record SHA-256 hash.
pub fn technical_record_hash(record: &TechnicalRecordV2) -> B256 {
    let mut out = Vec::new();
    encode_technical(&mut out, record);
    sha256(&out)
}

pub(crate) struct PreparedTransition {
    pub n: u64,
    pub open_data: Bytes,
    pub input_commitment: B256,
    pub origin_identity: B256,
    pub technical_record_hash: B256,
}

pub(crate) fn prepare_transition(
    input: &RootInputV2,
) -> Result<PreparedTransition, ExecutionError> {
    let class = input.origin_class()?;
    if !input.transitions.is_empty() {
        return Err(ExecutionError::InvalidInput("transitions unsupported in bounded profile"));
    }
    let input_commitment = input.input_commitment()?;
    let origin_identity = input.origin_identity()?;
    let technical_record_hash = technical_record_hash(&input.technical);
    let ir = &input.origin.input_record;
    let (certified_round, state_hash, has_block_hash, block_hash) = match class {
        OriginClass::Bootstrap => (0, B256::ZERO, false, B256::ZERO),
        _ => (
            ir.round,
            ir.state_hash.expect("validated"),
            ir.block_hash.is_some(),
            ir.block_hash.unwrap_or_default(),
        ),
    };
    let open_data = openCall {
        n: input.authorized_round,
        rootRound: input.origin.root_round,
        rootEpoch: input.origin.root_epoch,
        timestamp: input.origin.reference_time,
        treeRoot: input.origin.tree_root,
        originIdentity: origin_identity,
        trHash: technical_record_hash,
        shardConfHash: input.origin.shard_conf_hash,
        certifiedRound: certified_round,
        certEpoch: input.certified_epoch,
        authEpoch: input.authorized_epoch,
        stateHash: state_hash,
        hasBlockHash: has_block_hash,
        blockHash: block_hash,
        inputCommitment: input_commitment,
        transitionCount: 0,
    }
    .abi_encode()
    .into();
    Ok(PreparedTransition {
        n: input.authorized_round,
        open_data,
        input_commitment,
        origin_identity,
        technical_record_hash,
    })
}

/// Executes open then finalize on a disposable clone of the supplied parent cache.
///
/// The caller must hold that cache and its backing database as an immutable, consistent snapshot of
/// the actual parent named by `input.parent_hash`, and must independently authenticate and bind the
/// origin and configuration. This function checks only the registry account's recorded code hash,
/// not a cryptographic commitment to the whole database. The returned cache is the only publishable
/// state; every error leaves `parent` untouched.
pub fn execute_registry_transition<ExtDB>(
    input: &RootInputV2,
    parent: &CacheDB<ExtDB>,
    config: ExecutionConfig,
) -> Result<(ExecutionResult, CacheDB<ExtDB>), ExecutionError>
where
    ExtDB: DatabaseRef + Clone,
{
    let mut candidate = parent.clone();
    let result = execute_registry_transition_on_db(input, &mut candidate, config)?;
    Ok((result, candidate))
}

/// Runs the bounded pair against a disposable block candidate database.
///
/// The caller must discard the whole candidate on error. This is crate-visible so the shared
/// block executor uses exactly the same remaining-gas limits and post-state checks as the public
/// clone-on-success kernel.
pub(crate) fn execute_registry_transition_on_db<DB>(
    input: &RootInputV2,
    db: &mut DB,
    config: ExecutionConfig,
) -> Result<ExecutionResult, ExecutionError>
where
    DB: Database + DatabaseCommit,
{
    if config.system_gas_limit == 0 {
        return Err(ExecutionError::InvalidInput("system gas limit must be positive"));
    }
    let registry = db
        .basic(SEAL_REGISTRY)
        .map_err(|e| ExecutionError::Database(format!("{e:?}")))?
        .ok_or(ExecutionError::InvalidInput("SealRegistry account missing from parent state"))?;
    if registry.code_hash != SEAL_REGISTRY_CODE_HASH {
        return Err(ExecutionError::InvalidInput(
            "SealRegistry parent code hash does not match pinned artifact",
        ));
    }
    let prepared = prepare_transition(input)?;
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN))
        .with_db(db)
        .build_mainnet();
    let mut open_tx =
        TxEnv::new_system_tx_with_caller(SYSTEM_CALLER, SEAL_REGISTRY, prepared.open_data);
    open_tx.gas_limit = config.system_gas_limit;
    evm.ctx_mut().set_tx(open_tx);
    let open_result = MainnetHandler::<
        _,
        revm::context_interface::result::EVMError<<DB as Database>::Error>,
        _,
    >::default()
    .run_system_call(&mut evm)
    .map_err(|e| ExecutionError::OpenFailed(format!("{e:?}")))?;
    if !open_result.is_success() {
        return Err(ExecutionError::OpenFailed(format!("{open_result:?}")));
    }
    let open_gas_spent = open_result.gas().total_gas_spent();
    let open_gas_refunded = open_result.gas().inner_refunded();
    let open_state = evm.ctx_mut().journal_mut().finalize();
    evm.ctx_mut().db_mut().commit(open_state);
    let registry_commitment = system_outcome_commitment(open_gas_spent, prepared.input_commitment);
    let remaining = config.system_gas_limit.checked_sub(open_gas_spent).ok_or(
        ExecutionError::GasBudgetExceeded { spent: open_gas_spent, limit: config.system_gas_limit },
    )?;
    let finalize_data = finalizeCall { n: prepared.n, sealRegistryCommitment: registry_commitment }
        .abi_encode()
        .into();
    let mut finalize_tx =
        TxEnv::new_system_tx_with_caller(SYSTEM_CALLER, SEAL_REGISTRY, finalize_data);
    finalize_tx.gas_limit = remaining;
    evm.ctx_mut().set_tx(finalize_tx);
    let finalize_result = MainnetHandler::<
        _,
        revm::context_interface::result::EVMError<<DB as Database>::Error>,
        _,
    >::default()
    .run_system_call(&mut evm)
    .map_err(|e| ExecutionError::FinalizeFailed(format!("{e:?}")))?;
    if !finalize_result.is_success() {
        return Err(ExecutionError::FinalizeFailed(format!("{finalize_result:?}")));
    }
    let finalize_gas_spent = finalize_result.gas().total_gas_spent();
    let finalize_gas_refunded = finalize_result.gas().inner_refunded();
    let finalize_state = evm.ctx_mut().journal_mut().finalize();
    evm.ctx_mut().db_mut().commit(finalize_state);
    let total_gas_spent = open_gas_spent.checked_add(finalize_gas_spent).ok_or(
        ExecutionError::GasBudgetExceeded { spent: u64::MAX, limit: config.system_gas_limit },
    )?;
    if total_gas_spent > config.system_gas_limit {
        return Err(ExecutionError::GasBudgetExceeded {
            spent: total_gas_spent,
            limit: config.system_gas_limit,
        });
    }
    let candidate = evm.ctx.journaled_state.db_mut();
    let stored_round = candidate
        .storage(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_ROUND_SLOT.0))
        .map_err(|e| ExecutionError::Database(format!("{e:?}")))?;
    let stored_commitment = candidate
        .storage(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_COMMITMENT_SLOT.0))
        .map_err(|e| ExecutionError::Database(format!("{e:?}")))?;
    let stored_phase = candidate
        .storage(SEAL_REGISTRY, U256::from_be_bytes(PHASE_SLOT.0))
        .map_err(|e| ExecutionError::Database(format!("{e:?}")))?;
    if stored_round != U256::from(input.authorized_round) ||
        stored_commitment != U256::from_be_bytes(registry_commitment.0) ||
        stored_phase != U256::from(2)
    {
        return Err(ExecutionError::FinalizeFailed(
            "registry post-state does not contain the finalized round and outcome commitment"
                .into(),
        ));
    }
    Ok(ExecutionResult {
        open_gas_spent,
        open_gas_refunded,
        finalize_gas_spent,
        finalize_gas_refunded,
        total_gas_spent,
        input_commitment: prepared.input_commitment,
        origin_identity: prepared.origin_identity,
        technical_record_hash: prepared.technical_record_hash,
        registry_commitment,
    })
}

/// Derives `SHA-256(CBOR([["system", openGas, 1, "", inputCommitment]]))`.
pub fn system_outcome_commitment(open_gas_spent: u64, input_commitment: B256) -> B256 {
    let mut out = Vec::new();
    array(&mut out, 1);
    array(&mut out, 5);
    text(&mut out, "system");
    uint(&mut out, open_gas_spent);
    uint(&mut out, 1);
    text(&mut out, "");
    bytes(&mut out, input_commitment.as_slice());
    sha256(&out)
}

/// Derives D1 `prevRandao = SHA-256(CBOR(["UNICITY_EVM_RANDAO", r, n]))`.
pub fn derive_prev_randao(root_round: u64, shard_round: u64) -> B256 {
    derive_round_domain("UNICITY_EVM_RANDAO", root_round, shard_round)
}

/// Derives the D1 argument for the retained Cancun EIP-4788 system call.
pub fn derive_beacon_root(root_round: u64, shard_round: u64) -> B256 {
    derive_round_domain("UNICITY_EVM_BEACON", root_round, shard_round)
}

/// Derives the strictly increasing EVM timestamp from authenticated root time.
pub fn derive_timestamp(reference_time: u64, parent_timestamp: u64) -> Option<u64> {
    Some(reference_time.max(parent_timestamp.checked_add(1)?))
}

fn derive_round_domain(domain: &str, root_round: u64, shard_round: u64) -> B256 {
    let mut out = Vec::new();
    array(&mut out, 3);
    text(&mut out, domain);
    uint(&mut out, root_round);
    uint(&mut out, shard_round);
    sha256(&out)
}

fn encode_origin(out: &mut Vec<u8>, origin: &RootOriginV2) {
    array(out, 8);
    uint(out, origin.network_id);
    uint(out, origin.root_round);
    uint(out, origin.root_epoch);
    uint(out, origin.reference_time);
    bytes(out, origin.tree_root.as_slice());
    let ir = &origin.input_record;
    array(out, 6);
    uint(out, ir.round);
    uint(out, ir.epoch);
    nullable_word(out, ir.previous_hash);
    nullable_word(out, ir.state_hash);
    uint(out, ir.timestamp);
    nullable_word(out, ir.block_hash);
    bytes(out, origin.tr_hash.as_slice());
    bytes(out, origin.shard_conf_hash.as_slice());
}
fn encode_technical(out: &mut Vec<u8>, record: &TechnicalRecordV2) {
    array(out, 5);
    uint(out, record.round);
    uint(out, record.epoch);
    text(out, &record.leader);
    bytes(out, record.stat_hash.as_slice());
    bytes(out, record.fee_hash.as_slice());
}
fn nullable_word(out: &mut Vec<u8>, value: Option<B256>) {
    if let Some(word) = value {
        bytes(out, word.as_slice())
    } else {
        out.push(0xf6)
    }
}
fn array(out: &mut Vec<u8>, len: u64) {
    major(out, 4, len);
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    major(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    major(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn uint(out: &mut Vec<u8>, value: u64) {
    major(out, 0, value);
}
fn major(out: &mut Vec<u8>, kind: u8, value: u64) {
    match value {
        0..=23 => out.push((kind << 5) | value as u8),
        24..=0xff => out.extend_from_slice(&[(kind << 5) | 24, value as u8]),
        0x100..=0xffff => {
            out.push((kind << 5) | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push((kind << 5) | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push((kind << 5) | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}
fn sha256(value: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, U256};
    use revm::{
        database::EmptyDB,
        state::{AccountInfo, Bytecode},
    };
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OutcomeVector {
        input_commitment: B256,
        open_gas: u64,
        outcome_commitment: B256,
    }

    #[derive(Deserialize)]
    struct V2File {
        vectors: Vec<V2Vector>,
    }
    #[derive(Deserialize)]
    struct V2Vector {
        name: String,
        source: Source,
        origin: Encoded,
        #[serde(rename = "rootInput")]
        root_input: Encoded,
    }
    #[derive(Deserialize)]
    struct Encoded {
        cbor: String,
        #[serde(default)]
        identity: Option<B256>,
        #[serde(default)]
        commitment: Option<B256>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Source {
        version: u64,
        network_id: u64,
        partition_id: u64,
        shard_id: String,
        authorized_round: u64,
        certified_epoch: u64,
        authorized_epoch: u64,
        parent_hash: B256,
        root_round: u64,
        root_epoch: u64,
        reference_time: u64,
        unicity_tree_root: B256,
        input_record: SourceInputRecord,
        tr_hash: B256,
        shard_conf_hash: B256,
        technical: SourceTechnical,
        transitions: Vec<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceInputRecord {
        round: u64,
        epoch: u64,
        previous_hash: Option<B256>,
        hash: Option<B256>,
        timestamp: u64,
        block_hash: Option<B256>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceTechnical {
        round: u64,
        epoch: u64,
        leader: String,
        stat_hash: B256,
        fee_hash: B256,
    }
    #[derive(Deserialize)]
    struct Genesis {
        alloc: std::collections::BTreeMap<Address, GenesisAccount>,
    }
    #[derive(Deserialize)]
    struct GenesisAccount {
        balance: String,
        #[serde(default)]
        nonce: Option<String>,
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        storage: std::collections::BTreeMap<B256, B256>,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(value.trim_start_matches("0x")).unwrap()
    }
    fn input(source: Source) -> RootInputV2 {
        RootInputV2 {
            version: source.version,
            network_id: source.network_id,
            partition_id: source.partition_id,
            shard_id: decode_hex(&source.shard_id),
            authorized_round: source.authorized_round,
            certified_epoch: source.certified_epoch,
            authorized_epoch: source.authorized_epoch,
            parent_hash: source.parent_hash,
            origin: RootOriginV2 {
                network_id: source.network_id,
                root_round: source.root_round,
                root_epoch: source.root_epoch,
                reference_time: source.reference_time,
                tree_root: source.unicity_tree_root,
                input_record_version: 1,
                input_record: InputRecordV2 {
                    round: source.input_record.round,
                    epoch: source.input_record.epoch,
                    previous_hash: source.input_record.previous_hash,
                    state_hash: source.input_record.hash,
                    timestamp: source.input_record.timestamp,
                    block_hash: source.input_record.block_hash,
                },
                tr_hash: source.tr_hash,
                shard_conf_hash: source.shard_conf_hash,
            },
            technical: TechnicalRecordV2 {
                round: source.technical.round,
                epoch: source.technical.epoch,
                leader: source.technical.leader,
                stat_hash: source.technical.stat_hash,
                fee_hash: source.technical.fee_hash,
            },
            transitions: source.transitions.into_iter().map(|v| decode_hex(&v)).collect(),
        }
    }

    fn genesis_db() -> CacheDB<EmptyDB> {
        // Finalized standard JSON content from bft-core 77d47511, with a final newline added. Its
        // pinned-reth companion records
        // genesis 0x9d672f78…f1b9 and state root 0x8936f379…fdf0.
        let genesis: Genesis =
            serde_json::from_str(include_str!("../testdata/funded-genesis-vector.json")).unwrap();
        let mut db = CacheDB::new(EmptyDB::default());
        for (address, account) in genesis.alloc {
            let code = account.code.map(|value| Bytecode::new_raw(decode_hex(&value).into()));
            let code_hash = code.as_ref().map_or(B256::ZERO, Bytecode::hash_slow);
            db.insert_account_info(
                address,
                AccountInfo {
                    balance: U256::from_str_radix(account.balance.trim_start_matches("0x"), 16)
                        .unwrap(),
                    nonce: u64::from_str_radix(
                        account.nonce.as_deref().unwrap_or("0x0").trim_start_matches("0x"),
                        16,
                    )
                    .unwrap(),
                    code_hash,
                    code,
                    account_id: None,
                },
            );
            for (slot, value) in account.storage {
                db.insert_account_storage(
                    address,
                    U256::from_be_bytes(slot.0),
                    U256::from_be_bytes(value.0),
                )
                .unwrap();
            }
        }
        assert_eq!(
            db.basic_ref(SEAL_REGISTRY).unwrap().unwrap().code_hash,
            SEAL_REGISTRY_CODE_HASH
        );
        db
    }

    fn executable_input(round: u64, root_round: u64) -> RootInputV2 {
        let technical = TechnicalRecordV2 {
            round,
            epoch: 0,
            leader: "evm-node".into(),
            stat_hash: B256::repeat_byte(0xe0),
            fee_hash: B256::repeat_byte(0xf0),
        };
        RootInputV2 {
            version: 2,
            network_id: 3,
            partition_id: 8,
            shard_id: vec![],
            authorized_round: round,
            certified_epoch: 0,
            authorized_epoch: 0,
            parent_hash: b256!("9d672f7822f0747687bcf1c4273cecac83f987871d215d5554d71fb1d1f6f1b9"),
            origin: RootOriginV2 {
                network_id: 3,
                root_round,
                root_epoch: 1,
                reference_time: 1,
                tree_root: B256::repeat_byte(0xc0),
                input_record_version: 1,
                input_record: InputRecordV2 {
                    round: 0,
                    epoch: 0,
                    previous_hash: None,
                    state_hash: None,
                    timestamp: 0,
                    block_hash: None,
                },
                tr_hash: technical_record_hash(&technical),
                shard_conf_hash: b256!(
                    "4ba6ed4d7f56b668f781eb698b9ad1101d823050c677c8bc03b88b3b3b92a6ba"
                ),
            },
            technical,
            transitions: vec![],
        }
    }

    #[test]
    fn outcome_commitment_matches_independent_go_oracle() {
        // Generated by bft-core evmroot.SealRegistryCommitment at c9beef6c.
        let vectors: Vec<OutcomeVector> =
            serde_json::from_str(include_str!("../testdata/system-outcome-vectors.json")).unwrap();
        for vector in vectors {
            assert_eq!(
                system_outcome_commitment(vector.open_gas, vector.input_commitment),
                vector.outcome_commitment
            );
        }
    }

    #[test]
    fn canonical_v2_matches_all_independent_vectors() {
        let file: V2File =
            serde_json::from_str(include_str!("../testdata/v2-vectors.json")).unwrap();
        for vector in file.vectors {
            let root = input(vector.source);
            assert_eq!(
                root.canonical_cbor().unwrap(),
                decode_hex(&vector.root_input.cbor),
                "{} root input",
                vector.name
            );
            assert_eq!(
                root.input_commitment().unwrap(),
                vector.root_input.commitment.unwrap(),
                "{} commitment",
                vector.name
            );
            assert_eq!(
                root.origin_identity().unwrap(),
                vector.origin.identity.unwrap(),
                "{} origin",
                vector.name
            );
            let mut origin = Vec::new();
            encode_origin(&mut origin, &root.origin);
            assert_eq!(origin, decode_hex(&vector.origin.cbor), "{} origin CBOR", vector.name);
        }
    }

    #[test]
    fn real_registry_bootstrap_after_timeout_executes_deterministically() {
        let parent = genesis_db();
        let input = executable_input(7, 4);
        let (first, first_db) = execute_registry_transition(
            &input,
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        let (second, second_db) = execute_registry_transition(
            &input,
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert_eq!(first, second);
        for slot in [OUTCOMES_ROUND_SLOT, OUTCOMES_COMMITMENT_SLOT, PHASE_SLOT] {
            assert_eq!(
                first_db.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(slot.0)).unwrap(),
                second_db.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(slot.0)).unwrap()
            );
        }
        assert!(first.open_gas_spent > 0 && first.finalize_gas_spent > 0);
        assert_eq!(
            parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_ROUND_SLOT.0)).unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn pre_refund_gas_is_combined_and_storage_reset_refund_is_not_credited() {
        let parent = genesis_db();
        let first_input = executable_input(1, 1);
        let (_, after_first) = execute_registry_transition(
            &first_input,
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        let mut second_input = executable_input(2, 2);
        second_input.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 0,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        let (second, _) = execute_registry_transition(
            &second_input,
            &after_first,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert!(
            second.open_gas_refunded > 0,
            "open must observe the nonzero-to-zero outcome reset refund"
        );
        assert_eq!(second.total_gas_spent, second.open_gas_spent + second.finalize_gas_spent);
        // Recorded from revm 42 executing the pinned artifact/funded genesis. A
        // mutation to refund-adjusted tx_gas_used produces 131_512 and fails these assertions.
        assert_eq!(
            (second.open_gas_spent, second.finalize_gas_spent, second.total_gas_spent),
            (106_757, 29_555, 136_312)
        );
        let exact = 136_312;
        assert!(execute_registry_transition(
            &second_input,
            &after_first,
            ExecutionConfig { system_gas_limit: exact }
        )
        .is_ok());
        assert!(execute_registry_transition(
            &second_input,
            &after_first,
            ExecutionConfig { system_gas_limit: exact - 1 }
        )
        .is_err());
    }

    #[test]
    fn real_registry_projects_first_certified_changed_and_quiet_origins() {
        let parent = genesis_db();
        // Controlled ABI/kernel projection fixtures only: they do not claim authenticated UC
        // history or bind these synthetic IR states to the cache.
        let mut first = executable_input(2, 1);
        first.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 0,
            previous_hash: None,
            state_hash: Some(B256::repeat_byte(0x11)),
            timestamp: 1,
            block_hash: Some(B256::repeat_byte(0x21)),
        };
        let (_, after_first) = execute_registry_transition(
            &first,
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert_registry_projection(
            &after_first,
            1,
            B256::repeat_byte(0x11),
            true,
            B256::repeat_byte(0x21),
        );

        let mut changed = executable_input(3, 2);
        changed.origin.input_record = InputRecordV2 {
            round: 2,
            epoch: 0,
            previous_hash: Some(B256::repeat_byte(0x11)),
            state_hash: Some(B256::repeat_byte(0x12)),
            timestamp: 2,
            block_hash: Some(B256::repeat_byte(0x22)),
        };
        let (_, after_changed) = execute_registry_transition(
            &changed,
            &after_first,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert_registry_projection(
            &after_changed,
            2,
            B256::repeat_byte(0x12),
            true,
            B256::repeat_byte(0x22),
        );

        let mut quiet = executable_input(4, 3);
        quiet.origin.input_record = InputRecordV2 {
            round: 3,
            epoch: 0,
            previous_hash: Some(B256::repeat_byte(0x12)),
            state_hash: Some(B256::repeat_byte(0x12)),
            timestamp: 3,
            block_hash: None,
        };
        let (_, after_quiet) = execute_registry_transition(
            &quiet,
            &after_changed,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert_registry_projection(&after_quiet, 3, B256::repeat_byte(0x12), false, B256::ZERO);
        // Repeating the same controlled projection is rejected by strict n monotonicity.
        assert!(execute_registry_transition(
            &quiet,
            &after_quiet,
            ExecutionConfig { system_gas_limit: 500_000 }
        )
        .is_err());
    }

    #[test]
    fn privileged_calls_do_not_apply_eoa_or_fee_side_effects() {
        let mut parent = genesis_db();
        let funded = address!("1000000000000000000000000000000000000001");
        let ordinary_contract = address!("2000000000000000000000000000000000000001");
        let ordinary_slot = U256::from(1);
        let funded_before = parent.basic_ref(funded).unwrap();
        let ordinary_before = parent.basic_ref(ordinary_contract).unwrap();
        let storage_before = parent.storage_ref(ordinary_contract, ordinary_slot).unwrap();
        parent.insert_account_info(
            SYSTEM_CALLER,
            AccountInfo { balance: U256::from(123), nonce: 9, ..Default::default() },
        );
        let system_before = parent.basic_ref(SYSTEM_CALLER).unwrap();
        let (_, candidate) = execute_registry_transition(
            &executable_input(1, 1),
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        assert_eq!(candidate.basic_ref(SYSTEM_CALLER).unwrap(), system_before);
        assert_eq!(candidate.basic_ref(funded).unwrap(), funded_before);
        assert_eq!(candidate.basic_ref(ordinary_contract).unwrap(), ordinary_before);
        assert_eq!(
            candidate.storage_ref(ordinary_contract, ordinary_slot).unwrap(),
            storage_before
        );
    }

    fn assert_registry_projection(
        db: &CacheDB<EmptyDB>,
        round: u64,
        state: B256,
        has_block: bool,
        block: B256,
    ) {
        for (slot, expected) in [
            (CERTIFIED_ROUND_SLOT, U256::from(round)),
            (CERTIFIED_STATE_SLOT, U256::from_be_bytes(state.0)),
            (CERTIFIED_HAS_BLOCK_SLOT, U256::from(has_block as u8)),
            (CERTIFIED_BLOCK_SLOT, U256::from_be_bytes(block.0)),
        ] {
            assert_eq!(
                db.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(slot.0)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn missing_wrong_code_oog_and_revert_publish_no_state() {
        let input = executable_input(1, 1);
        let empty = CacheDB::new(EmptyDB::default());
        assert!(matches!(
            execute_registry_transition(
                &input,
                &empty,
                ExecutionConfig { system_gas_limit: 500_000 }
            ),
            Err(ExecutionError::InvalidInput(_))
        ));
        let mut wrong = genesis_db();
        wrong.cache.accounts.get_mut(&SEAL_REGISTRY).unwrap().info.code_hash = B256::repeat_byte(1);
        assert!(matches!(
            execute_registry_transition(
                &input,
                &wrong,
                ExecutionConfig { system_gas_limit: 500_000 }
            ),
            Err(ExecutionError::InvalidInput(_))
        ));
        let parent = genesis_db();
        assert!(execute_registry_transition(
            &input,
            &parent,
            ExecutionConfig { system_gas_limit: 1 }
        )
        .is_err());
        assert_eq!(
            parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_ROUND_SLOT.0)).unwrap(),
            U256::ZERO
        );
        let (_, finalized) = execute_registry_transition(
            &input,
            &parent,
            ExecutionConfig { system_gas_limit: 500_000 },
        )
        .unwrap();
        let before = finalized
            .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_COMMITMENT_SLOT.0))
            .unwrap();
        assert!(execute_registry_transition(
            &input,
            &finalized,
            ExecutionConfig { system_gas_limit: 500_000 }
        )
        .is_err());
        assert_eq!(
            finalized
                .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_COMMITMENT_SLOT.0))
                .unwrap(),
            before
        );
    }

    #[test]
    fn structured_input_guard_table_rejects_invalid_shapes() {
        let base = executable_input(1, 1);
        let invalid = |candidate: RootInputV2| {
            assert!(matches!(candidate.origin_class(), Err(ExecutionError::InvalidInput(_))));
        };
        let mut candidate = base.clone();
        candidate.version = 1;
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.origin.input_record_version = 2;
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.authorized_round = 0;
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.technical.round = 2;
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.authorized_epoch = 1;
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.origin.tr_hash = B256::repeat_byte(0x99);
        invalid(candidate);
        let mut candidate = base.clone();
        candidate.origin.input_record.previous_hash = Some(B256::ZERO);
        invalid(candidate);

        let mut candidate = base;
        candidate.transitions.push(vec![1]);
        assert!(matches!(
            execute_registry_transition(
                &candidate,
                &genesis_db(),
                ExecutionConfig { system_gas_limit: 500_000 }
            ),
            Err(ExecutionError::InvalidInput("transitions unsupported in bounded profile"))
        ));
    }
}
