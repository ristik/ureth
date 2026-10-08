//! Inactive bounded `SealRegistry` kernel and shared Reth block-execution adapter.
//!
//! Authentication of the structured input is an external prerequisite. This crate deliberately
//! accepts no caller authentication verdict. It derives the input and origin commitments locally,
//! checks the technical-record hash against the structured record, and derives the ABI projection
//! before executing the two privileged calls. Certificate authentication, configuration binding,
//! and binding `parent_hash` to the supplied parent state remain caller prerequisites. The shared
//! adapter supplies build and replay primitives. The `node_evm` module supplies the node-level EVM
//! component that resolves each seal block's bound input from its header commitment, so the engine
//! tree executes an imported block through the same bounded executor. RPC and Engine API exposure
//! lives in `reth-unicity-payload`.

use alloy_primitives::{b256, keccak256, Address, Bytes, B256, U256};
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

#[cfg(test)]
mod b1_profile;
#[cfg(test)]
mod b1_tests;
pub mod block;
pub mod block_executor;
pub mod evm_factory;
pub mod hook;
pub mod node_evm;
pub mod pairing;
pub mod quant;
pub mod records;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
pub mod update;
pub mod wire;

use records::{admit_import, ImportError};
use update::{admit, B1Context, Update, UpdateBinding, UpdateError};

sol! {
    struct AssignmentProjection {
        uint64 oldRootEpoch;
        uint64 oldShardEpoch;
        bytes32 oldActiveConfHash;
        uint64 newRootEpoch;
        uint64 newShardEpoch;
        bytes32 newActiveConfHash;
        uint64 supersessionSpan;
        bytes32 supersessionCommitment;
        bytes32 projectionHash;
    }

    struct B1Member {
        uint64 nodeIDLength;
        bytes32[4] nodeID;
        bytes32[2] key;
        uint64 weight;
    }

    struct B1Entry {
        uint64 epoch;
        uint64 bodyKind;
        bytes32 bodyID;
        bytes32 activationCommitID;
        uint64 start;
        bool hasEnd;
        uint64 end;
        uint64 signingScheme;
        bytes32 signingConfigHash;
        B1Member[] members;
    }

    struct B1UpdateAbi {
        uint64 priorTipEpoch;
        bool hasOldTipEnd;
        uint64 oldTipEnd;
        B1Entry[] newEntries;
    }

    /// The 23 static scalar arguments of `open`, in order. A static struct is encoded inline, so
    /// grouping them is byte-identical to the flat signature while keeping the encoded tuple
    /// within the 24 elements the ABI library supports. The selector is the registry's own.
    struct OpenHead {
        uint64 n; uint64 rootRound; uint64 rootEpoch; uint64 timestamp;
        bytes32 treeRoot; bytes32 originIdentity; bytes32 trHash; bytes32 shardConfHash;
        uint64 certifiedRound; uint64 certEpoch; uint64 authEpoch; bytes32 stateHash;
        bool hasBlockHash; bytes32 blockHash; bytes32 inputCommitment; uint64 transitionCount;
        bytes32 bodyID; bytes32 genesisID; bytes32 frozenID; bytes32 commitID;
        bytes32 frozenParent; bytes32 successorTR; bytes32 activeConfHash;
    }

    function openArguments(OpenHead head, AssignmentProjection assignment, B1UpdateAbi update);
    function finalize(uint64 n, bytes32 sealRegistryCommitment);
}

/// Selector of
/// `open(uint64,uint64,uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,
/// bytes32,bool,bytes32,bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,
/// (uint64,uint64,bytes32,uint64,uint64,bytes32,uint64,bytes32,bytes32),
/// (uint64,bool,uint64,(uint64,uint64,bytes32,bytes32,uint64,bool,uint64,uint64,bytes32,
/// (uint64,bytes32[4],bytes32[2],uint64)[])[]))`, from the pinned artifact's `openSelector`.
pub const OPEN_SELECTOR: [u8; 4] = [0x72, 0x42, 0x36, 0xc0];

/// Fixed privileged caller from the pinned profile.
pub const SYSTEM_CALLER: Address =
    Address::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
/// Fixed registry destination from the pinned profile.
pub const SEAL_REGISTRY: Address =
    Address::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
/// Keccak-256 of the pinned `SealRegistry` runtime artifact: B1 plus the authenticated root-record
/// log (contracts commit 30bc153).
pub const SEAL_REGISTRY_CODE_HASH: B256 =
    b256!("1c660647c1dc27aff97d9e9d5315e2ff60208ea8446253164d831c3ae0cd2611");
const GENESIS_SHARD_CONF_HASH_SLOT: B256 =
    b256!("4d19b7530faa2fa3495319b01857830cdc6ca35a5b20c4084d10119118d44afe");
const ASSIGNMENT_EPOCH_SLOT: B256 =
    b256!("d1358cd157e8920f4cfe36f79ae73373716b602bf47f574ea08d5281befa59ef");
const ASSIGNMENT_ROOT_EPOCH_SLOT: B256 =
    b256!("52ff97c9251b51e7f509a2b0fc46b23b06051f0336a4c2214c3a1b91f9bd79ad");
const ASSIGNMENT_ACTIVE_CONF_HASH_SLOT: B256 =
    b256!("d56125ba33c296e14f68d6694333af40f3cc48fa5a36f9e92163bf6a6a427ce1");
const OUTCOMES_ROUND_SLOT: B256 =
    b256!("df6054d2856db510df05f205217ce7e44e297a6e8637b87280ec2ea8c9f4c7ee");
const OUTCOMES_COMMITMENT_SLOT: B256 =
    b256!("a20cac25b5a8a5560378675c46b953deb71e952d3a217adf06a367755ed9e14c");
const B1_NETWORK_SLOT: B256 =
    b256!("36655612ed573010c759ea2241753af111519811fe26d69e6b788feffd5d8a5a");
const B1_W_CERT_SLOT: B256 =
    b256!("bc96539a5a8854ca78a846b195d14afa7f672a6576866a9ebcc3af80225331ea");
const B1_PROFILE_HASH_SLOT: B256 =
    b256!("134a17ec577b5250d3bf72a1025982cb0e0dcc333f6fcb9e4b09f238d462e907");
const B1_INITIALIZED_SLOT: B256 =
    b256!("86dbc6fb003fd76a5c36b58ac720e220e7b567a5a78a807dd5110458760d889b");
const PHASE_SLOT: B256 = b256!("bd46d80656ebd65ff40d271a180003a97a8f7200d2b0562e68a0b3455cd447d1");
#[cfg(test)]
const CERTIFIED_ROUND_SLOT: B256 =
    b256!("a0f08189724ae2bfb150fa140a6488830ddc10e8fdd94a55a0815e79eaf49a27");
#[cfg(test)]
const CERTIFIED_STATE_SLOT: B256 =
    b256!("250f2a1a88d823a14236a8068855c03dc5dc9076e6b0917b688be3c276b8bdb1");
#[cfg(test)]
const CERTIFIED_HAS_BLOCK_SLOT: B256 =
    b256!("22e2eb405e136cd16718e3c00d060333168f5e2545670217d461f5d019b06d87");
#[cfg(test)]
const CERTIFIED_BLOCK_SLOT: B256 =
    b256!("9814a3b8474ed9091981ace9b8cbd4a6520c2d32b1c0dcd03f05164d1a562592");

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
    /// Authenticated transition bodies; at most one bounded assignment acknowledgement.
    pub transitions: Vec<Vec<u8>>,
    /// `SHA-256` of the canonical B1 [`Update`] this block must carry and execute.
    pub b1_update_hash: B256,
    /// `SHA-256` of the canonical root-record import companion ([`records::RecordImport`]) this
    /// block must carry and execute: the thirteenth field. Mandatory, even for an empty batch.
    pub root_records_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EpochTransition {
    pub old_root_epoch: u64,
    pub new_root_epoch: u64,
    pub old_shard_epoch: u64,
    pub new_shard_epoch: u64,
    pub old_active_conf_hash: B256,
    pub new_active_conf_hash: B256,
    pub supersession_span: u64,
    pub supersession_commitment: B256,
    pub body_id: B256,
    pub genesis_id: B256,
    pub frozen_id: B256,
    pub commit_id: B256,
    pub frozen_parent: B256,
    pub successor_tr: B256,
    pub evm_round: u64,
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
    /// Combined gross gas cap for admission, open and finalize (`g_sys`).
    pub system_gas_limit: u64,
    /// Pinned B1 bindings every update must carry.
    pub b1: B1Context,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// The committed update for one block and the parent height it extends.
pub struct UpdateInput<'a> {
    /// Exact canonical update bytes carried with the root-input companion.
    pub bytes: &'a [u8],
    /// Exact canonical root-record import companion carried with the root-input companion.
    pub records: &'a [u8],
    /// Height of the execution parent.
    pub parent_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Derived commitments and gross pre-refund gas accounting for a successful pair.
pub struct ExecutionResult {
    /// Admission gas `G_admit` debited before open: the B1 scan and member charges plus the
    /// root-record import's.
    pub admission_gas: u64,
    /// The root-record share of `admission_gas`: `2000 + 16*C_R + 1000*N`.
    pub records_admission_gas: u64,
    /// Gross open gas spent before refunds.
    pub open_gas_spent: u64,
    /// Open refund observed but not credited to the privileged gas budget.
    pub open_gas_refunded: u64,
    /// Gross `importRootRecords` gas spent before refunds.
    pub import_gas_spent: u64,
    /// Import refund observed but not credited to the privileged gas budget.
    pub import_gas_refunded: u64,
    /// Gross finalize gas spent before refunds.
    pub finalize_gas_spent: u64,
    /// Finalize refund observed but not credited to the privileged gas budget.
    pub finalize_gas_refunded: u64,
    /// Checked sum of admission, open, import and finalize gross gas.
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
    /// The fixed `SealRegistry` has no authenticated epoch acknowledgement ABI.
    RegistryEpochRefused {
        /// Epoch stored by the registry in the parent state.
        assigned: u64,
        /// Epoch named by the supplied root input.
        received: u64,
    },
    /// The privileged root-record import errored, reverted, or halted.
    ImportFailed(String),
    /// Finalize errored, reverted, halted, or produced wrong storage.
    FinalizeFailed(String),
    /// The root-record import companion was refused at admission.
    RecordImport(ImportError),
    /// The committed B1 update was refused before execution.
    B1Update(UpdateError),
    /// The parent registry's immutable B1 words differ from the pinned profile.
    B1ProfileMismatch(&'static str),
    /// The records hook invalidated the block.
    Hook(hook::HookError),
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
        if self.b1_update_hash == B256::ZERO {
            return Err(ExecutionError::InvalidInput("B1 update hash must be non-zero"));
        }
        if self.root_records_hash == B256::ZERO {
            return Err(ExecutionError::InvalidInput("root records hash must be non-zero"));
        }
        if self.origin.input_record_version != 1 {
            return Err(ExecutionError::InvalidInput("input record version must be 1"));
        }
        if self.authorized_round == 0 || self.technical.round != self.authorized_round {
            return Err(ExecutionError::InvalidInput(
                "authorized round must be positive and equal the technical-record round",
            ));
        }
        if self.certified_epoch != ir.epoch {
            return Err(ExecutionError::InvalidInput(
                "certified epoch must match the authenticated input-record epoch",
            ));
        }
        if self.technical.epoch != self.authorized_epoch {
            return Err(ExecutionError::InvalidInput(
                "technical-record epoch must match the authorized epoch",
            ));
        }
        if self.network_id != self.origin.network_id {
            return Err(ExecutionError::InvalidInput("network identity mismatch"));
        }
        if self.transitions.len() > 1 {
            return Err(ExecutionError::InvalidInput("only one epoch transition is supported"));
        }
        if let Some(raw) = self.transitions.first() {
            let transition = wire::decode_epoch_transition(raw)
                .map_err(|_| ExecutionError::InvalidInput("invalid epoch transition encoding"))?;
            if transition.evm_round != self.authorized_round ||
                transition.new_root_epoch != self.origin.root_epoch ||
                transition.frozen_parent != self.parent_hash ||
                self.certified_epoch != transition.old_shard_epoch ||
                self.authorized_epoch != transition.new_shard_epoch ||
                ir.epoch != transition.old_shard_epoch ||
                self.origin.shard_conf_hash != transition.new_active_conf_hash
            {
                return Err(ExecutionError::InvalidInput("epoch transition context mismatch"));
            }
        } else if self.certified_epoch != self.authorized_epoch {
            return Err(ExecutionError::InvalidInput(
                "ordinary execution must use one certified and authorized shard epoch",
            ));
        }
        if technical_record_hash(&self.technical) != self.origin.tr_hash {
            return Err(ExecutionError::InvalidInput("technical record hash mismatch"));
        }
        match (&ir.previous_hash, &ir.state_hash, &ir.block_hash, ir.round, ir.timestamp) {
            (None, None, None, 0, 0) if ir.epoch == 0 => Ok(OriginClass::Bootstrap),
            (None, None, None, 0, 0) => {
                Err(ExecutionError::InvalidInput("bootstrap input-record epoch must be zero"))
            }
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
        array(&mut out, 13);
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
        bytes(&mut out, self.b1_update_hash.as_slice());
        bytes(&mut out, self.root_records_hash.as_slice());
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

fn pad_words<const N: usize>(raw: &[u8]) -> [B256; N] {
    let mut out = [B256::ZERO; N];
    for (word, chunk) in out.iter_mut().zip(raw.chunks(32)) {
        word.0[..chunk.len()].copy_from_slice(chunk);
    }
    out
}

/// Projects the admitted update onto the registry's `B1Update` tuple: node identifiers and keys
/// are left-aligned in wire order with zero right padding.
fn update_abi(update: &Update) -> B1UpdateAbi {
    B1UpdateAbi {
        priorTipEpoch: update.prior_tip_epoch,
        hasOldTipEnd: update.old_tip_end.is_some(),
        oldTipEnd: update.old_tip_end.unwrap_or_default(),
        newEntries: update
            .new_entries
            .iter()
            .map(|entry| B1Entry {
                epoch: entry.epoch,
                bodyKind: entry.body_kind,
                bodyID: entry.body_id,
                activationCommitID: entry.activation_commit_id,
                start: entry.start,
                hasEnd: entry.end.is_some(),
                end: entry.end.unwrap_or_default(),
                signingScheme: entry.signing_scheme,
                signingConfigHash: entry.signing_config_hash,
                members: entry
                    .members
                    .iter()
                    .map(|member| B1Member {
                        nodeIDLength: member.node_id.len() as u64,
                        nodeID: pad_words::<4>(member.node_id.as_bytes()),
                        key: pad_words::<2>(&member.key),
                        weight: member.weight,
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub(crate) fn prepare_transition(
    input: &RootInputV2,
    update: &Update,
    genesis_shard_conf_hash: B256,
) -> Result<PreparedTransition, ExecutionError> {
    let class = input.origin_class()?;
    let transition = input
        .transitions
        .first()
        .map(|raw| wire::decode_epoch_transition(raw))
        .transpose()
        .map_err(|_| ExecutionError::InvalidInput("invalid epoch transition encoding"))?;
    let input_commitment = input.input_commitment()?;
    let origin_identity = input.origin_identity()?;
    let technical_record_hash = technical_record_hash(&input.technical);
    let ir = &input.origin.input_record;
    let assignment = transition.map_or_else(zero_assignment_projection, assignment_projection);
    let active_conf_hash =
        transition.map_or(input.origin.shard_conf_hash, |t| t.new_active_conf_hash);
    let (certified_round, state_hash, has_block_hash, block_hash) = match class {
        OriginClass::Bootstrap => (0, B256::ZERO, false, B256::ZERO),
        _ => (
            ir.round,
            ir.state_hash.expect("validated"),
            ir.block_hash.is_some(),
            ir.block_hash.unwrap_or_default(),
        ),
    };
    let head = OpenHead {
        n: input.authorized_round,
        rootRound: input.origin.root_round,
        rootEpoch: input.origin.root_epoch,
        timestamp: input.origin.reference_time,
        treeRoot: input.origin.tree_root,
        originIdentity: origin_identity,
        trHash: technical_record_hash,
        shardConfHash: genesis_shard_conf_hash,
        certifiedRound: certified_round,
        certEpoch: input.certified_epoch,
        authEpoch: input.authorized_epoch,
        stateHash: state_hash,
        hasBlockHash: has_block_hash,
        blockHash: block_hash,
        inputCommitment: input_commitment,
        transitionCount: u64::from(transition.is_some()),
        bodyID: transition.map_or(B256::ZERO, |t| t.body_id),
        genesisID: transition.map_or(B256::ZERO, |t| t.genesis_id),
        frozenID: transition.map_or(B256::ZERO, |t| t.frozen_id),
        commitID: transition.map_or(B256::ZERO, |t| t.commit_id),
        frozenParent: transition.map_or(B256::ZERO, |t| t.frozen_parent),
        successorTR: transition.map_or(B256::ZERO, |t| t.successor_tr),
        activeConfHash: active_conf_hash,
    };
    let mut open_data = OPEN_SELECTOR.to_vec();
    open_data.extend_from_slice(
        &openArgumentsCall { head, assignment, update: update_abi(update) }.abi_encode()[4..],
    );
    let open_data: Bytes = open_data.into();
    Ok(PreparedTransition {
        n: input.authorized_round,
        open_data,
        input_commitment,
        origin_identity,
        technical_record_hash,
    })
}

const fn zero_assignment_projection() -> AssignmentProjection {
    AssignmentProjection {
        oldRootEpoch: 0,
        oldShardEpoch: 0,
        oldActiveConfHash: B256::ZERO,
        newRootEpoch: 0,
        newShardEpoch: 0,
        newActiveConfHash: B256::ZERO,
        supersessionSpan: 0,
        supersessionCommitment: B256::ZERO,
        projectionHash: B256::ZERO,
    }
}

fn assignment_projection(transition: EpochTransition) -> AssignmentProjection {
    let projection_hash = assignment_projection_hash(transition);
    AssignmentProjection {
        oldRootEpoch: transition.old_root_epoch,
        oldShardEpoch: transition.old_shard_epoch,
        oldActiveConfHash: transition.old_active_conf_hash,
        newRootEpoch: transition.new_root_epoch,
        newShardEpoch: transition.new_shard_epoch,
        newActiveConfHash: transition.new_active_conf_hash,
        supersessionSpan: transition.supersession_span,
        supersessionCommitment: transition.supersession_commitment,
        projectionHash: projection_hash,
    }
}

/// Mirrors `SealRegistry`'s `abi.encode(domain, first eight assignment projection fields)`.
fn assignment_projection_hash(transition: EpochTransition) -> B256 {
    let domain = keccak256("unicity.seal-registry.v2/assignment-ack-projection");
    let mut encoded = Vec::with_capacity(9 * 32);
    encoded.extend_from_slice(domain.as_slice());
    for epoch in [transition.old_root_epoch, transition.old_shard_epoch] {
        encoded.extend_from_slice(&U256::from(epoch).to_be_bytes::<32>());
    }
    encoded.extend_from_slice(transition.old_active_conf_hash.as_slice());
    for epoch in [transition.new_root_epoch, transition.new_shard_epoch] {
        encoded.extend_from_slice(&U256::from(epoch).to_be_bytes::<32>());
    }
    encoded.extend_from_slice(transition.new_active_conf_hash.as_slice());
    encoded.extend_from_slice(&U256::from(transition.supersession_span).to_be_bytes::<32>());
    encoded.extend_from_slice(transition.supersession_commitment.as_slice());
    keccak256(encoded)
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
    update: UpdateInput<'_>,
    parent: &CacheDB<ExtDB>,
    config: ExecutionConfig,
) -> Result<(ExecutionResult, CacheDB<ExtDB>), ExecutionError>
where
    ExtDB: DatabaseRef + Clone,
{
    let mut candidate = parent.clone();
    let result = execute_registry_transition_on_db(input, update, &mut candidate, config)?;
    Ok((result, candidate))
}

/// Runs the bounded pair against a disposable block candidate database.
///
/// The caller must discard the whole candidate on error. This is crate-visible so the shared
/// block executor uses exactly the same remaining-gas limits and post-state checks as the public
/// clone-on-success kernel.
pub(crate) fn execute_registry_transition_on_db<DB>(
    input: &RootInputV2,
    update: UpdateInput<'_>,
    db: &mut DB,
    config: ExecutionConfig,
) -> Result<ExecutionResult, ExecutionError>
where
    DB: Database + DatabaseCommit,
{
    if config.system_gas_limit == 0 {
        return Err(ExecutionError::InvalidInput("system gas limit must be positive"));
    }
    // Validate every encoded epoch/transition relationship before reading the parent assignment
    // or trusting its round projection.
    input.origin_class()?;
    let registry = db
        .basic(SEAL_REGISTRY)
        .map_err(|e| ExecutionError::Database(format!("{e:?}")))?
        .ok_or(ExecutionError::InvalidInput("SealRegistry account missing from parent state"))?;
    if registry.code_hash != SEAL_REGISTRY_CODE_HASH {
        return Err(ExecutionError::InvalidInput(
            "SealRegistry parent code hash does not match pinned artifact",
        ));
    }
    let mut storage = |slot: B256| {
        db.storage(SEAL_REGISTRY, U256::from_be_bytes(slot.0))
            .map_err(|e| ExecutionError::Database(format!("{e:?}")))
    };
    for (slot, expected, what) in [
        (B1_INITIALIZED_SLOT, U256::from(1), "B1 registry is not initialized"),
        (B1_NETWORK_SLOT, U256::from(config.b1.network), "B1 network differs from the profile"),
        (B1_W_CERT_SLOT, U256::from(config.b1.w_cert), "B1 window differs from the profile"),
        (
            B1_PROFILE_HASH_SLOT,
            U256::from_be_bytes(config.b1.profile_hash.0),
            "B1 profile hash differs from the profile",
        ),
    ] {
        if storage(slot)? != expected {
            return Err(ExecutionError::B1ProfileMismatch(what));
        }
    }
    let assigned = storage(ASSIGNMENT_ROOT_EPOCH_SLOT)?;
    let assigned_shard = storage(ASSIGNMENT_EPOCH_SLOT)?;
    let assigned_active = storage(ASSIGNMENT_ACTIVE_CONF_HASH_SLOT)?;
    let genesis_shard_conf_hash = storage(GENESIS_SHARD_CONF_HASH_SLOT)?;
    let assigned_active_hash = B256::from(assigned_active.to_be_bytes::<32>());
    let genesis_shard_conf_hash = B256::from(genesis_shard_conf_hash.to_be_bytes::<32>());
    if assigned_active_hash == B256::ZERO || genesis_shard_conf_hash == B256::ZERO {
        return Err(ExecutionError::InvalidInput("SealRegistry assignment is not initialized"));
    }
    let transition = input
        .transitions
        .first()
        .map(|raw| wire::decode_epoch_transition(raw))
        .transpose()
        .map_err(|_| ExecutionError::InvalidInput("invalid epoch transition encoding"))?;
    let epoch_ok = if let Some(t) = transition {
        assigned == U256::from(t.old_root_epoch) &&
            assigned_shard == U256::from(t.old_shard_epoch) &&
            assigned_active_hash == t.old_active_conf_hash &&
            input.origin.root_epoch == t.new_root_epoch &&
            input.authorized_epoch == t.new_shard_epoch &&
            input.certified_epoch == t.old_shard_epoch &&
            input.origin.shard_conf_hash == t.new_active_conf_hash
    } else {
        assigned == U256::from(input.origin.root_epoch) &&
            assigned_shard == U256::from(input.authorized_epoch) &&
            assigned_active_hash == input.origin.shard_conf_hash &&
            input.certified_epoch == input.authorized_epoch
    };
    if !epoch_ok {
        return Err(ExecutionError::RegistryEpochRefused {
            assigned: assigned.try_into().unwrap_or(u64::MAX),
            received: input.origin.root_epoch,
        });
    }
    // Staged admission: the byte cap and scan charge precede the scan, the member charge precedes
    // member allocation, point parsing and semantic validation. Any refusal discards the block.
    let admitted = admit(
        update.bytes,
        &config.b1,
        &UpdateBinding {
            committed_hash: input.b1_update_hash,
            parent_hash: input.parent_hash,
            parent_number: update.parent_number,
            origin_epoch: input.origin.root_epoch,
            origin_round: input.origin.root_round,
            origin_identity: input.origin_identity()?,
        },
        config.system_gas_limit,
    )?;
    // The root-record import is admitted from the budget the B1 admission left, in the same staged
    // order; G_admit is both charges.
    let records = admit_import(
        update.records,
        input.root_records_hash,
        config.system_gas_limit.checked_sub(admitted.gas).ok_or(
            ExecutionError::GasBudgetExceeded {
                spent: admitted.gas,
                limit: config.system_gas_limit,
            },
        )?,
    )
    .map_err(ExecutionError::RecordImport)?;
    let admission_gas =
        admitted.gas.checked_add(records.gas).ok_or(ExecutionError::GasBudgetExceeded {
            spent: u64::MAX,
            limit: config.system_gas_limit,
        })?;
    let prepared = prepare_transition(input, &admitted.update, genesis_shard_conf_hash)?;
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN))
        .with_db(db)
        .build_mainnet();
    let mut open_tx =
        TxEnv::new_system_tx_with_caller(SYSTEM_CALLER, SEAL_REGISTRY, prepared.open_data);
    open_tx.gas_limit = config.system_gas_limit - admission_gas;
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
    // Privileged import, forwarded exactly the system budget still unspent after admission and
    // open.
    let after_open =
        admission_gas.checked_add(open_gas_spent).ok_or(ExecutionError::GasBudgetExceeded {
            spent: u64::MAX,
            limit: config.system_gas_limit,
        })?;
    let import_remaining = config.system_gas_limit.checked_sub(after_open).ok_or(
        ExecutionError::GasBudgetExceeded { spent: after_open, limit: config.system_gas_limit },
    )?;
    let mut import_tx = TxEnv::new_system_tx_with_caller(
        SYSTEM_CALLER,
        SEAL_REGISTRY,
        records.import.call_data(prepared.n),
    );
    import_tx.gas_limit = import_remaining;
    evm.ctx_mut().set_tx(import_tx);
    let import_result = MainnetHandler::<
        _,
        revm::context_interface::result::EVMError<<DB as Database>::Error>,
        _,
    >::default()
    .run_system_call(&mut evm)
    .map_err(|e| ExecutionError::ImportFailed(format!("{e:?}")))?;
    if !import_result.is_success() {
        return Err(ExecutionError::ImportFailed(format!("{import_result:?}")));
    }
    let import_gas_spent = import_result.gas().total_gas_spent();
    let import_gas_refunded = import_result.gas().inner_refunded();
    let import_state = evm.ctx_mut().journal_mut().finalize();
    evm.ctx_mut().db_mut().commit(import_state);
    // G_pre = G_admit + G_open + G_import is the figure the outcome commitment carries; finalize's
    // gas (and the hooks') join only the combined system total, so the commitment never refers
    // to itself.
    let staged_gas =
        after_open.checked_add(import_gas_spent).ok_or(ExecutionError::GasBudgetExceeded {
            spent: u64::MAX,
            limit: config.system_gas_limit,
        })?;
    let registry_commitment = system_outcome_commitment(staged_gas, prepared.input_commitment);
    let remaining = config.system_gas_limit.checked_sub(staged_gas).ok_or(
        ExecutionError::GasBudgetExceeded { spent: staged_gas, limit: config.system_gas_limit },
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
    let total_gas_spent =
        staged_gas.checked_add(finalize_gas_spent).ok_or(ExecutionError::GasBudgetExceeded {
            spent: u64::MAX,
            limit: config.system_gas_limit,
        })?;
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
        admission_gas,
        records_admission_gas: records.gas,
        open_gas_spent,
        open_gas_refunded,
        import_gas_spent,
        import_gas_refunded,
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

    #[derive(Deserialize)]
    struct TimestampCase {
        reference_time: u64,
        parent_timestamp: u64,
        want: u64,
        overflow: bool,
    }

    /// bft-core's `evmroot.DeriveTimestampChecked` vectors: the same `max(reference, parent + 1)`,
    /// and a parent at the top of the 64-bit range has no successor in either implementation.
    #[test]
    fn derive_timestamp_reproduces_the_go_vectors_including_overflow() {
        #[derive(Deserialize)]
        struct File {
            cases: Vec<TimestampCase>,
        }
        let file: File =
            serde_json::from_str(include_str!("../testdata/timestamp-vectors.json")).unwrap();
        assert!(file.cases.iter().any(|c| c.overflow), "the vectors carry overflow rows");
        for c in file.cases {
            let got = derive_timestamp(c.reference_time, c.parent_timestamp);
            if c.overflow {
                assert_eq!(got, None, "{} / {}", c.reference_time, c.parent_timestamp);
            } else {
                assert_eq!(got, Some(c.want), "{} / {}", c.reference_time, c.parent_timestamp);
            }
        }
    }
    use super::*;
    use alloy_primitives::{address, U256};
    use revm::{database::EmptyDB, state::AccountInfo};
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
        b1_update_hash: B256,
        root_records_hash: B256,
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
            b1_update_hash: source.b1_update_hash,
            root_records_hash: source.root_records_hash,
        }
    }

    fn genesis_db() -> CacheDB<EmptyDB> {
        testing::genesis_db()
    }

    #[test]
    fn embedded_registry_artifact_matches_genesis_runtime() {
        let artifact: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/seal-registry.json")).unwrap();
        let genesis: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).unwrap();
        let code = artifact["runtimeBytecode"].as_str().unwrap();
        let registry = genesis["alloc"][format!("{SEAL_REGISTRY:#x}")]["code"].as_str().unwrap();
        assert_eq!(registry, code);
        assert_eq!(keccak256(decode_hex(code)), SEAL_REGISTRY_CODE_HASH);
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
            network_id: u64::from(testing::world().network),
            partition_id: 8,
            shard_id: vec![],
            authorized_round: round,
            certified_epoch: 0,
            authorized_epoch: 0,
            parent_hash: testing::world().genesis_hash,
            origin: RootOriginV2 {
                network_id: u64::from(testing::world().network),
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
                shard_conf_hash: testing::world().shard_conf_hash,
            },
            technical,
            transitions: vec![],
            // Placeholder: `run` commits the real update for the input as it stands at the call.
            b1_update_hash: B256::repeat_byte(0xb1),
            root_records_hash: B256::repeat_byte(0xb2),
        }
    }

    /// The tail of the registry's live set, read from the candidate's own storage.
    fn tail_of(db: &CacheDB<EmptyDB>) -> testing::Tail {
        let word = |slot: U256| db.storage_ref(SEAL_REGISTRY, slot).unwrap();
        let head = u64::try_from(word(reth_unicity_b1::fixed_slot("b1.head"))).unwrap();
        let count = u64::try_from(word(reth_unicity_b1::fixed_slot("b1.count"))).unwrap();
        if count == 0 {
            // No registry, or an emptied one: the refusal tests supply their own failure.
            return testing::GENESIS_TAIL;
        }
        let ring = u64::try_from(word(reth_unicity_b1::fixed_slot("b1.wCert"))).unwrap() + 1;
        let queue = |i: u64| {
            let mut bytes = reth_unicity_b1::fixed_slot("b1.queue").to_be_bytes::<32>().to_vec();
            bytes.extend_from_slice(&U256::from(i).to_be_bytes::<32>());
            U256::from_be_bytes(keccak256(bytes).0)
        };
        let epoch = u64::try_from(word(queue((head + count - 1) % ring))).unwrap();
        let start = u64::try_from(word(reth_unicity_b1::entry_slot(epoch, 4))).unwrap();
        testing::Tail { epoch, start }
    }

    /// Executes `input` against `parent` with the update an honest pair derives for the parent's
    /// actual live set. The parent height is `round - 1`, which these kernel fixtures use only
    /// to bind the update.
    fn run(
        input: &RootInputV2,
        parent: &CacheDB<EmptyDB>,
        limit: u64,
    ) -> Result<(ExecutionResult, CacheDB<EmptyDB>), ExecutionError> {
        let mut input = input.clone();
        let parent_number = input.authorized_round - 1;
        let update = testing::seal(&mut input, parent_number, tail_of(parent));
        execute_registry_transition(
            &input,
            UpdateInput { bytes: &update, records: &testing::empty_import(), parent_number },
            parent,
            ExecutionConfig { system_gas_limit: limit, b1: testing::b1_context() },
        )
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
        let (first, first_db) = run(&input, &parent, testing::world().system_gas).unwrap();
        let (second, second_db) = run(&input, &parent, testing::world().system_gas).unwrap();
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
        let (_, after_first) = run(&first_input, &parent, testing::world().system_gas).unwrap();
        let mut second_input = executable_input(2, 2);
        second_input.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 0,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        let (second, _) = run(&second_input, &after_first, testing::world().system_gas).unwrap();
        assert!(
            second.open_gas_refunded > 0,
            "open must observe the nonzero-to-zero outcome reset refund"
        );
        assert_eq!(
            second.total_gas_spent,
            second.admission_gas +
                second.open_gas_spent +
                second.import_gas_spent +
                second.finalize_gas_spent
        );
        // Recorded from revm 42 executing the pinned B1 artifact/test genesis.
        assert_eq!(
            (
                second.admission_gas,
                second.open_gas_spent,
                second.import_gas_spent,
                second.finalize_gas_spent,
                second.total_gas_spent
            ),
            (7_728, 123_610, 24_726, 47_525, 203_589)
        );
        let exact = second.total_gas_spent;
        assert!(run(&second_input, &after_first, exact).is_ok());
        assert!(run(&second_input, &after_first, exact - 1).is_err());
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
        let (_, after_first) = run(&first, &parent, testing::world().system_gas).unwrap();
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
        let (_, after_changed) = run(&changed, &after_first, testing::world().system_gas).unwrap();
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
        let (_, after_quiet) = run(&quiet, &after_changed, testing::world().system_gas).unwrap();
        assert_registry_projection(&after_quiet, 3, B256::repeat_byte(0x12), false, B256::ZERO);
        // Repeating the same controlled projection is rejected by strict n monotonicity.
        assert!(run(&quiet, &after_quiet, testing::world().system_gas).is_err());
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
        let (_, candidate) =
            run(&executable_input(1, 1), &parent, testing::world().system_gas).unwrap();
        assert_eq!(candidate.basic_ref(SYSTEM_CALLER).unwrap(), system_before);
        assert_eq!(candidate.basic_ref(funded).unwrap(), funded_before);
        assert_eq!(candidate.basic_ref(ordinary_contract).unwrap(), ordinary_before);
        assert_eq!(
            candidate.storage_ref(ordinary_contract, ordinary_slot).unwrap(),
            storage_before
        );
    }

    #[test]
    fn public_caller_cannot_advance_the_seal_registry_round() {
        let parent = genesis_db();
        let (_, mut candidate) =
            run(&executable_input(1, 1), &parent, testing::world().system_gas).unwrap();

        let mut next = executable_input(2, 2);
        next.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 0,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        let parent_number = next.authorized_round - 1;
        let update = testing::update_for(&next, parent_number, tail_of(&candidate));
        next.b1_update_hash = update.hash();
        let prepared = prepare_transition(&next, &update, next.origin.shard_conf_hash).unwrap();
        let public_caller = Address::repeat_byte(0x42);
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN))
            .with_db(&mut candidate)
            .build_mainnet();
        let mut open =
            TxEnv::new_system_tx_with_caller(public_caller, SEAL_REGISTRY, prepared.open_data);
        open.gas_limit = testing::world().system_gas;
        evm.ctx_mut().set_tx(open);
        let result = MainnetHandler::<
            _,
            revm::context_interface::result::EVMError<core::convert::Infallible>,
            _,
        >::default()
        .run_system_call(&mut evm)
        .unwrap();
        let state = evm.ctx_mut().journal_mut().finalize();
        evm.ctx_mut().db_mut().commit(state);
        drop(evm);

        assert!(!result.is_success(), "a public caller must not execute privileged open");
        assert_eq!(
            candidate
                .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_ROUND_SLOT.0))
                .unwrap(),
            U256::from(1),
            "a refused public call must leave the privileged round cursor unchanged"
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
            run(&input, &empty, testing::world().system_gas),
            Err(ExecutionError::InvalidInput(_))
        ));
        let mut wrong = genesis_db();
        wrong.cache.accounts.get_mut(&SEAL_REGISTRY).unwrap().info.code_hash = B256::repeat_byte(1);
        assert!(matches!(
            run(&input, &wrong, testing::world().system_gas),
            Err(ExecutionError::InvalidInput(_))
        ));
        let parent = genesis_db();
        assert!(run(&input, &parent, 1).is_err());
        assert_eq!(
            parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_ROUND_SLOT.0)).unwrap(),
            U256::ZERO
        );
        let (_, finalized) = run(&input, &parent, testing::world().system_gas).unwrap();
        let before = finalized
            .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(OUTCOMES_COMMITMENT_SLOT.0))
            .unwrap();
        assert!(run(&input, &finalized, testing::world().system_gas).is_err());
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
        candidate.authorized_epoch = 2;
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
            run(&candidate, &genesis_db(), testing::world().system_gas),
            Err(ExecutionError::InvalidInput("invalid epoch transition encoding"))
        ));
    }

    #[test]
    fn bootstrap_requires_zero_epoch_and_null_input_record() {
        let mut bootstrap = executable_input(1, 1);
        bootstrap.certified_epoch = 5;
        bootstrap.authorized_epoch = 5;
        bootstrap.technical.epoch = 5;
        bootstrap.origin.input_record = InputRecordV2 {
            round: 0,
            epoch: 5,
            previous_hash: None,
            state_hash: None,
            timestamp: 0,
            block_hash: None,
        };
        bootstrap.origin.tr_hash = technical_record_hash(&bootstrap.technical);
        assert_eq!(
            bootstrap.origin_class(),
            Err(ExecutionError::InvalidInput("bootstrap input-record epoch must be zero")),
        );
    }

    #[test]
    fn epoch_change_is_a_clean_registry_refusal() {
        let parent = genesis_db();
        let mut input = executable_input(1, 13);
        input.origin.root_epoch = 2;
        let before = parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(PHASE_SLOT.0)).unwrap();
        assert!(matches!(
            run(&input, &parent, testing::world().system_gas),
            Err(ExecutionError::RegistryEpochRefused { assigned: 1, received: 2 })
        ));
        assert_eq!(
            parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(PHASE_SLOT.0)).unwrap(),
            before
        );
    }

    use testing::transition_bytes;

    #[test]
    fn acknowledgement_uses_frozen_parent_and_exact_epoch() {
        let parent = genesis_db();
        let mut input = executable_input(1, 1);
        input.origin.root_epoch = 2;
        let old_conf = input.origin.shard_conf_hash;
        let new_conf = B256::repeat_byte(0x56);
        input.certified_epoch = 0;
        input.authorized_epoch = 1;
        input.technical.epoch = 1;
        input.origin.input_record.epoch = 0;
        input.origin.shard_conf_hash = new_conf;
        input.origin.tr_hash = technical_record_hash(&input.technical);
        input.transitions = vec![transition_bytes(
            1,
            2,
            0,
            1,
            old_conf,
            new_conf,
            0,
            B256::ZERO,
            1,
            input.parent_hash,
        )];
        let first = run(&input, &parent, testing::world().system_gas).unwrap();
        let repeated = run(&input, &parent, testing::world().system_gas).unwrap();
        assert_eq!(first.0, repeated.0);
        let assigned = keccak256("unicity.seal-registry/assignment.rootEpoch");
        assert_eq!(
            first.1.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(assigned.0)).unwrap(),
            U256::from(2)
        );
        let mut next = executable_input(2, 2);
        next.origin.root_epoch = 2;
        next.certified_epoch = 1;
        next.authorized_epoch = 1;
        next.technical.epoch = 1;
        next.origin.tr_hash = technical_record_hash(&next.technical);
        next.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 1,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        next.origin.shard_conf_hash = new_conf;
        run(&next, &first.1, testing::world().system_gas).unwrap();

        let mut wrong = input.clone();
        wrong.parent_hash = B256::repeat_byte(0xff);
        assert!(matches!(
            wrong.origin_class(),
            Err(ExecutionError::InvalidInput("epoch transition context mismatch"))
        ));
        wrong = input.clone();
        wrong.transitions = vec![transition_bytes(
            1,
            3,
            0,
            2,
            old_conf,
            B256::repeat_byte(0x57),
            0,
            B256::ZERO,
            1,
            wrong.parent_hash,
        )];
        assert!(matches!(
            wrong.origin_class(),
            Err(ExecutionError::InvalidInput("invalid epoch transition encoding"))
        ));
        wrong = input;
        wrong.transitions.clear();
        assert!(matches!(
            run(&wrong, &parent, testing::world().system_gas),
            Err(ExecutionError::InvalidInput(
                "ordinary execution must use one certified and authorized shard epoch",
            ))
        ));
    }

    #[test]
    fn root_only_ack_advances_root_epoch_without_changing_shard_assignment() {
        let parent = genesis_db();
        let mut input = executable_input(1, 1);
        let active = input.origin.shard_conf_hash;
        input.origin.root_epoch = 2;
        input.transitions =
            vec![transition_bytes(1, 2, 0, 0, active, active, 0, B256::ZERO, 1, input.parent_hash)];
        let (_, advanced) = run(&input, &parent, testing::world().system_gas).unwrap();
        assert_eq!(
            advanced
                .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(ASSIGNMENT_ROOT_EPOCH_SLOT.0))
                .unwrap(),
            U256::from(2)
        );
        assert_eq!(
            advanced
                .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(ASSIGNMENT_EPOCH_SLOT.0))
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(
            B256::from(
                advanced
                    .storage_ref(
                        SEAL_REGISTRY,
                        U256::from_be_bytes(ASSIGNMENT_ACTIVE_CONF_HASH_SLOT.0),
                    )
                    .unwrap()
                    .to_be_bytes::<32>()
            ),
            active
        );
        let mut ordinary = executable_input(2, 2);
        ordinary.origin.root_epoch = 2;
        run(&ordinary, &advanced, testing::world().system_gas).unwrap();
    }

    #[test]
    fn supersession_folds_verified_span_and_rejects_a_late_superseded_ack() {
        let parent = genesis_db();
        let mut latest = executable_input(1, 5);
        let old_conf = latest.origin.shard_conf_hash;
        let newest_conf = B256::repeat_byte(0x67);
        latest.origin.root_epoch = 3;
        latest.certified_epoch = 0;
        latest.authorized_epoch = 2;
        latest.technical.epoch = 2;
        latest.origin.shard_conf_hash = newest_conf;
        latest.origin.tr_hash = technical_record_hash(&latest.technical);
        latest.transitions = vec![transition_bytes(
            1,
            3,
            0,
            2,
            old_conf,
            newest_conf,
            2,
            B256::repeat_byte(0x68),
            1,
            latest.parent_hash,
        )];
        // This folds two already verified committed assignments onto the same frozen parent.
        let (_, after_latest) = run(&latest, &parent, testing::world().system_gas).unwrap();

        let mut late = executable_input(2, 6);
        late.origin.root_epoch = 2;
        late.certified_epoch = 0;
        late.authorized_epoch = 1;
        late.technical.epoch = 1;
        late.origin.tr_hash = technical_record_hash(&late.technical);
        late.origin.shard_conf_hash = B256::repeat_byte(0x66);
        late.transitions = vec![transition_bytes(
            1,
            2,
            0,
            1,
            old_conf,
            B256::repeat_byte(0x66),
            0,
            B256::ZERO,
            2,
            late.parent_hash,
        )];
        assert!(matches!(
            run(&late, &after_latest, testing::world().system_gas),
            Err(ExecutionError::RegistryEpochRefused { assigned: 3, received: 2 })
        ));
        assert_eq!(
            after_latest
                .storage_ref(SEAL_REGISTRY, U256::from_be_bytes(ASSIGNMENT_ROOT_EPOCH_SLOT.0))
                .unwrap(),
            U256::from(3),
            "late acknowledgement must not roll back certified assignment state"
        );
    }

    #[test]
    fn nonzero_ordinary_shard_epoch_is_accepted_and_delayed_tr_is_valid_only_with_ack() {
        let parent = genesis_db();
        let mut input = executable_input(1, 1);
        input.authorized_epoch = 5;
        input.certified_epoch = 5;
        input.technical.epoch = 5;
        input.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 5,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        input.origin.tr_hash = technical_record_hash(&input.technical);
        let mut parent = parent;
        parent
            .insert_account_storage(
                SEAL_REGISTRY,
                U256::from_be_bytes(ASSIGNMENT_EPOCH_SLOT.0),
                U256::from(5),
            )
            .unwrap();
        let (_, advanced) = run(&input, &parent, testing::world().system_gas).unwrap();

        let mut delayed = executable_input(2, 2);
        delayed.origin.root_epoch = 2;
        delayed.certified_epoch = 5;
        delayed.authorized_epoch = 6;
        delayed.technical.epoch = 6;
        delayed.origin.input_record = InputRecordV2 {
            round: 1,
            epoch: 5,
            previous_hash: Some(B256::repeat_byte(0x31)),
            state_hash: Some(B256::repeat_byte(0x31)),
            timestamp: 1,
            block_hash: None,
        };
        delayed.origin.tr_hash = technical_record_hash(&delayed.technical);
        let active = B256::repeat_byte(0x69);
        delayed.origin.shard_conf_hash = active;
        delayed.transitions = vec![transition_bytes(
            1,
            2,
            5,
            6,
            input.origin.shard_conf_hash,
            active,
            0,
            B256::ZERO,
            2,
            delayed.parent_hash,
        )];
        assert!(delayed.origin_class().is_ok(), "a later TR may wait for the frozen-parent ack");
        assert!(run(&delayed, &advanced, testing::world().system_gas).is_ok());
    }

    #[test]
    fn supersession_requires_a_bounded_nonempty_span() {
        let parent = executable_input(1, 1).parent_hash;
        let old_conf = B256::repeat_byte(0x11);
        let new_conf = B256::repeat_byte(0x22);
        let missing = transition_bytes(1, 3, 1, 3, old_conf, new_conf, 0, B256::ZERO, 1, parent);
        assert!(wire::decode_epoch_transition(&missing).is_err());
        let max = wire::MAX_SUPERSESSION_SPAN;
        // Every rule except the bound holds (shard delta == span == root delta, hash changed,
        // nonzero commitment), so only the bound check can refuse the oversized case.
        let at_limit = transition_bytes(
            1,
            1 + max,
            1,
            1 + max,
            old_conf,
            new_conf,
            max,
            B256::repeat_byte(0x33),
            1,
            parent,
        );
        assert!(wire::decode_epoch_transition(&at_limit).is_ok());
        let oversized = transition_bytes(
            1,
            2 + max,
            1,
            2 + max,
            old_conf,
            new_conf,
            max + 1,
            B256::repeat_byte(0x33),
            1,
            parent,
        );
        assert_eq!(
            wire::decode_epoch_transition(&oversized).unwrap_err(),
            wire::CanonicalCborError::InvalidRootInput("supersession span exceeds bound")
        );
        assert!(
            wire::decode_epoch_transition(&vec![0; wire::MAX_EPOCH_TRANSITION_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn supersession_span_is_exactly_the_primary_and_recovery_pair() {
        // Pinned to bft-core's handoff.MaxSupersessionSpan: raising either side alone would admit
        // a chain the other side can never acknowledge.
        assert_eq!(wire::MAX_SUPERSESSION_SPAN, 2);
        let parent = executable_input(1, 1).parent_hash;
        let old_conf = B256::repeat_byte(0x11);
        let new_conf = B256::repeat_byte(0x22);
        let commitment = B256::repeat_byte(0x33);
        let two = transition_bytes(1, 3, 1, 3, old_conf, new_conf, 2, commitment, 1, parent);
        assert!(wire::decode_epoch_transition(&two).is_ok());
        let three = transition_bytes(1, 4, 1, 4, old_conf, new_conf, 3, commitment, 1, parent);
        assert_eq!(
            wire::decode_epoch_transition(&three).unwrap_err(),
            wire::CanonicalCborError::InvalidRootInput("supersession span exceeds bound")
        );
    }

    #[test]
    fn assignment_projection_hash_matches_the_contract_vector() {
        let transition = EpochTransition {
            old_root_epoch: 4,
            new_root_epoch: 6,
            old_shard_epoch: 2,
            new_shard_epoch: 4,
            old_active_conf_hash: keccak256("old"),
            new_active_conf_hash: keccak256("new"),
            supersession_span: 2,
            supersession_commitment: keccak256("H2/H3"),
            body_id: B256::ZERO,
            genesis_id: B256::ZERO,
            frozen_id: B256::ZERO,
            commit_id: B256::ZERO,
            frozen_parent: B256::ZERO,
            successor_tr: B256::ZERO,
            evm_round: 1,
        };
        assert_eq!(
            assignment_projection_hash(transition),
            b256!("8a6712ca26e2085a0dc21ad07303ddc72665c61dc3290e5ce0abc3fda55acca1"),
            "the projection encoding must match SealRegistry v2"
        );
    }

    #[test]
    fn transition_body_is_refused_without_publishing_state() {
        let parent = genesis_db();
        let mut input = executable_input(1, 13);
        input.transitions.push(vec![0x01]);
        let before = parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(PHASE_SLOT.0)).unwrap();
        assert!(matches!(
            run(&input, &parent, testing::world().system_gas),
            Err(ExecutionError::InvalidInput("invalid epoch transition encoding"))
        ));
        assert_eq!(
            parent.storage_ref(SEAL_REGISTRY, U256::from_be_bytes(PHASE_SLOT.0)).unwrap(),
            before
        );
    }
}
