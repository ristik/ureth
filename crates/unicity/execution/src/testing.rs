//! Shared fixtures for the B1 world the checked-in vectors describe. Compiled only for this
//! crate's own tests and for dependents that enable the `test-utils` feature.
//!
//! The world is bft-core's K=2 deployment (`testdata/b1-vectors.json`): the exported B1 genesis,
//! its profile and its pinned numbers. Updates built here come from a small model that is
//! independent of the Go generator, so the Go vectors and these helpers cross-check each other.

use crate::{
    records::RecordImport,
    update::{B1Context, Entry, Member, Update},
    RootInputV2, SEAL_REGISTRY_CODE_HASH,
};
use alloy_primitives::{Address, Bytes, B256, U256};
use revm::{
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
    Database,
};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

const VECTORS: &str = include_str!("../testdata/b1-vectors.json");

/// The deployment numbers of the vector world.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct World {
    /// Root network identifier.
    pub network: u16,
    /// Execution chain identifier.
    pub execution_chain_id: u64,
    /// `W_cert`.
    pub w_cert: u64,
    /// Root genesis identity.
    pub root_genesis_id: B256,
    /// Registry runtime hash.
    pub runtime_hash: B256,
    /// Execution profile hash.
    pub profile_hash: B256,
    /// Reserved system gas.
    pub system_gas: u64,
    /// Header gas limit.
    pub max_gas: u64,
    /// Ordinary gas capacity.
    pub ordinary_capacity: u64,
    /// `G_rest` allowance of the profile.
    pub rest_gas: u64,
    /// Hash of the funded, beacon-equipped execution genesis.
    pub genesis_hash: B256,
    /// Full shard configuration hash, the registry's genesis assignment.
    pub shard_conf_hash: B256,
    /// The pinned genesis UC time: `records.ucTime` before any import.
    pub genesis_uc_time: u64,
}

#[derive(Deserialize)]
struct Vectors {
    world: World,
}

/// The vector world, parsed once.
pub fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| serde_json::from_str::<Vectors>(VECTORS).expect("vectors parse").world)
}

/// The pinned bindings of the vector world.
pub fn b1_context() -> B1Context {
    let w = world();
    B1Context {
        network: w.network,
        root_genesis_id: w.root_genesis_id,
        execution_chain_id: w.execution_chain_id,
        profile_hash: w.profile_hash,
        w_cert: w.w_cert,
        hook: Default::default(),
    }
}

/// The open tail of the registry's live set: the epoch and its actual start round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tail {
    /// Epoch of the open tail.
    pub epoch: u64,
    /// Actual start round of that epoch.
    pub start: u64,
}

/// The genesis tail: the root genesis epoch, started at round zero.
pub const GENESIS_TAIL: Tail = Tail { epoch: 1, start: 0 };

fn key(epoch: u64, index: u64) -> [u8; 33] {
    let mut secret = [0u8; 32];
    secret[24..32].copy_from_slice(&(epoch << 8 | (index + 1)).to_be_bytes());
    PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&secret).expect("scalar"))
        .serialize()
}

/// How many members and how long node identifiers an entry carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Members {
    /// Three short identifiers.
    Small,
    /// The registry maximum: 64 members whose identifiers are 128 bytes sharing a 96-byte prefix.
    Maximal,
}

fn members(shape: Members, epoch: u64) -> Vec<Member> {
    match shape {
        Members::Small => (0..3)
            .map(|i| Member {
                node_id: format!("node-{}", (b'a' + i as u8) as char),
                key: key(epoch, i),
                weight: 1 + i,
            })
            .collect(),
        Members::Maximal => (0..64)
            .map(|i| Member {
                node_id: format!("{}{i:032}", "p".repeat(96)),
                key: key(epoch, i),
                weight: 1 + i,
            })
            .collect(),
    }
}

fn entry(epoch: u64, start: u64, end: Option<u64>, shape: Members) -> Entry {
    let id = |tag: u8| B256::from([tag; 32]);
    let byte = (epoch % 200) as u8 + 1;
    Entry {
        epoch,
        body_kind: 3,
        body_id: id(byte),
        activation_commit_id: id(byte ^ 0x80),
        start,
        end,
        signing_scheme: 2,
        signing_config_hash: id(byte ^ 0x40),
        members: members(shape, epoch),
    }
}

/// Builds the update an honest pair derives for `input`'s block on a parent whose open tail is
/// `tail`. Intermediate epochs start one round apart ending at the origin, so a rotation by `d`
/// epochs needs `origin_round > tail.start + d - 1`. Only epochs that survive the window are
/// projected, and the former tip is closed at the first actual successor.
///
/// # Panics
///
/// Panics if a rotation cannot be laid out in the available rounds.
pub fn update_for(input: &RootInputV2, parent_number: u64, tail: Tail) -> Update {
    update_with(input, parent_number, tail, Members::Small)
}

/// [`update_for`] with the given member shape for every projected entry.
///
/// # Panics
///
/// Panics if a rotation cannot be laid out in the available rounds.
pub fn update_with(input: &RootInputV2, parent_number: u64, tail: Tail, shape: Members) -> Update {
    update_in(&b1_context(), input, parent_number, tail, shape)
}

/// [`update_with`] under any pinned context, for profiles other than the vector world's.
///
/// # Panics
///
/// Panics if a rotation cannot be laid out in the available rounds.
pub fn update_in(
    context: &B1Context,
    input: &RootInputV2,
    parent_number: u64,
    tail: Tail,
    shape: Members,
) -> Update {
    let round = input.origin.root_round;
    let target = input.origin.root_epoch;
    let mut update = Update {
        network: context.network,
        root_genesis_id: context.root_genesis_id,
        execution_chain_id: context.execution_chain_id,
        profile_hash: context.profile_hash,
        parent_hash: input.parent_hash,
        block_number: parent_number + 1,
        origin_epoch: target,
        origin_round: round,
        // An invalid origin has no honest update; refusal fixtures fail before admission anyway.
        origin_identity: input.origin_identity().unwrap_or(B256::repeat_byte(1)),
        prior_tip_epoch: tail.epoch,
        old_tip_end: None,
        new_entries: Vec::new(),
    };
    if target <= tail.epoch {
        // Quiet when equal. An older epoch has no honest update; the empty one is inadmissible,
        // which is what refusal fixtures need.
        return update;
    }
    let first = tail.epoch + 1;
    let start_of = |epoch: u64| round - (target - epoch);
    assert!(start_of(first) > tail.start, "rotation does not fit the rounds");
    let floor = round.saturating_sub(context.w_cert);
    update.old_tip_end = Some(start_of(first));
    for epoch in first..=target {
        let end = (epoch < target).then(|| start_of(epoch + 1));
        if end.is_none_or(|end| end > floor) {
            update.new_entries.push(entry(epoch, start_of(epoch), end, shape));
        }
    }
    update
}

/// The mandatory root-record import of an empty source log: no entries, a zero target and the
/// pinned genesis UC time. Every vector block imports it unless a test supplies a log.
pub fn empty_import() -> Bytes {
    RecordImport {
        progress: 0,
        uc_time: world().genesis_uc_time,
        target_count: 0,
        target_tip: B256::ZERO,
        entries: Vec::new(),
    }
    .to_bytes()
    .into()
}

/// A valid import of `n` linked one-word records (kind 1), the registry's whole log after it, with
/// anchors inside the world's genesis time. `n` of zero is [`empty_import`].
pub fn import_of(n: u64) -> Bytes {
    use alloy_sol_types::{sol, SolCall};
    sol! {
        function preimage(uint64 index, bytes32 predecessor, uint8 kind, uint64 progress, uint64 ucTime, bytes data) external;
    }
    let genesis = world().genesis_uc_time;
    let mut entries: Vec<crate::records::RecordEntry> = Vec::new();
    for i in 0..n {
        let predecessor = entries.last().map_or(B256::ZERO, |e| e.record_id);
        let data = B256::repeat_byte(i as u8 + 1).to_vec();
        let call = preimageCall {
            index: i,
            predecessor,
            kind: 1,
            progress: 10 + i,
            ucTime: genesis + 1 + i,
            data: data.clone().into(),
        };
        entries.push(crate::records::RecordEntry {
            index: i,
            record_id: alloy_primitives::keccak256(&call.abi_encode()[4..]),
            predecessor,
            kind: 1,
            progress: 10 + i,
            uc_time: genesis + 1 + i,
            data,
            closed_epoch: 0,
        });
    }
    RecordImport {
        progress: 100,
        uc_time: genesis + 1000,
        target_count: n,
        target_tip: entries.last().map_or(B256::ZERO, |e| e.record_id),
        entries,
    }
    .to_bytes()
    .into()
}

/// Like [`seal`], committing to `import` instead of the empty one.
pub fn seal_with_import(
    input: &mut RootInputV2,
    parent_number: u64,
    tail: Tail,
    import: &[u8],
) -> Bytes {
    let bytes = seal(input, parent_number, tail);
    input.root_records_hash = crate::sha256(import);
    bytes
}

/// `SHA-256` of [`empty_import`]: the `rootRecordsHash` of a block that imports nothing.
pub fn empty_import_hash() -> B256 {
    crate::sha256(&empty_import())
}

/// Commits `input` to the update [`update_for`] builds and to the [`empty_import`], and returns
/// the exact update bytes.
pub fn seal(input: &mut RootInputV2, parent_number: u64, tail: Tail) -> Bytes {
    let update = update_for(input, parent_number, tail);
    input.b1_update_hash = update.hash();
    input.root_records_hash = crate::sha256(&empty_import());
    update.to_bytes().into()
}

#[derive(Deserialize)]
struct Genesis {
    alloc: BTreeMap<Address, GenesisAccount>,
}

#[derive(Deserialize)]
struct GenesisAccount {
    balance: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    storage: BTreeMap<B256, B256>,
}

fn hex_bytes(value: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(value.trim_start_matches("0x")).expect("hex")
}

/// The execution genesis as a state database: the B1 registry, the funded test sender and the
/// EIP-4788 contract.
///
/// # Panics
///
/// Panics if the checked-in genesis does not carry the pinned registry runtime.
pub fn genesis_db() -> CacheDB<EmptyDB> {
    let genesis: Genesis =
        serde_json::from_str(include_str!("../testdata/signed-beacon-genesis.json")).expect("json");
    let mut db = CacheDB::new(EmptyDB::default());
    for (address, account) in genesis.alloc {
        let code = account.code.map(|value| Bytecode::new_raw(hex_bytes(&value).into()));
        let code_hash = code.as_ref().map_or(B256::ZERO, Bytecode::hash_slow);
        db.insert_account_info(
            address,
            AccountInfo {
                balance: U256::from_str_radix(account.balance.trim_start_matches("0x"), 16)
                    .expect("balance"),
                nonce: u64::from_str_radix(
                    account.nonce.as_deref().unwrap_or("0x0").trim_start_matches("0x"),
                    16,
                )
                .expect("nonce"),
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
            .expect("storage");
        }
    }
    let registry = db.basic(crate::SEAL_REGISTRY).expect("db").expect("registry account");
    assert_eq!(registry.code_hash, SEAL_REGISTRY_CODE_HASH);
    db
}

/// The registry's assignment as the previous block left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Assigned root epoch.
    pub root_epoch: u64,
    /// Assigned shard epoch.
    pub shard_epoch: u64,
    /// Active shard configuration hash.
    pub conf: B256,
}

/// The vector world's genesis assignment: root epoch 1, shard epoch 0.
pub fn genesis_assignment() -> Assignment {
    Assignment { root_epoch: 1, shard_epoch: 0, conf: world().shard_conf_hash }
}

/// Encodes an acknowledged EVM transition and its acknowledgement, with the fixed identities the
/// registry stores verbatim.
#[allow(clippy::too_many_arguments)]
pub fn transition_bytes(
    old_root_epoch: u64,
    new_root_epoch: u64,
    old_shard_epoch: u64,
    new_shard_epoch: u64,
    old_active_conf_hash: B256,
    new_active_conf_hash: B256,
    span: u64,
    span_commitment: B256,
    round: u64,
    parent: B256,
) -> Vec<u8> {
    use crate::{array, bytes, text, uint};
    let mut ack = Vec::new();
    array(&mut ack, 8);
    text(&mut ack, "UNICITY_HANDOFF_ACK");
    uint(&mut ack, 2);
    for word in
        [B256::repeat_byte(0x41), B256::repeat_byte(0x42), parent, parent, B256::repeat_byte(0x43)]
    {
        bytes(&mut ack, word.as_slice());
    }
    uint(&mut ack, round);
    let mut transition = Vec::new();
    array(&mut transition, 13);
    text(&mut transition, "UNICITY_HANDOFF_EVM_TRANSITION");
    uint(&mut transition, 3);
    for epoch in [old_root_epoch, new_root_epoch, old_shard_epoch, new_shard_epoch] {
        uint(&mut transition, epoch);
    }
    bytes(&mut transition, old_active_conf_hash.as_slice());
    bytes(&mut transition, new_active_conf_hash.as_slice());
    uint(&mut transition, span);
    bytes(&mut transition, span_commitment.as_slice());
    bytes(&mut transition, B256::repeat_byte(0x44).as_slice());
    bytes(&mut transition, B256::repeat_byte(0x45).as_slice());
    bytes(&mut transition, &ack);
    transition
}

/// Makes `input` the acknowledgement block that rotates the root epoch from
/// `assigned.root_epoch` to the origin's epoch and returns the assignment it leaves behind.
///
/// A single-epoch rotation is a root-only acknowledgement. A longer one folds a supersession
/// span: the shard epoch advances with it and the active configuration changes.
pub fn rotate(input: &mut RootInputV2, assigned: Assignment) -> Assignment {
    let target = input.origin.root_epoch;
    let delta = target - assigned.root_epoch;
    let (shard_epoch, conf, span, commitment) = if delta == 1 {
        (assigned.shard_epoch, assigned.conf, 0, B256::ZERO)
    } else {
        (
            assigned.shard_epoch + delta,
            crate::sha256(&[assigned.conf.as_slice(), &delta.to_be_bytes()].concat()),
            delta,
            crate::sha256(&delta.to_be_bytes()),
        )
    };
    input.certified_epoch = assigned.shard_epoch;
    input.authorized_epoch = shard_epoch;
    input.technical.epoch = shard_epoch;
    input.origin.input_record.epoch = assigned.shard_epoch;
    input.origin.shard_conf_hash = conf;
    input.origin.tr_hash = crate::technical_record_hash(&input.technical);
    input.transitions = vec![transition_bytes(
        assigned.root_epoch,
        target,
        assigned.shard_epoch,
        shard_epoch,
        assigned.conf,
        conf,
        span,
        commitment,
        input.authorized_round,
        input.parent_hash,
    )];
    Assignment { root_epoch: target, shard_epoch, conf }
}

/// A custody stand-in with the two entry points the hook uses: `recordCursor()` returns
/// storage word 0 and `applyRootRecords(uint32 n)` runs `body` (word 0 is the cursor).
pub fn custody_code(body: &[u8]) -> Bytes {
    let mut c = vec![0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c]; // selector
    c.extend([0x80, 0x63, 0xca, 0x01, 0xc9, 0x83, 0x14, 0x61, 0x00, 0x20, 0x57]); // -> cursor at 0x20
    c.extend([0x80, 0x63, 0x1d, 0x2a, 0x00, 0x37, 0x14, 0x61, 0x00, 0x2c, 0x57]); // -> apply at 0x2c
    c.extend([0x60, 0x00, 0x80, 0xfd]); // unknown selector: revert
    assert_eq!(c.len(), 0x20);
    c.extend([0x5b, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]); // cursor
    assert_eq!(c.len(), 0x2c);
    c.push(0x5b);
    c.extend(body);
    c.into()
}

/// cursor += n, and an empty batch reverts as custody's `EmptyBatch` does
pub const ADVANCE: &[u8] = &[
    0x60, 0x04, 0x35, 0x80, 0x15, 0x61, 0x00, 0x3e, 0x57, // n = arg; if n == 0 goto revert
    0x60, 0x00, 0x54, 0x01, 0x60, 0x00, 0x55, 0x00, // cursor += n; stop
    0x5b, 0x60, 0x00, 0x80, 0xfd, // revert
];
/// cursor += n + 1
pub const OVERSHOOT: &[u8] =
    &[0x60, 0x04, 0x35, 0x60, 0x01, 0x01, 0x60, 0x00, 0x54, 0x01, 0x60, 0x00, 0x55, 0x00];
/// `applyRootRecords` that does nothing: the cursor does not move
pub const NOTHING: &[u8] = &[0x00];
/// `applyRootRecords` that always reverts
pub const REVERT: &[u8] = &[0x60, 0x00, 0x80, 0xfd];
