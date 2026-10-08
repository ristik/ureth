//! The committed B1 `Update`: canonical bytes, bounded admission and its gas debit.
//!
//! The paired Go node authenticates the root history and derives the exact `Update` for the named
//! parent. This module never repeats that authentication. It checks everything Rust can check by
//! itself before any execution: canonical bounded bytes, the committed bindings (profile, parent,
//! height, origin), and the interval and member invariants of the entries that the registry will
//! store. State-dependent queue and coverage checks run in the metered registry call.
//!
//! Admission follows the design's staged order. The outer byte cap and the scan charge
//! `2000 + 16*C` are checked before the bytes are looked at. An allocation-free structural scan
//! then counts the members `T`, and the member charge `1000*T` is reserved before any member is
//! allocated, any point is parsed or any semantic rule runs. A scan or debit error rejects the
//! block, never the caller.

use crate::{
    block::{BlockAccountingError, BlockProfile},
    sha256, ExecutionError, RootInputV2,
};
use alloy_primitives::{Bytes, B256};
use secp256k1::PublicKey;

/// Domain string that opens every canonical update.
pub const UPDATE_DOMAIN: &str = "UNICITY_B1_UPDATE";
/// Most members one entry carries.
pub const MAX_MEMBERS: u64 = 64;
/// Longest node identifier in bytes.
pub const MAX_NODE_ID_BYTES: u64 = 128;
/// Largest encoded entry in bytes.
pub const MAX_ENTRY_BYTES: usize = 16384;
/// Fixed part of the scan charge.
pub const SCAN_BASE_GAS: u64 = 2000;
/// Per-byte part of the scan charge.
pub const SCAN_BYTE_GAS: u64 = 16;
/// Charge per member of the update, reserved before member allocation.
pub const MEMBER_GAS: u64 = 1000;
/// Measured-plus-margin `G_rest` constant term (contracts PR 6, to be re-measured here).
pub const REST_GAS_BASE: u64 = 1_136_500;
/// Measured-plus-margin `G_rest` term per ring slot.
pub const REST_GAS_PER_ENTRY: u64 = 1_147_500;
/// Largest measured ring size. A larger profile is refused, never truncated.
pub const MAX_MEASURED_K: u64 = 16;

/// Local profile bindings every update must carry. All values come from the node's pinned genesis
/// profile, never from the update itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct B1Context {
    /// Root network identifier.
    pub network: u16,
    /// Identity of the pinned root genesis.
    pub root_genesis_id: B256,
    /// Execution chain identifier.
    pub execution_chain_id: u64,
    /// `SHA-256` of the complete execution profile, equal to the registry's `b1.profileHash`.
    pub profile_hash: B256,
    /// Certificate window `W_cert`.
    pub w_cert: u64,
    /// The mandatory records hook the profile pins (no custody: no hook).
    pub hook: crate::hook::RecordsHook,
}

impl B1Context {
    /// Ring size `K_max = W_cert + 1`, refused above the measured cap.
    pub fn k_max(&self) -> Result<u64, UpdateError> {
        let k = self.w_cert.checked_add(1).ok_or(UpdateError::Overflow)?;
        if k > MAX_MEASURED_K {
            return Err(UpdateError::UnmeasuredRing(k));
        }
        Ok(k)
    }

    /// Canonical byte cap `C_max = 4096 + 16384*K_max`.
    pub fn max_update_bytes(&self) -> Result<u64, UpdateError> {
        Ok(4096 + MAX_ENTRY_BYTES as u64 * self.k_max()?)
    }

    /// The least `g_sys` the pinned profile admits: the maximum admission charge, the rectangular
    /// gross history-write allowance and the measured-plus-margin `G_rest(K_max)` of the registry
    /// runtime, `155936 + 15626944*K + 1136500 + 1147500*K`, plus the root-record import envelope
    /// (`records::IMPORT_ENVELOPE_GAS`) and the records hook's envelope. A smaller reservation is
    /// refused at startup, never truncated at runtime.
    pub fn required_system_gas(&self) -> Result<u64, UpdateError> {
        let k = self.k_max()?;
        let hook = self.hook.envelope_gas().map_err(|_| UpdateError::Overflow)?;
        Ok(155_936 +
            REST_GAS_BASE +
            (15_626_944 + REST_GAS_PER_ENTRY) * k +
            crate::records::IMPORT_ENVELOPE_GAS +
            hook)
    }

    /// Token cap `32 + 266*K_max`.
    pub fn max_tokens(&self) -> Result<u64, UpdateError> {
        Ok(32 + 266 * self.k_max()?)
    }
}

/// One authenticated root member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Raw UTF-8 node identifier.
    pub node_id: String,
    /// Compressed secp256k1 root consensus key.
    pub key: [u8; 33],
    /// Positive weight.
    pub weight: u64,
}

/// One authenticated interval of root authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Root epoch.
    pub epoch: u64,
    /// Native body kind, 1 genesis, 2 or 3 successor.
    pub body_kind: u64,
    /// Native body identity.
    pub body_id: B256,
    /// Activation commit identity; zero only for genesis.
    pub activation_commit_id: B256,
    /// Actual inclusive start round.
    pub start: u64,
    /// Actual exclusive end round, `None` for the open tail.
    pub end: Option<u64>,
    /// Signing scheme, 1 or 2.
    pub signing_scheme: u64,
    /// Signing configuration identity.
    pub signing_config_hash: B256,
    /// Members sorted by raw node identifier.
    pub members: Vec<Member>,
}

/// The decoded canonical update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    /// Root network identifier.
    pub network: u16,
    /// Root genesis identity.
    pub root_genesis_id: B256,
    /// Execution chain identifier.
    pub execution_chain_id: u64,
    /// Execution profile hash.
    pub profile_hash: B256,
    /// Execution parent hash.
    pub parent_hash: B256,
    /// Height of the block this update belongs to.
    pub block_number: u64,
    /// Origin root epoch.
    pub origin_epoch: u64,
    /// Origin root round.
    pub origin_round: u64,
    /// Origin identity.
    pub origin_identity: B256,
    /// Epoch of the parent's open tail.
    pub prior_tip_epoch: u64,
    /// Actual end of the former tip, present iff there are new entries.
    pub old_tip_end: Option<u64>,
    /// Newer epochs surviving the target window, in increasing epoch order.
    pub new_entries: Vec<Entry>,
}

/// Named refusal. The scan and debit variants reject the block; none is a caller verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// The profile ring exceeds the measured cap.
    UnmeasuredRing(u64),
    /// A checked size or gas computation overflowed.
    Overflow,
    /// The update is longer than `C_max`.
    TooLarge {
        /// Supplied length.
        len: usize,
        /// Cap.
        limit: u64,
    },
    /// The scan charge alone exceeds the system budget.
    ScanBudget,
    /// The member charge exceeds what remains of the system budget.
    MemberBudget,
    /// Not the fixed canonical shape, or over a structural bound.
    Encoding,
    /// `SHA-256(update)` differs from the root input's committed hash.
    UpdateHashMismatch,
    /// Network differs from the pinned profile.
    NetworkMismatch,
    /// Root genesis differs from the pinned profile.
    RootGenesisMismatch,
    /// Execution chain identifier differs from the pinned profile.
    ChainMismatch,
    /// Profile hash differs from the pinned profile.
    ProfileMismatch,
    /// Parent hash is zero or differs from the bound parent.
    ParentMismatch,
    /// Block number is zero or is not the parent number plus one.
    BlockNumberMismatch,
    /// Origin epoch differs from the root input.
    OriginEpochMismatch,
    /// Origin round differs from the root input.
    OriginRoundMismatch,
    /// Origin identity is zero or differs from the root input.
    OriginIdentityMismatch,
    /// Body kind, identity, signing configuration or activation identity is invalid.
    EntryIdentity,
    /// Member identifiers are not strictly increasing in raw byte order.
    MembersNotSorted,
    /// A compressed key is not a valid secp256k1 point.
    InvalidKey,
    /// Two members share a key.
    DuplicateKey,
    /// A member weight is zero.
    ZeroWeight,
    /// Member weights overflow `u64`.
    WeightOverflow,
    /// The committed total weight exceeds the profile cap `B` ([`crate::quant::WEIGHT_CAP_B`]).
    WeightCap,
    /// A closed entry has `end <= start`.
    EmptyInterval,
    /// A new entry has the genesis body kind.
    GenesisKindInUpdate,
    /// A new entry's epoch is not newer than the prior tip.
    EpochNotNewer,
    /// A new entry starts after the origin round.
    StartAfterOrigin,
    /// A closed new entry ends at or below the window floor, or after the origin.
    EndOutsideWindow,
    /// New entries are not consecutive epochs with end equal to the next start.
    NotContiguous,
    /// `oldTipEnd` is missing, exceeds the first start, or is not that start for the next epoch.
    OldTipEndMismatch,
    /// The final entry is closed or is not the origin epoch.
    TailNotOrigin,
    /// An empty update carries an old-tip end or does not name the origin epoch.
    EmptyUpdateMismatch,
}

impl From<UpdateError> for ExecutionError {
    fn from(error: UpdateError) -> Self {
        Self::B1Update(error)
    }
}

/// Window floor `L = max(0, O - W)`.
pub const fn window_floor(origin: u64, w_cert: u64) -> u64 {
    origin.saturating_sub(w_cert)
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    match value {
        0..=23 => out.push(m | value as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, value as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn optional(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(v) => head(out, 0, v),
        None => out.push(0xf6),
    }
}

impl Update {
    /// Canonical deterministic CBOR bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, 4, 13);
        head(&mut out, 3, UPDATE_DOMAIN.len() as u64);
        out.extend_from_slice(UPDATE_DOMAIN.as_bytes());
        head(&mut out, 0, u64::from(self.network));
        head(&mut out, 2, 32);
        out.extend_from_slice(self.root_genesis_id.as_slice());
        head(&mut out, 0, self.execution_chain_id);
        for hash in [&self.profile_hash, &self.parent_hash] {
            head(&mut out, 2, 32);
            out.extend_from_slice(hash.as_slice());
        }
        for v in [self.block_number, self.origin_epoch, self.origin_round] {
            head(&mut out, 0, v);
        }
        head(&mut out, 2, 32);
        out.extend_from_slice(self.origin_identity.as_slice());
        head(&mut out, 0, self.prior_tip_epoch);
        optional(&mut out, self.old_tip_end);
        head(&mut out, 4, self.new_entries.len() as u64);
        for entry in &self.new_entries {
            head(&mut out, 4, 9);
            head(&mut out, 0, entry.epoch);
            head(&mut out, 0, entry.body_kind);
            for hash in [&entry.body_id, &entry.activation_commit_id] {
                head(&mut out, 2, 32);
                out.extend_from_slice(hash.as_slice());
            }
            head(&mut out, 0, entry.start);
            optional(&mut out, entry.end);
            head(&mut out, 0, entry.signing_scheme);
            head(&mut out, 2, 32);
            out.extend_from_slice(entry.signing_config_hash.as_slice());
            head(&mut out, 4, entry.members.len() as u64);
            for member in &entry.members {
                head(&mut out, 4, 3);
                head(&mut out, 3, member.node_id.len() as u64);
                out.extend_from_slice(member.node_id.as_bytes());
                head(&mut out, 2, 33);
                out.extend_from_slice(&member.key);
                head(&mut out, 0, member.weight);
            }
        }
        out
    }

    /// `SHA-256` of the canonical bytes, committed as the root input's twelfth field.
    pub fn hash(&self) -> B256 {
        sha256(&self.to_bytes())
    }
}

/// Schema-directed reader. It cannot recurse: the only nesting is
/// update, entries, entry, members and member.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    tokens: u64,
    limit: u64,
}

impl<'a> Reader<'a> {
    fn head(&mut self) -> Result<(u8, u64), UpdateError> {
        self.tokens += 1;
        if self.tokens > self.limit {
            return Err(UpdateError::Encoding);
        }
        let first = *self.bytes.get(self.pos).ok_or(UpdateError::Encoding)?;
        self.pos += 1;
        let (major, info) = (first >> 5, first & 31);
        if info < 24 {
            return Ok((major, u64::from(info)));
        }
        if info > 27 {
            return Err(UpdateError::Encoding);
        }
        let n = 1usize << (info - 24);
        let raw = self.bytes.get(self.pos..self.pos + n).ok_or(UpdateError::Encoding)?;
        self.pos += n;
        let value = raw.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b));
        let minimal = match n {
            1 => value >= 24,
            2 => value > 0xff,
            4 => value > 0xffff,
            _ => value > 0xffff_ffff,
        };
        if !minimal {
            return Err(UpdateError::Encoding);
        }
        Ok((major, value))
    }

    fn arity(&mut self, n: u64) -> Result<(), UpdateError> {
        match self.head()? {
            (4, v) if v == n => Ok(()),
            _ => Err(UpdateError::Encoding),
        }
    }

    fn uint(&mut self) -> Result<u64, UpdateError> {
        match self.head()? {
            (0, v) => Ok(v),
            _ => Err(UpdateError::Encoding),
        }
    }

    fn string(&mut self, major: u8, min: u64, max: u64) -> Result<&'a [u8], UpdateError> {
        let (m, n) = self.head()?;
        if m != major || n < min || n > max || n > (self.bytes.len() - self.pos) as u64 {
            return Err(UpdateError::Encoding);
        }
        let out = &self.bytes[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        if major == 3 && core::str::from_utf8(out).is_err() {
            return Err(UpdateError::Encoding);
        }
        Ok(out)
    }

    fn hash(&mut self) -> Result<B256, UpdateError> {
        Ok(B256::from_slice(self.string(2, 32, 32)?))
    }

    fn optional(&mut self) -> Result<Option<u64>, UpdateError> {
        if self.bytes.get(self.pos) == Some(&0xf6) {
            self.tokens += 1;
            self.pos += 1;
            if self.tokens > self.limit {
                return Err(UpdateError::Encoding);
            }
            return Ok(None);
        }
        self.uint().map(Some)
    }
}

/// Parses once. With `decode == false` it allocates nothing and returns only the member count.
fn parse(
    bytes: &[u8],
    max_entries: u64,
    token_limit: u64,
    decode: bool,
) -> Result<(Option<Update>, u64), UpdateError> {
    let mut r = Reader { bytes, pos: 0, tokens: 0, limit: token_limit };
    r.arity(13)?;
    if r.string(3, UPDATE_DOMAIN.len() as u64, UPDATE_DOMAIN.len() as u64)? !=
        UPDATE_DOMAIN.as_bytes()
    {
        return Err(UpdateError::Encoding);
    }
    let network = r.uint()?;
    if network > u64::from(u16::MAX) {
        return Err(UpdateError::Encoding);
    }
    let root_genesis_id = r.hash()?;
    let execution_chain_id = r.uint()?;
    let profile_hash = r.hash()?;
    let parent_hash = r.hash()?;
    let block_number = r.uint()?;
    let origin_epoch = r.uint()?;
    let origin_round = r.uint()?;
    let origin_identity = r.hash()?;
    let prior_tip_epoch = r.uint()?;
    let old_tip_end = r.optional()?;
    let (major, count) = r.head()?;
    if major != 4 || count > max_entries || count > (bytes.len() - r.pos) as u64 {
        return Err(UpdateError::Encoding);
    }
    let mut entries = Vec::new();
    let mut total = 0u64;
    for _ in 0..count {
        // The 16 KiB entry cap needs no check of its own: the member count and identifier bounds
        // below keep a 64-member entry under 12 KiB (see the test of the maximal entry).
        r.arity(9)?;
        let epoch = r.uint()?;
        let body_kind = r.uint()?;
        let body_id = r.hash()?;
        let activation_commit_id = r.hash()?;
        let start = r.uint()?;
        let end = r.optional()?;
        let signing_scheme = r.uint()?;
        let signing_config_hash = r.hash()?;
        let (major, n) = r.head()?;
        if major != 4 || n == 0 || n > MAX_MEMBERS || n > (bytes.len() - r.pos) as u64 {
            return Err(UpdateError::Encoding);
        }
        total += n;
        let mut members = Vec::new();
        for _ in 0..n {
            r.arity(3)?;
            let id = r.string(3, 1, MAX_NODE_ID_BYTES)?;
            let key = r.string(2, 33, 33)?;
            let weight = r.uint()?;
            if decode {
                members.push(Member {
                    node_id: String::from_utf8(id.to_vec()).map_err(|_| UpdateError::Encoding)?,
                    key: key.try_into().map_err(|_| UpdateError::Encoding)?,
                    weight,
                });
            }
        }
        if decode {
            entries.push(Entry {
                epoch,
                body_kind,
                body_id,
                activation_commit_id,
                start,
                end,
                signing_scheme,
                signing_config_hash,
                members,
            });
        }
    }
    if r.pos != bytes.len() {
        return Err(UpdateError::Encoding);
    }
    let update = decode.then_some(Update {
        network: network as u16,
        root_genesis_id,
        execution_chain_id,
        profile_hash,
        parent_hash,
        block_number,
        origin_epoch,
        origin_round,
        origin_identity,
        prior_tip_epoch,
        old_tip_end,
        new_entries: entries,
    });
    Ok((update, total))
}

impl Entry {
    /// The member invariants. The reader already bounds the member count to `1..=64` and each
    /// identifier to `1..=128` bytes of UTF-8 before anything is allocated.
    fn check_members(&self) -> Result<(), UpdateError> {
        let mut total = 0u64;
        for (i, member) in self.members.iter().enumerate() {
            if i > 0 && self.members[i - 1].node_id.as_bytes() >= member.node_id.as_bytes() {
                return Err(UpdateError::MembersNotSorted);
            }
            if member.weight == 0 {
                return Err(UpdateError::ZeroWeight);
            }
            PublicKey::from_slice(&member.key).map_err(|_| UpdateError::InvalidKey)?;
            if self.members[..i].iter().any(|prev| prev.key == member.key) {
                return Err(UpdateError::DuplicateKey);
            }
            total = total.checked_add(member.weight).ok_or(UpdateError::WeightOverflow)?;
        }
        if total > crate::quant::WEIGHT_CAP_B {
            return Err(UpdateError::WeightCap);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), UpdateError> {
        let zero = B256::ZERO;
        if !(1..=3).contains(&self.body_kind) ||
            self.body_id == zero ||
            self.signing_config_hash == zero ||
            !matches!(self.signing_scheme, 1 | 2) ||
            (self.body_kind == 1) != (self.activation_commit_id == zero)
        {
            return Err(UpdateError::EntryIdentity);
        }
        if self.end.is_some_and(|end| end <= self.start) {
            return Err(UpdateError::EmptyInterval);
        }
        self.check_members()
    }
}

/// An admitted update and the gas its admission debits from `g_sys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The decoded update.
    pub update: Update,
    /// `G_admit = 2000 + 16*C + 1000*T`.
    pub gas: u64,
}

/// What an update must be bound to before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateBinding {
    /// `SHA-256(update)` committed by the root input.
    pub committed_hash: B256,
    /// Hash of the execution parent.
    pub parent_hash: B256,
    /// Height of the parent.
    pub parent_number: u64,
    /// Origin root epoch.
    pub origin_epoch: u64,
    /// Origin root round.
    pub origin_round: u64,
    /// Origin identity.
    pub origin_identity: B256,
}

/// Admits `raw` against `budget` (`g_sys`), in the staged order the design fixes.
pub fn admit(
    raw: &[u8],
    context: &B1Context,
    binding: &UpdateBinding,
    budget: u64,
) -> Result<Admitted, UpdateError> {
    let k = context.k_max()?;
    let cap = context.max_update_bytes()?;
    if raw.len() as u64 > cap {
        return Err(UpdateError::TooLarge { len: raw.len(), limit: cap });
    }
    let scan = SCAN_BASE_GAS + SCAN_BYTE_GAS * raw.len() as u64;
    if scan > budget {
        return Err(UpdateError::ScanBudget);
    }
    let tokens = context.max_tokens()?;
    let (_, members) = parse(raw, k, tokens, false)?;
    if members > (budget - scan) / MEMBER_GAS {
        return Err(UpdateError::MemberBudget);
    }
    let gas = scan + MEMBER_GAS * members;
    // The reader accepts exactly one encoding per value (minimal heads, fixed arities, exact
    // lengths, no trailing bytes), so decode followed by re-encode reproduces `raw` by
    // construction; the tests assert that property over every single-bit mutation.
    let (Some(update), _) = parse(raw, k, tokens, true)? else {
        return Err(UpdateError::Encoding);
    };
    if sha256(raw) != binding.committed_hash {
        return Err(UpdateError::UpdateHashMismatch);
    }
    check_bindings(&update, context, binding)?;
    check_entries(&update, context)?;
    Ok(Admitted { update, gas })
}

fn check_bindings(u: &Update, c: &B1Context, b: &UpdateBinding) -> Result<(), UpdateError> {
    if u.network != c.network {
        return Err(UpdateError::NetworkMismatch);
    }
    if u.root_genesis_id != c.root_genesis_id {
        return Err(UpdateError::RootGenesisMismatch);
    }
    if u.execution_chain_id != c.execution_chain_id {
        return Err(UpdateError::ChainMismatch);
    }
    if u.profile_hash != c.profile_hash {
        return Err(UpdateError::ProfileMismatch);
    }
    if u.parent_hash == B256::ZERO || u.parent_hash != b.parent_hash {
        return Err(UpdateError::ParentMismatch);
    }
    if b.parent_number.checked_add(1) != Some(u.block_number) {
        return Err(UpdateError::BlockNumberMismatch);
    }
    if u.origin_epoch != b.origin_epoch {
        return Err(UpdateError::OriginEpochMismatch);
    }
    if u.origin_round != b.origin_round {
        return Err(UpdateError::OriginRoundMismatch);
    }
    if u.origin_identity == B256::ZERO || u.origin_identity != b.origin_identity {
        return Err(UpdateError::OriginIdentityMismatch);
    }
    Ok(())
}

fn check_entries(u: &Update, c: &B1Context) -> Result<(), UpdateError> {
    let floor = window_floor(u.origin_round, c.w_cert);
    for (i, e) in u.new_entries.iter().enumerate() {
        e.validate()?;
        if e.body_kind == 1 {
            return Err(UpdateError::GenesisKindInUpdate);
        }
        if e.epoch <= u.prior_tip_epoch {
            return Err(UpdateError::EpochNotNewer);
        }
        if e.start > u.origin_round {
            return Err(UpdateError::StartAfterOrigin);
        }
        if e.end.is_some_and(|end| end <= floor || end > u.origin_round) {
            return Err(UpdateError::EndOutsideWindow);
        }
        if i > 0 {
            let prev = &u.new_entries[i - 1];
            if prev.epoch.checked_add(1) != Some(e.epoch) || prev.end != Some(e.start) {
                return Err(UpdateError::NotContiguous);
            }
        }
    }
    match u.new_entries.first() {
        Some(first) => {
            let end = u.old_tip_end.ok_or(UpdateError::OldTipEndMismatch)?;
            if end > first.start ||
                (u.prior_tip_epoch.checked_add(1) == Some(first.epoch) && end != first.start)
            {
                return Err(UpdateError::OldTipEndMismatch);
            }
            let tail = &u.new_entries[u.new_entries.len() - 1];
            if tail.end.is_some() || tail.epoch != u.origin_epoch {
                return Err(UpdateError::TailNotOrigin);
            }
        }
        None => {
            if u.old_tip_end.is_some() || u.prior_tip_epoch != u.origin_epoch {
                return Err(UpdateError::EmptyUpdateMismatch);
            }
        }
    }
    Ok(())
}

/// The committed update bytes of one block job with the pinned bindings they are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1Job {
    /// Local profile bindings.
    pub context: B1Context,
    /// Exact canonical update bytes the root input commits to.
    pub update: Bytes,
    /// Exact canonical root-record import companion the root input commits to
    /// (`rootRecordsHash`), carried with the update and re-executed with it.
    pub records: Bytes,
}

impl B1Job {
    /// Binds this job to `input` and `profile`: the update must hash to the root input's
    /// committed twelfth field, and the reservation `g_sys` must cover the profile envelope for
    /// the pinned ring size, so no job can be built on an undersized or unmeasured profile.
    pub fn check_bound(
        &self,
        input: &RootInputV2,
        profile: &BlockProfile,
    ) -> Result<(), BlockAccountingError> {
        if sha256(&self.update) != input.b1_update_hash {
            return Err(BlockAccountingError::UpdateHashMismatch);
        }
        if sha256(&self.records) != input.root_records_hash {
            return Err(BlockAccountingError::RecordsHashMismatch);
        }
        let required =
            self.context.required_system_gas().map_err(|_| BlockAccountingError::B1Profile)?;
        if profile.system_gas < required {
            return Err(BlockAccountingError::B1Profile);
        }
        Ok(())
    }
}
