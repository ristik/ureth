//! The one rule resolver for the authenticated activation schedule (VT-07b, bft-core#1164;
//! validator-registry design sections 7.1 to 7.4).
//!
//! The registry (VR) keeps an append-only `activations[]` list of `{ruleId, releaseDigest, E, T,
//! state}` entries. [`UnicityRules::resolve`] reads it at the block's parent state and answers
//! which EVM spec the block runs under and which known rules are active at the block's root epoch
//! `E_b`. A rule is identified by `keccak256("unicity.rule/" + name)`.
//!
//! - The latest non-superseded entry of a rule is its effective entry. An effective (Active) or
//!   Latched entry with `E <= E_b` that this binary does not know refuses the block with
//!   [`UpgradeRequired`], at every site that executes, validates or builds a block.
//! - Chain-spec timestamp forks stay at the genesis spec ([`GENESIS_SPEC`], Cancun). Nothing in the
//!   chain spec, and no unknown rule, ever selects another spec.
//! - Entries that the binary lacks but that are not yet in force warn ahead of `E`: a log line and
//!   the gauge `unicity_upgrade_required{rule,epoch}`.
//!
//! The registry is read from storage directly (no EVM call, no gas), by the frozen schema-v1
//! layout (`docs/design/validator-registry/schema-v1.md` section 2.1 and 2.4).

use alloy_primitives::{b256, keccak256, Address, B256, U256};
use revm::{primitives::hardfork::SpecId, Database};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

/// Prefix of every rule name in its identifier.
pub const RULE_PREFIX: &str = "unicity.rule/";
/// `MAX_ACTIVATIONS`: the registry's bound on `activations[]`.
pub const MAX_ACTIVATIONS: u32 = 64;
/// The spec every Unicity block runs under unless a known active rule says otherwise.
pub const GENESIS_SPEC: SpecId = SpecId::CANCUN;

/// Name of the harmless test rule. It changes nothing in execution; it exists so an activation can
/// be scheduled, observed and refused end to end (see `briefs/vt07-test-rule.md`).
pub const NOOP_TEST_RULE_NAME: &str = "noop-test-v1";

/// `ruleId = keccak256("unicity.rule/" + name)`.
pub fn rule_id(name: &str) -> B256 {
    let mut preimage = Vec::with_capacity(RULE_PREFIX.len() + name.len());
    preimage.extend_from_slice(RULE_PREFIX.as_bytes());
    preimage.extend_from_slice(name.as_bytes());
    keccak256(preimage)
}

/// The id of the harmless test rule.
pub fn noop_test_rule_id() -> B256 {
    rule_id(NOOP_TEST_RULE_NAME)
}

/// `V = keccak256(abi.encode(uint256(keccak256("unicity.vr.registry.v1")) - 1)) & ~0xff`
/// (`vr-layout.json` `namespace`; recomputed in the tests).
pub const VR_NAMESPACE: B256 =
    b256!("2015195c564edf8b5942ad7bb1fe48e96d190815eb762db2ddff1d85ce73f900");
/// Slot offset of the packed `status` word (holds `activationCount`).
const STATUS_OFFSET: u64 = 6;
/// Slot offset of the `activations` mapping.
const ACTIVATIONS_OFFSET: u64 = 35;

/// A rule this binary implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownRule {
    /// The rule's name (the part after `unicity.rule/`).
    pub name: &'static str,
    /// `keccak256("unicity.rule/" + name)`.
    pub id: B256,
    /// The EVM spec the rule selects while active (the highest of the active rules wins).
    pub spec: SpecId,
}

/// The set of rule ids a binary knows, or the set of those active at one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    ids: BTreeSet<B256>,
}

impl RuleSet {
    /// A set of exactly `ids`.
    pub fn new(ids: impl IntoIterator<Item = B256>) -> Self {
        Self { ids: ids.into_iter().collect() }
    }

    /// The rules this binary was built with. Without the `no-test-rule` feature this is the
    /// harmless test rule; with it, nothing (a binary that lacks the rule, for refusal tests).
    pub fn builtin() -> Self {
        Self::new(builtin_rules().iter().map(|r| r.id))
    }

    /// Whether `id` is in the set.
    pub fn contains(&self, id: &B256) -> bool {
        self.ids.contains(id)
    }

    /// The ids, ascending.
    pub fn ids(&self) -> impl Iterator<Item = &B256> {
        self.ids.iter()
    }

    /// Number of ids.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// The rules the binary implements.
#[cfg(not(feature = "no-test-rule"))]
pub fn builtin_rules() -> Vec<KnownRule> {
    vec![KnownRule {
        name: NOOP_TEST_RULE_NAME,
        id: noop_test_rule_id(),
        // changes nothing in execution
        spec: GENESIS_SPEC,
    }]
}

/// The rules the binary implements: none, in a `no-test-rule` build.
#[cfg(feature = "no-test-rule")]
pub fn builtin_rules() -> Vec<KnownRule> {
    Vec::new()
}

/// The state of an `activations[i]` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// Scheduled and effective for its rule.
    Active,
    /// Replaced by a later entry of the same rule (a postponement); ignored.
    Superseded,
    /// The handoff into an epoch `>= E` committed; permanent.
    Latched,
}

/// One `activations[i]` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleEntry {
    /// `keccak256("unicity.rule/" + name)`.
    pub rule_id: B256,
    /// The release that carries the rule (advisory).
    pub release_digest: B256,
    /// The root epoch `E` the rule takes effect from.
    pub root_epoch: u64,
    /// Earliest UC time the schedule may be acted on (roots gate it; ureth ignores it).
    pub not_before_uc_time: u64,
    /// Entry state.
    pub state: EntryState,
    /// The governance change that produced the entry.
    pub change_id: u64,
}

/// A rule the block needs and this binary lacks (design section 7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpgradeRequired {
    /// The rule this binary does not know.
    pub rule_id: B256,
    /// The release digest the schedule names for it.
    pub release_digest: B256,
    /// The root epoch `E` it is effective from.
    pub root_epoch: u64,
    /// The root epoch of the refused block (`>= root_epoch`).
    pub block_epoch: u64,
}

impl fmt::Display for UpgradeRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UpgradeRequired{{ruleId: {}, releaseDigest: {}}}: this binary does not support the \
             rule scheduled for root epoch {}; the block is at root epoch {}. Install the release \
             with that digest",
            self.rule_id, self.release_digest, self.root_epoch, self.block_epoch
        )
    }
}

/// Why a block cannot be run by this binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// An effective or latched rule at or before the block's epoch is unknown.
    UpgradeRequired(UpgradeRequired),
    /// The EVM environment is not the genesis spec (a chain-spec fork tried to move it).
    UnsupportedSpec(String),
    /// The registry's schedule is malformed.
    Schedule(&'static str),
    /// Reading the parent state failed.
    Database(String),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpgradeRequired(u) => u.fmt(f),
            Self::UnsupportedSpec(s) => {
                write!(f, "only the fixed Cancun profile is supported, found {s}")
            }
            Self::Schedule(why) => write!(f, "malformed activation schedule: {why}"),
            Self::Database(e) => write!(f, "activation schedule read failed: {e}"),
        }
    }
}

impl std::error::Error for RuleError {}

/// An entry of the schedule that is effective or latched but unknown to the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lacking {
    /// The unknown rule.
    pub rule_id: B256,
    /// Its release digest.
    pub release_digest: B256,
    /// Its root epoch `E`.
    pub root_epoch: u64,
    /// Whether the entry is latched (permanent).
    pub latched: bool,
}

/// The full result of resolving a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The spec the block runs under.
    pub spec: SpecId,
    /// The known rules active at the block's root epoch.
    pub active: RuleSet,
    /// Every effective or latched entry the binary lacks, in force or not yet (warnings).
    pub lacking: Vec<Lacking>,
    /// The first lacking entry in force at the block's epoch, if any: the refusal.
    pub refusal: Option<UpgradeRequired>,
}

/// Decodes the schedule from the registry's storage at `vr`, by the frozen layout.
pub fn read_schedule<DB: Database>(
    db: &mut DB,
    vr: Address,
) -> Result<Vec<ScheduleEntry>, RuleError> {
    let count = read_count(db, vr)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        out.push(read_entry(db, vr, i)?);
    }
    Ok(out)
}

fn vr_slot(offset: u64) -> U256 {
    U256::from_be_bytes(VR_NAMESPACE.0) + U256::from(offset)
}

fn load<DB: Database>(db: &mut DB, vr: Address, slot: U256) -> Result<[u8; 32], RuleError> {
    db.storage(vr, slot)
        .map(|v| v.to_be_bytes::<32>())
        .map_err(|e| RuleError::Database(format!("{e:?}")))
}

fn read_count<DB: Database>(db: &mut DB, vr: Address) -> Result<u32, RuleError> {
    let word = load(db, vr, vr_slot(STATUS_OFFSET))?;
    // activationCount is a u32 at byte offset 17 from the low end
    let count = u32::from_be_bytes(word[11..15].try_into().expect("four bytes"));
    if count > MAX_ACTIVATIONS {
        return Err(RuleError::Schedule("activationCount exceeds MAX_ACTIVATIONS"));
    }
    Ok(count)
}

fn entry_base(index: u32) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[28..32].copy_from_slice(&index.to_be_bytes());
    preimage[32..].copy_from_slice(&vr_slot(ACTIVATIONS_OFFSET).to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(preimage).0)
}

fn read_entry<DB: Database>(
    db: &mut DB,
    vr: Address,
    index: u32,
) -> Result<ScheduleEntry, RuleError> {
    let base = entry_base(index);
    let w0 = load(db, vr, base)?;
    let w1 = load(db, vr, base + U256::from(1))?;
    let w2 = load(db, vr, base + U256::from(2))?;
    decode_entry(w0, w1, w2)
}

/// Decodes the three words of an `activations[i]` entry, strictly.
pub fn decode_entry(w0: [u8; 32], w1: [u8; 32], w2: [u8; 32]) -> Result<ScheduleEntry, RuleError> {
    let be8 = |b: &[u8]| u64::from_be_bytes(b.try_into().expect("eight bytes"));
    if w2[..7].iter().any(|b| *b != 0) {
        return Err(RuleError::Schedule("reserved bytes of an activation are not zero"));
    }
    let state = match w2[15] {
        1 => EntryState::Active,
        2 => EntryState::Superseded,
        3 => EntryState::Latched,
        _ => return Err(RuleError::Schedule("activation state outside 1..=3")),
    };
    let rule_id = B256::from(w0);
    let change_id = be8(&w2[7..15]);
    if rule_id == B256::ZERO || change_id == 0 {
        return Err(RuleError::Schedule("activation with a zero ruleId or changeId"));
    }
    Ok(ScheduleEntry {
        rule_id,
        release_digest: B256::from(w1),
        root_epoch: be8(&w2[24..32]),
        not_before_uc_time: be8(&w2[16..24]),
        state,
        change_id,
    })
}

/// Pure evaluation of a schedule at a block's root epoch against a known-rule list.
pub fn evaluate(entries: &[ScheduleEntry], known: &[KnownRule], block_epoch: u64) -> Resolution {
    // The latest non-superseded entry of each rule is its effective entry.
    let mut effective: BTreeMap<B256, &ScheduleEntry> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.state != EntryState::Superseded) {
        effective.insert(e.rule_id, e);
    }
    let mut spec = GENESIS_SPEC;
    let mut active = BTreeSet::new();
    let mut lacking = Vec::new();
    let mut refusal = None;
    // Index order keeps the refusal deterministic.
    let mut ordered: Vec<&ScheduleEntry> = effective.values().copied().collect();
    ordered.sort_by_key(|e| e.change_id);
    for e in ordered {
        match known.iter().find(|k| k.id == e.rule_id) {
            Some(k) => {
                if e.root_epoch <= block_epoch {
                    active.insert(k.id);
                    if k.spec > spec {
                        spec = k.spec;
                    }
                }
            }
            None => {
                lacking.push(Lacking {
                    rule_id: e.rule_id,
                    release_digest: e.release_digest,
                    root_epoch: e.root_epoch,
                    latched: e.state == EntryState::Latched,
                });
                if refusal.is_none() && e.root_epoch <= block_epoch {
                    refusal = Some(UpgradeRequired {
                        rule_id: e.rule_id,
                        release_digest: e.release_digest,
                        root_epoch: e.root_epoch,
                        block_epoch,
                    });
                }
            }
        }
    }
    Resolution { spec, active: RuleSet { ids: active }, lacking, refusal }
}

/// An effective or latched schedule entry as the operator view shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledView {
    /// The rule.
    pub rule_id: B256,
    /// Its release digest.
    pub release_digest: B256,
    /// The root epoch it takes effect from.
    pub root_epoch: u64,
    /// Whether the entry is latched.
    pub latched: bool,
    /// Whether this binary knows the rule.
    pub known: bool,
}

/// The schedule as the canonical head holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    /// Every effective or latched entry.
    pub scheduled: Vec<ScheduledView>,
    /// Those this binary lacks (the warnings).
    pub lacking: Vec<Lacking>,
}

#[derive(Debug, Default)]
struct State {
    /// `(rule, epoch)` labels currently reported on the gauge.
    reported: BTreeSet<(B256, u64)>,
    /// The canonical head's schedule view (`unicity_rulesV1`); set only by
    /// [`UnicityRules::observe_head`].
    head: Option<HeadView>,
}

#[derive(Debug)]
struct Inner {
    known: Vec<KnownRule>,
    /// Observability only, driven by the canonical head alone; execution attempts (build, import,
    /// replay) never write it. No decision ever reads it: every refusal is a pure function of the
    /// parent state and the block's root epoch, so a cold and a warm node decide identically.
    state: Mutex<State>,
}

/// The activation-schedule rule resolver; cheap to clone, shared by every site of a node.
#[derive(Clone, Debug)]
pub struct UnicityRules {
    inner: Arc<Inner>,
}

impl Default for UnicityRules {
    fn default() -> Self {
        Self::global()
    }
}

impl UnicityRules {
    /// The process-wide resolver over [`builtin_rules`].
    pub fn global() -> Self {
        static GLOBAL: OnceLock<UnicityRules> = OnceLock::new();
        GLOBAL.get_or_init(|| Self::with_known(builtin_rules())).clone()
    }

    /// A resolver over exactly `known` (own observability state; for tests and embedders).
    pub fn with_known(known: Vec<KnownRule>) -> Self {
        Self { inner: Arc::new(Inner { known, state: Mutex::new(State::default()) }) }
    }

    /// The rules this resolver knows.
    pub fn known(&self) -> RuleSet {
        RuleSet::new(self.inner.known.iter().map(|k| k.id))
    }

    /// The rules this resolver knows, with names.
    pub fn known_rules(&self) -> &[KnownRule] {
        &self.inner.known
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Resolves the spec and the active rules of a block at root epoch `root_epoch`, reading the
    /// schedule from the registry `vr` in `parent_state`. A zero `vr` is a profile without a
    /// registry: an empty schedule, the genesis spec.
    ///
    /// Errors with [`RuleError::UpgradeRequired`] when an effective or latched entry with
    /// `E <= root_epoch` is unknown to this binary.
    pub fn resolve<DB: Database>(
        &self,
        parent_state: &mut DB,
        vr: Address,
        root_epoch: u64,
    ) -> Result<(SpecId, RuleSet), RuleError> {
        let resolution = self.resolve_full(parent_state, vr, root_epoch)?;
        Ok((resolution.spec, resolution.active))
    }

    /// [`Self::resolve`] with the whole [`Resolution`].
    ///
    /// The bounded schedule (at most 64 entries, 3 words each) is read and evaluated on every
    /// call. There is deliberately no result cache: a cache key cannot cover earlier entries
    /// without reading them, and an in-place latch changes an entry without changing its count, so
    /// any cheaper key could serve another parent's schedule across a reorg or replay. A
    /// resolution is an execution attempt and never touches the operator view: historical
    /// execution must not overwrite what the canonical head shows.
    pub fn resolve_full<DB: Database>(
        &self,
        parent_state: &mut DB,
        vr: Address,
        root_epoch: u64,
    ) -> Result<Resolution, RuleError> {
        let entries =
            if vr == Address::ZERO { Vec::new() } else { read_schedule(parent_state, vr)? };
        finish(evaluate(&entries, &self.inner.known, root_epoch))
    }

    /// Publishes the operator view (gauge `unicity_upgrade_required`, the warning log and
    /// `unicity_rulesV1`) from the schedule in the canonical head's state. Call it only on a
    /// canonical-head update (the canonical-state stream), never from execution of other blocks.
    pub fn observe_head<DB: Database>(
        &self,
        head_state: &mut DB,
        vr: Address,
    ) -> Result<(), RuleError> {
        let entries = if vr == Address::ZERO { Vec::new() } else { read_schedule(head_state, vr)? };
        // the lacking set does not depend on the epoch
        let resolution = evaluate(&entries, &self.inner.known, 0);
        let mut effective: BTreeMap<B256, &ScheduleEntry> = BTreeMap::new();
        for e in entries.iter().filter(|e| e.state != EntryState::Superseded) {
            effective.insert(e.rule_id, e);
        }
        let scheduled = effective
            .values()
            .map(|e| ScheduledView {
                rule_id: e.rule_id,
                release_digest: e.release_digest,
                root_epoch: e.root_epoch,
                latched: e.state == EntryState::Latched,
                known: self.inner.known.iter().any(|k| k.id == e.rule_id),
            })
            .collect();
        self.publish(HeadView { scheduled, lacking: resolution.lacking });
        Ok(())
    }

    fn publish(&self, view: HeadView) {
        let mut state = self.lock();
        let now: BTreeSet<(B256, u64)> =
            view.lacking.iter().map(|l| (l.rule_id, l.root_epoch)).collect();
        for l in &view.lacking {
            if state.reported.insert((l.rule_id, l.root_epoch)) {
                tracing::warn!(
                    target: "unicity::rules",
                    rule = %l.rule_id,
                    epoch = l.root_epoch,
                    release_digest = %l.release_digest,
                    latched = l.latched,
                    "the activation schedule holds a rule this binary lacks; upgrade before the \
                     root epoch or the node will refuse to run past it"
                );
            }
            metrics::gauge!(
                "unicity_upgrade_required",
                "rule" => alloy_primitives::hex::encode(l.rule_id),
                "epoch" => l.root_epoch.to_string()
            )
            .set(1.0);
        }
        let cleared: Vec<(B256, u64)> = state.reported.difference(&now).copied().collect();
        for (rule, epoch) in cleared {
            metrics::gauge!(
                "unicity_upgrade_required",
                "rule" => alloy_primitives::hex::encode(rule),
                "epoch" => epoch.to_string()
            )
            .set(0.0);
            state.reported.remove(&(rule, epoch));
        }
        state.head = Some(view);
    }

    /// The structural check for sites that hold no state (`evm_env`, `next_evm_env`): the spec must
    /// be the genesis spec, because chain-spec timestamp forks never move it. It carries no
    /// schedule information and so cannot differ between a cold and a warm node; the
    /// epoch-dependent refusal happens where the parent state is, with the typed
    /// [`UpgradeRequired`].
    pub fn check_chain_spec(spec: SpecId) -> Result<(), RuleError> {
        if spec != GENESIS_SPEC {
            return Err(RuleError::UnsupportedSpec(format!("{spec:?}")));
        }
        Ok(())
    }

    /// The canonical head's schedule view, if one was observed (`unicity_rulesV1`).
    pub fn head_view(&self) -> Option<HeadView> {
        self.lock().head.clone()
    }
}

fn finish(resolution: Resolution) -> Result<Resolution, RuleError> {
    match resolution.refusal {
        Some(u) => Err(RuleError::UpgradeRequired(u)),
        None => Ok(resolution),
    }
}

/// The storage words of a registry holding `entries`, by the frozen layout (test support).
#[cfg(any(test, feature = "test-utils"))]
pub fn schedule_storage(entries: &[ScheduleEntry]) -> Vec<(U256, U256)> {
    let mut out = Vec::new();
    let mut status = [0u8; 32];
    status[11..15].copy_from_slice(&(entries.len() as u32).to_be_bytes());
    out.push((vr_slot(STATUS_OFFSET), U256::from_be_bytes(status)));
    for (i, e) in entries.iter().enumerate() {
        let base = entry_base(i as u32);
        let mut w2 = [0u8; 32];
        w2[24..].copy_from_slice(&e.root_epoch.to_be_bytes());
        w2[16..24].copy_from_slice(&e.not_before_uc_time.to_be_bytes());
        w2[15] = match e.state {
            EntryState::Active => 1,
            EntryState::Superseded => 2,
            EntryState::Latched => 3,
        };
        w2[7..15].copy_from_slice(&e.change_id.to_be_bytes());
        for (j, w) in [e.rule_id.0, e.release_digest.0, w2].into_iter().enumerate() {
            out.push((base + U256::from(j as u64), U256::from_be_bytes(w)));
        }
    }
    out
}

/// Seeds `entries` into `db` at `vr` (test support).
#[cfg(any(test, feature = "test-utils"))]
pub fn seed_schedule(
    db: &mut revm::database::CacheDB<revm::database::EmptyDB>,
    vr: Address,
    entries: &[ScheduleEntry],
) {
    for (slot, value) in schedule_storage(entries) {
        db.insert_account_storage(vr, slot, value).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use revm::database::{CacheDB, EmptyDB};

    const VR: Address = address!("ff00000000000000000000000000000000000003");

    fn known_noop() -> Vec<KnownRule> {
        vec![KnownRule { name: "noop", id: rule_id("noop"), spec: GENESIS_SPEC }]
    }

    fn entry(name: &str, epoch: u64, state: EntryState, change_id: u64) -> ScheduleEntry {
        ScheduleEntry {
            rule_id: rule_id(name),
            release_digest: B256::repeat_byte(0xd1),
            root_epoch: epoch,
            not_before_uc_time: 5000,
            state,
            change_id,
        }
    }

    fn seed(entries: &[ScheduleEntry]) -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        seed_schedule(&mut db, VR, entries);
        db
    }

    #[test]
    fn namespace_and_rule_id_derive_from_the_design() {
        let id = keccak256("unicity.vr.registry.v1");
        let minus_one = U256::from_be_bytes(id.0) - U256::from(1);
        let derived =
            U256::from_be_bytes(keccak256(minus_one.to_be_bytes::<32>()).0) & !U256::from(0xffu64);
        assert_eq!(derived, U256::from_be_bytes(VR_NAMESPACE.0));
        assert_eq!(rule_id("x"), keccak256("unicity.rule/x"));
        println!("noop-test rule id: {}", noop_test_rule_id());
    }

    /// The frozen `storage.json` vector "vr activations[0]" (bft-core, testvectors/
    /// validator-registry): slots and words.
    #[test]
    fn frozen_vector_activation_zero() {
        let base = entry_base(0);
        assert_eq!(
            B256::from(base.to_be_bytes::<32>()),
            b256!("158dc14c7058711b0be1d3e4e36ee1d4550b10736c4c1511bc30ab51ad122cd2")
        );
        let w = |s: &str| -> [u8; 32] { s.parse::<B256>().unwrap().0 };
        let e = decode_entry(
            w("b23b7325f96d7fbdf65f8ec04a0954c629ac750d5ddef5dc2493047be82d7da7"),
            w("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6"),
            w("0000000000000000000000000000040200000000000013880000000000000007"),
        )
        .unwrap();
        assert_eq!(e.root_epoch, 7);
        assert_eq!(e.not_before_uc_time, 5000);
        assert_eq!(e.state, EntryState::Superseded);
        assert_eq!(e.change_id, 4);
    }

    #[test]
    fn empty_schedule_is_cancun_with_no_rules() {
        let rules = UnicityRules::with_known(known_noop());
        let mut db = seed(&[]);
        let (spec, set) = rules.resolve(&mut db, VR, 100).unwrap();
        assert_eq!(spec, SpecId::CANCUN);
        assert!(set.is_empty());
        // no registry in the profile
        let (spec, set) = rules.resolve(&mut db, Address::ZERO, 100).unwrap();
        assert_eq!((spec, set.len()), (SpecId::CANCUN, 0));
    }

    #[test]
    fn known_rule_is_active_at_e_and_not_before() {
        let rules = UnicityRules::with_known(known_noop());
        let mut db = seed(&[entry("noop", 10, EntryState::Active, 1)]);
        assert!(rules.resolve(&mut db, VR, 9).unwrap().1.is_empty());
        assert!(rules.resolve(&mut db, VR, 10).unwrap().1.contains(&rule_id("noop")));
        assert!(rules.resolve(&mut db, VR, 11).unwrap().1.contains(&rule_id("noop")));
    }

    #[test]
    fn unknown_rule_refuses_from_e_and_warns_before() {
        let rules = UnicityRules::with_known(known_noop());
        let mut db = seed(&[entry("future", 10, EntryState::Active, 1)]);
        let before = rules.resolve_full(&mut db, VR, 9).unwrap();
        assert_eq!(before.lacking.len(), 1, "the warning is visible ahead of E");
        assert!(before.refusal.is_none());
        for epoch in [10, 11, 1000] {
            match rules.resolve(&mut db, VR, epoch) {
                Err(RuleError::UpgradeRequired(u)) => {
                    assert_eq!(u.rule_id, rule_id("future"));
                    assert_eq!(u.release_digest, B256::repeat_byte(0xd1));
                    assert_eq!((u.root_epoch, u.block_epoch), (10, epoch));
                }
                other => panic!("expected UpgradeRequired, got {other:?}"),
            }
        }
    }

    #[test]
    fn superseded_entries_are_ignored_and_postponement_moves_e() {
        let rules = UnicityRules::with_known(known_noop());
        // "future" at 10 was postponed to 20: only the effective entry counts
        let mut db = seed(&[
            entry("future", 10, EntryState::Superseded, 1),
            entry("future", 20, EntryState::Active, 2),
        ]);
        assert!(rules.resolve(&mut db, VR, 19).is_ok());
        assert!(matches!(rules.resolve(&mut db, VR, 20), Err(RuleError::UpgradeRequired(_))));
        // a superseded unknown with no effective successor is not in force
        let mut only_superseded = seed(&[entry("future", 10, EntryState::Superseded, 1)]);
        assert!(rules.resolve_full(&mut only_superseded, VR, 99).unwrap().lacking.is_empty());
    }

    #[test]
    fn latched_unknown_is_refused() {
        let rules = UnicityRules::with_known(known_noop());
        let mut db = seed(&[entry("future", 10, EntryState::Latched, 1)]);
        assert!(rules.resolve(&mut db, VR, 9).is_ok());
        assert!(matches!(rules.resolve(&mut db, VR, 10), Err(RuleError::UpgradeRequired(_))));
    }

    #[test]
    fn a_moved_chain_spec_is_refused_structurally() {
        assert!(UnicityRules::check_chain_spec(SpecId::CANCUN).is_ok());
        for spec in [SpecId::SHANGHAI, SpecId::PRAGUE, SpecId::OSAKA] {
            assert!(matches!(
                UnicityRules::check_chain_spec(spec),
                Err(RuleError::UnsupportedSpec(_))
            ));
        }
    }

    /// Cold and warm resolvers, and parents that agree on count and tail but differ in an earlier
    /// entry, decide identically: the answer is a function of the parent state alone.
    #[test]
    fn decisions_are_a_pure_function_of_the_parent_state() {
        let warm = UnicityRules::with_known(known_noop());
        let tail = entry("noop", 50, EntryState::Active, 3);
        let a = [
            entry("future", 10, EntryState::Active, 1),
            entry("x", 99, EntryState::Active, 2),
            tail,
        ];
        let b = [
            entry("future", 10, EntryState::Superseded, 1),
            entry("x", 99, EntryState::Active, 2),
            tail,
        ];
        // warm up on A, then ask B and A again, against a cold resolver each time
        for epoch in [9, 10, 11] {
            for entries in [&a, &b, &a] {
                let cold = UnicityRules::with_known(known_noop());
                let mut db1 = seed(entries);
                let mut db2 = seed(entries);
                assert_eq!(
                    format!("{:?}", warm.resolve(&mut db1, VR, epoch)),
                    format!("{:?}", cold.resolve(&mut db2, VR, epoch))
                );
            }
        }
        let mut db_a = seed(&a);
        let mut db_b = seed(&b);
        assert!(warm.resolve(&mut db_a, VR, 10).is_err());
        assert!(warm.resolve(&mut db_b, VR, 10).is_ok(), "the earlier entry is superseded in B");
        assert!(warm.resolve(&mut db_b, VR, 99).is_err(), "x (unknown) is in force from 99");
        let b2 = [entry("future", 10, EntryState::Superseded, 1), tail];
        let mut db_b2 = seed(&b2);
        assert!(warm.resolve(&mut db_b2, VR, 10).is_ok());
    }

    #[test]
    fn only_the_canonical_head_drives_the_operator_view() {
        let rules = UnicityRules::with_known(known_noop());
        let mut head = seed(&[entry("future", 10, EntryState::Active, 1)]);
        let mut older = seed(&[]);
        assert!(rules.head_view().is_none());
        rules.observe_head(&mut head, VR).unwrap();
        assert_eq!(rules.head_view().unwrap().lacking.len(), 1);
        // replay or import of an older parent resolves its own schedule and leaves the view alone
        rules.resolve(&mut older, VR, 4).unwrap();
        assert!(rules.resolve_full(&mut head, VR, 5).is_ok());
        assert_eq!(rules.head_view().unwrap().lacking.len(), 1, "head warning survives");
        assert_eq!(rules.lock().reported.len(), 1, "and so does its gauge label");
        // a new canonical head without the entry (postponed away) clears it
        rules.observe_head(&mut older, VR).unwrap();
        assert!(rules.head_view().unwrap().lacking.is_empty());
        assert!(rules.lock().reported.is_empty());
    }

    #[test]
    fn count_is_bounded_by_64() {
        let rules = UnicityRules::with_known(known_noop());
        let mut db = seed(&[]);
        let mut status = [0u8; 32];
        status[11..15].copy_from_slice(&65u32.to_be_bytes());
        db.insert_account_storage(VR, vr_slot(STATUS_OFFSET), U256::from_be_bytes(status)).unwrap();
        assert!(matches!(rules.resolve(&mut db, VR, 1), Err(RuleError::Schedule(_))));
        // 64 is the bound and accepted
        let entries: Vec<_> =
            (1..=64).map(|i| entry(&format!("r{i}"), 1_000, EntryState::Active, i)).collect();
        let mut full = seed(&entries);
        assert_eq!(read_schedule(&mut full, VR).unwrap().len(), 64);
        assert!(rules.resolve(&mut full, VR, 5).is_ok());
    }

    #[test]
    fn malformed_entries_are_refused() {
        let mut w2 = [0u8; 32];
        w2[15] = 9;
        w2[14] = 1;
        assert!(decode_entry([1; 32], [2; 32], w2).is_err(), "state 9");
        w2[15] = 1;
        w2[0] = 1;
        assert!(decode_entry([1; 32], [2; 32], w2).is_err(), "reserved byte");
        w2[0] = 0;
        assert!(decode_entry([0; 32], [2; 32], w2).is_err(), "zero rule id");
        w2[14] = 0;
        assert!(decode_entry([1; 32], [2; 32], w2).is_err(), "zero change id");
    }

    #[test]
    fn highest_known_active_spec_wins() {
        let known = vec![
            KnownRule { name: "a", id: rule_id("a"), spec: SpecId::CANCUN },
            KnownRule { name: "b", id: rule_id("b"), spec: SpecId::PRAGUE },
        ];
        let entries = [entry("a", 1, EntryState::Active, 1), entry("b", 5, EntryState::Active, 2)];
        assert_eq!(evaluate(&entries, &known, 4).spec, SpecId::CANCUN);
        assert_eq!(evaluate(&entries, &known, 5).spec, SpecId::PRAGUE);
    }

    #[cfg(not(feature = "no-test-rule"))]
    #[test]
    fn the_binary_knows_the_test_rule() {
        assert!(RuleSet::builtin().contains(&noop_test_rule_id()));
    }

    #[cfg(feature = "no-test-rule")]
    #[test]
    fn the_no_test_rule_build_lacks_it() {
        assert!(RuleSet::builtin().is_empty());
        let rules = UnicityRules::with_known(builtin_rules());
        let mut db = seed(&[ScheduleEntry {
            rule_id: noop_test_rule_id(),
            ..entry("noop", 3, EntryState::Active, 1)
        }]);
        assert!(matches!(rules.resolve(&mut db, VR, 3), Err(RuleError::UpgradeRequired(_))));
    }
}
