//! The proof-system-independent interface of the B7 succinct redemption fallback (bft-core `b7rel`;
//! design `briefs/b7-succinct-fallback-design.md` steps 1 and 2): the candidate limits and the
//! relation ID, the per-epoch registry commitment `C_e` the seal registry caches, and the canonical
//! public journal a proof commits to. The guest (step 3) reports its output through
//! [`Journal::encode`]; the Go reference produces `tests/testdata/b7-relation-vectors-v1.json`.
//! Inactive: nothing here proves, verifies or redeems.

use alloy_primitives::{keccak256, Address, B256, U256};

// Candidate ceilings of the first expanded profile (design §5): benchmark targets, not measured
// capacity. They define `relation_id`.

/// Leaves of the whole history, mint and burn included.
pub const MAX_LEAVES: u64 = 1024;
/// Transfers including the final burn.
pub const MAX_TRANSFERS: u64 = 1023;
/// Distinct root epochs whose certificates the history uses.
pub const MAX_EPOCHS: u64 = 64;
/// Distinct UC anchors (and seals).
pub const MAX_ANCHORS: u64 = 1024;
/// Bytes of the history projection.
pub const MAX_SEMANTIC_BYTES: u64 = 1 << 20;
/// Bytes of the whole witness.
pub const MAX_WITNESS_BYTES: u64 = 16 << 20;
/// Validators per root epoch (the registry's member limit).
pub const MAX_MEMBERS_PER_EPOCH: u64 = 16;
/// Siblings of one RSMT inclusion path.
pub const MAX_RSMT_SIBLINGS: u64 = 32;

const HEADER_WORDS: usize = 16;
const EPOCH_USE_WORDS: usize = 4;

/// `keccak256("unicity.b7.relation.v1")`.
pub fn relation_domain() -> B256 {
    keccak256(b"unicity.b7.relation.v1")
}
/// `keccak256("unicity.seal-registry.v2/epoch-commitment")`, separating `C_e` from every other
/// registry hash.
pub fn commitment_domain() -> B256 {
    keccak256(b"unicity.seal-registry.v2/epoch-commitment")
}
/// `keccak256("unicity.b7.journal.v1")`, the first word of every journal.
pub fn journal_domain() -> B256 {
    keccak256(b"unicity.b7.journal.v1")
}

fn word(v: u64) -> B256 {
    B256::from(U256::from(v))
}

fn keccak_words(words: &[B256]) -> B256 {
    let mut b = Vec::with_capacity(32 * words.len());
    for w in words {
        b.extend_from_slice(w.as_slice());
    }
    keccak256(&b)
}

/// `keccak256(relation domain || the limits as 32-byte words, in declaration order)`.
pub fn relation_id() -> B256 {
    keccak_words(&[
        relation_domain(),
        word(MAX_LEAVES),
        word(MAX_TRANSFERS),
        word(MAX_EPOCHS),
        word(MAX_ANCHORS),
        word(MAX_SEMANTIC_BYTES),
        word(MAX_WITNESS_BYTES),
        word(MAX_MEMBERS_PER_EPOCH),
        word(MAX_RSMT_SIBLINGS),
    ])
}

/// `C_e` over an entry's stored words: `keccak256(commitment domain || genesisCommitment ||
/// profileHash || epoch || metadata words 0-4 and 7-10 || every member's 8 words in order)`. The
/// closure words 5 and 6 (end, hasEnd) are excluded, so `C_e` does not change when the epoch
/// closes.
pub fn epoch_commitment(
    genesis_commitment: B256,
    profile_hash: B256,
    epoch: u64,
    metadata: &[B256; 11],
    members: &[[B256; 8]],
) -> B256 {
    let mut ws = vec![commitment_domain(), genesis_commitment, profile_hash, word(epoch)];
    for (f, w) in metadata.iter().enumerate() {
        if f != 5 && f != 6 {
            ws.push(*w);
        }
    }
    for m in members {
        ws.extend_from_slice(m);
    }
    keccak_words(&ws)
}

/// Any journal that is not the canonical encoding of a valid [`Journal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalMalformed;

impl core::fmt::Display for JournalMalformed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed B7 journal")
    }
}

impl std::error::Error for JournalMalformed {}

/// The kernel result fields the vault consumes (the direct path's `KernelResult` without its
/// leaves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Bridge configuration.
    pub cfg: B256,
    /// Lock nonce.
    pub nonce: U256,
    /// Amount released.
    pub amount: U256,
    /// Locked token ID.
    pub token_id: B256,
    /// Token salt.
    pub salt: B256,
    /// Hash of the first predicate.
    pub first_predicate_hash: B256,
    /// Lock digest.
    pub lock_digest: B256,
    /// Release recipient.
    pub release_to: Address,
    /// Redemption nullifier.
    pub nullifier: B256,
}

/// One root epoch the proven history uses: its cached commitment and the root-round span of the
/// certificates verified under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochUse {
    /// Root epoch.
    pub epoch: u64,
    /// Its cached `C_e`.
    pub commitment: B256,
    /// Lowest root round used.
    pub min_round: u64,
    /// Highest root round used.
    pub max_round: u64,
}

/// The public output of a B7 proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    /// The relation ID: `relation_id()` for this profile.
    pub relation_id: B256,
    /// EVM chain ID.
    pub chain_id: U256,
    /// The registry's `genesisCommitment`.
    pub genesis_commitment: B256,
    /// The registry's `b1.profileHash`.
    pub profile_hash: B256,
    /// Commitment to the private witness.
    pub witness_commitment: B256,
    /// The release the vault consumes.
    pub release: Release,
    /// `1..=MAX_EPOCHS` entries, strictly ascending by epoch.
    pub epochs: Vec<EpochUse>,
}

fn u64_word(w: &[u8]) -> Result<u64, JournalMalformed> {
    if w[..24].iter().any(|b| *b != 0) {
        return Err(JournalMalformed);
    }
    Ok(u64::from_be_bytes(w[24..32].try_into().expect("8 bytes")))
}

impl Journal {
    /// The canonical encoding: 32-byte big-endian words, the 16-word header then four words per
    /// epoch use. Refuses what [`Journal::decode`] refuses.
    pub fn encode(&self) -> Result<Vec<u8>, JournalMalformed> {
        let mut words = vec![
            journal_domain(),
            self.relation_id,
            B256::from(self.chain_id),
            self.genesis_commitment,
            self.profile_hash,
            self.witness_commitment,
            self.release.cfg,
            B256::from(self.release.nonce),
            B256::from(self.release.amount),
            self.release.token_id,
            self.release.salt,
            self.release.first_predicate_hash,
            self.release.lock_digest,
            self.release.release_to.into_word(),
            self.release.nullifier,
            word(self.epochs.len() as u64),
        ];
        for e in &self.epochs {
            words.extend_from_slice(&[
                word(e.epoch),
                e.commitment,
                word(e.min_round),
                word(e.max_round),
            ]);
        }
        let out: Vec<u8> = words.iter().flat_map(|w| w.0).collect();
        Self::decode(&out)?;
        Ok(out)
    }

    /// Accepts exactly the canonical encoding: the domain word; an epoch count in `1..=MAX_EPOCHS`
    /// matching the length, with no trailing bytes; zero high bytes in the address and every
    /// `u64` field; epochs strictly ascending; `min_round <= max_round`.
    pub fn decode(b: &[u8]) -> Result<Self, JournalMalformed> {
        if b.len() < 32 * HEADER_WORDS || !b.len().is_multiple_of(32) {
            return Err(JournalMalformed);
        }
        let w = |i: usize| &b[32 * i..32 * i + 32];
        let b256 = |i: usize| B256::from_slice(w(i));
        if b256(0) != journal_domain() {
            return Err(JournalMalformed);
        }
        let n = u64_word(w(15))?;
        if n == 0 ||
            n > MAX_EPOCHS ||
            b.len() as u64 != 32 * (HEADER_WORDS as u64 + EPOCH_USE_WORDS as u64 * n)
        {
            return Err(JournalMalformed);
        }
        if w(13)[..12].iter().any(|c| *c != 0) {
            return Err(JournalMalformed);
        }
        let mut epochs: Vec<EpochUse> = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let base = HEADER_WORDS + i * EPOCH_USE_WORDS;
            let u = EpochUse {
                epoch: u64_word(w(base))?,
                commitment: b256(base + 1),
                min_round: u64_word(w(base + 2))?,
                max_round: u64_word(w(base + 3))?,
            };
            if u.min_round > u.max_round || epochs.last().is_some_and(|p| u.epoch <= p.epoch) {
                return Err(JournalMalformed);
            }
            epochs.push(u);
        }
        Ok(Self {
            relation_id: b256(1),
            chain_id: U256::from_be_slice(w(2)),
            genesis_commitment: b256(3),
            profile_hash: b256(4),
            witness_commitment: b256(5),
            release: Release {
                cfg: b256(6),
                nonce: U256::from_be_slice(w(7)),
                amount: U256::from_be_slice(w(8)),
                token_id: b256(9),
                salt: b256(10),
                first_predicate_hash: b256(11),
                lock_digest: b256(12),
                release_to: Address::from_slice(&w(13)[12..]),
                nullifier: b256(14),
            },
            epochs,
        })
    }
}
