//! The durable MDBX-backed companion store.
//!
//! The store owns its own MDBX environment; it never borrows reth's. It keeps three named
//! databases inside that environment:
//!
//! - `companions`: `block_hash -> stored value`, the primary keyspace;
//! - `by_number`: `block_number || block_hash -> ()`, an ordered index that lets
//!   [`CompanionStore::prune_below`] range-scan the pruned prefix instead of walking every record;
//! - `meta`: the published retention horizon.
//!
//! The stored value is the block number as eight big-endian bytes followed by the versioned record
//! from [`crate::encoding`]. Keeping the number next to the record is what lets
//! [`CompanionStore::remove`] find and drop the matching `by_number` entry without a reverse scan.
//!
//! Every mutating operation runs in one read-write transaction and then forces an environment
//! sync before returning, so a write is durable on return and a reopen in a fresh process observes
//! it. A single transaction also makes [`CompanionStore::prune_below`] atomic: the removals and
//! the raised horizon become visible together or not at all.

use std::path::Path;

use alloy_primitives::B256;
use reth_libmdbx::{
    Database, DatabaseFlags, Environment, Geometry, Transaction, TransactionKind, WriteFlags,
};
use reth_unicity_execution::wire::SealCompanion;

use crate::{
    accounting::{decode as decode_accounting, encode as encode_accounting, StoredAccounting},
    encoding::{decode, encode},
    StoreError,
};

/// Name of the primary keyspace.
const COMPANIONS: &str = "companions";

/// Name of the block-number index keyspace.
const BY_NUMBER: &str = "by_number";

/// Name of the metadata keyspace.
const META: &str = "meta";

const ACCOUNTING: &str = "accounting";
const ACCOUNTING_BY_NUMBER: &str = "accounting_by_number";

/// Key under which the retention horizon is stored in `meta`.
const HORIZON_KEY: &[u8] = b"horizon";

/// Key under which the eviction cursor is stored in `meta`.
const EVICTION_CURSOR_KEY: &[u8] = b"eviction_cursor";

/// Length of a block hash in bytes.
const HASH_LEN: usize = 32;

/// Length of an encoded block number in bytes.
const NUMBER_LEN: usize = 8;

/// Length of one `by_number` index key: the number followed by the hash.
const INDEX_KEY_LEN: usize = NUMBER_LEN + HASH_LEN;

/// Number of named databases the store opens.
const NAMED_DATABASES: usize = 5;

/// Upper bound of the memory map this store's environment may grow to.
///
/// The companion set is small next to reth's own databases, so four gibibytes is a generous
/// ceiling that still keeps the environment from trying to reserve an enormous address range.
const MAX_MAP_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// The three outcomes of a companion lookup.
///
/// The distinction between [`Self::Unavailable`] and [`Self::Unknown`] is deliberate and is
/// documented on each variant. Neither is a verdict on the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The companion is present and is byte-identical to what was stored.
    Found(SealCompanion),
    /// This node cannot produce the companion and has published a retention horizon.
    ///
    /// The horizon is the node's retention boundary, not a claim about this block's number.
    /// Because the store keeps no tombstones, this variant covers both a block that was pruned
    /// and a hash the node never recorded, so a caller cannot infer from it that the block is
    /// below the horizon. See the crate docs for that trade-off.
    ///
    /// The horizon accompanies the answer. A node with no horizon never returns this variant.
    Unavailable {
        /// The node's published retention boundary: pruning removes the companions with a block
        /// number below this number. A companion at this number was not dropped by pruning.
        horizon: u64,
    },
    /// This node has no record of the block hash, and has never published a horizon.
    ///
    /// This is only reachable on a node that has never pruned. Once
    /// [`CompanionStore::set_horizon`] or [`CompanionStore::prune_below`] has run, an absent
    /// hash answers [`Self::Unavailable`] instead, because without tombstones the store cannot
    /// tell a pruned hash from one it never saw.
    ///
    /// Per D2 this is explicitly **not** a statement about the block's validity or certification.
    /// A missing companion never un-certifies a block; it means only that this node cannot produce
    /// the companion right now.
    Unknown,
}

/// A durable, block-hash-keyed store for [`SealCompanion`] values.
///
/// The store is told what to keep and what to drop. It has no notion of canonicality and never
/// inspects the chain; [`Self::remove`] exists for the caller that has decided an entry is no
/// longer canonical, and [`Self::prune_below`] exists for the caller that has decided a number is
/// now historical.
#[derive(Debug)]
pub struct CompanionStore {
    companions: Database,
    by_number: Database,
    accounting: Database,
    accounting_by_number: Database,
    meta: Database,
    env: Environment,
}

/// Opens or creates a companion store at `path`.
///
/// The directory is created if it does not exist. The environment is the store's own; no reth
/// environment is touched. Dropping the returned value closes it, and a later [`open`] on the same
/// path observes every write that returned successfully.
pub fn open(path: impl AsRef<Path>) -> Result<CompanionStore, StoreError> {
    let path = path.as_ref();
    std::fs::create_dir_all(path)?;

    let mut builder = Environment::builder();
    builder.set_max_dbs(NAMED_DATABASES);
    builder.set_geometry(Geometry { size: Some(0..MAX_MAP_SIZE), ..Default::default() });
    let env = builder.open(path)?;

    let txn = env.begin_rw_txn()?;
    let companions = txn.create_db(Some(COMPANIONS), DatabaseFlags::empty())?;
    let by_number = txn.create_db(Some(BY_NUMBER), DatabaseFlags::empty())?;
    let meta = txn.create_db(Some(META), DatabaseFlags::empty())?;
    let accounting = txn.create_db(Some(ACCOUNTING), DatabaseFlags::empty())?;
    let accounting_by_number = txn.create_db(Some(ACCOUNTING_BY_NUMBER), DatabaseFlags::empty())?;
    txn.commit()?;

    Ok(CompanionStore { companions, by_number, accounting, accounting_by_number, meta, env })
}

impl CompanionStore {
    /// Durably records a locally completed block before it is advertised to the engine or caller.
    pub fn put_accounting(&self, record: StoredAccounting) -> Result<(), StoreError> {
        let hash = record.accounting.block_hash;
        let value = encode_accounting(record);
        let txn = self.env.begin_rw_txn()?;
        if let Some(old) = txn.get::<Vec<u8>>(self.accounting.dbi(), hash.as_slice())? {
            let old = decode_accounting(&old)?;
            if old != record {
                return Err(StoreError::Corrupt("conflicting accounting for block hash"));
            }
        }
        txn.put(self.accounting.dbi(), hash.as_slice(), &value, WriteFlags::empty())?;
        txn.put(
            self.accounting_by_number.dbi(),
            index_key(record.block_number, &hash),
            [],
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Reads one accounting record without assigning canonical status to its hash.
    pub fn get_accounting(&self, hash: B256) -> Result<Option<StoredAccounting>, StoreError> {
        let txn = self.env.begin_ro_txn()?;
        txn.get::<Vec<u8>>(self.accounting.dbi(), hash.as_slice())?
            .map(|bytes| {
                let record = decode_accounting(&bytes)?;
                if record.accounting.block_hash != hash {
                    return Err(StoreError::Corrupt("accounting key/hash mismatch"));
                }
                Ok(record)
            })
            .transpose()
    }

    /// Prunes accounting independently of the companion retention horizon.
    pub fn prune_accounting_below(&self, number: u64) -> Result<(), StoreError> {
        let txn = self.env.begin_rw_txn()?;
        {
            let mut cursor = txn.cursor(self.accounting_by_number.dbi())?;
            let mut entry = cursor.first::<Vec<u8>, ()>()?;
            while let Some((key, ())) = entry {
                if key.len() != INDEX_KEY_LEN {
                    return Err(StoreError::Corrupt("accounting index key length"));
                }
                let block_number = u64::from_be_bytes(key[..NUMBER_LEN].try_into().unwrap());
                if block_number >= number {
                    break;
                }
                txn.del(self.accounting.dbi(), &key[NUMBER_LEN..], None)?;
                cursor.del(WriteFlags::empty())?;
                entry = cursor.next::<Vec<u8>, ()>()?;
            }
        }
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Stores `companion` under `block_hash`, indexed by `block_number`.
    ///
    /// The write is durable when the call returns: the transaction commits and the environment is
    /// synced before the result is produced. Re-putting a hash moves its block-number index entry
    /// if the number changed, so the index never points at a stale number.
    pub fn put(
        &self,
        block_hash: B256,
        block_number: u64,
        companion: &SealCompanion,
    ) -> Result<(), StoreError> {
        let record = encode(companion)?;

        let mut value = Vec::with_capacity(NUMBER_LEN + record.len());
        value.extend_from_slice(&block_number.to_be_bytes());
        value.extend_from_slice(&record);

        let txn = self.env.begin_rw_txn()?;

        // A block hash names one block, so a re-put should carry the same number. If it does not,
        // drop the old index entry first so no stale `by_number` key survives.
        if let Some(existing) = txn.get::<Vec<u8>>(self.companions.dbi(), block_hash.as_slice())? {
            let old_number = stored_number(&existing)?;
            if old_number != block_number {
                txn.del(self.by_number.dbi(), index_key(old_number, &block_hash), None)?;
            }
        }

        txn.put(self.companions.dbi(), block_hash.as_slice(), &value, WriteFlags::empty())?;
        txn.put(
            self.by_number.dbi(),
            index_key(block_number, &block_hash),
            [],
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Looks up the companion for `block_hash`.
    ///
    /// See [`Lookup`] for what each outcome means. A `Found` companion is decoded from exactly the
    /// bytes that [`Self::put`] wrote.
    pub fn get(&self, block_hash: B256) -> Result<Lookup, StoreError> {
        let txn = self.env.begin_ro_txn()?;

        if let Some(value) = txn.get::<Vec<u8>>(self.companions.dbi(), block_hash.as_slice())? {
            let record = stored_record(&value)?;
            return Ok(Lookup::Found(decode(record)?));
        }

        match read_meta_number(&txn, &self.meta, HORIZON_KEY)? {
            Some(horizon) => Ok(Lookup::Unavailable { horizon }),
            None => Ok(Lookup::Unknown),
        }
    }

    /// Drops the entry for `block_hash` without touching the horizon.
    ///
    /// This is the non-canonical case: the caller has decided this hash is no longer one it will
    /// serve. It is idempotent, and it does not affect any other key.
    pub fn remove(&self, block_hash: B256) -> Result<(), StoreError> {
        let txn = self.env.begin_rw_txn()?;

        if let Some(existing) = txn.get::<Vec<u8>>(self.companions.dbi(), block_hash.as_slice())? {
            let number = stored_number(&existing)?;
            txn.del(self.companions.dbi(), block_hash.as_slice(), None)?;
            txn.del(self.by_number.dbi(), index_key(number, &block_hash), None)?;
        }

        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Returns the `(block_hash, block_number)` pairs whose number lies in the half-open range
    /// `from..to`.
    ///
    /// `from` is included and `to` is excluded, matching [`Self::prune_below`]'s exclusive
    /// boundary. The read walks only the `by_number` index keys inside the range, so the caller
    /// bounds the cost by choosing the range; there is deliberately no way to ask for every entry.
    /// A caller that wants the whole index has to say so by name and accept the cost.
    ///
    /// The returned pairs are ordered by `(block_number, block_hash)`, the `by_number` key order.
    pub fn entries_in_range(&self, from: u64, to: u64) -> Result<Vec<(B256, u64)>, StoreError> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.cursor(self.by_number.dbi())?;
        // The first key not below `from`. Every key starts with the big-endian number, so an
        // eight-byte prefix positions the cursor at the first entry whose number is at least
        // `from`.
        let mut entry = cursor.set_range::<Vec<u8>, ()>(&from.to_be_bytes())?;
        let mut entries = Vec::new();
        while let Some((key, ())) = entry {
            if key.len() != INDEX_KEY_LEN {
                return Err(StoreError::Corrupt("index key has the wrong length"));
            }
            let mut raw = [0u8; NUMBER_LEN];
            raw.copy_from_slice(&key[..NUMBER_LEN]);
            let number = u64::from_be_bytes(raw);
            if number >= to {
                break;
            }
            entries.push((B256::from_slice(&key[NUMBER_LEN..]), number));
            entry = cursor.next::<Vec<u8>, ()>()?;
        }
        Ok(entries)
    }

    /// Removes every entry with `block_number < number`, then raises the horizon to `number`.
    ///
    /// The removals happen before the horizon write, inside one read-write transaction. MDBX makes
    /// that transaction atomic, so a crash can never publish a horizon that covers an entry which
    /// is still present: either the removals and the horizon both land, or neither does. The
    /// ordering is kept explicit anyway, because a future implementation that splits the two
    /// operations must preserve it to avoid advertising a horizon that runs ahead of its data.
    ///
    /// The horizon itself is monotonic. If the requested number is below one already published,
    /// the removals still run for any entry below it that somehow remains, but the horizon stays
    /// where it was rather than moving backwards.
    pub fn prune_below(&self, number: u64) -> Result<(), StoreError> {
        let txn = self.env.begin_rw_txn()?;

        let current = read_meta_number(&txn, &self.meta, HORIZON_KEY)?;
        let target = current.map_or(number, |current| current.max(number));

        {
            let mut cursor = txn.cursor(self.by_number.dbi())?;
            let mut entry = cursor.first::<Vec<u8>, ()>()?;
            while let Some((key, ())) = entry {
                if key.len() != INDEX_KEY_LEN {
                    return Err(StoreError::Corrupt("index key has the wrong length"));
                }
                let mut raw = [0u8; NUMBER_LEN];
                raw.copy_from_slice(&key[..NUMBER_LEN]);
                if u64::from_be_bytes(raw) >= number {
                    break;
                }
                let hash = &key[NUMBER_LEN..];
                txn.del(self.companions.dbi(), hash, None)?;
                cursor.del(WriteFlags::empty())?;
                entry = cursor.next::<Vec<u8>, ()>()?;
            }
        }

        txn.put(self.meta.dbi(), HORIZON_KEY, target.to_be_bytes(), WriteFlags::empty())?;
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Publishes a new retention horizon.
    ///
    /// The horizon is durable and monotonic. A number below the published horizon is refused with
    /// [`StoreError::HorizonRegression`], never silently ignored or clamped. An equal number is
    /// accepted and is a no-op.
    ///
    /// [`Self::prune_below`] is deliberately asymmetric: it is an idempotent "ensure nothing below
    /// `n` remains" and keeps the current horizon when called with an older number, so only this
    /// method reports a backwards move as an error.
    pub fn set_horizon(&self, number: u64) -> Result<(), StoreError> {
        let txn = self.env.begin_rw_txn()?;

        if let Some(current) =
            read_meta_number(&txn, &self.meta, HORIZON_KEY)?.filter(|current| number < *current)
        {
            return Err(StoreError::HorizonRegression { current, requested: number });
        }

        txn.put(self.meta.dbi(), HORIZON_KEY, number.to_be_bytes(), WriteFlags::empty())?;
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }

    /// Returns the published retention horizon, or `None` when the node has never pruned.
    pub fn horizon(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.env.begin_ro_txn()?;
        read_meta_number(&txn, &self.meta, HORIZON_KEY)
    }

    /// Returns the durable eviction cursor: the next block number an eviction pass should read.
    ///
    /// This is bookkeeping the caller keeps beside the horizon so a restart resumes instead of
    /// rescanning the chain. The store only stores the number and never interprets it; it has no
    /// notion of canonicality or eviction.
    pub fn eviction_cursor(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.env.begin_ro_txn()?;
        read_meta_number(&txn, &self.meta, EVICTION_CURSOR_KEY)
    }

    /// Persists the eviction cursor, never moving it backwards.
    ///
    /// The cursor is monotonic for the same reason the horizon is: the caller only advances it over
    /// numbers that finality has settled, so a lower value would only cause needless rescans. A
    /// lower request is clamped to the published value rather than refused, matching
    /// [`Self::prune_below`].
    pub fn set_eviction_cursor(&self, number: u64) -> Result<(), StoreError> {
        let txn = self.env.begin_rw_txn()?;

        let current = read_meta_number(&txn, &self.meta, EVICTION_CURSOR_KEY)?;
        let target = current.map_or(number, |current| current.max(number));

        txn.put(self.meta.dbi(), EVICTION_CURSOR_KEY, target.to_be_bytes(), WriteFlags::empty())?;
        txn.commit()?;
        self.env.sync(true)?;
        Ok(())
    }
}

/// Builds the `by_number` index key for one number and hash.
fn index_key(number: u64, hash: &B256) -> [u8; INDEX_KEY_LEN] {
    let mut key = [0u8; INDEX_KEY_LEN];
    key[..NUMBER_LEN].copy_from_slice(&number.to_be_bytes());
    key[NUMBER_LEN..].copy_from_slice(hash.as_slice());
    key
}

/// Reads the block number that precedes the record in a stored value.
fn stored_number(value: &[u8]) -> Result<u64, StoreError> {
    let raw: [u8; NUMBER_LEN] = value
        .get(..NUMBER_LEN)
        .ok_or(StoreError::Corrupt("stored value has no block number"))?
        .try_into()
        .map_err(|_| StoreError::Corrupt("stored value has a malformed block number"))?;
    Ok(u64::from_be_bytes(raw))
}

/// Returns the record that follows the block number in a stored value.
fn stored_record(value: &[u8]) -> Result<&[u8], StoreError> {
    value.get(NUMBER_LEN..).ok_or(StoreError::Corrupt("stored value has no record"))
}

/// Reads an eight-byte big-endian number stored under `key` in the metadata keyspace.
fn read_meta_number<K: TransactionKind>(
    txn: &Transaction<K>,
    meta: &Database,
    key: &[u8],
) -> Result<Option<u64>, StoreError> {
    match txn.get::<Vec<u8>>(meta.dbi(), key)? {
        None => Ok(None),
        Some(bytes) => {
            let raw: [u8; NUMBER_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("metadata number is not eight bytes"))?;
            Ok(Some(u64::from_be_bytes(raw)))
        }
    }
}
