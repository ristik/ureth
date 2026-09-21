//! Behaviour tests for the durable companion store.

use alloy_primitives::{Bytes, B256};
use reth_unicity_execution::wire::SealCompanion;
use reth_unicity_store::{open, CompanionStore, Lookup, StoreError};
use tempfile::tempdir;

/// A companion whose fields all differ per `tag`, so a mix-up is visible.
fn companion(tag: u8) -> SealCompanion {
    SealCompanion {
        root_input: Bytes::from(vec![tag; 32]),
        witnesses: vec![Bytes::from(vec![tag; 7]), Bytes::from(vec![tag; 3])],
        provenance: format!("test-{tag}"),
    }
}

/// A block hash that is distinct per `tag`.
const fn hash(tag: u8) -> B256 {
    B256::repeat_byte(tag)
}

/// An open store in a fresh temporary directory.
fn store() -> (tempfile::TempDir, CompanionStore) {
    let dir = tempdir().unwrap();
    let store = open(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn a_written_companion_survives_a_reopen_unchanged() {
    let dir = tempdir().unwrap();
    let value = companion(0x11);

    // Byte stability of the stored record is proven by `encode_of_decode_returns_the_same_bytes`
    // in the encoding module. This test proves that a full close and reopen changes no field.
    // The store is dropped at the end of this block, closing the environment.
    {
        let store = open(dir.path()).unwrap();
        store.put(hash(0x11), 7, &value).unwrap();
    }

    let reopened = open(dir.path()).unwrap();
    match reopened.get(hash(0x11)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, value),
        other => panic!("expected the companion back after reopen, got {other:?}"),
    }
}

#[test]
fn a_store_without_a_horizon_answers_unknown_for_an_unseen_hash() {
    let (_dir, store) = store();

    assert_eq!(store.horizon().unwrap(), None);
    match store.get(hash(0x01)).unwrap() {
        Lookup::Unknown => {}
        other => panic!("expected Unknown on a full node, got {other:?}"),
    }
}

#[test]
fn pruning_below_a_horizon_reports_unavailable_and_keeps_the_boundary() {
    let (_dir, store) = store();

    let below = companion(0x02);
    let at = companion(0x03);
    let above = companion(0x04);
    store.put(hash(0x02), 2, &below).unwrap();
    store.put(hash(0x03), 3, &at).unwrap();
    store.put(hash(0x04), 5, &above).unwrap();

    store.prune_below(3).unwrap();

    assert_eq!(store.horizon().unwrap(), Some(3));
    match store.get(hash(0x02)).unwrap() {
        Lookup::Unavailable { horizon } => assert_eq!(horizon, 3),
        other => panic!("expected the pruned entry to be Unavailable, got {other:?}"),
    }
    // The boundary is exclusive: a block at the horizon number is retained.
    match store.get(hash(0x03)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, at),
        other => panic!("expected the boundary block to be retained, got {other:?}"),
    }
    match store.get(hash(0x04)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, above),
        other => panic!("expected the block above the boundary to be retained, got {other:?}"),
    }
    // Without tombstones, a hash the node never saw also answers Unavailable once a horizon
    // exists. This records the documented trade-off rather than pretending it does not happen.
    match store.get(hash(0x09)).unwrap() {
        Lookup::Unavailable { horizon } => assert_eq!(horizon, 3),
        other => {
            panic!("expected Unavailable for an unseen hash once a horizon exists, got {other:?}")
        }
    }
}

#[test]
fn the_horizon_and_a_pruned_entry_survive_a_reopen() {
    let dir = tempdir().unwrap();
    let value = companion(0x07);
    {
        let store = open(dir.path()).unwrap();
        store.put(hash(0x07), 2, &value).unwrap();
        store.prune_below(3).unwrap();
    }

    let store = open(dir.path()).unwrap();
    assert_eq!(store.horizon().unwrap(), Some(3));
    match store.get(hash(0x07)).unwrap() {
        Lookup::Unavailable { horizon } => assert_eq!(horizon, 3),
        other => panic!("expected the pruned entry to stay pruned after reopen, got {other:?}"),
    }
}

#[test]
fn the_horizon_refuses_to_move_backwards() {
    let (_dir, store) = store();

    store.set_horizon(10).unwrap();
    match store.set_horizon(9) {
        Err(StoreError::HorizonRegression { current, requested }) => {
            assert_eq!(current, 10);
            assert_eq!(requested, 9);
        }
        other => panic!("expected HorizonRegression, got {other:?}"),
    }

    // The refused write must not have taken effect, and re-publishing the same number is allowed.
    assert_eq!(store.horizon().unwrap(), Some(10));
    store.set_horizon(10).unwrap();
    assert_eq!(store.horizon().unwrap(), Some(10));
}

#[test]
fn remove_drops_only_the_named_key_and_does_not_touch_the_horizon() {
    let (_dir, store) = store();

    let first = companion(0x05);
    let second = companion(0x06);
    store.put(hash(0x05), 5, &first).unwrap();
    store.put(hash(0x06), 6, &second).unwrap();

    store.remove(hash(0x05)).unwrap();

    // With no horizon, a removed key is unknown: it was dropped as non-canonical, not pruned.
    match store.get(hash(0x05)).unwrap() {
        Lookup::Unknown => {}
        other => panic!("a removed key must report Unknown while no horizon exists, got {other:?}"),
    }
    match store.get(hash(0x06)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, second),
        other => panic!("remove must not affect another key, got {other:?}"),
    }
    assert_eq!(store.horizon().unwrap(), None);
    // Removing the same key again is idempotent.
    store.remove(hash(0x05)).unwrap();
}

#[test]
fn remove_after_a_horizon_exists_reports_unavailable_like_any_absent_hash() {
    let (_dir, store) = store();

    let value = companion(0x0a);
    store.put(hash(0x0a), 4, &value).unwrap();
    store.set_horizon(2).unwrap();

    store.remove(hash(0x0a)).unwrap();

    // The no-tombstone trade-off applies to removal too: once a horizon is published the store
    // cannot tell a removed hash from a pruned one, so it answers Unavailable.
    match store.get(hash(0x0a)).unwrap() {
        Lookup::Unavailable { horizon } => assert_eq!(horizon, 2),
        other => panic!("expected Unavailable once a horizon exists, got {other:?}"),
    }
}

#[test]
fn re_putting_a_hash_moves_its_block_number_index() {
    let (_dir, store) = store();

    let first = companion(0x08);
    let second = companion(0x18);
    store.put(hash(0x08), 4, &first).unwrap();
    store.put(hash(0x08), 6, &second).unwrap();

    // A stale index entry at number 4 would make this prune delete the hash; the current number is
    // 6, so the entry must survive.
    store.prune_below(5).unwrap();

    match store.get(hash(0x08)).unwrap() {
        Lookup::Found(found) => assert_eq!(found, second),
        other => panic!("expected the re-put companion to survive prune_below(5), got {other:?}"),
    }
}

#[test]
fn prune_below_walks_the_whole_prefix_and_stops_at_the_boundary() {
    let (_dir, store) = store();

    // Insert out of number order so the store cannot rely on insertion order.
    for number in [9u64, 0, 7, 2, 5, 1, 8, 3, 6, 4] {
        store.put(hash(number as u8), number, &companion(number as u8)).unwrap();
    }

    store.prune_below(6).unwrap();

    for number in 0..6u64 {
        match store.get(hash(number as u8)).unwrap() {
            Lookup::Unavailable { horizon } => assert_eq!(horizon, 6),
            other => panic!("block {number} should be pruned, got {other:?}"),
        }
    }
    for number in 6..10u64 {
        match store.get(hash(number as u8)).unwrap() {
            Lookup::Found(found) => assert_eq!(found, companion(number as u8)),
            other => panic!("block {number} should be retained, got {other:?}"),
        }
    }
}

#[test]
fn a_backwards_prune_below_does_not_lower_the_horizon() {
    let (_dir, store) = store();

    store.set_horizon(10).unwrap();
    store.prune_below(4).unwrap();

    assert_eq!(store.horizon().unwrap(), Some(10));
}

#[test]
fn open_creates_a_missing_directory() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("a").join("b");

    let store = open(&nested).unwrap();
    assert_eq!(store.horizon().unwrap(), None);
    assert!(nested.is_dir());
}
