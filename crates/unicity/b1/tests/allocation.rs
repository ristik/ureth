//! Verify that complete admission scanning never allocates before its full debit.
use alloy_primitives::U256;
use reth_unicity_b1::{run, Error, Operation, RegistryRead};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! {static TRACK:Cell<bool>=const{Cell::new(false)};static ALLOCS:Cell<usize>=const{Cell::new(0)};}
struct Counting;
// SAFETY: Every allocation/deallocation is forwarded to System with its exact
// original pointer/layout. Per-thread counters do not own or change allocations.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        }
        // SAFETY: Forward the caller's valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Forward the original allocation pointer and layout unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct NeverRead;
impl RegistryRead for NeverRead {
    type Error = ();
    fn sload(&mut self, _: U256) -> Result<U256, ()> {
        panic!("read before full debit")
    }
}
#[test]
fn complete_scan_has_zero_allocations_before_second_debit() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("testdata/go-4ba487e.json")).unwrap();
    for id in [
        "cert.single.ok",
        "cert.shared.max-8.ok",
        "quorum.max.all",
        "paths.shard-depth-256.ok",
        "rsmt.depth-256.ok",
    ] {
        let v = manifest["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
        let raw = v["request"].as_str().unwrap();
        let input: Vec<u8> = raw
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let op = match v["op"].as_str().unwrap() {
            "UC_V1" => Operation::Uc,
            "SHARED_SEAL_V1" => Operation::Shared,
            _ => Operation::Member,
        };
        let gas = v["expected"]["gas"].as_u64().unwrap() - 1;
        ALLOCS.with(|c| c.set(0));
        TRACK.with(|c| c.set(true));
        let result = run(op, &input, gas, &mut NeverRead);
        TRACK.with(|c| c.set(false));
        let allocs = ALLOCS.with(Cell::get);
        assert_eq!(result, Err(Error::OutOfGas), "{id}");
        assert_eq!(allocs, 0, "{id}");
    }
}
