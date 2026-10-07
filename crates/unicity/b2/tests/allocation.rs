//! Both gas debits happen before any allocation or cryptographic construction.
mod common;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! { static TRACK: Cell<bool> = const { Cell::new(false) }; static COUNT: Cell<usize> = const { Cell::new(0) }; }
struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        TRACK.with(|t| {
            if t.get() {
                COUNT.with(|n| n.set(n.get() + 1));
            }
        });
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        TRACK.with(|t| {
            if t.get() {
                COUNT.with(|n| n.set(n.get() + 1));
            }
        });
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;
#[test]
fn both_debits_are_allocation_free() {
    let f = common::Fixture::new();
    let history = f.history(5, &[1], Some(63));
    let input = common::abi(2, &f.cfg, &history);
    let full = 26000 + 16 * input.len() as u64 + 13000 * 65;
    for gas in [20000 + 16 * input.len() as u64 - 1, full - 1] {
        COUNT.with(|n| n.set(0));
        TRACK.with(|t| t.set(true));
        let result = reth_unicity_b2::run(&input, gas);
        TRACK.with(|t| t.set(false));
        assert_eq!(result, Err(reth_unicity_b2::Error::OutOfGas));
        assert_eq!(COUNT.with(Cell::get), 0);
    }
    // Exercise the same fixture generator under the ordinary allocator as well.
    assert_eq!(common::vectors()["vectors"].as_array().unwrap().len(), 34);
}
