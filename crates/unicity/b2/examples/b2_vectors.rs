//! Emit independently constructed inputs and native outputs for the pinned Go
//! checker; the generator constructs rather than reads golden fixture bytes.
#[path = "../tests/common/mod.rs"]
mod common;
fn main() {
    println!("{}", serde_json::to_string_pretty(&common::vectors()).unwrap());
}
