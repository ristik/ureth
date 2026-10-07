//! Independently generated native bytes cross-checked against the Go pin.
#[allow(dead_code)]
#[path = "../examples/vectors.rs"]
mod generator;
use serde_json::Value;
#[test]
fn independent_rust_bytes_signatures_gas_and_prestate_match_go() {
    let generated = generator::generate();
    let oracle: Value = serde_json::from_str(include_str!("testdata/go-4ba487e.json")).unwrap();
    for v in generated["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let go = oracle["vectors"].as_array().unwrap().iter().find(|g| g["id"] == id);
        let Some(go) = go else {
            assert!(id.starts_with("rust."));
            continue;
        };
        for field in ["request", "preState", "sealSigBytes", "sealDigest"] {
            if !go[field].is_null() && !v[field].is_null() {
                assert_eq!(v[field], go[field], "{id}: {field}");
            }
        }
        for field in ["status", "valid", "output", "gas"] {
            if !v["expected"][field].is_null() {
                assert_eq!(v["expected"][field], go["expected"][field], "{id}: {field}");
            }
        }
    }
}
