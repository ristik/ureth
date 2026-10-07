//! Independent Rust construction compared byte-for-byte with the pinned Go oracle.
mod common;
use common::*;

#[test]
fn independent_cfg_and_histories_equal_go_bytes() {
    let f = Fixture::new();
    let go: serde_json::Value =
        serde_json::from_str(include_str!("testdata/go-9136c661.json")).unwrap();
    assert_eq!(hex(&f.cfg), go["fixtures"][0]["cfg"]);
    for count in [0, 1, 2, 16] {
        let id = format!("return-valid-{count}");
        let v = go["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
        let payload = f.history(5, &[0x3b, 0x9a, 0xca, 7], Some(count));
        assert_eq!(hex(&payload), v["input"], "{id}");
        let out = reth_unicity_b2::run(&abi(2, &f.cfg, &payload), u64::MAX).unwrap();
        assert_eq!(out.reason, None);
        assert_eq!(out.bytes.len(), 448 + 64 * (count + 2));
    }
    let built = vectors();
    assert_eq!(built["vectors"].as_array().unwrap().len(), 34);
    for vector in built["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let expected = match id {
            "prepare-zero-nonce" | "prepare-zero-amount" => "ErrLockInput",
            "return-no-burn" => "ErrNoTransfers",
            "mint-transfers" => "ErrHasTransfers",
            "return-65-transfers" => "ErrTooManyTx",
            "high-recovery-2-flipped" | "high-recovery-3-flipped" => "ErrUnlockKey",
            _ => "",
        };
        assert_eq!(vector["reason"], expected, "{id}");
    }
}
