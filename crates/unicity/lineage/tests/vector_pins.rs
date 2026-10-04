//! The vector files copied from bft-core are pinned by SHA-256 to the bytes at the commits under
//! review, so a change on the Go side (or a stray edit here) fails this suite instead of silently
//! moving the target.

mod support;

use support::{hex, sha256, testdata};

/// `q3format/testdata/vectors.json` at bft-core #407 `767cb360d4f157af5a906d3c2e8d3b48ad9acd88`.
const Q3FORMAT_VECTORS: &str = "b5302754686d4aa9ca29fddb3b139517f4e741d2d220b0bfb266eae6ff29a103";
/// `network/protocol/abdrc/testdata/domain_bound_vectors.json`, identical at merged #394 `e33070b6`
/// and at #407.
const DOMAIN_BOUND_VECTORS: &str =
    "e2191022b67485b9c023e28f235ba5fca362e2d031e2f0286280fcd35bfa36e5";

#[test]
fn copied_go_vector_files_are_the_pinned_bytes() {
    for (file, pin) in [
        ("q3format-vectors.json", Q3FORMAT_VECTORS),
        ("domain_bound_vectors.json", DOMAIN_BOUND_VECTORS),
    ] {
        assert_eq!(hex(&sha256(testdata(file).as_bytes())), pin, "{file}");
    }
}
