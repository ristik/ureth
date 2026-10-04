//! The vector files copied from bft-core are pinned by SHA-256 to the bytes at the commits under
//! review, so a change on the Go side (or a stray edit here) fails this suite instead of silently
//! moving the target.

mod support;

use support::{hex, sha256, testdata};

/// `q3format/testdata/vectors.json` at the head of bft-core #407, `d36d3611`. #407 (B2) is not
/// merged: the merged B1 file at #406 is
/// `0b526fee0b16b3f9eace1b31dd5482e4589befc5e951b71f51129d8ec6e3084a` and lacks the envelope field.
/// Re-pin once #407 merges.
const Q3FORMAT_VECTORS: &str = "b5302754686d4aa9ca29fddb3b139517f4e741d2d220b0bfb266eae6ff29a103";
/// `network/protocol/abdrc/testdata/domain_bound_vectors.json` at merged #406
/// `c82cc8266390357b1166913b59269e063cce37d8` (nine vectors, including #396's two paired quorum
/// certificates); identical at the #407 head.
const DOMAIN_BOUND_VECTORS: &str =
    "3f913e56c6976f36ef1cce216a50d0c3658a5db44a5f28046786ca4f21ee40c2";

#[test]
fn copied_go_vector_files_are_the_pinned_bytes() {
    for (file, pin) in [
        ("q3format-vectors.json", Q3FORMAT_VECTORS),
        ("domain_bound_vectors.json", DOMAIN_BOUND_VECTORS),
    ] {
        assert_eq!(hex(&sha256(testdata(file).as_bytes())), pin, "{file}");
    }
}
