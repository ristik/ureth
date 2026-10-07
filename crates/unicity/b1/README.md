# Inactive B1 native kernel/provider

Implements the native caller slice of B1 A′ from `b1-design-v4.md`
(SHA256 `e94c681529201bce9c945809f6154a99252f208b958f9f1d3889eb37d61e0713`).
The byte/oracle pin is bft-core PR #416,
`4ba487e4b9141ff17466ffa31d8deab540dae02f`; native bft-go-base is
`01ab63a83bf5`, and rugregator's RSMT reference is
`696de8dc62fea8f2509168bf24a7c891f7b533d7`.

No production crate depends on this crate and no production factory installs
its provider. Addresses are UC `0x0100`, shared seal `0x0101`, RSMT `0x0102`;
S1 `0x0103` stays outside this implementation. Fixtures use Cancun. Later
Ethereum specs already assign `0x0100` to P256: activation must resolve that
profile/address conflict without replacing an Ethereum builtin. Merely
constructing `B1Precompile` or converting it with `into_dyn` installs nothing.

The single claims-only ABI has no caller authority view. A bounded borrowed
CBOR scan enforces canonical heads, map ordering/uniqueness, native tags and
arities, null distinctions, UTF-8, depth/tokens and all field/resource bounds.
It preserves complete tagged IR/seal bytes, computes the native CBOR-aware
shard/IMT folds, and verifies every named low-s secp256k1 signature over exactly
SHA256(native Seal.SigBytes). Weighted quorum is `total-(total-1)/3`; unknown
or invalid extra signatures fail even after quorum. RSMT proves membership
under the supplied root and provides no authentication of that root.

`run` checks the outer cap and reserves base+16*bytes before scanning. It
reserves the full candidate charge before storage reads, member allocation,
point parsing, signatures or hashing. All shaped false calls pay the full
charge. UC/shared include 64 member allowances and the fixed 1,117,700 source
allowance; RSMT retains its stateless formula. These are candidate prices,
not measured production pricing.

The provider reads the eight common words, all eleven selected epoch words
for a common seal, and all eight words of each populated member through
`EvmInternals::sload`. It uses the current journal and normal warmth/revert
behavior; it never accesses `Database::storage` directly. Absent metadata is
an authenticated unknown epoch, while unavailable state and impossible
admitted invariants follow the fatal execution channel. A valid phase 1 is
false. UC/shared always disable input/spec-only result caching, including
when converted to a dynamic map entry.

Malformed/OOG callers yield `Ok(PrecompileOutput::halt(...))`. Revm maps that
to failed CALL/STATICCALL, empty returndata and all forwarded gas consumed.
Host failures yield `Err(PrecompileError::Fatal(...))` and abort execution.
Successful true/false returns are exactly `abi.encode(uint256(1),bool)`.

## Reproduce

Use a private target directory, and delete it after validation:

```sh
export CARGO_TARGET_DIR=/private/tmp/cargo-b1pr2
cargo +nightly-2026-08-12 fmt --all --check
cargo clippy -p reth-unicity-b1 --all-targets --all-features -- -D warnings
cargo test -p reth-unicity-b1
cargo run -p reth-unicity-b1 --example vectors > /private/tmp/b1-rust-vectors.json
python3 crates/unicity/b1/tools/mutate_guards.py
```

The pinned Go manifest is conformance input only. The Rust example never
reads it or invokes the kernel: it constructs records, CBOR, trees,
RFC6979 signatures and candidate charges independently from explicit scalars
and seed `b1-oracle-v1`. Tests compare every shared generated request byte,
signing preimage/digest, pre-state, status, returndata and charge against Go.
The entire 144-case Go manifest runs as individually named tests. Additional
Rust required-null cases, exact error variants, staged debit precedence,
registry invariants, all 531 source reads, epoch-zero/member storage words,
journal overrides, warmth rollback, host failures and actual STATICCALL
followed by measured cold/warm SLOAD cover the provider boundary.

The mutation script changes one source expression at a time, runs a named
negative test, refuses compile failures/timeouts/zero-test runs as evidence,
and restores source files even on failure. It does not claim automated
mutation coverage outside its explicitly listed guards.

## Remaining gates

PR1b authenticates and derives committed projected Updates per paired node.
PR3 supplies the final privileged registry/runtime/compiler/genesis artifacts
and bounded G_rest. PR4 must integrate Update admission/gross system metering,
all builder/follower/replay/recovery/RPC/trace factories, the accepted address
profile, actual multi-pair rotation/supersession/reorg/restart and x86-64/arm64
measurements before enabling anything. No injected fixture establishes
history authentication, deployment readiness, or completion of B1 #62.
