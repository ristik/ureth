# Inactive B2 whole-token semantics kernel

B2 #63 PR2 reserves `0x0104` for a pure native DEV kernel. No production crate
imports this crate; no factory, genesis, fork or precompile map installs it.
`B2Precompile` exists for explicit tests and subsequent integration only. A
successful result exports inclusion obligations, not a backing, admission or
inclusion proof. The composing verifier and vault remain PR3 work.

## Consumed immutable sources

- bft-core PR #418 merge: `9136c66146e56e1c5dc02c51e810a8df7f6b4fe4`,
  `bridgeprofile/` and `docs/pos/specification/amendments/b2-whole-token-bridge-profile.md`.
- ureth B1 PR #50 merge/base: `f54d45d38e19e588055c01d899d552511b0f3df3`.
  The borrowed canonical scanner is reused, with a separate token subset mode;
  certificate grammar and B1 seal signature semantics remain unchanged.
- Rust SDK bridge companion: `366952967a5ae9ce1f1636ad6817745034e1dbd1`
  on `7ed017effd4bd0a201ab2a9ef36793cb9924a048`.
- JS SDK bridge companion: `5af57b0e9d6aba6a5dd0e304c73b901e75577adb`
  on `ca0361bfc12deb7240d41d183e027f0603b3692b`.

The SDK companion commits are local immutable commits recorded by merged PR1;
PR1 did not publish them upstream. They are conformance inputs, not a claim that
arbitrary SDK versions enforce the bridge. The narrow Rust relation is ported
from that amended companion, using ureth's pinned libsecp256k1 rather than the
SDK's k256. No SDK networking, extension dispatch, mutable registry or host
callbacks are linked.

## ABI and failure contract

Input is exactly `abi.encode(uint8 operation,bytes Cfg,bytes payload)` with
operations 0 prepare-lock, 1 mint, 2 return. Canonical offsets, contiguous tails,
zero padding, exact operation arities and no trailing bytes are required.
Payload is `[nonce,amountBstr,P0]` or the unchanged tagged transaction/CD compact
history `[[M,CD0],[[T1,CD1],...]]` frozen by PR1.

Output is exactly `abi.encode(bytes32("UNICITY_TOKEN_SEMANTICS"),bool,Result)`.
Result is `(cfg,nonce,amount,tokenId,salt,firstPredicateHash,lockDigest,releaseTo,
nullifier,Leaf[])`; Leaf is `(sid,txHash)`. False has nine zero scalar words and
an empty leaf list. The dynamic Result offset is 96, leaf offset is 320, and
output length is `448+64*leaves` (448 for false/prepare). The marker is a
left-aligned 23-byte ASCII literal followed by nine zero bytes. An inactive
address's empty success does not have this shape.

`run` distinguishes `Malformed(exact reason)`, `BudgetExceeded(exact reason)`
and `OutOfGas`. Unsupported/false relations return a shaped false result with
an exact diagnostic reason in the Rust `Output`, outside ABI returndata. An
embedded malformed justification/data/reason is a false profile relation,
matching PR1's exact sentinels. Full outer CBOR scanning and embedded resource
preflight precede evaluation, including a malformed last item following an
earlier false mint. The provider maps malformed/budget/OOG to exceptional
precompile halts; exceptional EVM execution has no promised revert data.

## Provisional metering and ceilings

For complete ABI request length B and actual transaction/leaf count m:

`G = 20000 + 16*B + 6000 + 13000*m`

Prepare has m=0. `20000+16*B` is reserved before scanning; the remainder before
any allocation, hash, public-key parse, key derivation or signature work. False
pays the full determined charge. There is no state, host access, warmth or
late-failure discount. Pure input-result caching preserves the same charge.

The complete native ABI request is capped at 64 KiB, with at most 64 transfers
including terminal burn (65 leaves), CBOR depth 16 and 32768 cumulative scanned
items across Cfg/history and embedded justification/data/return reason. All
lengths are bounded before allocation, and ABI arithmetic is checked. These
are development ceilings and candidate prices, not measured activation values
or a claim that maximum cases fit a target block.

## Reproduction

Use a private target and at most four Cargo jobs. Remove the target afterwards.

```sh
export CARGO_TARGET_DIR=/private/tmp/ureth-b2-check
export CARGO_BUILD_JOBS=4
export CARGO_PROFILE_DEV_DEBUG=0
export RUST_TEST_THREADS=4
cargo test -p reth-unicity-b1 -p reth-unicity-b2 -j 4
cargo clippy -p reth-unicity-b2 --all-targets --all-features -j 4 -- -D warnings
cargo +nightly-2026-08-12 fmt --all --check
python3 crates/unicity/b2/tools/mutate_guards.py
cargo run -p reth-unicity-b2 --example b2_vectors -j 4 > /private/tmp/b2-rust.json
```

Extract a separate bft-core archive at the exact merge pin above. From that
archive, run (with a private Go cache):

```sh
GOCACHE=/private/tmp/b2-go GOMAXPROCS=4 go run -p 4 \
  /path/to/ureth/crates/unicity/b2/tools/check_go.go /private/tmp/b2-rust.json
```

The pinned manifest is retained byte-for-byte. Its 78 relevant kernel/unlock
vectors are named native tests; policy/envelope/MPT vectors belong to composing
layers. Rust independently constructs Cfg, CBOR, source hashes, transactions
and RFC6979 signatures, reproducing shared Go history bytes and constructing
maximum histories, nonce/amount boundaries and complete histories with matching
IDs 2 and 3 plus flipped-parity failures. The Go checker independently compares
exact ABI output, error reason and gas. Reading the golden manifest alone is
not counted as independent construction.

Zero hash sentinels, invalid derived scalars, repeated-SID detection and compact
verification are also tested as primitives. Hitting zero SHA-256 or a repeated
source state in a valid full history is infeasible to construct. Recovery to
the expected key mathematically implies compact validity, but the required
second verification is retained and tested independently with an invalid
compact signature/key pair. Mutation evidence must distinguish these primitive
tests from full-history tests.

## Merge and activation boundary

This implements the inactive PR2 unit from the SOUND v2 design. It does not
freeze accepted profile hashes/prices, verify policy admission, call B1, check
positive EVM backing, store locks/replay state, credit/payout funds or close B2.
Both-CPU native/worst-case benchmarks, accepted B1 runtime/layout/genesis/gas
pins, joined verifier/vault integration, SDK publication pins and the actual
round trip remain activation/PR5 gates. No deployment or issuance is authorized
by this crate or its tests.
