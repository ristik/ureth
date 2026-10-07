# Inactive native token kernel

`reth-unicity-b2` implements the pure SDK 3.0.1 native bridge relation at reserved
address `0x0104`. No production crate imports it and no node factory registers it.
`0x0103` remains reserved. This does not enable bridging or change B1.

The byte contract is native-bridge-plugins PR1 revision
`85a8e507eabe6aaaf5a117b0d435b0e0a9aec802`; exact source artifacts and their digests
are under `protocol/`. The sealed candidate corpus has manifest digest
`d890912549947d1ade346002206ebe306d6937c3e43b7fe3ea1d338eb6827820` and Go oracle
revision `2b6d9494cca8033b495ea97ff33d660ee84f9760`. All 336 sealed cases replay
against that oracle. The ordinary Rust test suite enforces all 116 B2 kernel calls
with exact ABI output or exact halt diagnostics, plus corpus/artifact integrity.
The remaining operations concern SDK codecs, policy, offline backing, composition
and vault behavior outside this pure kernel. Local signed constructors are tests,
not a second golden corpus. `kernel-expectations.json` is derived by executing the
pinned Go Kernel on the sealed inputs, after verifying all original expectations;
this also preserves the direct PrepareLock/ABI distinction for zero amounts.

PR1 and bft-core #422 are **unmerged**. These are sealed candidate revision pins,
not merged release pins. Release/activation remains gated on their merge and the
corresponding pin update (`verify_protocol.py --require-release`). No merge or
activation is claimed. The SDK-extension pure core remains a constants-only
skeleton, so this crate implements the narrow relation itself.

Both SDK 3.0.1 NetworkId codecs require `1..=65535`. The shared profile,
manifest schema, Go oracle and Rust Cfg/mint wire decoders enforce that range;
zero and values above 65535 halt with `IntRange`. The sealed corpus includes
14 shared boundary cases at 0, 1, 65535 and 65536, including fully reconstructed,
cfg-bound and signed mints, prepare calls and independent mint wire checks.
Local constructors independently cover the same boundary.

CI verifies the checked-in sealed digest and replays all 116 pure Kernel calls.
A separate CI job anonymously checks out the public bft-core source commit
pinned in provenance and replays all 336 cases with exact outcomes; it also
regenerates and compares every data file. Full Go replay runs locally and in
bft-core CI as well. No repository secret is needed.

## Boundary

Input is canonical `abi.encode(uint8 operation, bytes Cfg, bytes payload)`.
Operations 0/1/2 prepare a lock, verify a genesis-only mint, or verify a complete
return projection with a terminal burn. Projection tuples contain the exact
transaction, CD and original reference time. The entire borrowed CBOR tree is
scanned with bounded depth/items before semantic decoding; embedded J/value/return
CBOR shares the item budget. No wire length causes an unbounded allocation.

Every source predicate/hash is reconstructed, every txHash is recomputed, CD
fields and nullable deadlines must match, and explicit deadlines require `t<e`.
There is no wall-clock comparison. Every unlock requires 65 bytes, in-range
nonzero r/s, low-s, recovery ID 0..3, recovered-key equality and compact verification.
No signature normalization occurs. Source IDs cannot repeat. Native identity,
one minimal positive uint256 amount, exact value envelope, strict signature
owners and terminal whole-amount burn are enforced.

The embedded lock proof is structurally parsed, bounded and cfg-bound here.
The kernel does not verify its UC, trust authority, PDR, Ethereum header or MPTs.
Those are the offline issuance verifier's responsibility; the universal minter
secret is public and proves no backing. The owner's SDK trust-base decision does
not introduce an authority module or epoch bundle into this crate. The opaque
`trustBaseId` never authorizes keys or selects a kernel trust base.

The result is exactly `448+128*m` bytes, with ordered
`(sid,txHash,referenceTime,leafValue)` and
`leafValue=SHA256(CBOR([b(txHash),referenceTime]))`. Prepare exports zero leaves,
mint one, return all. Relation failures return the marker, false, and an entirely
zero/empty result. Framing, encoding, budget failures and insufficient gas halt
exceptionally; the public error enum preserves exact diagnostic identities.

A kernel success authenticates neither aggregator admission nor inclusion.
Composition must authenticate both expected state root and expected IR hash with
unchanged B1, open the exact canonical native InputRecord, bind its state root,
check each `t<=authenticated IR.timestamp`, and prove each raw leafValue under
that same admitted root. Inactive-address empty success must be rejected by the
caller. No proof fetching, caller-selected authority or storage access exists here.

## Limits and candidate metering

History <=128 KiB; Cfg <=1024 bytes; complete kernel ABI <=128 KiB+4096;
64 transfers including burn; 65 leaves; depth 16/items 32768 cumulatively;
J <=64 KiB; PDR/UC <=16 KiB each; header <=2048 bytes; each MPT <=65 nodes,
each node <=1024 bytes, combined node bytes <=24 KiB. These limits intersect.
They do not grant additive entitlements or establish usable block capacity.

The provisional schedule is `26000 + 20*ABI_input_bytes + 14000*leaves`.
The fixed/byte debit precedes scanning; the complete leaf-dependent debit precedes
semantic allocation, point parsing, public-key derivation, hashing and recovery.
It retains the former 6000 mint-key allowance, increases scan allowance by 4/byte
and leaf hashing/scanning allowance to 2000/leaf. Every shaped false pays the same
full determined charge; there is no warmth or late-failure discount. This pure
provider may cache deterministic results with their full charge. Native timings
are measurements of this kernel only, not Solidity calldata/storage/composition
costs or activation pricing.

## Reproduction

Use a private target and four compiler jobs on constrained machines:

```sh
export CARGO_TARGET_DIR=/private/tmp/cargo-ureth-nbp4
cargo test -p reth-unicity-b2 --locked -j 4
cargo clippy -p reth-unicity-b2 --all-targets --all-features --locked -j 4 -- -D warnings
cargo +nightly-2026-08-12 fmt --all --check
python3 crates/unicity/b2/tools/verify_protocol.py --require-corpus
python3 crates/unicity/b2/tools/mutate_guards.py
cargo test -p reth-unicity-b2 --release --locked -j 4 benchmark_native_kernel -- --ignored --nocapture
```

To independently replay all sealed cases and verify the generated Kernel
expectations, use a clean bft-core checkout at `pin.json`'s `oracleRevision`:

```sh
cd /path/to/bft-core
GOMAXPROCS=4 go run /path/to/ureth/crates/unicity/b2/tools/replay_oracle.go /path/to/ureth/crates/unicity/b2/protocol
```

The timing experiment defaults to 1000 warmups/10000 samples per history size;
`NBP4_WARMUP`/`NBP4_ITERATIONS` can explicitly select shorter development runs.
It reports p99 and max. Run on real x86-64 and arm64 before any activation decision.
Delete the private target after work. The guard harness restores every mutation
and distinguishes compiled test failures from build failures or zero-test runs;
its report explicitly identifies redundant or cryptographically unreachable
checks whose removal has no observable effect on those test inputs.

The zero-digest guards remain normative even though ordinary inputs cannot
produce a zero SHA-256 digest. The mint-recipient type guard and duplicate
justification size bound remain defensive. The scanner count precheck is
observable: declaring 32769 elements with only 32768 zero bytes yields
`Truncated`; removing that guard yields `TooManyItems`. A regression pins this
exact diagnostic. Guard-removal survival on other inputs does not establish
semantic equivalence.
