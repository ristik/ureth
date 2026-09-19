# ureth — Unicity's execution-client fork of reth

This repository is the **approved execution-client fork** required by
[bft-core F3 (#11)](https://github.com/ristik/bft-core/issues/11). Every reth change that the
enshrined-EVM profile needs belongs here, not in bft-core: the Go adapter cannot implement EVM
validity rules.

## Fork point

| | |
| --- | --- |
| Upstream | [`paradigmxyz/reth`](https://github.com/paradigmxyz/reth) |
| Fork point | `189c0df32617afc488e0f091dbface1bd72cceb4` (tag `v2.5.0`, 2026-08-12) |
| Working branch | `unicity/main` |
| Version string | `2.5.0-dev` |

This is a private mirror rather than a GitHub fork: GitHub forks inherit the parent's visibility, so
a fork of public `paradigmxyz/reth` cannot itself be private. `upstream` is configured as a remote,
so `git fetch upstream` and ordinary rebases onto a later tag work exactly as they would in a fork.

At the fork point `unicity/main` was byte-identical to upstream `v2.5.0`. The current divergence is
limited to two inactive crates: the U2 per-payload commitment provision in
`crates/unicity/payload` and the bounded `SealRegistry` kernel plus shared block adapter in
`crates/unicity/execution`. Neither is wired into an `EngineTypes`, node, RPC module or capability,
so normal node operation and live execution semantics remain unchanged.

## What this fork is allowed to change

The owner's 2026-09-06 constraint (recorded in bft-core #1 and #4) is to **minimise execution-client
and Engine API divergence**, to keep the security-critical surface, threat model and audit scope
small. Concretely:

- Implement only the justified deviations in the accepted D2 inventory
  ([ADR 0004](https://github.com/ristik/bft-core/blob/integration/enshrined-evm/docs/adr/0004-reth-system-call-fee-profile.md)).
- Preserve standard Engine API signatures and semantics wherever feasible; new methods are
  versioned (`engine_*WithSealV1`) and negotiated explicitly, never silent changes to standard ones.
- Every retained custom hook must be linked to builder/follower/import/replay conformance evidence
  **and its exact upstream delta**.

As of the fork point, bft-core's adapter uses only standard Engine API V3 (`exchangeCapabilities`,
`forkchoiceUpdatedV3`, `getPayloadV3`, `newPayloadV3`) plus three plain `eth_*` calls — the
divergence surface is currently **empty**. Keep it as close to that as the profile allows.

## Known deviations this fork must close

Measured against stock upstream at this exact commit by bft-core F1
(`docs/design/f1-baseline.md` §4, reproducible with `scripts/reth-baseline.sh`):

- **D-1: the genesis base fee is not preserved, and there is no *configurable* floor.** For an empty
  block the update is the integer recurrence `next = parent - floor(parent/8)`. From a 1 gwei
  genesis it descends to **7 wei by block 145 and stays there** — 7 is a fixed point because
  `floor(7/8) == 0`. Note carefully: that fixed point is an artefact of integer division, **not** a
  fee floor. Nothing configures it and it derives from no policy. A configurable protocol floor is
  still needed. Owner: bft-core F5 (#13).
- **D-2: only *our* builder's gas limit is unpinned by default, and a standard flag fixes that.**
  Under the default builder `gasLimit` drifts up ~1/1024 per block (30,000,000 → 35,070,622 over
  160 blocks) as it walks toward its own target via `gas_limit_with_target` →
  `calculate_block_gas_limit`. But `--builder.gaslimit 30000000` holds every block at exactly
  30,000,000 **with no client change**, so this is a configuration default, not a client defect,
  and it is not by itself a reason to diverge. What is unevidenced — and may need a validity rule
  here — is whether a follower rejects a *peer's* block carrying a different gas limit or exceeding
  the configured capacity. A flag on our own builder constrains only blocks we build. Owner:
  bft-core F5 (#13), with builder/follower/import/replay evidence from F3 (#11).

An earlier revision of this file claimed the base fee reaches 1 wei and that the gas-limit growth
was unbounded and required a client fix. Both were wrong; see bft-core PR #84 review 5131229148.

Relevant crates: `crates/ethereum/evm`, `crates/engine`, `crates/payload`, `crates/chainspec`.

## Keeping the pin honest

bft-core pins this fork by commit in `docs/design/f1-baseline.md` §2 and asserts the two deviations
above **in their current broken form** in `scripts/reth-baseline.sh`. When a change here closes one,
that assertion flips to FAIL by design — update the bft-core baseline document and F5 in the same
change rather than deleting the assertion.

## U2 (bft-core #11): per-payload commitment provision, inactive

The first code divergence, and deliberately the smallest one the D2 profile needs: a builder that
writes a per-payload 32-byte commitment into the header `extraData`. It is **not wired**: no
`EngineTypes`, node, RPC module or capability uses it, so no Engine API method accepts it and normal
node operation cannot reach it. It carries no system call, import hook, companion data or
`WithSealV1` semantics.

Historical U2-only upstream-change inventory when this was the sole divergence:

| Change | Kind |
| --- | --- |
| `Cargo.toml`: one workspace member line, `crates/unicity/payload/` | the only edit to an upstream source or manifest file |
| `Cargo.lock`: one added package entry, `reth-unicity-payload`, with no existing dependency version changed | generated by cargo for the new member |
| `crates/unicity/payload/Cargo.toml`, `crates/unicity/payload/src/lib.rs` | new crate `reth-unicity-payload` |
| `UNICITY.md` | this record |

No upstream crate source file changes. The crate uses reth's own extension points: its own
`PayloadAttributes` type (as `examples/custom-engine-types` does) and the public
`EthereumPayloadBuilder` constructed per job with that job's commitment as `extra_data`. Its payload
id binds the stock id to the commitment under a domain tag, because the stock `payload_id` hashes
only the standard attribute fields and would otherwise merge two jobs that differ only in their
commitment.

## M1 (bft-core #11): bounded SealRegistry execution, inactive

`crates/unicity/execution` implements the reviewable execution unit for the pinned registry
contract. From structured v2 input it derives the canonical input, origin and technical-record
hashes; checks the registry code hash already present in the supplied parent state; executes the
reserved `open` then `finalize` system calls against a disposable state clone; enforces their
combined gross pre-refund gas cap; derives the canonical system-outcome commitment; and returns
state only after the finalized phase, round and commitment are present in registry storage.

The same crate now supplies an immutable per-block `ConfigureEvm` adapter around Reth's real
Ethereum builder and executor. Build and replay share the fixed order `open` → `finalize` → stock
Cancun EIP-4788 → ordinary paid transactions, retain standard ordinary receipts and fee/revert
semantics, and put gross system plus ordinary receipt gas in the header. Completion computes or
checks real roots and yields an opaque parent-accounting token, so the next block's base fee uses
derived ordinary work rather than a caller-provided scalar.

Authentication and exact parent-state provenance are explicit caller prerequisites. The crate does
not authenticate certificates or configuration, bind the supplied database cryptographically to
the claimed parent, or activate node/RPC/Engine API paths. Its fixture provenance and bounded test inventory are recorded in
`crates/unicity/execution/README.md`. The inactive payload crate also contains an execution-aware
builder whose immutable resolver binds each job's full parent, attributes and commitment to that
shared configuration. Resolution is structural; certificate/JWT authentication and exact-parent
state provenance remain caller prerequisites, and no Engine API path is activated.

## Current total fork inventory

Upstream-change inventory against the fork point `189c0df32617afc488e0f091dbface1bd72cceb4`:

| Change | Kind |
| --- | --- |
| `Cargo.toml`: two workspace member lines and one local dependency entry for `reth-unicity-execution` | makes the two inactive crates workspace-visible and lets payload reuse execution |
| `Cargo.lock`: two added Unicity package entries; security updates to `h2` 0.4.16 and `rustls` 0.23.45 with their compatible transitive lock updates | fixes RUSTSEC-2026-0258 and RUSTSEC-2026-0285 without changing dependency requirements |
| `crates/unicity/payload/` | inactive per-payload commitment provision |
| `crates/unicity/execution/` | inactive bounded registry kernel, shared build/replay adapter and fixtures |
| Ten upstream Rust source files formatted by the current nightly rustfmt | repairs hosted formatting drift only |
| `crates/trie/sparse/src/arena/mod.rs` | removes one redundant clone rejected by current Clippy |
| `crates/net/network/src/config.rs` | removes one redundant rustdoc link target rejected by current rustdoc |
| `.github/workflows/lint.yml` | drops the `wasm` and `riscv` jobs and the `wasm` gate entry; pins the lint toolchains and the `deny` reusable workflow |
| `.github/scripts/check_wasm.sh` | one exclusion entry, now in a script nothing invokes; see below |
| `UNICITY.md` | this record |

## The wasm and RISC-V targets are not built

The owner's decision on 2026-09-19: no Unicity component targets WebAssembly or RISC-V, so the fork
carries neither build. The `wasm` and `riscv` jobs are removed, along with the `wasm` entry in the
`lint success` gate. `riscv` was never in that gate.

Upstream's `.github/scripts/check_wasm.sh` and `check_rv32imac.sh` are left in place, unreferenced,
deliberately. Deleting them would be larger edits to upstream for no gain, and keeping them means
re-enabling a target later is restoring one job block rather than reconstructing a script. Nothing
runs either.

The `wasm` job failed on `reth-unicity-payload`, whose dependency on `secp256k1-sys` does not build
for `wasm32-wasip1`. The payload work added an exclusion entry for it, which is why that entry is
still listed above: the line remains in the tree, in a script the workflow no longer invokes. It is
retained rather than reverted so that re-enabling the target restores a working configuration in one
step.

## The lint toolchains are pinned

Upstream runs `fmt`, `clippy`, `docs`, `udeps` and `book` on a floating `@nightly`, and
`clippy binaries` on a floating stable. For upstream that is the right default: it is the tree those
lints are written against, and upstream fixes its own code when a new release tightens a lint.

For a fork it inverts. A new toolchain can fail CI on a tree nobody touched, and the only way to
make it green is to edit upstream source that this fork otherwise leaves alone, which spends
divergence budget on the calendar rather than on the profile. That is the opposite of the constraint
in "What this fork is allowed to change".

So the lint jobs are pinned to toolchains contemporaneous with the fork point, `v2.5.0` of
2026-08-12, where upstream's own CI was green against this exact source:

- the five nightly jobs to `nightly-2026-08-12`;
- `clippy binaries` to stable `1.97.1`, the stable series current at the fork point.

`rustfmt.toml` uses nightly-only options (`imports_granularity`, `wrap_comments`,
`format_code_in_doc_comments` among them), so `fmt` cannot move to stable without changing that file
and reformatting the tree. Pinning is the option that leaves upstream source untouched.

This uses `dtolnay/rust-toolchain@master` with an explicit `toolchain:`, which is the form the `msrv`
job in this same workflow already uses, rather than a new mechanism.

Updating a pin is then a deliberate commit: raise the date, run CI, and fix what it reports, at a
moment of our choosing rather than whenever a toolchain ships.

The `deny` job is pinned for the same reason and by a sharper lesson. It called
`tempoxyz/ci/.github/workflows/deny.yml@main`, and on 2026-09-18 that workflow began requiring
`id-token: write` for a new "secure runner" step. This caller grants only `contents: read`, so the
call became invalid and **the entire `lint` workflow stopped starting**, taking `clippy`, `fmt`,
`docs`, `typos`, `udeps` and `book` down with it for two days without a single commit here. A
floating reference to someone else's workflow is a floating reference to their permission
requirements too. It is pinned to `400fd3f4`, the last revision that needs no token. Granting
`id-token: write`, which would let that workflow mint an OIDC identity for this repository, is a
decision for the owner and not a way to make CI green.

No upstream runtime behavior and no dependency requirement is changed. Every upstream file this fork
touches is listed above, formatting and lint repairs included. Check:

```sh
git diff --stat 189c0df32617afc488e0f091dbface1bd72cceb4 -- . ':!UNICITY.md' ':!crates/unicity'
git diff 189c0df32617afc488e0f091dbface1bd72cceb4 -- Cargo.toml Cargo.lock
```

The first command must show exactly the upstream files listed above and nothing else; the second
provides the exact workspace and lock changes.
