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

`unicity/main` is byte-identical to upstream `v2.5.0` at this commit. Nothing has diverged yet — the
first divergence will be F3's privileged system call.

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

- **D-1: the base fee has no floor.** `baseFeePerGas` decays exactly 7/8 per empty block; from a
  1 gwei genesis it reaches 1 wei in 156 empty blocks. Since system-only blocks are empty by
  construction, an idle shard drives it there continuously. Setting the genesis base fee is
  demonstrably not a fix. Owner: bft-core F5 (#13).
- **D-2: the gas limit is not pinned.** The builder walks `gasLimit` up by 1/1024 per block toward
  its own default target (30,000,000 → 31,224,868 over 41 blocks), unbounded, so any capacity split
  computed from "the configured total" silently inflates. Owner: bft-core F5 (#13).

Relevant crates: `crates/ethereum/evm`, `crates/engine`, `crates/payload`, `crates/chainspec`.

## Keeping the pin honest

bft-core pins this fork by commit in `docs/design/f1-baseline.md` §2 and asserts the two deviations
above **in their current broken form** in `scripts/reth-baseline.sh`. When a change here closes one,
that assertion flips to FAIL by design — update the bft-core baseline document and F5 in the same
change rather than deleting the assertion.
