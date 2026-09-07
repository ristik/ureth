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
