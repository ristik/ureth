# Unicity execution kernel

This crate contains the bounded execution kernel and shared Reth block-execution adapter for the
single B1 profile: full authenticated root members in deterministically pruned ordinary EVM state.
It pins the B1 `SealRegistry` of unicity-pos-contracts PR 6 (`71eb6325`), whose runtime is in
`testdata/seal-registry.json` with code hash
`0x28ebc47d5beeb45307cb92ff1521be6a5623d4e4fa1721bc13a6f755cdf0781c`. There is no layout version
and no older registry: the fixed words, the circular live-set queue and the entry and member words
are the one layout, and a genesis that does not carry it is refused.

## The committed update

The canonical root input has twelve fields: the earlier eleven followed by
`b1UpdateHash = SHA-256(Update)`. The exact `Update` bytes travel with the root-input companion
(`b1Update` in the build envelope and the seal companion), are persisted with it, and are
re-executed by build, import, replay and recovery. [`update`] decodes them with a schema-directed
reader that accepts one encoding per value, and admits them in the design's staged order:

1. the byte cap `C_max` and the scan charge `2000 + 16*C` are checked before the bytes are read;
2. an allocation-free structural scan counts the members `T`, and the member charge `1000*T` is
   reserved before any member is allocated, any key point is parsed or any rule is checked;
3. the update must hash to the root input's committed value and bind to the pinned profile, the
   parent hash and height and the origin epoch, round and identity;
4. entries are checked for interval, window and member invariants.

Every failure rejects the whole block; none is a caller verdict. The registry's own queue and
coverage checks run inside the metered `open` call, so they cost gas like any other work and never
scan old storage natively. The paired Go node authenticates the root history; this crate does not
repeat that, and a peer's boolean or a JWT cannot authorize a projection.

## Gross system accounting

The system reservation `g_sys` is `G_admit + G_open + G_finalize`, all gross and pre-refund:

- `G_admit = 2000 + 16*C + 1000*T` is debited before `open`;
- `open` receives `g_sys - G_admit` and `finalize` receives `g_sys - G_admit - G_open`;
- the outcome commitment covers `G_admit + G_open` and the input commitment, so finalize's own gas
  never refers to itself;
- storage-clear refunds neither lower the total nor fund another operation, and header `gasUsed`,
  parent ordinary-gas recovery and replay use the same gross total.

A job is refused at binding time if `g_sys` is below the profile envelope
`155936 + 15626944*K + G_rest(K)` or the ring exceeds the measured cap of 16.

## Adapter

The shared adapter wraps Reth's real Ethereum block executor for build and replay. One immutable job
configuration binds the structured companion, its update, the actual parent header, the gas profile,
the fee collector and the ordinary-only parent accounting. It executes the staged registry
sequence, then the retained Cancun EIP-4788 call, then ordinary paid transactions. Standard receipts
remain ordinary-only while the header records gross system gas plus ordinary receipt gas.
Completion functions mutate disposable candidate state; callers must discard it on error. The
standalone kernel keeps its clone-on-success behavior and never mutates the supplied parent.

Authentication remains outside this crate. Its caller must authenticate the certificate, the
transition bodies, the configuration, the genesis origin and the exact parent snapshot, and must
verify recovered senders. Supplied `State` and `StateProvider` values must be consistent views of
that immutable exact parent.

## Test data

`testdata/generate-b1-vectors_test.go` is run from bft-core's Go module at `ce9cad819` (see the
file header). It builds the funded, EIP-4788-equipped B1 genesis (`signed-beacon-genesis.json` and
its oracle), the K=2 scenario `b1-vectors.json` (Updates, root inputs, acknowledgement
transitions and every changed registry word, all from bft-core's `b1state` model and `evmroot`
encoder) and re-encodes the executable sources of `v2-vectors.json` as twelve-field inputs. The
Rust tests execute the real registry runtime and require every addressed word to equal bft-core's
model after each step. `system-outcome-vectors.json` was generated independently through bft-core
`evmroot.SealRegistryCommitment`. The `testing` module (feature `test-utils`) builds the updates an
honest pair derives for these fixtures from a model independent of the Go generator. The
integration tests in `tests/` use the same fixtures and are built with the feature:
`cargo test -p reth-unicity-execution --features test-utils`.

`tools/mutate_b1_guards.py` disables each admission and accounting guard once and requires a named
test to fail.

Transition bodies are unchanged by B1: a root jump larger than one is accepted only with
`span == rootDelta`, matching shard delta, a nonzero span commitment and a span of at most 2 (a
committed primary and its one recovery).

UC time: the seal timestamp is quorum-approved wall-clock time, bounded by root consensus
(monotonic against the parent, 30 s voter clock skew: ristik/bft-core#445). Importers also keep it
monotonic on one lineage.
