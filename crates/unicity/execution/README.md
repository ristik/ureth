# Unicity execution kernel

This inactive crate is the bounded M1 execution unit for the pinned `SealRegistry` v1 contract. It
derives canonical v2 CBOR commitments from structured input, checks the technical-record hash and
pinned registry code hash, then executes `open` followed by `finalize` with revm system-call
semantics. The two calls share one gross, pre-refund gas cap. Only a fully finalized cloned state is
returned; errors publish no state.

Authentication and context remain outside this crate. Its caller must authenticate the certificate,
transition bodies, configuration, and genesis origin, and supply an immutable parent snapshot that
is independently bound to `RootInputV2.parent_hash`. A later adapter must perform those checks and
integrate ordinary transactions, block/header accounting, import/replay, and node/RPC paths.

The test fixture contents are copied from bft-core at design merge `77d47511` (the vendored JSON
files add a final newline): `evmroot/testdata/v2-vectors.json`
and `registrygenesis/testdata/funded-genesis-vector.json`. The latter is the full finalized standard
genesis JSON whose pinned reth companion records genesis hash
`0x9d672f7822f0747687bcf1c4273cecac83f987871d215d5554d71fb1d1f6f1b9` and state root
`0x8936f379e65d90577242c6333f644cd0716325117e5bb064a2a32c08ba8afdf0`.
`system-outcome-vectors.json` was generated independently through bft-core
`evmroot.SealRegistryCommitment` at `c9beef6c`.
