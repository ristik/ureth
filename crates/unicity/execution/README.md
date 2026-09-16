# Unicity execution kernel

This inactive crate is the bounded M1 execution unit for the pinned `SealRegistry` v1 contract. It
derives canonical v2 CBOR commitments from structured input, checks the technical-record hash and
pinned registry code hash, then executes `open` followed by `finalize` with revm system-call
semantics. The two calls share one gross, pre-refund gas cap. Only a fully finalized cloned state is
returned; errors publish no state.

The shared adapter wraps Reth's real Ethereum block executor for build and replay. One immutable job
configuration binds the structured companion, actual parent header, gas profile, fee collector and
ordinary-only parent accounting. It executes the bounded registry pair, then the retained Cancun
EIP-4788 call, then ordinary paid transactions. Standard receipts remain ordinary-only while the
header records gross system gas plus ordinary receipt gas. Successful completion computes real
state roots and mints an opaque accounting token for the next job.
The completion functions mutate disposable candidate state; callers must discard that candidate on
error. The standalone registry kernel keeps its clone-on-success behavior and never mutates its
supplied parent cache.

Authentication remains outside this crate. Its caller must authenticate the certificate,
transition bodies, configuration, genesis origin and exact parent snapshot. Supplied `State` and
`StateProvider` values must be consistent views of that immutable exact parent. The caller must also
verify the recovered senders attached to transactions and replay blocks. The adapter checks the
listed structural, header, receipt, gas and state-root bindings; it does not independently perform
certificate authentication, sender recovery or whole-database authentication. Node, RPC and Engine
API activation remain separate work.

The test fixture contents are copied from bft-core at design merge `77d47511` (the vendored JSON
files add a final newline): `evmroot/testdata/v2-vectors.json`
and `registrygenesis/testdata/funded-genesis-vector.json`. The latter is the full finalized standard
genesis JSON whose pinned reth companion records genesis hash
`0x9d672f7822f0747687bcf1c4273cecac83f987871d215d5554d71fb1d1f6f1b9` and state root
`0x8936f379e65d90577242c6333f644cd0716325117e5bb064a2a32c08ba8afdf0`.
`system-outcome-vectors.json` was generated independently through bft-core
`evmroot.SealRegistryCommitment` at `c9beef6c`.

`signed-beacon-genesis.json` is a test-only standard-JSON variant generated with geth 1.14.11. It
adds the stock beacon-roots code and funds the public secp256k1 scalar-1 test signer; it is never a
deployment default. Its independent oracle pins genesis hash
`0x82430ee9e534f0e454399cdaa06042c5dcc52b0378f48609e9c45c3cc1ae01f0` and state root
`0xcc17df719a9c043b34c3b5c0297775feb4c9ff8cfecf3b77ffe29bee9b0fe40a`.
