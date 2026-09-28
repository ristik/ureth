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
`0xdf28d41ed53c949eacd7f1db41c9a412e3d8e98da6b100931df337cf9f48992d` and state root
`0xd63fd616fa91fea173cfef70a8f15336488c6cb31d7b26b6ff72c924515359a4`.
`system-outcome-vectors.json` was generated independently through bft-core
`evmroot.SealRegistryCommitment` at `c9beef6c`.

`signed-beacon-genesis.json` is a test-only standard-JSON variant generated with geth 1.14.11. It
adds the stock beacon-roots code and funds the public secp256k1 scalar-1 test signer; it is never a
deployment default. Its independent oracle pins genesis hash
`0x5622984260859a170f61839f6f6114d57a653a3743049216f0451124fa77e269` and state root
`0xcd7b3a14c0f90bf0a7acf6dd9e824b27b3bab825aeccfa2699539e4810ed65b4`.
