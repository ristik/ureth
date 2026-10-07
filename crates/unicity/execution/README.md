# Unicity execution kernel

This crate contains the bounded execution kernel and shared Reth block-execution adapter. H3 pins
`SealRegistry` v2 to unicity-pos-contracts `h3/contracts-assignment` at
`8b30801afaa887db0d7aa2e4957ecae2c01293e4`, including the runtime in
`testdata/seal-registry-v2.json`. Its runtime code hash is
`0x7787f3166565c8e5ebd73801bf71cbacf0cf69f6bcfb8dea8bedbef8198caf38`.

Root-input v2 keeps its existing tuple. Its transition list now accepts one canonical
`UNICITY_HANDOFF_EVM_TRANSITION/v3` body with the assignment's old/new root and shard epochs,
active configuration hashes, and bounded supersession span. A root jump larger than one is accepted
only with `span == rootDelta`, matching shard delta, a nonzero span commitment, and a span no larger
than 2 (a committed primary and its one recovery). The paired BFT verifier authenticates the ordered handoff history before this input reaches
Ureth; this crate does not verify root or shard signatures. Build envelopes must repeat exactly the
same transition bytes as root-input `D[]`, and the decoder refuses any mismatch.

The kernel checks the certified/input-record epoch pairing on every path. Ordinary inputs require
the certified and authorized shard epochs to match; an acknowledgement may authorize the installed
successor epoch while certifying the frozen parent's previous epoch. The registry's immutable genesis
configuration hash is loaded from parent state, while the authenticated active hash is supplied by
the root origin/transition. The kernel then executes `open` followed by `finalize` with revm system-call
semantics. Both calls share one gross, pre-refund gas cap. Only a fully finalized cloned state is
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

`seal-registry-v2-genesis.json` is a test-only H3-shaped genesis that substitutes the pinned v2
runtime and initializes the assignment active hash. `generate-h3-assignment-beacon-genesis.go`
adds the stock beacon-roots code and funds the public secp256k1 scalar-1 test signer; neither file
is a deployment default. Its independent geth 1.14.11 oracle pins genesis hash
`0xefbe99d08e86d7e06034bfcb0d48f0f40a92b321fb3f96ca82a58e83d0c62363` and state root
`0x868d8ac89ecb4bd0ab588ab97aba438a51898b0eaf18860a054b224897100f4a`.

UC time: this crate does not bound the seal timestamp. Importers keep it monotonic on one lineage; bounding the root's own proposal timestamp is a root consensus rule tracked as ristik/bft-core#445.
