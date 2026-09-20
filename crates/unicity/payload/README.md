# Unicity payload construction

The commitment-only `UnicityPayloadBuilder` preserves U2's provision interface.
`UnicityExecutionPayloadBuilder` connects the actual transaction-pool payload builder to the
shared Unicity executor. `UnicityEngineTypes` and `UnicityNode` carry the Unicity payload
attributes end to end and use that builder with a bounded `SealJobRegistry`. The
`engine_forkchoiceUpdatedWithSealV1` sibling is registered on the authenticated engine module.

The method is reachable but not advertised: `engine_exchangeCapabilities` is the stock list and no
capability names it, so the standard `engine_*` surface a client can discover is unchanged. U3f
advertises all three seal methods together or none.

## Per-job authority

An `ExecutionPayloadJobResolver` supplies an immutable `UnicityEvmConfig` for the requested
parent, attributes and commitment. `SealJobRegistry` is the production resolver: a bounded,
shareable collection of jobs that a future seal method inserts into and the builder resolves
through. `FixedPayloadJobResolver` is the immutable test resolver; it holds an explicitly supplied
set of jobs and does not fetch or authenticate witnesses.

A job's eight-byte payload ID is only a lookup handle. Selection also compares the full parent and
attributes. The builder checks the returned execution configuration even for a custom resolver.

The caller must authenticate the certificate, technical record and configured profile before
creating a job. It must also supply state providers and any execution/read/root caches for the
exact parent. Structural resolution cannot authenticate a peer's assertion or prove the origin
of a database snapshot. D2's authenticated Engine input and independent replay integration
remain prerequisites of node activation.

## Execution

Normal, empty and missing-payload paths resolve the job. There is no fallback to the stock
Ethereum EVM configuration. Disabling state-root computation is refused.

Execution uses the shared order: registry `open`, registry `finalize`, the standard Cancun
beacon-root call, then ordinary transactions. Registry gas is counted before refunds; the
standard beacon-root call retains Ethereum's gas treatment. Ordinary transactions use the
separate ordinary capacity and base-fee calculation. A pool candidate exceeding the remaining
ordinary capacity can be skipped without aborting useful work. Replay still rejects an invalid
block containing such a transaction.

The result is an ordinary Ethereum payload with the commitment in `extraData`, real execution
and trie roots. A completed-parent capability for the next block is obtained through the shared
completion path; a payload ID or caller-provided gas scalar cannot mint one.

## Node wiring

`UnicityNode` implements `NodeTypes` with `UnicityEngineTypes` and the stock Ethereum network,
pool, executor and consensus components. Its payload component uses
`UnicityExecutionPayloadBuilder` with a `SealJobRegistry` the node holds. All clones of the
registry see the same entries, so the payload service and the seal method share one collection. The
engine API is the stock `BasicEngineApiBuilder` plus the `engine_forkchoiceUpdatedWithSealV1`
sibling, and the validator is the stock Ethereum payload structure and version-field validation
with no Unicity-specific verdict.

A seal job is constructed outside the node, so every piece of node configuration it needs must be
published by the node. The node publishes the exact `EthereumBuilderConfig` it hands to the payload
builder through `UnicityNode::builder_config`, and raises the registry capacity to
`max(16, max_payload_tasks * 4)` when that builder is constructed. A method that creates a
`ResolvedPayloadJob` must pass the published configuration, because the builder re-derives the
next-block attributes from its own copy and refuses a job that does not match; a second derivation
would drift and fail resolution at runtime.

## The seal methods

`engine_forkchoiceUpdatedWithSealV1(forkchoiceState, payloadAttributesV3, sealBuildInput)` runs the
D2 build flow in order: decode `rootInput` through the canonical CBOR codec; resolve
`headBlockHash`, where an unknown parent is SYNCING; bind the decoded input to that parent through
the U3a entry points; build the `UnicityEvmConfig` and `ResolvedPayloadJob` with the node's
published `EthereumBuilderConfig`; insert the job into the registry; and forward to the consensus
handle. A refusal from decoding, binding, the job checks or a duplicate payload id is INVALID with
the refusal in `validationError`. Absent `payloadAttributes` is INVALID. A missing
`builder_config` or a missing non-genesis parent accounting token is an internal error, not caller
input.

The method does not trial-execute the system operation. "Runs the system operation as step 0"
describes where the privileged `open` and `finalize` pair sits in the built block, which the bounded
kernel already does. A failed system operation therefore surfaces as a failed build.

The build path retains the opaque `CompletedParent` token for each block it builds and looks it up
when a later build names that block as its parent. The token is never derived from the parent
header, because the header carries the gross gas but not the system/ordinary split, so deriving it
would let a caller invent the parent's base-fee input. The store is bounded and evicts the oldest
entry first.

Only blocks this node built are recorded. A follower that imported the parent through
`engine_newPayloadWithSealV1` has no token for it, so a node cannot currently build on an imported
parent and the method refuses that parent as an internal error. U3e's import path executes imported
blocks through the same executor and must record the token there too; that is what lets a follower
lead in a rotating-leader shard. The token is not and must not be derived from the parent header.

`engine_getPayloadWithSealV1(payloadId)` resolves the built payload the way the stock `getPayloadV3`
path does and returns `{ executionPayload, blockValue, sealCompanion }`, with an unknown payload id
keeping the stock unknown-payload error. The companion's `rootInput` is re-encoded from the job's
decoded input with the canonical codec. That is byte-identical to what the caller supplied, because
the decoder accepts only canonical encodings and its round-trip invariant is asserted in both
directions, so re-encoding cannot differ from the caller's bytes. Its `provenance` is `"build"`.

The companion's `witnesses` list is empty. `sealBuildInput` carries no witnesses, so this node holds
none to put there, and a companion without them is not sufficient for a follower to authenticate
from: D2 has `VerifyCompanionWitnesses` consume a `VerifiedCert`, check the technical record against
`TRHash`, and require the transitions to equal the authenticated `ExpectedTransitions` byte for
byte. bft-core holds the authenticated certificate and is the party that can populate the witnesses
before dissemination. This is an open question on D2 rather than a decision made here; this crate
invents no witnesses, synthesises nothing from material it does not have, and does not widen
`sealBuildInput`.

The node keeps the stock EVM configuration out of Unicity builds. `UnicityExecutionPayloadBuilder`
resolves the per-job `UnicityEvmConfig` instead, so an operator's EVM caches or JIT settings do not
apply to a Unicity payload. The node-level EVM configuration is the next value that will have to be
published through the same slot mechanism as `builder_config` rather than a second channel; U3f
must do that before activation.

## Verification scope

The integration fixtures use the signed genesis and real trie provider introduced by the
execution crate. Their allocation includes the public test signing key and stock Cancun
beacon-root contract. The copies in this crate are test-only; they are not a deployment genesis
or a separately approved monetary configuration. The independent genesis oracle and provenance
are retained under `../execution/testdata/`.

These tests exercise in-process payload construction, replay, the bounded job registry and the
seal build refusals: a non-canonical `rootInput`, an unknown parent, absent attributes, a duplicate
payload id, and a job that resolves to the same configuration the payload service uses. The node
wiring and the RPC registration are compile-checked but not launch-tested here: launching the full
node and exchanging Engine RPC remains the M1 gate. They do not demonstrate an Engine RPC exchange,
certificate authentication, persistence or public activation. `v0` and the bft-core
execution-client pin are unchanged.