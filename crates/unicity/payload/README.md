# Unicity payload construction

The commitment-only `UnicityPayloadBuilder` preserves U2's provision interface.
`UnicityExecutionPayloadBuilder` connects the actual transaction-pool payload builder to the
shared Unicity executor. `UnicityEngineTypes` and `UnicityNode` carry the Unicity payload
attributes end to end and use that builder with a bounded `SealJobRegistry`. The
`engine_forkchoiceUpdatedWithSealV1` sibling is registered on the authenticated engine module.

The three seal methods are reachable and advertised together. The M1 node does not register or
advertise stock `engine_newPayloadV1` through `engine_newPayloadV5`: those routes have no
authenticated root input or checked parent-accounting preflight. Network admission uses a no-op
network, so autonomous P2P and pipeline header sync cannot advance this node. General stock
Engine import and headers-first sync are deferred capabilities. Seal imports and builds remain the
authenticated advancement path; missing local accounting answers `SYNCING` and can be retried.

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

`UnicityNode` implements `NodeTypes` with `UnicityEngineTypes`, a no-op network, and
`UnicityConsensus`, which retains the Ethereum checks except for ordinary-gas fee feedback. Its payload component uses `UnicityExecutionPayloadBuilder` with a
`SealJobRegistry` the node holds, and its executor component is `UnicityExecutorBuilder`, which
supplies `UnicityNodeEvmConfig`. All clones of the registry see the same entries, so the payload
service and the seal method share one collection. The engine API advertises the three seal
methods and withholds stock `newPayload` versions. The validator
is the stock Ethereum payload structure and version-field validation with no Unicity-specific
verdict.

A seal job is constructed outside the node, so every piece of node configuration it needs must be
published by the node. The node publishes the exact `EthereumBuilderConfig` it hands to the payload
builder through `UnicityNode::builder_config`, and raises the registry capacity to
`max(16, max_payload_tasks * 4)` when that builder is constructed. A method that creates a
`ResolvedPayloadJob` must pass the published configuration, because the builder re-derives the
next-block attributes from its own copy and refuses a job that does not match; a second derivation
would drift and fail resolution at runtime.

## Durable parent accounting

Every completed build and checked seal replay writes a versioned accounting record to the
companion store's separate accounting table before the block can be delivered to the engine or
caller. The record is keyed by exact block hash and binds chain ID, configured genesis, block
number, the full five-value profile, and the accounting rule version. Companion v1 bytes do not
change. A failed accounting write stops build or import before advancement.

Consensus initialization opens the shared store and hydrates canonical tokens around both the
visible and persisted database tips before exposing the validator. Later exact-hash lookups can
restore side-branch tokens without substituting the canonical head. Every memory and disk hit is
checked against the supplied sealed header, chain, and profile. Active lookups pin the token
through header validation. A missing or corrupt record discovered during a request returns
recoverable unavailability; one found during startup stops launch with a diagnostic.

If the canonical head record is missing at startup, repair replays forward from the nearest
verified record within `--unicity.accounting-repair-limit` blocks (default 64). B0 is the
configured-genesis anchor with zero system gas, so B1 can be repaired when its body and companion
remain available. A longer gap stops startup with an unavailable diagnostic. Accounting retention
uses the persisted database frontier and keeps the hydration window plus the repair bound,
independently of companion pruning.
When companion pruning is configured, its depth must cover the 16-block accounting window plus
the repair limit. The node rejects a smaller depth at startup because replay needs companions.

## The seal methods

`engine_forkchoiceUpdatedWithSealV1(forkchoiceState, payloadAttributesV3, sealBuildInput)` runs the
D2 build flow in order: decode `rootInput` through the canonical CBOR codec; resolve
`headBlockHash`, where an unknown parent is SYNCING; bind the decoded input to that parent through
the U3a entry points; build the `UnicityEvmConfig` and `ResolvedPayloadJob` with the node's
published `EthereumBuilderConfig`; insert the job into the registry; and forward to the consensus
handle. An identical build retry reuses its existing payload id and job. A refusal from decoding,
binding, the job checks or a payload id collision with different input is INVALID with
the refusal in `validationError`. Absent `payloadAttributes` is INVALID. A missing
`builder_config` is an internal error. Missing non-genesis parent accounting returns `SYNCING` so
the same request can be retried when the token becomes available.

The method does not trial-execute the system operation. "Runs the system operation as step 0"
describes where the privileged `open` and `finalize` pair sits in the built block, which the bounded
kernel already does. A failed system operation therefore surfaces as a failed build.

The build path retains the opaque `CompletedParent` token for each block it builds and looks it up
when a later build names that block as its parent. The token is never derived from the parent
header, because the header carries the gross gas but not the system/ordinary split, so deriving it
would let a caller invent the parent's base-fee input. The store is bounded and evicts the oldest
entry first.

Both the build path and the import path record the opaque `CompletedParent` token for each block
they process: the build path after a successful build, and `engine_newPayloadWithSealV1` after a
successful replay. A node that followed round N can therefore lead round N+1 in a rotating-leader
shard, which was previously impossible because the token existed only for blocks the node built.
The token is never derived from the parent header.

`engine_getPayloadWithSealV1(payloadId)` resolves the built payload the way the stock `getPayloadV3`
path does and returns `{ executionPayload, blockValue, sealCompanion }`, with an unknown payload id
keeping the stock unknown-payload error. If the payload resolves while its build job has been
evicted from the bounded registry, the method returns its own error code (`-39001`) saying the
companion is no longer retained for that payload id, so an operator can tell that apart from an
unknown id. The companion's `rootInput` is re-encoded from the job's decoded input with the
canonical codec. That is byte-identical to what the caller supplied, because the decoder accepts
only canonical encodings and its round-trip invariant is asserted in both directions, so
re-encoding cannot differ from the caller's bytes. Its `provenance` is `"build"`.

Reth drops the payload build job after `getPayload` resolves it. An identical build retry while the
job is live reuses it; a retry after delivery creates a fresh job and can select a different
transaction set if the pool changed. Ureth therefore does not guarantee one block per payload id
across delivery. The bft-core execution journal is the guard: it prevents publishing a second
distinct locally built candidate for the same authorization.

The companion's `witnesses` list is empty, and that is correct rather than incomplete.

D2 §2 "The authentication lifecycle" settles it. The witness is not a commitment-bound field: the
header commits only to `SHA-256(CBOR(rootInput))`, and D2 states that witnesses authenticate
`rootInput` and are "not re-hashed into the commitment". A receiver therefore cannot validate them
by hashing, and D2's implementation boundary says `VerifiedCert` and `ExpectedTransitions` are
"verifier-owned inputs, never trusted fields deserialized straight from a peer companion", with
`VerifyCompanionWitnesses` being "the check, never the source of trust".

D2's "Who runs it, per path" list assigns the work accordingly. On the build path the shard node is
the leader, holds the verified certificate and emits `VerifiedCert` and `ExpectedTransitions` in the
companion. On `newPayloadWithSealV1` the shard-node adapter derives both verified inputs and runs
`VerifyCompanionWitnesses` before the call, and reth accepts that verdict only over the
JWT-authenticated channel. On devp2p import and offline re-execution the importer re-derives both
itself.

The execution client is not the verifier on any path. It holds no trust base, no certificate and no
committed cursor, and acquiring them would move the authentication boundary into the execution
client, which is the surface this fork exists to keep small. So this method returns the companion
fields the node owns, and bft-core supplies the verifier-owned part before dissemination. This crate
invents no witnesses, synthesises nothing from material it does not have, and does not widen
`sealBuildInput`.

`engine_newPayloadWithSealV1(executionPayloadV3, expectedBlobVersionedHashes, parentBeaconBlockRoot,
sealCompanion)` is the import path. It runs its pre-checks (canonical decode, empty blob hash list,
version-field validation, payload conversion with sender recovery, parent resolution, binding and
the shared `replay_complete`), records the returned accounting token, registers the bound execution
input for the block's commitment, forwards the payload to the consensus engine as the stock
`newPayloadV3` does, and returns the engine's `PayloadStatus`. A state-root or execution mismatch is
INVALID with the refusal in `validationError`. An unknown parent or a parent without a token is
SYNCING. It does not verify witnesses; the shard-node adapter runs `VerifyCompanionWitnesses` before
the call and reth accepts that verdict over the JWT-authenticated channel.

A local parent without a recorded token is also SYNCING, not INVALID. This is a reading of D2: the
block is not invalid, and the node cannot establish the parent accounting until the parent has been
seal-executed locally through this same path. Treating a never-seal-executed parent as not yet local
is what makes the seal chain import contiguous. The method never re-executes the parent recursively
and never mints a token from a header.

The import needs a node executor that can execute a seal block. `UnicityNodeEvmConfig` replaces the
stock Ethereum executor component and resolves each block's bound input from its 32-byte `extraData`
commitment, so the engine tree executes an imported seal block through the same bounded executor as
a locally built one. Without a registered commitment the execution fails with the named
missing-input error rather than falling back to stock execution, which would accept a block nobody
authenticated. The import registers the input before forwarding.

Devp2p sync of seal blocks does not work yet. Nothing populates the execution-input registry on that
path, so a seal block received from a peer fails execution with the named missing-input error. D2
expects a devp2p importer to re-derive the certificate and transitions and re-run the check, which
is a different entry point from this unit's forward. That is remaining work.

The node keeps the stock EVM configuration out of Unicity builds. `UnicityExecutionPayloadBuilder`
resolves the per-job `UnicityEvmConfig` instead, so an operator's EVM caches or JIT settings do not
apply to a Unicity payload. The node-level EVM options are the next value that will have to be
published through the same slot mechanism as `builder_config` rather than a second channel, so that
the node executor can use them too.

## Verification scope

The integration fixtures use the signed genesis and real trie provider introduced by the
execution crate. Their allocation includes the public test signing key and stock Cancun
beacon-root contract. The copies in this crate are test-only; they are not a deployment genesis
or a separately approved monetary configuration. The independent genesis oracle and provenance
are retained under `../execution/testdata/`.

These tests exercise in-process payload construction, replay, the bounded job registry, the seal
build refusals and the seal import verdicts: a non-canonical `rootInput`, an unknown parent, absent
attributes, an identical build retry, a job that resolves to the same configuration the payload
service uses, a state-root mismatch, a missing parent, a parent without a token, non-empty blob
hashes, and that ACCEPTED is never produced. They also cover the execution-input registry
(idempotent duplicate, conflicting input, oldest-first eviction), node EVM resolution by commitment,
closed execution without a registered input, a forward to a fake engine handle that returns its
verdict, and the advertised capability set. The fake engine does not execute or persist. The
`fee_consensus_smoke.py` process check builds and imports B1 through B3 through the real Engine
RPC; it does not demonstrate certificate authentication,
certificate authentication, real persistence or public activation. `v0` and the bft-core
execution-client pin are unchanged.
