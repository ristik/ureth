# Unicity payload construction

The commitment-only `UnicityPayloadBuilder` preserves U2's provision interface.
`UnicityExecutionPayloadBuilder` connects the actual transaction-pool payload builder to the
shared Unicity executor. `UnicityEngineTypes` and `UnicityNode` carry the Unicity payload
attributes end to end and use that builder with a bounded `SealJobRegistry`.

No Engine API method and no capability is registered, so the standard `engine_*` surface is
unchanged and normal node operation cannot reach a seal method. The node wiring is the attachment
point U3c to U3f build on, not activation of D2.

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
registry see the same entries, so the payload service and a future seal method share one
collection. The engine API is the stock `BasicEngineApiBuilder` and the validator is the stock
Ethereum payload structure and version-field validation with no Unicity-specific verdict.

A seal job is constructed outside the node, so every piece of node configuration it needs must be
published by the node. The node publishes the exact `EthereumBuilderConfig` it hands to the payload
builder through `UnicityNode::builder_config`, and raises the registry capacity to
`max(16, max_payload_tasks * 4)` when that builder is constructed. A method that creates a
`ResolvedPayloadJob` must pass the published configuration, because the builder re-derives the
next-block attributes from its own copy and refuses a job that does not match; a second derivation
would drift and fail resolution at runtime.

The node keeps the stock EVM configuration out of Unicity builds. `UnicityExecutionPayloadBuilder`
resolves the per-job `UnicityEvmConfig` instead, so an operator's EVM caches or JIT settings do not
apply to a Unicity payload. The node-level EVM configuration is the next value that will have to be
published through the same slot mechanism as `builder_config` rather than a second channel; U3c to
U3f must do that before activation.

## Verification scope

The integration fixtures use the signed genesis and real trie provider introduced by the
execution crate. Their allocation includes the public test signing key and stock Cancun
beacon-root contract. The copies in this crate are test-only; they are not a deployment genesis
or a separately approved monetary configuration. The independent genesis oracle and provenance
are retained under `../execution/testdata/`.

These tests exercise in-process payload construction, replay and the bounded job registry. The
node wiring is compile-checked but not launch-tested here: launching the full node and exchanging
Engine RPC remains the M1 gate. They do not demonstrate an Engine RPC exchange, certificate
authentication, persistence or public activation. `v0` and the bft-core execution-client pin are
unchanged.