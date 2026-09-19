# Unicity payload construction

This crate is inactive: no node, Engine API method or capability registers either builder.
The commitment-only `UnicityPayloadBuilder` preserves U2's provision interface.
`UnicityExecutionPayloadBuilder` connects the actual transaction-pool payload builder to the
shared Unicity executor. It is the next private M1 integration step, not activation of D2.

## Per-job authority

An `ExecutionPayloadJobResolver` supplies an immutable `UnicityEvmConfig` for the requested
parent, attributes and commitment. `FixedPayloadJobResolver` is an immutable in-process
collection of explicitly supplied jobs; it does not fetch or authenticate witnesses.
Its eight-byte payload ID is only a lookup handle. Selection also compares the full parent and
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

## Verification scope

The integration fixtures use the signed genesis and real trie provider introduced by the
execution crate. Their allocation includes the public test signing key and stock Cancun
beacon-root contract. The copies in this crate are test-only; they are not a deployment genesis
or a separately approved monetary configuration. The independent genesis oracle and provenance
are retained under `../execution/testdata/`.

These tests exercise in-process payload construction and replay. They do not demonstrate an
Engine RPC exchange, certificate authentication, a running Unicity node, persistence or public
activation. `v0` and the bft-core execution-client pin are unchanged.
