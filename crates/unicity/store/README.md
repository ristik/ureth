# Unicity companion store

This inactive crate is the persistence half of Unicity companion retention: a durable,
block-hash-keyed store for `SealCompanion` values, with a settable retention horizon and pruning. It
is a library only. There is no node wiring, no RPC, no reth component and no notion of
canonicality; the store is told what to keep and what to drop.

`CompanionStore` owns a separate MDBX environment under the directory it is given. It does not
register a table in reth's environment and does not touch reth's databases. A `put` commits its
own transaction and syncs the environment before returning, so a reopen in a fresh process observes
the write.

`get` has three outcomes. `Found` carries the companion, byte-identical to what was stored.
`Unavailable` says the node cannot produce the companion and has published a retention horizon,
which accompanies the answer. The horizon is the node's retention boundary, not a claim about the
block's number. `Unknown` says the node has no record of the hash and has never published a horizon.

The store keeps no tombstones for dropped entries, because that would retain the unbounded set that
pruning exists to drop. The accepted consequence is that `Unknown` is only reachable on a node that
has never published a horizon; once a horizon exists, any absent hash answers `Unavailable`. Both
are statements about what the node can serve, never about the validity or certification of the
block. The crate documentation states this trade-off in full.

Values use the crate's own versioned, length-prefixed record encoding, so a stored companion decodes
back to exactly the bytes that were written without a serde or JSON round trip. An unknown version
byte is a typed error.