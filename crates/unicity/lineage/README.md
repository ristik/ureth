# reth-unicity-lineage

Inactive Q3 lineage and activation-proof verifier (bft-core Q3 #50, slice C2a; design: `briefs/q3-design-v2.md`
sections 2 and 6). Nothing imports this crate yet, nothing registers it and no node path reaches it.

## What it verifies

`History::new(genesis_trust_base, pinned_id)` starts from the **locally pinned** root genesis: the epoch-1 unit
committee, self-signed by a quorum of its own members, whose canonical bytes hash to the pinned identity. Every
later epoch is appended only by `History::with_v3` (or `History::verify_envelope`, which calls it per link), and an
`Entry` has no public constructor, so a caller cannot mint an activation.

For each V3 link the verifier does not trust a supplied body id, projection or claim:

1. validates the V3 body (`BodyV3::validate`: bounded weights, unique identities and keys, exact threshold
   `floor(2W/3)+1`, the one Q3 protocol tuple, tuple network equal to the body's) and checks the network and root
   genesis against the history's, epoch order, and the predecessor hash against the tip (the tagged
   `UNICITY_TRUSTBASE_TO_V3` rule for the first V3 body);
2. resolves the **previous** epoch's scheme, keys and threshold from the verified history only, and verifies the
   old-committee commit proof under them: the committed `OrderedHandoffRecord`, the control leaf that carries it,
   the unicity-tree path to the state root, the commit QC's rounds, epoch, network and timestamps, and a strict
   quorum of signatures on its commit info;
3. derives the activation from that authenticated record, not from the envelope: the record must name the body
   identity and the tip as predecessor, `A* >= A_min`, `A*` after the previous epoch's start; the frozen identity
   and the candidate context must be those of the supplied evidence; every successor member must have signed one
   readiness receipt bound to network, genesis, predecessor, attempt, candidate, body and tuple;
4. derives the activation commit id and the epoch-anchor id `(E, A*-1)` and requires the envelope's claim to equal
   them field for field (`Kind::Binding` otherwise).

A link for an epoch the history already holds is a *retained* link and is not trusted for matching its claim: the body
identity is recomputed, the supplied commit proof is authenticated under the retained predecessor's committee, and the
committed record, candidate evidence and receipts must be the entry's (`Kind::Conflict` otherwise, as in #407's `retained`).
An epoch the history lacks is `Kind::MissingHistory`; an unknown epoch or round is `Kind::UnknownEpoch`, never a
legacy default. A previous epoch signed under scheme 2 is `Kind::Scheme`: there is no scheme-2 commit verifier yet
and no fallback to scheme 1. Every refusal is a typed `Error` whose `Kind::go_name()` is the name of the matching Go
sentinel in `bft-core/q3format`.

`votesig` holds the Q1 scheme-2 vote and timeout preimage encoders and signature checks, byte-for-byte those of
`bft-core/rootchain/consensus/votesig`. Nothing activates them.

## Not in this slice

* Build, import, devp2p-sync and recovery wiring, and durable retention of the envelopes (C2b).
* Chains that already took V2 handoffs: the first V3 link must follow the genesis directly. A V2 prior needs the
  legacy V2 activation verifier, which is not ported.
* The scheme-2 commit verifier for a second V3 handoff (`Kind::Scheme`).
* Authentication of the opaque envelope fields `rootInput`, `transitions`, `targetParent` and `blockId` against the
  verified context (they are carried and bounded, not yet compared).

## Conformance

`tests/` holds the Go/Rust suites. Vectors are committed under `testdata/` with their provenance:

* `go-lineage-vectors.json` is not part of #406/#407; it is emitted by bft-core's production `q3format` verifier at the #407 head
  (`d36d3611`) through `emit-go-lineage-vectors.go.txt` (copy it into `q3format/` as `rustvectors_test.go` and run
  `Q3_EMIT_RUST_VECTORS=out.json go test ./q3format -run TestEmitRustVectors`). The signers are random, so the file
  is generated once and committed. Rust reaches the same named verdict for every case, and the same epoch, A*, body
  id, activation commit id and anchor id for the accepted ones.
* `q3format-vectors.json` is #407's golden file (pinned by SHA-256 in `tests/vector_pins.rs`) (config, body, predecessor hashes, receipt message, envelope).
* `domain_bound_vectors.json` is the Q1 file at merged #406 (`c82cc826`): nine vectors, the seven of #394 plus #396's two
  paired quorum certificates (committing, with vote and seal signature maps, and non-committing). All are reproduced.

go-base verifies the 64-byte compact form of a 65-byte signature and drops its recovery byte, so flipping that byte
leaves a signature valid in Go and here; nothing hashes a signature, so no identity can change.
