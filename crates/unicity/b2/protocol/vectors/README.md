# Canonical corpus workflow

The corpus is the bft-core PR2 SDK3 candidate (generator commit and command in
provenance.json), imported with `vectors.py import` under the digest in
MANIFEST.sha256. The fixed SDK trust document config/sdk-root-trust-base.json is
the bytes JS SDK 3.0.1 emits (`node tools/sdk_trust_fixture.mjs` reproduces it;
`--corpus protocol/vectors` checks every trust document of the corpus). Do not
import the old `bridge-pr1-vectors-v1.json` or make up deployment/runtime pins.

The candidate producer writes fixtures under all nine family directories.
Include the actual canonical profile at `config/semantic-profile.json`; its
exact bytes must match semanticProfileSha256. Each case must publish ID, canonical preimages/bytes/digests, semantic outcome,
profile/version, leaves (sid,txHash,referenceTime,leafValue), B1 requests/results
and provenance. Preserve the 99 baseline IDs as mapped regressions where
meaningful; the SDK3 corpus count/bytes need not equal the old corpus. Required
new coverage includes deadlines/time equality and mutations, IR openings,
refresh preserving t, all pre-3.0 shapes, exact recovery, value/issuance policy,
embedded UC/header/MPT bindings and budgets, fixed-base offline receipt,
JSON digest mismatch, missing/mismatched base, epoch mismatch rejection,
unit-weight count-quorum boundaries, supported certificate encoding, and
same-base refresh preserving J/M/CD/t; crash-recovered burn and nonce replay/
accounting failures. DEFERRED under bft-core #421: arbitrary weights, mixed
committees, trust-base append/fetch, interval closure, old-J validity through
rotation and full B1/SDK seal acceptance parity. These are unsupported scenarios,
not passing coverage or current-profile activation prerequisites.

Provenance JSON has exactly these fields (replace metavariables with real pins):

```json
{
  "protocolVersion": 2,
  "sdkVersion": "3.0.1",
  "semanticProfileSha256": "<64 lowercase hex: actual canonical profile artifact>",
  "generator": {
    "repository": "https://github.com/ristik/bft-core.git",
    "commit": "<40 lowercase hex: committed candidate oracle revision>",
    "command": ["go", "run", "./cmd/<PR2 generator>", "-out", "{output}"]
  }
}
```

The generator command must write all fixture files into its output directory,
never a second authoritative golden copy. The entry-point name/flags are
recorded from the actual PR2 implementation, not an invented future command.
`seal` writes canonical provenance, VERSION=2, a sorted SHA256SUMS over every
fixture plus VERSION/provenance, and MANIFEST.sha256 hashing the exact sums.
The README, .gitkeep and digest control files are excluded from recursive sums.
Timestamps, absolute paths and machine metadata must not enter the artifact.

```sh
python3 tools/vectors.py seal /path/to/candidate --provenance /path/to/provenance.json
python3 tools/vectors.py import /path/to/candidate --expected-digest <producer-digest>
python3 tools/vectors.py check --expected-digest <producer-digest>
python3 tools/vectors.py regenerate --oracle /path/to/bft-core
```

Import validates and stages the full snapshot before replacing bytes. Review
its diff and semantic evidence. Hash checking protects integrity, not semantic
correctness; review and oracle/independent constructor tests establish that.
Regeneration executes the pinned Go command from an isolated checkout with a
private disposable GOCACHE, writes to a temporary directory and byte-compares
the full result. No consumer worktree is modified. Consumer cache keys are the
merged protocol commit plus MANIFEST.sha256 digest; verify before offline use.
Candidate commits may be used for cross-repo CI bootstrap; released consumers
must pin merged revisions. PR3 finalizes the merged oracle pin and independent
TS/Rust SDK construction. Consumers never hand-edit or regenerate their own
copies as a competing authority.
