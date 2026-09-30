# M2 companion-admission route matrix

The captured fixture test is
`crates/unicity/payload/tests/execution_payload.rs::captured_paid_idle_transition_fixture_covers_enabled_routes_and_mutations`.
It creates a three-block chain through the real Unicity builder: a paid block, an idle block,
then an idle epoch-acknowledgement block that advances the registry root epoch from 1 to 2 at the
frozen parent. The acknowledgement uses deterministic test IDs; BFT certificate authentication is
outside this Ureth route fixture. The bounded profile keeps the shard epoch at zero, so this does
not claim shard membership handoff coverage. Block 1 carries a first-certified input record and is
the certified boundary retained across the reorg mutation.
The same returned payload/companion pairs are then passed to follower import and restore replay.

| Route | State | Fixture evidence | Refusal / limit |
|---|---|---|---|
| `forkchoiceUpdatedWithSealV1` → payload build → `getPayloadWithSealV1` | Enabled | Captures the three blocks with the real payload builder and verifies the exact returned companion is stored by block hash. | Wrong-context root input is refused before a build job is inserted. |
| `newPayloadWithSealV1` follower import | Enabled | Imports those same three captured payload/companion pairs in order; checks valid status, Engine forwarding, accounting-token publication and companion retention. | Wrong context is INVALID before Engine forwarding. Importing block 2 before its parent token is SYNCING and is not forwarded. |
| Startup `repair_accounting` replay | Enabled | Replays the same three canonical blocks from the configured genesis anchor and checks all three exact-hash tokens. | Wrong parent/context is refused; a reorg above the first certified block cannot reuse the orphan companion or remove the boundary token. |
| Authenticated shard-journal suffix catch-up | Enabled transport in the BFT M2 profile | Existing BFT archive suffix and binding tests cover the transport and journal admission boundary. The pre-rebase M2a run `m2a-final-merged-20260930T071819Z` passed configured replica catch-up; the current post-rebase shared run `m3-acceptance-shared-20260930T1233Z` failed before Handoff 1 and adds no catch-up evidence. Seal execution after delivery still uses the paired import path above. | This Ureth in-process fixture does not claim to exercise the BFT network transport. The current lane helper probes the intentionally offline validator; details are recorded in [bft-core #311](https://github.com/ristik/bft-core/pull/311). |
| Stock `engine_newPayloadV1`–`V5` and generic P2P/pipeline sync | Disabled | Ureth #44 capability/refusal tests; the node uses a no-op network. | Must remain refused until a separately authenticated companion route is implemented. |

| Mutation | Build | Follower import | Restore replay |
|---|---|---|---|
| Wrong root context / parent binding | INVALID before job insertion | INVALID before Engine forwarding | Wrong parent binding fails before token publication |
| Wrong order / missing parent token | Refused before job insertion | SYNCING before Engine forwarding | Reordered parent binding is refused |
| Reorg above certified boundary | — | — | Alternate canonical hash cannot reuse the old companion; the first-certified boundary token remains |
| Interrupted before main DB acceptance | — | Engine INVALID after durable accounting-sidecar write | Canonical-only hydration ignores the orphan sidecar while the DB remains at genesis |
| Interrupted after main DB acceptance, before companion write | — | Engine VALID is preserved; the injected companion write failure is visible | Canonical accounting token hydrates; no token is invented from a missing companion |

Independent negative coverage is in the same acceptance change: `UnicityConsensus` reports the
typed `BaseFeeDiff`, `GasLimitInvalidDecrease` and `TimestampIsInPast` variants for one-field
header mutations, and the pinned registry EVM refuses `open` from a non-system public caller
without moving its round cursor. BFT `TestRound_RefusesCertificationWhenSelfVerificationIsInvalid`
pins the final certification boundary.
