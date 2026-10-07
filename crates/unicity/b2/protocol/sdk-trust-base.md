# Fixed SDK trust input (unreleased protocol v2)

Use the existing SDK 3.0.1 verification model with one provisioned RootTrustBase
for every ordinary inclusion UC and the embedded EVM UC. Every configured
stake/native validator weight MUST be 1, with N distinct validators and SDK
`quorumThreshold=N-(N-1)/3`, describing the same native deployment committee.
Installation rejects non-unit weights and mismatched deployment authority;
it never flattens arbitrary weights into a count threshold. Provisioning
explicitly authenticates correspondence to network/root genesis out of band.

Every UC seal's network/epoch MUST equal that base; root round MUST be at least
`epochStartRound`. These scope checks do not implement epoch evolution. No end
interval, successor selection, alternate keys, epoch resolver, private trust
bundle, weighted verifier or handoff verifier is supplied by the bridge.

## Exact trustBaseId preimage

Publish once, using JS SDK 3.0.1 at
`f5f0737306901215860aa920a6ab570b699efba8`:

`B=UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))`

B has no BOM or trailing newline; `trustBaseId=SHA256(B)` is raw 32 bytes. The
manifest's `trustBase.document.sha256` identifies those exact installed bytes
and MUST equal J's existing 32-byte slot. No J/LockProof arity changes. B is the
existing SDK JSON representation, not an order-independent canonical JSON
scheme, native epoch artifact, SDK stateHash, or the external bridge's six-field
hash. Semantically equivalent alternative serializations have different IDs.

The SDK top-level field order is `changeRecordHash, epoch, epochStartRound,
networkId, previousEntryHash, quorumThreshold, rootNodes, signatures, stateHash,
version`; node fields are `nodeId, sigKey, stake`. Keep SDK numeric strings,
hex/null handling, node/signature order, version 1 and values representable in
both SDKs. Verification hashes the installed original B, never a reconstructed
Rust object (which retains fewer JSON metadata fields).

TS loads B with `fromJSON`; Rust loads the same bytes with `from_json` under std.
Alloc-only provisioning may construct SDK objects via public constructors but
MUST bind their complete verification-relevant fields to B and its digest;
an independently caller-asserted ID/object pair is insufficient. A digest and
successful parsing establish integrity, not authority. Locations are optional
installation metadata; receipt receives the installed input and never fetches.

Exact synthetic fixture: [sdk-root-trust-base.json](vectors/config/sdk-root-trust-base.json),
358 UTF-8 bytes, SHA-256
`e503a064a16d43c5ad3d53bb8b859667781a349f26e7d4ca03446652741d3c08`.
It is SDK-emitted JSON, network 1/epoch 7/start 100, one unit-stake generator-key
validator, count threshold 1. It is test data, not an authenticated deployment.
[Provenance](vectors/config/sdk-root-trust-base.provenance.json) records the SDK
pin, method and digest; `node tools/sdk_trust_fixture.mjs` reproduces/checks it.
The full single corpus remains unreleased until the PR2 candidate is imported.

## Existing SDK verification and transport

After cumulative canonical pre-scan, ordinary proofs use the SDK's existing
token verification: TS default token/certified-transaction/inclusion/UC rules;
Rust `verify_token_with_policy` with justification/data registries. Add bridge
strict unlock recovery, issuance/whole-asset/no-split, configuration and Rust's
missing `t<=IR.timestamp` check; missing genesis reason/data rejects explicitly.
No native-weight authority gate is conjoined with or substituted for SDK checks.

Embedded UC verification uses existing SDK objects and rules. TS decodes
`UnicityCertificate.fromCBOR`, checks network against the supplied base, and
requires OK from `UnicitySealHashMatchesWithRootHashRule.verify(uc)` and
`UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()).verify(base, uc.unicitySeal)`.
Its higher-level UC verifier requires an inclusion proof; do not invent one for
EVM storage evidence.

Rust's standalone UC verifier is private. Its minimal `verify_embedded_uc`
helper reproduces only that SDK composition using public primitives:
`base.validate()`, seal-network equality, `uc.computed_seal_hash()` equality,
`seal.calculate_hash()`, SDK `Signature::decode/verify`, and distinct valid
signer-ID/key count against `base.quorum_threshold`. Preserve SDK skipping of
unknown/invalid signatures and error outcomes. It defines no authority format,
selection policy or native-weight logic and is used only for embedded backing;
ordinary verification already calls the SDK. No private SDK-module access.

Both ordinary and embedded UC bytes MUST satisfy canonical native shapes
intersected with the pinned SDK codecs: 65-byte seal signatures with native suffix 0/1, byte-string IR
summary, array-valued shard siblings/Unicity steps (empty arrays allowed), valid
signature maps, SDK integer/key widths, and tighter existing bridge/native
bounds. Construction/import/refresh fails `UnsupportedCertificateEncoding`
outside this subset. No 64-to-65-byte conversion, null-to-empty rewrite or
mutation of committed J is allowed. Shared positives use low-s, correctly
recoverable signatures accepted by both SDKs and B1.

TS seal verification binds recovery parity; Rust SDK explicit-key seal checking
does not. Native B1 accepts additional encodings (64 bytes, or an ignored 0/1
suffix). Keep these acceptance-set differences as conformance limitations;
strict token-unlock recovery equality is separate and unchanged. Native B1
consensus, registry, live window and ABI are unchanged.

After SDK UC authentication, backing still requires bridge-specific pinned
PDR/partition/shard/configuration and PDR epoch=IR epoch, header hash/state root,
vault account/code hash, storage MPT and reconstructed permanent lock digest.
SDK acceptance never replaces these backing bindings.

## Fixed profile lifecycle and deferred work

Keep J immutable. Refresh paths/UCs only within the provisioned base/epoch while
preserving M/T/CD/original t. Another base/epoch is unsupported; never fetch,
append records, union keys or claim old backing survives rotation. Bind caches
to token bytes, SDK document digest and manifest/profile revision.

**DEFERRED: common SDK trust-base work / unsupported in this profile** —
arbitrary weights (including 98/1/1), mixed historical/current committees,
trust-base append/fetch, epoch changes/interval closure, old-J validity through
rotation and full B1/SDK seal parity. Track [bft-core #421](https://github.com/ristik/bft-core/issues/421).
Supported acceptance covers fixed-base offline verification, unit-weight count
quorum, digest/base/network/epoch mismatch rejection, SDK-codec round trips,
embedded backing and same-base refresh. Deferred scenarios are not passing
coverage or promised rotating-deployment acceptance.
