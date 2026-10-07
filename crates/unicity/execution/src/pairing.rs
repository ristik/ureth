//! The paired-execution binding: what the local Go verification vouches for, and the Rust gate
//! that checks it before anything is installed or executed.
//!
//! Each co-hosted BFT/EVM pair trusts its own authenticated Go verification. That verification
//! reconstructs the history from the pinned root genesis, derives the exact execution input for the
//! named parent, and then signs nothing: it hands the execution client a [`PairBinding`], a
//! canonical CBOR value naming everything the derivation depended on. This module decodes that
//! value strictly, and [`verify_pair_binding`] compares every field with what Rust can see for
//! itself: its own pins, the genesis it was configured with, the parent header it holds, the
//! decoded root input and the exact build job or imported block.
//!
//! A binding is not a certificate and Rust verifies no signature here. It is a commitment that
//! makes substitution detectable: an input for another network, genesis, parent, origin,
//! configuration or block cannot be presented under a binding that names a different one, and a
//! remote peer's boolean or an unbound request carries no binding at all and is refused by the
//! decoder.
//!
//! # Encoding
//!
//! One fixed RFC 8949 deterministic array, no optional or unknown fields, one version:
//!
//! ```text
//! [ "UNICITY_PAIR_BINDING", 1,
//!   networkId, rootGenesisId, executionGenesisHash,
//!   parentHash, parentNumber, originRootEpoch, originRootRound,
//!   configurationId, activationId, rootInputHash, transitionsHash,
//!   subjectKind, subjectId ]
//! ```
//!
//! Every identity is a 32-byte string. `subjectKind` is [`SUBJECT_BUILD`] with `subjectId` the
//! [`attributes_digest`] of the build job, or [`SUBJECT_IMPORT`] with `subjectId` the hash of the
//! imported block.
//!
//! # Interface assumptions (to be agreed with bft-core D2b)
//!
//! - `rootGenesisId` and `networkId` are pinned in the node's seal configuration and echoed by
//!   `sealConfigV1`, so the Go side compares them against its own genesis before the first build.
//! - `configurationId` is the root origin's `shardConfHash`.
//! - `activationId` is the acknowledged transition's `commitId` when the root input carries a
//!   transition; with no transition the epoch's activation is not derivable from the input and the
//!   field is carried and retained unchecked, except that it may not be all zero. It is inert
//!   metadata from this pair's trusted Go side, not an independently checked activation binding,
//!   and it never substitutes for restart reauthentication (`engine_admitParentV1`). Go's rule: the
//!   verified activation commit id of the origin's root epoch when its history holds one, otherwise
//!   a fixed non-zero identity derived from the configuration (Go's genesis entry has no activation
//!   commit id).
//! - `rootInputHash` is `SHA-256` of the canonical root input, the header `extraData` commitment.
//! - `transitionsHash` is `SHA-256` of the canonical CBOR array of the transition byte strings,
//!   exactly the `D[]` encoding inside the root input.
//! - `attributesDigest` is `SHA-256` of the canonical CBOR array `["UNICITY_PAIR_JOB", 1,
//!   timestamp, prevRandao, suggestedFeeRecipient, parentBeaconBlockRoot]`.

use crate::{
    array, bytes, sha256, text, uint,
    wire::{CanonicalCborError, Decoder},
    ExecutionError, RootInputV2,
};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use reth_primitives_traits::SealedHeader;

/// Domain string that opens every binding.
pub const PAIR_BINDING_DOMAIN: &str = "UNICITY_PAIR_BINDING";
/// The only binding version.
pub const PAIR_BINDING_VERSION: u64 = 1;
/// Domain string of the build-job digest.
pub const PAIR_JOB_DOMAIN: &str = "UNICITY_PAIR_JOB";
/// Largest accepted encoded binding. The fixed shape is under 400 bytes.
pub const MAX_PAIR_BINDING_BYTES: usize = 512;
/// `subjectKind` of a build job.
pub const SUBJECT_BUILD: u64 = 1;
/// `subjectKind` of an imported block.
pub const SUBJECT_IMPORT: u64 = 2;

/// What the binding says it is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairSubject {
    /// A block this node is about to build: the digest of the exact attributes.
    Build {
        /// [`attributes_digest`] of the build attributes.
        attributes_digest: B256,
    },
    /// A block this node is about to import or has imported.
    Import {
        /// Hash of the block.
        block_hash: B256,
    },
}

impl PairSubject {
    const fn kind(self) -> u64 {
        match self {
            Self::Build { .. } => SUBJECT_BUILD,
            Self::Import { .. } => SUBJECT_IMPORT,
        }
    }

    const fn id(self) -> B256 {
        match self {
            Self::Build { attributes_digest } => attributes_digest,
            Self::Import { block_hash } => block_hash,
        }
    }
}

/// The decoded, structurally valid binding. Decoding is not verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairBinding {
    /// Root network identifier.
    pub network_id: u64,
    /// Identity of the pinned root genesis.
    pub root_genesis_id: B256,
    /// Hash of the execution genesis block.
    pub execution_genesis_hash: B256,
    /// Hash of the execution parent the input is derived for.
    pub parent_hash: B256,
    /// Height of that parent.
    pub parent_number: u64,
    /// Root epoch of the input's origin.
    pub origin_root_epoch: u64,
    /// Root round of the input's origin.
    pub origin_root_round: u64,
    /// Authenticated shard configuration identity.
    pub configuration_id: B256,
    /// Activation identity; see the module docs.
    pub activation_id: B256,
    /// `SHA-256` of the canonical root input.
    pub root_input_hash: B256,
    /// `SHA-256` of the canonical array of transition bodies.
    pub transitions_hash: B256,
    /// The exact build job or imported block.
    pub subject: PairSubject,
}

/// Named refusal for a binding that is malformed or does not match what Rust holds.
///
/// The decoding variants say the bytes are not a binding; every `*Mismatch` variant says the
/// binding is well formed but names something other than the local value, and each is raised by
/// exactly one comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairBindingError {
    /// The binding is absent.
    Missing,
    /// The encoded binding is longer than [`MAX_PAIR_BINDING_BYTES`].
    TooLarge {
        /// Length supplied.
        len: usize,
    },
    /// The bytes are not a canonical CBOR binding of the fixed shape.
    Malformed(CanonicalCborError),
    /// The domain string is not [`PAIR_BINDING_DOMAIN`].
    WrongDomain,
    /// The version is not [`PAIR_BINDING_VERSION`].
    WrongVersion(u64),
    /// The subject kind is neither [`SUBJECT_BUILD`] nor [`SUBJECT_IMPORT`].
    UnknownSubject(u64),
    /// A required identity is all zero.
    ZeroIdentity(&'static str),
    /// The supplied root input could not be committed.
    RootInput(ExecutionError),
    /// `networkId` differs from the node's pinned network.
    NetworkMismatch,
    /// `rootGenesisId` differs from the node's pinned root genesis.
    RootGenesisMismatch,
    /// `executionGenesisHash` differs from the configured genesis.
    ExecutionGenesisMismatch,
    /// The root input names another network than the binding.
    InputNetworkMismatch,
    /// `parentHash` differs from the local parent.
    ParentHashMismatch,
    /// `parentNumber` differs from the local parent's height.
    ParentNumberMismatch,
    /// `originRootEpoch` differs from the root input's origin.
    OriginEpochMismatch,
    /// `originRootRound` differs from the root input's origin.
    OriginRoundMismatch,
    /// `configurationId` differs from the root input's configuration.
    ConfigurationMismatch,
    /// `activationId` differs from the root input's acknowledged transition.
    ActivationMismatch,
    /// `rootInputHash` differs from the supplied root input.
    RootInputMismatch,
    /// `transitionsHash` differs from the supplied transitions.
    TransitionsMismatch,
    /// The binding is for a build but an import was expected, or the reverse.
    WrongSubjectKind {
        /// The kind the flow requires.
        expected: u64,
        /// The kind the binding carries.
        found: u64,
    },
    /// The build job's attributes differ from the ones the binding names.
    JobMismatch,
    /// The imported block differs from the one the binding names.
    BlockMismatch,
}

impl std::fmt::Display for PairBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "pair binding refused: {self:?}")
    }
}

impl std::error::Error for PairBindingError {}

/// The node's pinned pair identity: what its local Go verification was configured against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairPins {
    /// Root network identifier.
    pub network_id: u64,
    /// Identity of the pinned root genesis.
    pub root_genesis_id: B256,
}

/// What the flow expects the binding's subject to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedSubject {
    /// A build with these exact attributes.
    Build {
        /// [`attributes_digest`] of the attributes the job was resolved with.
        attributes_digest: B256,
    },
    /// An import of this exact block.
    Import {
        /// Hash of the block.
        block_hash: B256,
    },
}

/// Everything Rust holds locally that a binding is compared against.
#[derive(Clone, Copy, Debug)]
pub struct PairContext<'a> {
    /// The node's pins.
    pub pins: PairPins,
    /// Hash of the configured execution genesis.
    pub execution_genesis_hash: B256,
    /// The local parent header.
    pub parent: &'a SealedHeader<Header>,
    /// The decoded root input the binding must name.
    pub root: &'a RootInputV2,
    /// The build job or block the flow is about.
    pub subject: ExpectedSubject,
}

impl PairBinding {
    /// Encodes the binding canonically.
    pub fn canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        array(&mut out, 15);
        text(&mut out, PAIR_BINDING_DOMAIN);
        uint(&mut out, PAIR_BINDING_VERSION);
        uint(&mut out, self.network_id);
        bytes(&mut out, self.root_genesis_id.as_slice());
        bytes(&mut out, self.execution_genesis_hash.as_slice());
        bytes(&mut out, self.parent_hash.as_slice());
        uint(&mut out, self.parent_number);
        uint(&mut out, self.origin_root_epoch);
        uint(&mut out, self.origin_root_round);
        bytes(&mut out, self.configuration_id.as_slice());
        bytes(&mut out, self.activation_id.as_slice());
        bytes(&mut out, self.root_input_hash.as_slice());
        bytes(&mut out, self.transitions_hash.as_slice());
        uint(&mut out, self.subject.kind());
        bytes(&mut out, self.subject.id().as_slice());
        out
    }

    /// Decodes one canonical binding. The only way to obtain a [`PairBinding`] from bytes.
    ///
    /// Refuses an empty input, anything over [`MAX_PAIR_BINDING_BYTES`], non-minimal heads,
    /// indefinite lengths, wrong arity or types, wrong domain or version, an unknown subject kind,
    /// an all-zero identity and trailing bytes.
    pub fn from_canonical_cbor(raw: &[u8]) -> Result<Self, PairBindingError> {
        if raw.is_empty() {
            return Err(PairBindingError::Missing);
        }
        if raw.len() > MAX_PAIR_BINDING_BYTES {
            return Err(PairBindingError::TooLarge { len: raw.len() });
        }
        let mut decoder = Decoder::new(raw);
        let arity = decoder.read_array().map_err(PairBindingError::Malformed)?;
        if arity != 15 {
            return Err(PairBindingError::Malformed(CanonicalCborError::WrongArity {
                expected: 15,
                found: arity,
            }));
        }
        if decoder.read_text().map_err(PairBindingError::Malformed)? != PAIR_BINDING_DOMAIN {
            return Err(PairBindingError::WrongDomain);
        }
        let version = decoder.read_uint().map_err(PairBindingError::Malformed)?;
        if version != PAIR_BINDING_VERSION {
            return Err(PairBindingError::WrongVersion(version));
        }
        let m = PairBindingError::Malformed;
        let network_id = decoder.read_uint().map_err(m)?;
        let root_genesis_id = decoder.read_word().map_err(m)?;
        let execution_genesis_hash = decoder.read_word().map_err(m)?;
        let parent_hash = decoder.read_word().map_err(m)?;
        let parent_number = decoder.read_uint().map_err(m)?;
        let origin_root_epoch = decoder.read_uint().map_err(m)?;
        let origin_root_round = decoder.read_uint().map_err(m)?;
        let configuration_id = decoder.read_word().map_err(m)?;
        let activation_id = decoder.read_word().map_err(m)?;
        let root_input_hash = decoder.read_word().map_err(m)?;
        let transitions_hash = decoder.read_word().map_err(m)?;
        let kind = decoder.read_uint().map_err(m)?;
        let subject_id = decoder.read_word().map_err(m)?;
        decoder.finish().map_err(m)?;
        let subject = match kind {
            SUBJECT_BUILD => PairSubject::Build { attributes_digest: subject_id },
            SUBJECT_IMPORT => PairSubject::Import { block_hash: subject_id },
            other => return Err(PairBindingError::UnknownSubject(other)),
        };
        for (name, word) in [
            ("rootGenesisId", root_genesis_id),
            ("executionGenesisHash", execution_genesis_hash),
            ("parentHash", parent_hash),
            ("configurationId", configuration_id),
            ("activationId", activation_id),
            ("rootInputHash", root_input_hash),
            ("transitionsHash", transitions_hash),
            ("subjectId", subject_id),
        ] {
            if word == B256::ZERO {
                return Err(PairBindingError::ZeroIdentity(name));
            }
        }
        Ok(Self {
            network_id,
            root_genesis_id,
            execution_genesis_hash,
            parent_hash,
            parent_number,
            origin_root_epoch,
            origin_root_round,
            configuration_id,
            activation_id,
            root_input_hash,
            transitions_hash,
            subject,
        })
    }
}

/// `SHA-256` of the canonical CBOR array of the transition byte strings.
pub fn transitions_hash(transitions: &[Vec<u8>]) -> B256 {
    let mut out = Vec::new();
    array(&mut out, transitions.len() as u64);
    for transition in transitions {
        bytes(&mut out, transition);
    }
    sha256(&out)
}

/// The digest that names one build job.
pub fn attributes_digest(
    timestamp: u64,
    prev_randao: B256,
    suggested_fee_recipient: Address,
    parent_beacon_block_root: B256,
) -> B256 {
    let mut out = Vec::new();
    array(&mut out, 6);
    text(&mut out, PAIR_JOB_DOMAIN);
    uint(&mut out, 1);
    uint(&mut out, timestamp);
    bytes(&mut out, prev_randao.as_slice());
    bytes(&mut out, suggested_fee_recipient.as_slice());
    bytes(&mut out, parent_beacon_block_root.as_slice());
    sha256(&out)
}

/// The build-job digest a built block's own header implies, for checking a retained binding after
/// the fact. `None` when the header lacks the Cancun beacon root.
pub fn header_attributes_digest(header: &Header) -> Option<B256> {
    Some(attributes_digest(
        header.timestamp,
        header.mix_hash,
        header.beneficiary,
        header.parent_beacon_block_root?,
    ))
}

/// Decodes `raw` and compares every field with the local context.
///
/// The comparisons run in a fixed order and each raises its own variant, so a test can mutate one
/// field and name the guard that must catch it. Nothing is returned that was not compared: on
/// success the binding equals what Rust derived from its own pins, genesis, parent, root input and
/// subject.
pub fn verify_pair_binding(
    raw: &[u8],
    context: &PairContext<'_>,
) -> Result<PairBinding, PairBindingError> {
    let binding = PairBinding::from_canonical_cbor(raw)?;
    let root = context.root;
    if binding.network_id != context.pins.network_id {
        return Err(PairBindingError::NetworkMismatch);
    }
    if binding.root_genesis_id != context.pins.root_genesis_id {
        return Err(PairBindingError::RootGenesisMismatch);
    }
    if binding.execution_genesis_hash != context.execution_genesis_hash {
        return Err(PairBindingError::ExecutionGenesisMismatch);
    }
    if root.network_id != binding.network_id {
        return Err(PairBindingError::InputNetworkMismatch);
    }
    if binding.parent_hash != context.parent.hash() {
        return Err(PairBindingError::ParentHashMismatch);
    }
    if binding.parent_number != context.parent.number {
        return Err(PairBindingError::ParentNumberMismatch);
    }
    if binding.origin_root_epoch != root.origin.root_epoch {
        return Err(PairBindingError::OriginEpochMismatch);
    }
    if binding.origin_root_round != root.origin.root_round {
        return Err(PairBindingError::OriginRoundMismatch);
    }
    if binding.configuration_id != root.origin.shard_conf_hash {
        return Err(PairBindingError::ConfigurationMismatch);
    }
    if let Some(raw_transition) = root.transitions.first() {
        let transition = crate::wire::decode_epoch_transition(raw_transition)
            .map_err(|_| PairBindingError::ActivationMismatch)?;
        if binding.activation_id != transition.commit_id {
            return Err(PairBindingError::ActivationMismatch);
        }
    }
    let commitment = root.input_commitment().map_err(PairBindingError::RootInput)?;
    if binding.root_input_hash != commitment {
        return Err(PairBindingError::RootInputMismatch);
    }
    if binding.transitions_hash != transitions_hash(&root.transitions) {
        return Err(PairBindingError::TransitionsMismatch);
    }
    match (binding.subject, context.subject) {
        (
            PairSubject::Build { attributes_digest },
            ExpectedSubject::Build { attributes_digest: expected },
        ) => {
            if attributes_digest != expected {
                return Err(PairBindingError::JobMismatch);
            }
        }
        (PairSubject::Import { block_hash }, ExpectedSubject::Import { block_hash: expected }) => {
            if block_hash != expected {
                return Err(PairBindingError::BlockMismatch);
            }
        }
        (found, ExpectedSubject::Build { .. }) => {
            return Err(PairBindingError::WrongSubjectKind {
                expected: SUBJECT_BUILD,
                found: found.kind(),
            })
        }
        (found, ExpectedSubject::Import { .. }) => {
            return Err(PairBindingError::WrongSubjectKind {
                expected: SUBJECT_IMPORT,
                found: found.kind(),
            })
        }
    }
    Ok(binding)
}

/// Builds the binding Go's verification would produce for `root` under `context`; used by tests
/// and by tools that need a reference value. The node never calls this to authenticate: a binding
/// the node derived itself would prove nothing.
pub fn reference_binding(
    context: &PairContext<'_>,
    activation_id: B256,
) -> Result<PairBinding, PairBindingError> {
    let root = context.root;
    Ok(PairBinding {
        network_id: context.pins.network_id,
        root_genesis_id: context.pins.root_genesis_id,
        execution_genesis_hash: context.execution_genesis_hash,
        parent_hash: context.parent.hash(),
        parent_number: context.parent.number,
        origin_root_epoch: root.origin.root_epoch,
        origin_root_round: root.origin.root_round,
        configuration_id: root.origin.shard_conf_hash,
        activation_id: match root.transitions.first() {
            Some(raw) => {
                crate::wire::decode_epoch_transition(raw)
                    .map_err(|_| PairBindingError::ActivationMismatch)?
                    .commit_id
            }
            None => activation_id,
        },
        root_input_hash: root.input_commitment().map_err(PairBindingError::RootInput)?,
        transitions_hash: transitions_hash(&root.transitions),
        subject: match context.subject {
            ExpectedSubject::Build { attributes_digest } => {
                PairSubject::Build { attributes_digest }
            }
            ExpectedSubject::Import { block_hash } => PairSubject::Import { block_hash },
        },
    })
}
