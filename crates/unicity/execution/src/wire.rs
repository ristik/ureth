//! Wire types for the `engine_*WithSealV1` siblings and the canonical CBOR decoder for
//! [`RootInputV2`].
//!
//! The D2 methods are JSON-RPC, so [`SealBuildInput`] and [`SealCompanion`] are JSON envelopes:
//! `rootInput` and the array elements are 0x-hex strings carried as [`alloy_primitives::Bytes`],
//! and `provenance` is a JSON string. The envelope is not commitment-bound. `rootInput` itself is
//! canonical CBOR, and `input_commitment` is `SHA-256` over its canonical bytes, so
//! [`RootInputV2::from_canonical_cbor`] must accept exactly one encoding per value. If two byte
//! strings could decode to the same [`RootInputV2`], a caller could present one encoding and be
//! bound to another. It therefore accepts only RFC 8949 deterministic encodings: definite lengths
//! only, minimal-length integer and length heads, no indefinite-length items, no tags, no floats,
//! no duplicate or unexpected fields, and exact array arities. Every refusal is named by
//! [`CanonicalCborError`].
//!
//! The decoder is the exact inverse of [`RootInputV2::canonical_cbor`]:
//!
//! - `canonical_cbor(from_canonical_cbor(bytes)?)` equals `bytes` for every accepted `bytes`;
//! - `from_canonical_cbor(canonical_cbor(&value)?)` equals `value` for every valid `value`.
//!
//! Decoding is not authentication. Certificate authentication, the authenticated transition
//! sequence and the exact parent snapshot remain caller prerequisites as the crate docs state, and
//! this module adds no verdict over them.
//!
//! Nothing here is registered, advertised or reachable from a node. The module is a library
//! boundary only.

use crate::{
    block::{BlockAccountingError, BlockProfile},
    block_executor::{BoundExecutionInput, CompletedParent},
    ExecutionError, InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2,
};
use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, B256};
use reth_primitives_traits::SealedHeader;
use serde::{Deserialize, Serialize};

/// Build-path parameter `sealBuildInput = { rootInput, transitions }`.
///
/// This is the JSON envelope carried by `engine_forkchoiceUpdatedWithSealV1`. `root_input` is a
/// CBOR blob, not a structured JSON object, so there is exactly one root-input codec. Call
/// [`SealBuildInput::decode_root_input`] to get a validated [`RootInputV2`]. `transitions` is the
/// outer committed-body array the design carries alongside the structured root input; its
/// relationship to the authenticated sequence remains the authentication boundary's concern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealBuildInput {
    /// Canonical CBOR bytes for one root input.
    pub root_input: Bytes,
    /// Outer committed-body array carried next to the root input.
    pub transitions: Vec<Bytes>,
}

impl SealBuildInput {
    /// Decodes `root_input` through the single canonical [`RootInputV2`] codec.
    pub fn decode_root_input(&self) -> Result<RootInputV2, CanonicalCborError> {
        RootInputV2::from_canonical_cbor(&self.root_input)
    }
}

/// Import-path parameter `sealCompanion = { rootInput, witnesses, provenance }`.
///
/// This is the JSON envelope carried by `engine_newPayloadWithSealV1`. `witnesses` is opaque to
/// this crate: the certificate binding and the authenticated transition sequence are verified by
/// the caller. `provenance` records where the companion came from as the design's
/// `"build" | "newPayload" | "devp2p" | "reexec"` label; this type does not enforce that set
/// because the label is not a commitment field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealCompanion {
    /// Canonical CBOR bytes for one root input.
    pub root_input: Bytes,
    /// Authentication witness byte strings; opaque to this crate.
    pub witnesses: Vec<Bytes>,
    /// Companion provenance label.
    pub provenance: String,
}

impl SealCompanion {
    /// Decodes `root_input` through the single canonical [`RootInputV2`] codec.
    pub fn decode_root_input(&self) -> Result<RootInputV2, CanonicalCborError> {
        RootInputV2::from_canonical_cbor(&self.root_input)
    }
}

/// Binds a decoded root input to a parent whose execution accounting was locally minted.
///
/// This forwards to [`BoundExecutionInput::from_completed_parent`] without repeating any of its
/// parent checks, so exactly the same parent requirements apply: the sealed header must hash to
/// itself, the input and the completion token must name that parent, and the token's profile must
/// equal `profile`.
pub fn bind_completed_parent(
    input: RootInputV2,
    profile: BlockProfile,
    parent: &SealedHeader<Header>,
    completed: CompletedParent,
    fee_collector: Address,
) -> Result<BoundExecutionInput, BlockAccountingError> {
    BoundExecutionInput::from_completed_parent(
        std::sync::Arc::new(input),
        profile,
        parent,
        completed,
        fee_collector,
    )
}

/// Binds a decoded root input to an already-validated genesis header.
///
/// This forwards to [`BoundExecutionInput::from_validated_genesis`] without repeating its checks,
/// so the same requirements apply: the header must hash to itself and to
/// `configured_genesis_hash`, the number and gas used must be zero, the input must name that
/// parent, and the parent base fee must be valid for the profile.
pub fn bind_validated_genesis(
    input: RootInputV2,
    profile: BlockProfile,
    parent: &SealedHeader<Header>,
    configured_genesis_hash: B256,
    fee_collector: Address,
) -> Result<BoundExecutionInput, BlockAccountingError> {
    BoundExecutionInput::from_validated_genesis(
        std::sync::Arc::new(input),
        profile,
        parent,
        configured_genesis_hash,
        fee_collector,
    )
}

impl RootInputV2 {
    /// Decodes one canonical RFC 8949 root input and validates it through
    /// [`RootInputV2::origin_class`], so an accepted value is a valid value.
    ///
    /// This is the exact inverse of [`RootInputV2::canonical_cbor`]. It refuses non-minimal integer
    /// and length heads, indefinite-length items, tags, floats, negative integers, wrong arities
    /// and wrong value types with named [`CanonicalCborError`] variants, and it refuses trailing
    /// bytes after the top-level array. A byte string that decodes to a structurally valid but
    /// profile-invalid root input is refused as [`CanonicalCborError::InvalidRootInput`].
    pub fn from_canonical_cbor(input: &[u8]) -> Result<Self, CanonicalCborError> {
        let mut decoder = Decoder::new(input);
        let value = decode_root_input(&mut decoder)?;
        decoder.finish()?;
        match value.origin_class() {
            Ok(_) => Ok(value),
            Err(ExecutionError::InvalidInput(reason)) => {
                Err(CanonicalCborError::InvalidRootInput(reason))
            }
            Err(_) => {
                Err(CanonicalCborError::InvalidRootInput("root input failed profile validation"))
            }
        }
    }
}

fn decode_root_input(decoder: &mut Decoder<'_>) -> Result<RootInputV2, CanonicalCborError> {
    let arity = decoder.read_array()?;
    if arity != 11 {
        return Err(CanonicalCborError::WrongArity { expected: 11, found: arity });
    }
    Ok(RootInputV2 {
        version: decoder.read_uint()?,
        network_id: decoder.read_uint()?,
        partition_id: decoder.read_uint()?,
        shard_id: decoder.read_bytes()?.to_vec(),
        authorized_round: decoder.read_uint()?,
        certified_epoch: decoder.read_uint()?,
        authorized_epoch: decoder.read_uint()?,
        parent_hash: decoder.read_word()?,
        origin: decode_origin(decoder)?,
        technical: decode_technical(decoder)?,
        transitions: decode_byte_string_array(decoder)?,
    })
}

fn decode_origin(decoder: &mut Decoder<'_>) -> Result<RootOriginV2, CanonicalCborError> {
    let arity = decoder.read_array()?;
    if arity != 8 {
        return Err(CanonicalCborError::WrongArity { expected: 8, found: arity });
    }
    let network_id = decoder.read_uint()?;
    let root_round = decoder.read_uint()?;
    let root_epoch = decoder.read_uint()?;
    let reference_time = decoder.read_uint()?;
    let tree_root = decoder.read_word()?;
    let record_arity = decoder.read_array()?;
    if record_arity != 6 {
        return Err(CanonicalCborError::WrongArity { expected: 6, found: record_arity });
    }
    let input_record = InputRecordV2 {
        round: decoder.read_uint()?,
        epoch: decoder.read_uint()?,
        previous_hash: decoder.read_nullable_word()?,
        state_hash: decoder.read_nullable_word()?,
        timestamp: decoder.read_uint()?,
        block_hash: decoder.read_nullable_word()?,
    };
    Ok(RootOriginV2 {
        network_id,
        root_round,
        root_epoch,
        reference_time,
        tree_root,
        // Deliberately not part of the canonical origin array, matching bft-core's
        // rootorigin_v2.go: its canonicalBody also omits the version and its Class() also
        // rejects anything other than one. Do not add it to the encoding, which would change
        // the commitment.
        input_record_version: 1,
        input_record,
        tr_hash: decoder.read_word()?,
        shard_conf_hash: decoder.read_word()?,
    })
}

fn decode_technical(decoder: &mut Decoder<'_>) -> Result<TechnicalRecordV2, CanonicalCborError> {
    let arity = decoder.read_array()?;
    if arity != 5 {
        return Err(CanonicalCborError::WrongArity { expected: 5, found: arity });
    }
    Ok(TechnicalRecordV2 {
        round: decoder.read_uint()?,
        epoch: decoder.read_uint()?,
        leader: decoder.read_text()?.to_owned(),
        stat_hash: decoder.read_word()?,
        fee_hash: decoder.read_word()?,
    })
}

fn decode_byte_string_array(decoder: &mut Decoder<'_>) -> Result<Vec<Vec<u8>>, CanonicalCborError> {
    let length = decoder.read_array()?;
    // Do not pre-allocate from the untrusted length: a nine-byte head can claim a huge count while
    // the input ends immediately. Pushing instead fails at the first missing byte.
    let mut values = Vec::new();
    for _ in 0..length {
        values.push(decoder.read_bytes()?.to_vec());
    }
    Ok(values)
}

/// Named refusal for a byte string that is not the unique canonical encoding of a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalCborError {
    /// The input ended before the encoded item did.
    UnexpectedEof,
    /// Bytes remained after the top-level item.
    TrailingBytes,
    /// An indefinite-length item (additional information 31) was encountered.
    IndefiniteLength,
    /// Reserved additional information 28 to 30 was encountered.
    ReservedAdditionalInfo(u8),
    /// An integer or length was encoded in more bytes than necessary.
    NonMinimalLength,
    /// A value had the wrong CBOR major type; the byte is the major type observed.
    UnexpectedItem {
        /// CBOR major type observed.
        major: u8,
        /// Value kind the profile requires at this position.
        expected: &'static str,
    },
    /// An array or map had a length other than the exact one the profile fixes.
    WrongArity {
        /// Fixed length the profile requires.
        expected: usize,
        /// Length observed.
        found: usize,
    },
    /// A fixed-width byte string had the wrong length.
    WrongByteStringLength {
        /// Required length in bytes.
        expected: usize,
        /// Length observed.
        found: usize,
    },
    /// A length or count did not fit in the host's `usize`.
    LengthOutOfRange,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// A structurally valid root input failed [`RootInputV2::origin_class`].
    InvalidRootInput(&'static str),
}

impl std::fmt::Display for CanonicalCborError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => formatter.write_str("canonical CBOR input ended early"),
            Self::TrailingBytes => formatter.write_str("canonical CBOR input has trailing bytes"),
            Self::IndefiniteLength => formatter.write_str("indefinite-length CBOR item"),
            Self::ReservedAdditionalInfo(info) => {
                write!(formatter, "reserved CBOR additional information {info}")
            }
            Self::NonMinimalLength => formatter.write_str("non-minimal CBOR length encoding"),
            Self::UnexpectedItem { major, expected } => {
                write!(formatter, "CBOR major type {major} where {expected} was required")
            }
            Self::WrongArity { expected, found } => {
                write!(formatter, "CBOR arity {found} where {expected} was required")
            }
            Self::WrongByteStringLength { expected, found } => {
                write!(formatter, "byte string length {found} where {expected} was required")
            }
            Self::LengthOutOfRange => formatter.write_str("CBOR length does not fit usize"),
            Self::InvalidUtf8 => formatter.write_str("CBOR text string is not valid UTF-8"),
            Self::InvalidRootInput(reason) => write!(formatter, "invalid root input: {reason}"),
        }
    }
}

impl std::error::Error for CanonicalCborError {}

/// Minimal deterministic CBOR reader for the fixed root-input and wire shapes.
///
/// It intentionally exposes only the value kinds the profile uses, so anything else is a type
/// error rather than something later code has to defend against.
struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalCborError> {
        let end = self.offset.checked_add(length).ok_or(CanonicalCborError::LengthOutOfRange)?;
        let slice = self.input.get(self.offset..end).ok_or(CanonicalCborError::UnexpectedEof)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, CanonicalCborError> {
        Ok(self.take(1)?[0])
    }

    fn peek(&self) -> Result<u8, CanonicalCborError> {
        self.input.get(self.offset).copied().ok_or(CanonicalCborError::UnexpectedEof)
    }

    const fn finish(&self) -> Result<(), CanonicalCborError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(CanonicalCborError::TrailingBytes)
        }
    }

    /// Reads one item head and enforces minimal-length integer and length encoding.
    fn read_head(&mut self) -> Result<(u8, u64), CanonicalCborError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let argument = match info {
            0..=23 => u64::from(info),
            24 => {
                let value = u64::from(self.read_u8()?);
                if value < 24 {
                    return Err(CanonicalCborError::NonMinimalLength);
                }
                value
            }
            25 => {
                let bytes = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                if value <= u64::from(u8::MAX) {
                    return Err(CanonicalCborError::NonMinimalLength);
                }
                value
            }
            26 => {
                let bytes = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                if value <= u64::from(u16::MAX) {
                    return Err(CanonicalCborError::NonMinimalLength);
                }
                value
            }
            27 => {
                let bytes = self.take(8)?;
                let value = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                if value <= u64::from(u32::MAX) {
                    return Err(CanonicalCborError::NonMinimalLength);
                }
                value
            }
            31 => return Err(CanonicalCborError::IndefiniteLength),
            reserved => return Err(CanonicalCborError::ReservedAdditionalInfo(reserved)),
        };
        Ok((major, argument))
    }

    fn read_uint(&mut self) -> Result<u64, CanonicalCborError> {
        match self.read_head()? {
            (0, value) => Ok(value),
            (major, _) => {
                Err(CanonicalCborError::UnexpectedItem { major, expected: "unsigned integer" })
            }
        }
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], CanonicalCborError> {
        match self.read_head()? {
            (2, length) => {
                let length =
                    usize::try_from(length).map_err(|_| CanonicalCborError::LengthOutOfRange)?;
                self.take(length)
            }
            (major, _) => {
                Err(CanonicalCborError::UnexpectedItem { major, expected: "byte string" })
            }
        }
    }

    fn read_text(&mut self) -> Result<&'a str, CanonicalCborError> {
        let bytes = match self.read_head()? {
            (3, length) => {
                let length =
                    usize::try_from(length).map_err(|_| CanonicalCborError::LengthOutOfRange)?;
                self.take(length)?
            }
            (major, _) => {
                return Err(CanonicalCborError::UnexpectedItem { major, expected: "text string" })
            }
        };
        std::str::from_utf8(bytes).map_err(|_| CanonicalCborError::InvalidUtf8)
    }

    fn read_array(&mut self) -> Result<usize, CanonicalCborError> {
        match self.read_head()? {
            (4, length) => {
                usize::try_from(length).map_err(|_| CanonicalCborError::LengthOutOfRange)
            }
            (major, _) => Err(CanonicalCborError::UnexpectedItem { major, expected: "array" }),
        }
    }

    fn read_word(&mut self) -> Result<B256, CanonicalCborError> {
        let bytes = self.read_bytes()?;
        if bytes.len() != 32 {
            return Err(CanonicalCborError::WrongByteStringLength {
                expected: 32,
                found: bytes.len(),
            });
        }
        Ok(B256::from_slice(bytes))
    }

    fn read_nullable_word(&mut self) -> Result<Option<B256>, CanonicalCborError> {
        // 0xf6 is the canonical encoding of null, the profile's only non-word alternative here.
        if self.peek()? == 0xf6 {
            self.offset += 1;
            return Ok(None);
        }
        Ok(Some(self.read_word()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block::MAX_BASE_FEE, technical_record_hash};

    const PROFILE: BlockProfile = BlockProfile {
        max_gas: 30_000_000,
        system_gas: 2_000_000,
        base_fee_floor: 1_000_000,
        elasticity: 2,
        change_denominator: 8,
    };

    fn sample() -> RootInputV2 {
        let technical = TechnicalRecordV2 {
            round: 1,
            epoch: 0,
            leader: "leader".into(),
            stat_hash: B256::repeat_byte(0xaa),
            fee_hash: B256::repeat_byte(0xbb),
        };
        RootInputV2 {
            version: 2,
            network_id: 3,
            partition_id: 8,
            shard_id: vec![0x01, 0x02],
            authorized_round: 1,
            certified_epoch: 0,
            authorized_epoch: 0,
            parent_hash: B256::repeat_byte(0x11),
            origin: RootOriginV2 {
                network_id: 3,
                root_round: 4,
                root_epoch: 1,
                reference_time: 100,
                tree_root: B256::repeat_byte(0x22),
                input_record_version: 1,
                input_record: InputRecordV2 {
                    round: 0,
                    epoch: 0,
                    previous_hash: None,
                    state_hash: None,
                    timestamp: 0,
                    block_hash: None,
                },
                tr_hash: technical_record_hash(&technical),
                shard_conf_hash: B256::repeat_byte(0x33),
            },
            technical,
            transitions: vec![vec![0x01], vec![0x02, 0x03]],
        }
    }

    fn encoded_sample() -> Vec<u8> {
        let encoded = sample().canonical_cbor().unwrap();
        // The mutations below index the sample encoding directly, so pin the shape they assume.
        assert_eq!(encoded[0], 0x8b, "top-level array of eleven");
        assert_eq!(encoded[1], 0x02, "version two");
        assert_eq!(encoded[4], 0x42, "two-byte shard id");
        encoded
    }

    fn decode_error(bytes: &[u8]) -> CanonicalCborError {
        RootInputV2::from_canonical_cbor(bytes).unwrap_err()
    }

    #[derive(serde::Deserialize)]
    struct V2File {
        vectors: Vec<V2Vector>,
    }

    #[derive(serde::Deserialize)]
    struct V2Vector {
        name: String,
        #[serde(rename = "rootInput")]
        root_input: Encoded,
    }

    #[derive(serde::Deserialize)]
    struct Encoded {
        cbor: String,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(value.trim_start_matches("0x")).unwrap()
    }

    #[test]
    fn root_input_round_trips_in_both_directions() {
        let value = sample();
        let encoded = value.canonical_cbor().unwrap();
        let decoded = RootInputV2::from_canonical_cbor(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.canonical_cbor().unwrap(), encoded);
    }

    #[test]
    fn independent_root_input_vectors_decode_and_reencode_byte_for_byte() {
        let file: V2File =
            serde_json::from_str(include_str!("../testdata/v2-vectors.json")).unwrap();
        assert!(!file.vectors.is_empty());
        for vector in file.vectors {
            let raw = decode_hex(&vector.root_input.cbor);
            let decoded = RootInputV2::from_canonical_cbor(&raw)
                .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
            assert_eq!(decoded.canonical_cbor().unwrap(), raw, "{}", vector.name);
        }
    }

    #[test]
    fn trailing_and_truncated_inputs_are_refused() {
        let mut trailing = encoded_sample();
        trailing.push(0x00);
        assert_eq!(decode_error(&trailing), CanonicalCborError::TrailingBytes);

        let mut truncated = encoded_sample();
        truncated.pop();
        assert_eq!(decode_error(&truncated), CanonicalCborError::UnexpectedEof);
    }

    #[test]
    fn non_minimal_and_indefinite_heads_are_refused() {
        let mut indefinite = encoded_sample();
        indefinite[0] = 0x9f;
        assert_eq!(decode_error(&indefinite), CanonicalCborError::IndefiniteLength);

        let mut non_minimal_int = encoded_sample();
        non_minimal_int[1] = 0x18;
        assert_eq!(decode_error(&non_minimal_int), CanonicalCborError::NonMinimalLength);

        let mut non_minimal_length = encoded_sample();
        non_minimal_length[4] = 0x58;
        assert_eq!(decode_error(&non_minimal_length), CanonicalCborError::NonMinimalLength);
    }

    #[test]
    fn wrong_major_types_are_refused() {
        let mut reserved = encoded_sample();
        reserved[1] = 0x1c;
        assert_eq!(decode_error(&reserved), CanonicalCborError::ReservedAdditionalInfo(28));

        let mut negative = encoded_sample();
        negative[1] = 0x20;
        assert_eq!(
            decode_error(&negative),
            CanonicalCborError::UnexpectedItem { major: 1, expected: "unsigned integer" }
        );

        let mut tag = encoded_sample();
        tag[1] = 0xc0;
        assert_eq!(
            decode_error(&tag),
            CanonicalCborError::UnexpectedItem { major: 6, expected: "unsigned integer" }
        );

        let mut float = encoded_sample();
        float[1] = 0xfa;
        assert_eq!(
            decode_error(&float),
            CanonicalCborError::UnexpectedItem { major: 7, expected: "unsigned integer" }
        );

        let mut null = encoded_sample();
        null[1] = 0xf6;
        assert_eq!(
            decode_error(&null),
            CanonicalCborError::UnexpectedItem { major: 7, expected: "unsigned integer" }
        );
    }

    #[test]
    fn wrong_arities_and_widths_are_refused() {
        let mut short_array = encoded_sample();
        short_array[0] = 0x8a;
        assert_eq!(
            decode_error(&short_array),
            CanonicalCborError::WrongArity { expected: 11, found: 10 }
        );

        // Point the thirty-two-byte parent hash head at only sixteen bytes.
        let mut narrow_word = encoded_sample();
        let needle = B256::repeat_byte(0x11);
        let at = narrow_word
            .windows(needle.len())
            .position(|window| window == needle.as_slice())
            .expect("parent hash present");
        assert_eq!(&narrow_word[at - 2..at], &[0x58, 0x20]);
        narrow_word[at - 2] = 0x50;
        narrow_word.remove(at);
        assert_eq!(
            decode_error(&narrow_word),
            CanonicalCborError::WrongByteStringLength { expected: 32, found: 16 }
        );
    }

    #[test]
    fn structurally_valid_but_invalid_inputs_are_refused() {
        let mut wrong_version = encoded_sample();
        wrong_version[1] = 0x01;
        assert_eq!(
            decode_error(&wrong_version),
            CanonicalCborError::InvalidRootInput("profile version must be 2")
        );
    }

    fn root_input_hex() -> String {
        format!("0x{}", alloy_primitives::hex::encode(sample().canonical_cbor().unwrap()))
    }

    #[test]
    fn seal_build_input_round_trips_as_json() {
        let value = SealBuildInput {
            root_input: sample().canonical_cbor().unwrap().into(),
            transitions: vec![Bytes::from(vec![0xaa]), Bytes::new()],
        };
        let json = serde_json::to_string(&value).unwrap();
        assert!(json.contains("\"rootInput\":\"0x"), "rootInput is a 0x-hex byte string: {json}");
        assert_eq!(serde_json::from_str::<SealBuildInput>(&json).unwrap(), value);
        assert_eq!(value.decode_root_input().unwrap(), sample());
    }

    #[test]
    fn seal_companion_round_trips_as_json() {
        let value = SealCompanion {
            root_input: sample().canonical_cbor().unwrap().into(),
            witnesses: vec![Bytes::from(vec![0x0a, 0x0b]), Bytes::new()],
            provenance: "newPayload".into(),
        };
        let json = serde_json::to_string(&value).unwrap();
        assert!(json.contains("\"rootInput\":\"0x"));
        assert_eq!(serde_json::from_str::<SealCompanion>(&json).unwrap(), value);
        assert_eq!(value.decode_root_input().unwrap(), sample());
    }

    #[test]
    fn seal_build_input_json_shape_is_enforced() {
        let root = root_input_hex();
        let good = format!(r#"{{"rootInput":"{root}","transitions":[]}}"#);
        assert!(serde_json::from_str::<SealBuildInput>(&good).is_ok());

        let unknown = format!(r#"{{"rootInput":"{root}","transitions":[],"bogus":1}}"#);
        assert!(serde_json::from_str::<SealBuildInput>(&unknown).is_err());

        let missing = format!(r#"{{"rootInput":"{root}"}}"#);
        assert!(serde_json::from_str::<SealBuildInput>(&missing).is_err());

        let wrong_type = format!(r#"{{"rootInput":"{root}","transitions":5}}"#);
        assert!(serde_json::from_str::<SealBuildInput>(&wrong_type).is_err());

        let bad_hex = r#"{"rootInput":"0xzz","transitions":[]}"#;
        assert!(serde_json::from_str::<SealBuildInput>(bad_hex).is_err());

        let parsed: SealBuildInput = serde_json::from_str(&good).unwrap();
        assert_eq!(parsed.root_input, Bytes::from(sample().canonical_cbor().unwrap()));
    }

    #[test]
    fn seal_companion_json_shape_is_enforced() {
        let root = root_input_hex();
        let good = format!(r#"{{"rootInput":"{root}","witnesses":[],"provenance":"build"}}"#);
        assert!(serde_json::from_str::<SealCompanion>(&good).is_ok());

        let unknown =
            format!(r#"{{"rootInput":"{root}","witnesses":[],"provenance":"build","x":0}}"#);
        assert!(serde_json::from_str::<SealCompanion>(&unknown).is_err());

        let missing = format!(r#"{{"rootInput":"{root}","witnesses":[]}}"#);
        assert!(serde_json::from_str::<SealCompanion>(&missing).is_err());

        let wrong_type = format!(r#"{{"rootInput":"{root}","witnesses":[],"provenance":7}}"#);
        assert!(serde_json::from_str::<SealCompanion>(&wrong_type).is_err());

        let bad_hex = r#"{"rootInput":"0xzz","witnesses":[],"provenance":"build"}"#;
        assert!(serde_json::from_str::<SealCompanion>(bad_hex).is_err());
    }

    #[test]
    fn non_canonical_nested_root_inputs_are_refused_through_the_envelope() {
        let build = SealBuildInput { root_input: vec![0x80].into(), transitions: vec![] };
        assert_eq!(
            build.decode_root_input(),
            Err(CanonicalCborError::WrongArity { expected: 11, found: 0 })
        );

        let companion = SealCompanion {
            root_input: vec![0x01].into(),
            witnesses: vec![],
            provenance: "build".into(),
        };
        assert_eq!(
            companion.decode_root_input(),
            Err(CanonicalCborError::UnexpectedItem { major: 0, expected: "array" })
        );
    }

    #[test]
    fn genesis_binding_forwards_to_the_existing_constructor() {
        let mut header = Header {
            number: 0,
            gas_used: 0,
            base_fee_per_gas: Some(PROFILE.base_fee_floor),
            ..Default::default()
        };
        header.gas_limit = PROFILE.max_gas;
        let genesis_hash = header.hash_slow();
        let parent = SealedHeader::new(header, genesis_hash);

        let mut input = sample();
        input.parent_hash = genesis_hash;
        bind_validated_genesis(input.clone(), PROFILE, &parent, genesis_hash, Address::ZERO)
            .unwrap();

        // The wrapper adds no checks of its own: the constructor still refuses a different
        // configured genesis hash.
        assert!(bind_validated_genesis(
            input,
            PROFILE,
            &parent,
            B256::repeat_byte(0x44),
            Address::ZERO
        )
        .is_err());

        // A base fee above the profile maximum is refused by the constructor, not here.
        let mut high_fee = Header {
            number: 0,
            gas_used: 0,
            base_fee_per_gas: Some(MAX_BASE_FEE + 1),
            ..Default::default()
        };
        high_fee.gas_limit = PROFILE.max_gas;
        let high_parent = SealedHeader::new(high_fee.clone(), high_fee.hash_slow());
        let mut high_input = sample();
        high_input.parent_hash = high_fee.hash_slow();
        assert!(bind_validated_genesis(
            high_input,
            PROFILE,
            &high_parent,
            high_fee.hash_slow(),
            Address::ZERO
        )
        .is_err());
    }
}
