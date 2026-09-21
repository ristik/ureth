//! The store's record codec for [`SealCompanion`].
//!
//! The record is not CBOR and not JSON: it is a deliberately small, versioned, length-prefixed
//! framing. Every variable-length field is preceded by its length as a four-byte big-endian
//! unsigned integer, so the encoding of a value is unique by construction. That uniqueness is what
//! lets the store promise a byte-identical read: a caller that writes a companion and reads it
//! back sees exactly the record that was written, and re-encoding a decoded record reproduces the
//! input bytes.
//!
//! Layout, in order:
//!
//! 1. one version byte, currently [`RECORD_VERSION`];
//! 2. `root_input`, one length-prefixed frame;
//! 3. the witness count as a four-byte big-endian integer, followed by that many length-prefixed
//!    frames;
//! 4. `provenance`, one length-prefixed UTF-8 frame.
//!
//! There is no compression and no field is optional, so there is exactly one encoding per value.
//! An unknown version byte is refused with [`StoreError::UnknownVersion`] rather than skipped,
//! and a truncated or over-long record is refused with [`StoreError::MalformedRecord`]. Decoding
//! never authenticates anything, which matches [`SealCompanion`] itself: the certificate binding
//! and the authenticated transition sequence remain the caller's prerequisites.

use alloy_primitives::Bytes;
use reth_unicity_execution::wire::SealCompanion;

use crate::StoreError;

/// The only record version this crate writes and accepts.
pub(crate) const RECORD_VERSION: u8 = 1;

/// Width of every length prefix and of the witness count, in bytes.
const LENGTH_BYTES: usize = 4;

/// Upper bound on the witness-vector capacity reserved from an untrusted count.
///
/// The count is read before its frames are, so a hostile record could name a huge count and make
/// the decoder reserve memory for frames that are not there. Reserving only up to this many slots
/// keeps a malformed record from forcing a large allocation; the vector still grows if a real
/// record carries more witnesses.
const MAX_WITNESS_PREALLOC: usize = 1024;

/// Encodes one companion into its canonical store record.
///
/// Returns [`StoreError::RecordTooLarge`] if a field is longer than a four-byte frame prefix can
/// describe. The codec is pure framing: it does not inspect `root_input`, because the store is
/// told what to keep and validating the companion's contents is the caller's job, not the store's.
pub(crate) fn encode(companion: &SealCompanion) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    out.push(RECORD_VERSION);
    put_frame(&mut out, &companion.root_input)?;
    put_count(&mut out, companion.witnesses.len())?;
    for witness in &companion.witnesses {
        put_frame(&mut out, witness)?;
    }
    put_frame(&mut out, companion.provenance.as_bytes())?;
    Ok(out)
}

/// Decodes exactly one store record back into a companion.
///
/// Every failure mode is a named [`StoreError`]: an unrecognised version, a field that runs past
/// the end of the input, a witness count that cannot be honoured, or trailing bytes after the
/// record. The function reads no further than the record it was given.
pub(crate) fn decode(bytes: &[u8]) -> Result<SealCompanion, StoreError> {
    let mut reader = Reader { bytes, offset: 0 };

    let version = reader.read_u8()?;
    if version != RECORD_VERSION {
        return Err(StoreError::UnknownVersion(version));
    }

    let root_input = Bytes::copy_from_slice(reader.read_frame()?);

    let witness_count = reader.read_u32()? as usize;
    let mut witnesses = Vec::with_capacity(witness_count.min(MAX_WITNESS_PREALLOC));
    for _ in 0..witness_count {
        witnesses.push(Bytes::copy_from_slice(reader.read_frame()?));
    }

    let provenance = std::str::from_utf8(reader.read_frame()?)
        .map_err(|_| StoreError::MalformedRecord("provenance is not valid UTF-8"))?
        .to_owned();

    if !reader.is_empty() {
        return Err(StoreError::MalformedRecord("trailing bytes after record"));
    }

    Ok(SealCompanion { root_input, witnesses, provenance })
}

/// Appends one length-prefixed frame.
fn put_frame(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StoreError> {
    put_u32(out, u32::try_from(bytes.len()).map_err(|_| StoreError::RecordTooLarge)?);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Appends a witness count as a four-byte big-endian integer.
fn put_count(out: &mut Vec<u8>, count: usize) -> Result<(), StoreError> {
    put_u32(out, u32::try_from(count).map_err(|_| StoreError::RecordTooLarge)?);
    Ok(())
}

/// Appends one four-byte big-endian integer.
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// A bounds-checked cursor over the record bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Returns `true` when every byte has been consumed.
    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    /// Reads one byte.
    fn read_u8(&mut self) -> Result<u8, StoreError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(StoreError::MalformedRecord("record ended before its version byte"))?;
        self.offset += 1;
        Ok(byte)
    }

    /// Reads one four-byte big-endian integer.
    fn read_u32(&mut self) -> Result<u32, StoreError> {
        let end = self
            .offset
            .checked_add(LENGTH_BYTES)
            .ok_or(StoreError::MalformedRecord("length prefix overflows"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(StoreError::MalformedRecord("record ended inside a length prefix"))?;
        self.offset = end;
        let mut raw = [0u8; LENGTH_BYTES];
        raw.copy_from_slice(slice);
        Ok(u32::from_be_bytes(raw))
    }

    /// Reads one length-prefixed frame.
    fn read_frame(&mut self) -> Result<&'a [u8], StoreError> {
        let len = self.read_u32()? as usize;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(StoreError::MalformedRecord("frame length overflows"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(StoreError::MalformedRecord("record ended inside a frame"))?;
        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn companion(root_input: &[u8], witnesses: &[&[u8]], provenance: &str) -> SealCompanion {
        SealCompanion {
            root_input: Bytes::copy_from_slice(root_input),
            witnesses: witnesses.iter().map(|w| Bytes::copy_from_slice(w)).collect(),
            provenance: provenance.to_owned(),
        }
    }

    // The codec is opaque framing, so the root input is an arbitrary blob here. Whether it is
    // canonical CBOR is a property of the companion's producer, not of the store.
    const ROOT_INPUT: &[u8] = b"opaque-root-input";

    #[test]
    fn decode_of_encode_returns_the_same_value() {
        let cases = [
            companion(ROOT_INPUT, &[], "build"),
            companion(ROOT_INPUT, &[b"single"], "newPayload"),
            companion(ROOT_INPUT, &[b"first", b"second", b""], "reexec"),
            companion(ROOT_INPUT, &[&[0u8; 300]], "devp2p"),
        ];

        for value in cases {
            let encoded = encode(&value).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn encode_of_decode_returns_the_same_bytes() {
        // A spread of witnesses makes the witness count and the per-frame prefixes differ.
        let cases = [
            companion(ROOT_INPUT, &[], "build"),
            companion(ROOT_INPUT, &[b"a"], "newPayload"),
            companion(ROOT_INPUT, &[b"a", b"bb", b"ccc", b"dddd"], "provenance with spaces"),
        ];

        for value in cases {
            let encoded = encode(&value).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(encode(&decoded).unwrap(), encoded);
        }
    }

    #[test]
    fn an_unknown_version_byte_is_a_typed_error() {
        let mut encoded = encode(&companion(ROOT_INPUT, &[], "build")).unwrap();
        encoded[0] = 7;

        match decode(&encoded) {
            Err(StoreError::UnknownVersion(7)) => {}
            other => panic!("expected UnknownVersion(7), got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_record_is_a_malformed_record() {
        let encoded = encode(&companion(ROOT_INPUT, &[b"witness"], "build")).unwrap();

        // Every proper prefix of a valid record is truncated somewhere, and none may decode.
        for end in 0..encoded.len() {
            match decode(&encoded[..end]) {
                Err(StoreError::MalformedRecord(_)) => {}
                other => panic!("expected a malformed record at prefix {end}, got {other:?}"),
            }
        }
    }

    #[test]
    fn trailing_bytes_after_a_record_are_refused() {
        let mut encoded = encode(&companion(ROOT_INPUT, &[], "build")).unwrap();
        encoded.push(0x00);

        match decode(&encoded) {
            Err(StoreError::MalformedRecord("trailing bytes after record")) => {}
            other => panic!("expected trailing bytes to be refused, got {other:?}"),
        }
    }
}
