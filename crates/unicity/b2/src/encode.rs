//! Canonical CBOR encoders. Each function returns the encoded bytes for a
//! single CBOR data item.

use std::vec::Vec;

/// Emit the initial byte(s): major type combined with `value`, using the
/// minimal power-of-two argument width (matching the reference SDKs).
fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        out.push(major | (value as u8));
    } else if value <= u8::MAX as u64 {
        out.push(major | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn head(major: u8, value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    push_head(&mut out, major, value);
    out
}

/// Encode an unsigned integer.
pub(crate) fn encode_uint(value: u64) -> Vec<u8> {
    head(0, value)
}

/// Encode a byte string.
pub(crate) fn encode_byte_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 9);
    push_head(&mut out, 0x40, data.len() as u64);
    out.extend_from_slice(data);
    out
}

/// Frame already-encoded `items` as a definite-length CBOR array.
pub(crate) fn encode_array(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::with_capacity(total + 9);
    push_head(&mut out, 0x80, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Wrap an already-encoded item in a CBOR tag.
pub(crate) fn encode_tag(tag: u64, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 9);
    push_head(&mut out, 0xc0, tag);
    out.extend_from_slice(content);
    out
}
