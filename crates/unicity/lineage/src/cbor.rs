//! A strict deterministic-CBOR reader and the minimal writer the identities are hashed from.
//!
//! The reader accepts exactly the RFC 8949 section 4.2.1 deterministic encoding of unsigned
//! integers, byte strings, text strings, definite arrays, definite maps, tags and null. It refuses
//! indefinite lengths, non-minimal heads, negative integers, floats, simple values other than null,
//! invalid UTF-8, maps whose keys are not strictly increasing in encoded bytes, trailing bytes, and
//! anything nested deeper than the caller's bound. Every array or map length is checked against the
//! bytes that remain before anything is allocated, so a hostile length cannot reserve memory.

use crate::error::{format, Error, Kind, Result};

/// A decoded CBOR value of the supported kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Tag(u64, Box<Self>),
    Null,
}

/// Decoder bounds: input size, nesting depth, and the largest array and map.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) bytes: usize,
    pub(crate) depth: usize,
    pub(crate) array: usize,
    pub(crate) map: usize,
}

/// Parses one complete value from `raw` under `limits`.
pub(crate) fn parse(raw: &[u8], limits: Limits) -> Result<Value> {
    if raw.len() > limits.bytes {
        return Err(Error::new(
            Kind::TooLarge,
            format_args!("{} bytes, limit {}", raw.len(), limits.bytes),
        ));
    }
    let mut d = Decoder { raw, pos: 0, limits };
    let v = d.value(0)?;
    if d.pos != raw.len() {
        return Err(format(format_args!("{} trailing bytes", raw.len() - d.pos)));
    }
    Ok(v)
}

struct Decoder<'a> {
    raw: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.raw.get(self.pos).ok_or_else(|| format("truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.raw.len())
            .ok_or_else(|| format("truncated"))?;
        let s = &self.raw[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Reads the argument of a head; refuses every non-minimal form and indefinite length.
    fn argument(&mut self, info: u8) -> Result<u64> {
        let (n, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 1 << 8)
            }
            26 => {
                let b = self.take(4)?;
                (u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])), 1 << 16)
            }
            27 => {
                let b = self.take(8)?;
                (u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]), 1 << 32)
            }
            _ => return Err(format("indefinite length or reserved additional information")),
        };
        if n < min {
            return Err(format("non-minimal head"));
        }
        Ok(n)
    }

    /// A length that the remaining input could still hold at one byte per item.
    fn length(&self, n: u64, cap: usize, what: &str) -> Result<usize> {
        let n = usize::try_from(n).map_err(|_| format(format_args!("{what} length overflows")))?;
        if n > cap {
            return Err(Error::new(
                Kind::TooLarge,
                format_args!("{what} of {n} items, limit {cap}"),
            ));
        }
        if n > self.raw.len() - self.pos {
            return Err(format("truncated"));
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > self.limits.depth {
            return Err(Error::new(Kind::TooLarge, "nesting too deep"));
        }
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 0x1f);
        match major {
            0 => Ok(Value::Uint(self.argument(info)?)),
            2 | 3 => {
                let n = self.argument(info)?;
                let n = self.length(n, usize::MAX, "string")?;
                let s = self.take(n)?.to_vec();
                if major == 2 {
                    Ok(Value::Bytes(s))
                } else {
                    String::from_utf8(s).map(Value::Text).map_err(|_| format("text is not UTF-8"))
                }
            }
            4 => {
                let n = self.argument(info)?;
                let n = self.length(n, self.limits.array, "array")?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.argument(info)?;
                let n = self.length(n, self.limits.map, "map")?;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(n);
                let mut last: Option<(usize, usize)> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.value(depth + 1)?;
                    let range = (start, self.pos);
                    if let Some((a, b)) = last &&
                        self.raw[a..b] >= self.raw[range.0..range.1]
                    {
                        return Err(format("map keys are not strictly increasing"));
                    }
                    last = Some(range);
                    let v = self.value(depth + 1)?;
                    pairs.push((k, v));
                }
                Ok(Value::Map(pairs))
            }
            6 => {
                let tag = self.argument(info)?;
                Ok(Value::Tag(tag, Box::new(self.value(depth + 1)?)))
            }
            7 if info == 22 => Ok(Value::Null),
            _ => Err(format("unsupported CBOR item (negative integer, float or simple value)")),
        }
    }
}

impl Value {
    /// The canonical encoding of the value (shortest heads; maps are written in their decoded,
    /// already sorted, order).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Self::Uint(n) => {
                w.uint(*n);
            }
            Self::Bytes(b) => {
                w.bytes(b);
            }
            Self::Text(t) => {
                w.text(t);
            }
            Self::Array(a) => {
                w.array(a.len());
                for v in a {
                    v.write(w);
                }
            }
            Self::Map(m) => {
                w.map(m.len());
                for (k, v) in m {
                    k.write(w);
                    v.write(w);
                }
            }
            Self::Tag(t, v) => {
                w.tag(*t);
                v.write(w);
            }
            Self::Null => {
                w.null();
            }
        }
    }
}

/// A walk over the items of one decoded array; every read is checked and in order.
pub(crate) struct Items<'a> {
    items: &'a [Value],
    next: usize,
}

impl<'a> Items<'a> {
    /// Requires `v` to be an array, of exactly `n` items when `n` is given.
    pub(crate) fn of(v: &'a Value, n: Option<usize>) -> Result<Self> {
        match v {
            Value::Array(a) if n.is_none_or(|n| a.len() == n) => Ok(Self { items: a, next: 0 }),
            _ => Err(format(format_args!(
                "expected an array of {} items",
                n.map_or_else(|| "any".to_owned(), |n| n.to_string())
            ))),
        }
    }

    /// A walk over an already-checked slice.
    pub(crate) const fn over(items: &'a [Value]) -> Self {
        Self { items, next: 0 }
    }

    pub(crate) const fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn take(&mut self) -> Result<&'a Value> {
        let v = self.items.get(self.next).ok_or_else(|| format("truncated"))?;
        self.next += 1;
        Ok(v)
    }

    pub(crate) fn uint(&mut self) -> Result<u64> {
        match self.take()? {
            Value::Uint(n) => Ok(*n),
            _ => Err(format("expected an unsigned integer")),
        }
    }

    /// A byte string of exactly `size` bytes.
    pub(crate) fn bytes_exact(&mut self, size: usize) -> Result<&'a [u8]> {
        match self.take()? {
            Value::Bytes(b) if b.len() == size => Ok(b),
            Value::Bytes(b) => Err(format(format_args!("byte string of {}, want {size}", b.len()))),
            _ => Err(format("expected a byte string")),
        }
    }

    /// A byte string of at most `max` bytes.
    pub(crate) fn bytes_max(&mut self, max: usize) -> Result<&'a [u8]> {
        match self.take()? {
            Value::Bytes(b) if b.len() <= max => Ok(b),
            Value::Bytes(b) => Err(Error::new(
                Kind::TooLarge,
                format_args!("byte string of {}, limit {max}", b.len()),
            )),
            _ => Err(format("expected a byte string")),
        }
    }

    pub(crate) fn text(&mut self, max: usize) -> Result<&'a str> {
        match self.take()? {
            Value::Text(t) if t.len() <= max => Ok(t),
            Value::Text(t) => {
                Err(Error::new(Kind::TooLarge, format_args!("text of {}, limit {max}", t.len())))
            }
            _ => Err(format("expected a text string")),
        }
    }

    /// A byte string of at most `max` bytes, or null.
    pub(crate) fn opt_bytes(&mut self, max: usize) -> Result<Option<&'a [u8]>> {
        if matches!(self.items.get(self.next), Some(Value::Null)) {
            self.next += 1;
            return Ok(None);
        }
        self.bytes_max(max).map(Some)
    }

    /// A nested array of at most `max` items.
    pub(crate) fn array(&mut self, max: usize) -> Result<&'a [Value]> {
        match self.take()? {
            Value::Array(a) if a.len() <= max => Ok(a),
            Value::Array(a) => {
                Err(Error::new(Kind::TooLarge, format_args!("{} items, limit {max}", a.len())))
            }
            _ => Err(format("expected an array")),
        }
    }

    /// A nested array of exactly `n` items, as a walk.
    pub(crate) fn sub(&mut self, n: usize) -> Result<Self> {
        let v = self.take()?;
        Self::of(v, Some(n))
    }

    /// Fails on items that were not read.
    pub(crate) fn done(&self) -> Result<()> {
        if self.next == self.items.len() {
            Ok(())
        } else {
            Err(format(format_args!("{} trailing items", self.items.len() - self.next)))
        }
    }
}

/// The minimal canonical writer: shortest heads, definite lengths, the kinds above only.
#[derive(Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn head(&mut self, major: u8, n: u64) -> &mut Self {
        let m = major << 5;
        match n {
            0..=23 => self.0.push(m | n as u8),
            24..=0xff => self.0.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                self.0.push(m | 25);
                self.0.extend((n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(m | 26);
                self.0.extend((n as u32).to_be_bytes());
            }
            _ => {
                self.0.push(m | 27);
                self.0.extend(n.to_be_bytes());
            }
        }
        self
    }

    pub(crate) fn array(&mut self, n: usize) -> &mut Self {
        self.head(4, n as u64)
    }

    pub(crate) fn uint(&mut self, n: u64) -> &mut Self {
        self.head(0, n)
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }

    pub(crate) fn text(&mut self, t: &str) -> &mut Self {
        self.head(3, t.len() as u64);
        self.0.extend_from_slice(t.as_bytes());
        self
    }

    pub(crate) fn null(&mut self) -> &mut Self {
        self.0.push(0xf6);
        self
    }

    pub(crate) fn map(&mut self, n: usize) -> &mut Self {
        self.head(5, n as u64)
    }

    pub(crate) fn tag(&mut self, n: u64) -> &mut Self {
        self.head(6, n)
    }

    pub(crate) fn opt_bytes(&mut self, b: Option<&[u8]>) -> &mut Self {
        match b {
            Some(b) => self.bytes(b),
            None => self.null(),
        }
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
