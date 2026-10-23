//! Borrowed CBOR views. A complete bounded scan precedes semantic decoding.
use crate::{Error, Result};

#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    pub raw: &'a [u8],
    pub major: u8,
    pub arg: u64,
    pub data: &'a [u8],
}
fn head(data: &mut &[u8]) -> Result<(u8, u64)> {
    let first = *data.first().ok_or(Error::Truncated)?;
    *data = &data[1..];
    let ai = first & 31;
    let n = match ai {
        0..=23 => u64::from(ai),
        24..=27 => {
            let len = 1 << (ai - 24);
            let bytes = data.get(..len).ok_or(Error::Truncated)?;
            let n = bytes.iter().fold(0, |v, b| (v << 8) | u64::from(*b));
            *data = &data[len..];
            if n < [24, 256, 65536, 4294967296][usize::from(ai - 24)] {
                return Err(Error::NonCanonical);
            }
            n
        }
        // Reserved additional information 28..=30 is a non-canonical head; only 31 (indefinite) is
        // forbidden.
        28..=30 => return Err(Error::NonCanonical),
        _ => return Err(Error::ForbiddenCBOR),
    };
    Ok((first >> 5, n))
}
/// The CBOR item budget of each scanned object (bft-core: every object is scanned on its own
/// budget). The Cfg, the payload and every embedded object get a fresh budget of `cap` items; the
/// composition scans its history root with no ceiling, its items being paid.
#[derive(Clone, Copy, Debug)]
pub struct Items {
    count: usize,
    cap: usize,
    native: bool,
}
impl Items {
    /// The item ceiling of one object.
    pub const MAX: usize = 32768;
    /// A fresh budget of `cap` items for each scanned object.
    pub const fn per_object(cap: usize) -> Self {
        Self { count: 0, cap, native: false }
    }
    /// A budget of `cap` items for an object scanned as the oracle's native scanner does: definite
    /// text strings and maps are admitted as structure (their field-type errors come later, as
    /// `Shape`), with no ordering or UTF-8 rule. Used for the pieces of an embedded SDK token,
    /// which that scanner reads.
    pub const fn native(cap: usize) -> Self {
        Self { count: 0, cap, native: true }
    }
}
impl Default for Items {
    fn default() -> Self {
        Self::per_object(Self::MAX)
    }
}
fn scan(data: &mut &[u8], depth: usize, tokens: &mut Items) -> Result<()> {
    tokens.count += 1;
    if tokens.count > tokens.cap {
        return Err(Error::TooManyItems);
    }
    // Text strings, maps and simple values other than null are refused before the head is read (the
    // oracle's order), so a malformed head of such an item is `ForbiddenCBOR`, not `NonCanonical`.
    if data
        .first()
        .is_some_and(|b| (!tokens.native && matches!(b >> 5, 3 | 5)) || (b >> 5 == 7 && *b != 0xf6))
    {
        return Err(Error::ForbiddenCBOR);
    }
    let (m, n) = head(data)?;
    match m {
        0 => {}
        2 | 3 => {
            let len = usize::try_from(n).map_err(|_| Error::Truncated)?;
            *data = data.get(len..).ok_or(Error::Truncated)?;
        }
        4..=6 => {
            if depth >= 16 {
                return Err(Error::TooDeep);
            }
            // Each map pair needs at least two bytes: bound the head before doubling it.
            if m == 5 && n > data.len() as u64 {
                return Err(Error::Truncated);
            }
            let count = match m {
                6 => 1,
                5 => n * 2,
                _ => n,
            };
            if count > data.len() as u64 {
                return Err(Error::Truncated);
            }
            for _ in 0..count {
                scan(data, depth + 1, tokens)?;
            }
        }
        7 if n == 22 => {}
        _ => return Err(Error::ForbiddenCBOR),
    }
    Ok(())
}
pub fn one<'a>(data: &'a [u8], tokens: &mut Items) -> Result<Item<'a>> {
    tokens.count = 0;
    let mut rest = data;
    scan(&mut rest, 0, tokens)?;
    if !rest.is_empty() {
        return Err(Error::Trailing);
    }
    item(data)
}
fn item(data: &[u8]) -> Result<Item<'_>> {
    let mut rest = data;
    let (major, arg) = head(&mut rest)?;
    Ok(Item { raw: data, major, arg, data: rest })
}
impl<'a> Item<'a> {
    pub const fn null(self) -> bool {
        self.major == 7 && self.arg == 22
    }
    pub const fn uint(self, max: u64) -> Result<u64> {
        if self.major != 0 {
            return Err(Error::Shape);
        }
        if self.arg > max {
            return Err(Error::IntRange);
        }
        Ok(self.arg)
    }
    pub const fn bytes(self, n: usize) -> Result<&'a [u8]> {
        if self.major != 2 {
            return Err(Error::Shape);
        }
        if self.arg != n as u64 {
            return Err(Error::Length);
        }
        Ok(self.data)
    }
    pub const fn blob(self, max: usize) -> Result<&'a [u8]> {
        if self.major != 2 {
            return Err(Error::Shape);
        }
        if self.data.len() > max {
            return Err(Error::ProofTooLarge);
        }
        Ok(self.data)
    }
    pub const fn count(self, max: u64) -> Result<u64> {
        if self.major != 4 {
            return Err(Error::Shape);
        }
        if self.arg > max {
            return Err(Error::TooManyTx);
        }
        Ok(self.arg)
    }
    pub fn array<const N: usize>(self) -> Result<[Self; N]> {
        if self.major != 4 || self.arg != N as u64 {
            return Err(Error::Shape);
        }
        let mut out = [self; N];
        for (dst, v) in out.iter_mut().zip(self.children()) {
            *dst = v;
        }
        Ok(out)
    }
    pub fn tagged<const N: usize>(self, tag: u64, version: u64) -> Result<[Self; N]> {
        if self.major != 6 {
            return Err(Error::Shape);
        }
        if self.arg != tag {
            return Err(Error::Tag);
        }
        let a = item(self.data)?.array::<N>()?;
        if a[0].uint(u64::MAX)? != version {
            return Err(Error::Version);
        }
        Ok(a)
    }
    pub const fn children(self) -> Children<'a> {
        Children { rest: self.data }
    }
}
#[derive(Debug)]
pub struct Children<'a> {
    rest: &'a [u8],
}
impl<'a> Iterator for Children<'a> {
    type Item = Item<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let start = self.rest;
        scan(&mut self.rest, 0, &mut Items::native(usize::MAX)).expect("validated CBOR child");
        Some(item(&start[..start.len() - self.rest.len()]).expect("validated CBOR head"))
    }
}

pub fn uint(n: u64) -> Vec<u8> {
    header(0, n)
}
fn header(major: u8, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 24 {
        out.push((major << 5) | n as u8);
    } else {
        let (ai, size) = if n <= 255 {
            (24, 1)
        } else if n <= 65535 {
            (25, 2)
        } else if n <= u64::from(u32::MAX) {
            (26, 4)
        } else {
            (27, 8)
        };
        out.push((major << 5) | ai);
        out.extend_from_slice(&n.to_be_bytes()[8 - size..]);
    }
    out
}
pub fn bytes(b: &[u8]) -> Vec<u8> {
    let mut out = header(2, b.len() as u64);
    out.extend_from_slice(b);
    out
}
pub fn array(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = header(4, parts.len() as u64);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}
pub fn tag(n: u64, body: &[u8]) -> Vec<u8> {
    let mut out = header(6, n);
    out.extend_from_slice(body);
    out
}
