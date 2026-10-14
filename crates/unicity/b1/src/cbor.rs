//! Borrowed deterministic CBOR. The first pass validates the full generic tree
//! with shared token accounting and a fixed stack bound. No wire length allocates.
use crate::{Malformed, Reader};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Item<'a> {
    pub raw: &'a [u8],
    pub major: u8,
    pub arg: u64,
    pub data: &'a [u8],
}
fn head(r: &mut Reader<'_>) -> Result<(u8, u64), Malformed> {
    let first = r.uint(1)? as u8;
    let ai = first & 31;
    let n = match ai {
        0..=23 => u64::from(ai),
        24..=27 => r.uint(1 << (ai - 24))?,
        _ => return Err(Malformed::Cbor),
    };
    if (ai == 24 && n < 24) ||
        (ai == 25 && n <= 255) ||
        (ai == 26 && n <= 65535) ||
        (ai == 27 && n <= u64::from(u32::MAX))
    {
        return Err(Malformed::Canonical);
    }
    Ok((first >> 5, n))
}
fn scan(r: &mut Reader<'_>, depth: usize, tokens: &mut usize) -> Result<(), Malformed> {
    *tokens += 1;
    if *tokens > 32768 {
        return Err(Malformed::Limit);
    }
    if r.data.first().is_some_and(|b| b >> 5 == 7 && *b != 0xf6) {
        return Err(Malformed::Cbor);
    }
    let (m, n) = head(r)?;
    match m {
        0 => {}
        2 | 3 => {
            let len = usize::try_from(n).map_err(|_| Malformed::Truncated)?;
            let data = r.take(len)?;
            if m == 3 && core::str::from_utf8(data).is_err() {
                return Err(Malformed::Utf8);
            }
        }
        4..=6 => {
            if depth >= 16 {
                return Err(Malformed::Limit);
            }
            let count = match m {
                5 => {
                    if n > 64 {
                        return Err(Malformed::Limit);
                    }
                    n * 2
                }
                6 => 1,
                _ => n,
            };
            if count > r.data.len() as u64 {
                return Err(Malformed::Truncated);
            }
            let mut keys: [&[u8]; 64] = [&[]; 64];
            for i in 0..count {
                let start = r.data;
                scan(r, depth + 1, tokens)?;
                if m == 5 && i % 2 == 0 {
                    let key = &start[..start.len() - r.data.len()];
                    let idx = (i / 2) as usize;
                    if keys[..idx].contains(&key) || (idx > 0 && keys[idx - 1] >= key) {
                        return Err(Malformed::Canonical);
                    }
                    keys[idx] = key;
                }
            }
        }
        7 if n == 22 => {}
        _ => return Err(Malformed::Cbor),
    }
    Ok(())
}

pub(crate) fn one<'a>(data: &'a [u8], tokens: &mut usize) -> Result<Item<'a>, Malformed> {
    let mut r = Reader { data };
    scan(&mut r, 0, tokens)?;
    if !r.data.is_empty() {
        return Err(Malformed::Trailing);
    }
    item(data)
}
fn item(data: &[u8]) -> Result<Item<'_>, Malformed> {
    let mut r = Reader { data };
    let (major, arg) = head(&mut r)?;
    Ok(Item { raw: data, major, arg, data: r.data })
}
impl<'a> Item<'a> {
    pub(crate) const fn null(self) -> bool {
        self.major == 7 && self.arg == 22
    }
    pub(crate) const fn uint(self, max: u64) -> Result<u64, Malformed> {
        if self.major != 0 || self.arg > max {
            return Err(Malformed::Shape);
        }
        Ok(self.arg)
    }
    pub(crate) const fn blob(
        self,
        major: u8,
        min: usize,
        max: usize,
    ) -> Result<&'a [u8], Malformed> {
        if self.major != major || self.data.len() < min {
            return Err(Malformed::Shape);
        }
        if self.data.len() > max {
            return Err(Malformed::Limit);
        }
        Ok(self.data)
    }
    pub(crate) const fn bytes(self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.major != 2 || self.arg != n as u64 {
            return Err(Malformed::Shape);
        }
        Ok(self.data)
    }
    pub(crate) fn array<const N: usize>(self) -> Result<[Self; N], Malformed> {
        if self.major != 4 || self.arg != N as u64 {
            return Err(Malformed::Shape);
        }
        let mut out = [self; N];
        for (dst, v) in out.iter_mut().zip(self.children()) {
            *dst = v;
        }
        Ok(out)
    }
    pub(crate) fn tagged<const N: usize>(self, tag: u64) -> Result<[Self; N], Malformed> {
        if self.major != 6 || self.arg != tag {
            return Err(Malformed::Shape);
        }
        let a = item(self.data)?.array::<N>()?;
        if a[0].uint(u64::MAX)? != 1 {
            return Err(Malformed::Version);
        }
        Ok(a)
    }
    pub(crate) const fn collection(self, major: u8, max: u64) -> Result<u64, Malformed> {
        if self.null() {
            return Ok(0);
        }
        if self.major != major {
            return Err(Malformed::Shape);
        }
        if self.arg > max {
            return Err(Malformed::Limit);
        }
        Ok(self.arg)
    }
    pub(crate) const fn children(self) -> Children<'a> {
        Children { rest: if self.null() { &[] } else { self.data } }
    }
}
pub(crate) struct Children<'a> {
    rest: &'a [u8],
}
impl<'a> Iterator for Children<'a> {
    type Item = Item<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let start = self.rest;
        let mut r = Reader { data: start };
        // All views originate in the successful full-tree scan. Rescanning a
        // child only locates its boundary; it cannot observe new caller bytes.
        scan(&mut r, 0, &mut 0).expect("validated CBOR child");
        self.rest = r.data;
        Some(item(&start[..start.len() - r.data.len()]).expect("validated CBOR head"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn depth_tokens_and_types_are_bounded_without_allocation() {
        let deep = [vec![0x81; 17], vec![0xf6]].concat();
        assert_eq!(one(&deep, &mut 0).unwrap_err(), Malformed::Limit);
        let allowed = [vec![0x81; 16], vec![0xf6]].concat();
        assert!(one(&allowed, &mut 0).is_ok());
        assert_eq!(one(&[0], &mut 32768).unwrap_err(), Malformed::Limit);
        for data in [
            &[0x18, 0x17][..],
            &[0x19, 0, 255],
            &[0x1a, 0, 0, 255, 255],
            &[0x1b, 0, 0, 0, 0, 255, 255, 255, 255],
        ] {
            assert_eq!(one(data, &mut 0).unwrap_err(), Malformed::Canonical);
        }
        for data in [&[0x9f, 0xff][..], &[0xf5], &[0xf9, 0, 0], &[0x20]] {
            assert_eq!(one(data, &mut 0).unwrap_err(), Malformed::Cbor);
        }
        assert_eq!(one(&[0x61, 255], &mut 0).unwrap_err(), Malformed::Utf8);
        assert_eq!(one(&[0x58, 255], &mut 0).unwrap_err(), Malformed::Truncated);
        assert_eq!(one(&[0, 0], &mut 0).unwrap_err(), Malformed::Trailing);
    }
}

#[cfg(test)]
mod shape_tests {
    use super::*;
    #[test]
    fn schema_guards_have_exact_errors() {
        let version = one(&[0xd9, 0x98, 0x59, 0x81, 2], &mut 0).unwrap();
        assert_eq!(version.tagged::<1>(39001).unwrap_err(), Malformed::Version);
        assert_eq!(version.tagged::<1>(39002).unwrap_err(), Malformed::Shape);
        let u = one(&[24, 24], &mut 0).unwrap();
        assert_eq!(u.uint(23), Err(Malformed::Shape));
        assert_eq!(u.bytes(32), Err(Malformed::Shape));
        assert_eq!(u.blob(2, 0, 32), Err(Malformed::Shape));
        assert_eq!(u.array::<1>().unwrap_err(), Malformed::Shape);
        assert_eq!(u.collection(4, 64), Err(Malformed::Shape));
        let empty = one(&[0x40], &mut 0).unwrap();
        assert_eq!(empty.blob(2, 1, 32), Err(Malformed::Shape));
        assert_eq!(empty.bytes(1), Err(Malformed::Shape));
        let b = one(&[0x42, 0, 0], &mut 0).unwrap();
        assert_eq!(b.blob(2, 0, 1), Err(Malformed::Limit));
        let a = one(&[0x82, 0, 0], &mut 0).unwrap();
        assert_eq!(a.collection(4, 1), Err(Malformed::Limit));
        assert_eq!(a.array::<1>().unwrap_err(), Malformed::Shape);
    }
}
