//! Borrowed token views over the merged B1 canonical scanner.
use crate::{
    error::{BridgeError as E, Result},
    limits::*,
};
use reth_unicity_b1::{cbor, Malformed};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Item<'a>(pub(crate) cbor::Item<'a>);

pub(crate) fn scan_one(b: &[u8]) -> Result<Item<'_>> {
    scan_shared(b, &mut 0)
}
pub(crate) fn scan_shared<'a>(b: &'a [u8], tokens: &mut usize) -> Result<Item<'a>> {
    cbor::one_token(b, tokens).map(Item).map_err(|e| match e {
        Malformed::Truncated => E::Truncated,
        Malformed::Trailing => E::Trailing,
        Malformed::Canonical => E::NonCanonical,
        Malformed::Limit if *tokens > MAX_CBOR_ITEMS => E::TooManyItems,
        Malformed::Limit => E::TooDeep,
        _ => E::ForbiddenCBOR,
    })
}
impl<'a> Item<'a> {
    pub(crate) const fn raw(&self, _b: &[u8]) -> &'a [u8] {
        self.0.raw
    }
    pub(crate) fn array<const N: usize>(&self) -> Result<[Self; N]> {
        self.0.array::<N>().map(|a| a.map(Self)).map_err(|_| E::Shape)
    }
    pub(crate) const fn any_array(&self) -> Result<cbor::Children<'a>> {
        if self.0.major != 4 {
            return Err(E::Shape);
        }
        Ok(self.0.children())
    }
    pub(crate) fn bytes_n(&self, n: usize) -> Result<&'a [u8]> {
        let b = self.bytes()?;
        if b.len() != n {
            return Err(E::Length);
        }
        Ok(b)
    }
    pub(crate) const fn bytes(&self) -> Result<&'a [u8]> {
        if self.0.major != 2 {
            return Err(E::Shape);
        }
        Ok(self.0.data)
    }
    pub(crate) fn tag_content(&self, tag: u64) -> Result<Self> {
        if self.0.major != 6 {
            return Err(E::Shape);
        }
        if self.0.arg != tag {
            return Err(E::Tag);
        }
        Ok(Self(self.0.children().next().expect("scanned tag child")))
    }
    pub(crate) const fn uint_max(&self, max: u64) -> Result<u64> {
        if self.0.major != 0 {
            return Err(E::Shape);
        }
        if self.0.arg > max {
            return Err(E::IntRange);
        }
        Ok(self.0.arg)
    }
    pub(crate) fn version(&self) -> Result<()> {
        if self.uint_max(u64::MAX)? != 1 {
            return Err(E::Version);
        }
        Ok(())
    }
    pub(crate) fn amount(&self) -> Result<&'a [u8]> {
        let d = self.bytes()?;
        if d.is_empty() || d.len() > MAX_AMOUNT_BYTES || d[0] == 0 {
            return Err(E::IntRange);
        }
        Ok(d)
    }
}
