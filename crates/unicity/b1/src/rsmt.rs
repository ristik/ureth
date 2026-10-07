use crate::{hash, Error, Malformed, Output, Reader};
pub(crate) fn run<E>(input: &[u8], gas: u64) -> Result<Output, Error<E>> {
    let mut r = Reader { data: input };
    if r.header()? != 1 {
        return Err(Malformed::Count.into());
    }
    let root = r.take(32)?;
    let key = r.take(32)?;
    let len = r.uint(4)? as usize;
    if len > 4096 {
        return Err(Malformed::Limit.into());
    }
    let value = r.take(len)?;
    let bitmap = r.take(32)?;
    let count: usize = bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if r.data.len() != 32 * count {
        return Err(Malformed::Shape.into());
    }
    let charge = 2000 + 16 * input.len() as u64 + 250 * (1 + count as u64);
    if gas < charge {
        return Err(Error::OutOfGas);
    }
    let mut h = hash(&[&[0], key, value]);
    let mut idx = count;
    for d in (0..256).rev() {
        if bitmap[d / 8] & (0x80 >> (d % 8)) == 0 {
            continue;
        }
        idx -= 1;
        let sibling = &r.data[idx * 32..(idx + 1) * 32];
        let mut region = [0u8; 32];
        region[..d / 8].copy_from_slice(&key[..d / 8]);
        if d % 8 != 0 {
            region[d / 8] = key[d / 8] & (0xff << (8 - d % 8));
        }
        h = if key[d / 8] & (0x80 >> (d % 8)) == 0 {
            hash(&[&[1, d as u8], &region, &h, sibling])
        } else {
            hash(&[&[1, d as u8], &region, sibling, &h])
        };
    }
    Ok(Output::new(charge, root != [0u8; 32] && h == root))
}
