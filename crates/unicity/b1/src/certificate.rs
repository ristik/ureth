use crate::{
    cbor::{self, Item},
    hash, Malformed, Reader,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Claim<'a> {
    pub partition: u32,
    pub shard: &'a [u8],
    pub config: &'a [u8],
    pub state: &'a [u8],
    pub ir_hash: &'a [u8],
    pub ir: Item<'a>,
    pub tr: Item<'a>,
    pub conf: Item<'a>,
    pub shard_cert: [Item<'a>; 3],
    pub tree_cert: [Item<'a>; 3],
    pub seal: Item<'a>,
    pub seal_fields: [Item<'a>; 8],
}
pub(crate) fn shard_depth(b: &[u8]) -> Result<usize, Malformed> {
    let last = *b.last().ok_or(Malformed::Shard)?;
    if last == 0 {
        return Err(Malformed::Shard);
    }
    let depth = b.len() * 8 - last.trailing_zeros() as usize - 1;
    if b.len() > 33 || depth > 256 {
        return Err(Malformed::Shard);
    }
    Ok(depth)
}
fn nullable_hash(v: Item<'_>) -> Result<(), Malformed> {
    if !v.null() {
        v.bytes(32)?;
    }
    Ok(())
}
pub(crate) struct Parsed<'a> {
    pub claim: Claim<'a>,
    /// Shard siblings plus Unicity-tree steps of this occurrence.
    pub paths: u64,
    /// Signature-map cardinality of this occurrence's seal.
    pub sigs: u64,
}
/// Parse and structurally validate one packed claim (the layout shared by every B1 certificate
/// operation) against the caller's cumulative CBOR item budget.
pub(crate) fn parse_claim<'a>(
    r: &mut Reader<'a>,
    tokens: &mut usize,
) -> Result<Parsed<'a>, Malformed> {
    let mut paths = 0;
    let mut max_sigs = 0;
    let partition = r.uint(4)? as u32;
    let sl = r.uint(2)? as usize;
    if sl > 33 {
        return Err(Malformed::Shard);
    }
    let shard = r.take(sl)?;
    shard_depth(shard)?;
    let config = r.take(32)?;
    let state = r.take(32)?;
    let ir_hash = r.take(32)?;
    let uc_len = r.uint(4)? as usize;
    if uc_len > 24576 {
        return Err(Malformed::Limit);
    }
    let uc = cbor::one(r.take(uc_len)?, tokens)?.tagged::<7>(39001)?;
    let ir = uc[1].tagged::<10>(39002)?;
    for i in [1, 2, 6, 8] {
        ir[i].uint(u64::MAX)?;
    }
    for i in [3, 7, 9] {
        nullable_hash(ir[i])?;
    }
    ir[4].bytes(32)?;
    if !ir[5].null() {
        ir[5].blob(2, 0, 256)?;
    }
    uc[2].bytes(32)?;
    uc[3].bytes(32)?;
    let sc = uc[4].tagged::<3>(39003)?;
    shard_depth(sc[1].blob(2, 1, 33)?)?;
    paths += sc[2].collection(4, 256)?;
    for sib in sc[2].children() {
        sib.bytes(32)?;
    }
    let tc = uc[5].tagged::<3>(39004)?;
    tc[1].uint(u64::from(u32::MAX))?;
    paths += tc[2].collection(4, 32)?;
    for step in tc[2].children() {
        let pair = step.array::<2>()?;
        pair[0].uint(u64::from(u32::MAX))?;
        pair[1].bytes(32)?;
    }
    let sf = uc[6].tagged::<8>(39005)?;
    sf[1].uint(u64::from(u16::MAX))?;
    for v in &sf[2..5] {
        v.uint(u64::MAX)?;
    }
    sf[5].bytes(32)?;
    sf[6].bytes(32)?;
    max_sigs = max_sigs.max(sf[7].collection(5, 64)?);
    let mut sigs = sf[7].children();
    while let Some(id) = sigs.next() {
        id.blob(3, 0, 128)?;
        let sig = sigs.next().ok_or(Malformed::Shape)?.blob(2, 0, usize::MAX)?;
        if !(sig.len() == 64 || (sig.len() == 65 && sig[64] <= 1)) {
            return Err(Malformed::Signature);
        }
    }
    Ok(Parsed {
        claim: Claim {
            partition,
            shard,
            config,
            state,
            ir_hash,
            ir: uc[1],
            tr: uc[2],
            conf: uc[3],
            shard_cert: sc,
            tree_cert: tc,
            seal: uc[6],
            seal_fields: sf,
        },
        paths,
        sigs: max_sigs,
    })
}
pub(crate) fn folds(c: &Claim<'_>) -> bool {
    let ir = c.ir.tagged::<10>(39002).expect("scanned IR");
    let sf = c.seal_fields;
    if (ir[1].arg != 0 && (ir[5].null() || ir[6].arg == 0)) ||
        ((ir[3].data == ir[4].data) == !ir[7].null()) ||
        sf[2].arg == 0 ||
        sf[4].arg < 1681971084 ||
        sf[7].null() ||
        sf[7].arg == 0
    {
        return false;
    }
    if c.tree_cert[1].arg != u64::from(c.partition) ||
        c.shard_cert[1].data != c.shard ||
        c.conf.data != c.config ||
        ir[4].data != c.state ||
        hash(&[c.ir.raw]) != c.ir_hash
    {
        return false;
    }
    let shard = c.shard_cert[1].data;
    let depth = shard_depth(shard).expect("scanned shard");
    if c.shard_cert[2].children().count() != depth {
        return false;
    }
    let mut h = hash(&[c.ir.raw, c.tr.raw, c.conf.raw]);
    for (i, sib) in c.shard_cert[2].children().enumerate() {
        let d = depth - 1 - i;
        h = if shard[d / 8] & (0x80 >> (d % 8)) == 0 {
            hash(&[&[0x58, 0x20], &h, &[0x58, 0x20], sib.data])
        } else {
            hash(&[&[0x58, 0x20], sib.data, &[0x58, 0x20], &h])
        };
    }
    let data = hash(&[&[0x58, 0x20], &h]);
    let partition = c.tree_cert[1].arg as u32;
    let key = partition.to_be_bytes();
    h = hash(&[&[0x41, 1, 0x44], &key, &[0x58, 0x20], &data]);
    for step in c.tree_cert[2].children() {
        let pair = step.array::<2>().expect("scanned path");
        let k = (pair[0].arg as u32).to_be_bytes();
        h = if partition > pair[0].arg as u32 {
            hash(&[&[0x41, 0, 0x44], &k, &[0x58, 0x20], pair[1].data, &[0x58, 0x20], &h])
        } else {
            hash(&[&[0x41, 0, 0x44], &k, &[0x58, 0x20], &h, &[0x58, 0x20], pair[1].data])
        };
    }
    h == sf[6].data
}

/// One Unicity certificate scanned on its own item budget with the structure and sublimits
/// `parse_claim` applies to a claim's certificate, and nothing else (the bridge's scan of an
/// embedded ancestor proof, bft-core `b1ref.ScanUC`). `parse_claim` is the authority; the bridge's
/// split-corpus mutation replay (`every_seeded_mutation_of_a_depth_two_input_replays_exactly`) compares this scan with the oracle's.
pub fn scan_certificate(raw: &[u8]) -> Result<(), Malformed> {
    if raw.len() > 24576 {
        return Err(Malformed::Limit);
    }
    let uc = cbor::one(raw, &mut 0)?.tagged::<7>(39001)?;
    // The bridge's restrictions run first, in the oracle's order (bft-core `scanCertificate`): the
    // SDK codec's required majors, the seal network and the seal signature widths. Only a width
    // that is neither 64 nor 65 is `Signature`; every other failure is `Shape` or `Limit`.
    for (i, tag, arity, req, major) in
        [(1, 39002, 10, 5, 2), (4, 39003, 3, 2, 4), (5, 39004, 3, 2, 4), (6, 39005, 8, 7, 5)]
    {
        let body = uc[i];
        if body.major != 6 || body.arg != tag {
            return Err(Malformed::Shape);
        }
        let inner = cbor::one(body.data, &mut 0)?;
        if inner.major != 4 || inner.arg != arity {
            return Err(Malformed::Shape);
        }
        if inner.children().nth(req).is_none_or(|c| c.major != major) {
            return Err(Malformed::Shape);
        }
    }
    let seal = cbor::one(uc[6].data, &mut 0)?.array::<8>()?;
    if seal[1].major != 0 || seal[1].arg == 0 || seal[1].arg > 65535 {
        return Err(Malformed::Shape);
    }
    for (i, v) in seal[7].children().enumerate() {
        if i % 2 == 1 {
            if v.major != 2 {
                return Err(Malformed::Shape);
            }
            if v.data.len() != 64 && v.data.len() != 65 {
                return Err(Malformed::Signature);
            }
        }
    }
    let ir = uc[1].tagged::<10>(39002)?;
    for i in [1, 2, 6, 8] {
        ir[i].uint(u64::MAX)?;
    }
    for i in [3, 7, 9] {
        nullable_hash(ir[i])?;
    }
    ir[4].bytes(32)?;
    if !ir[5].null() {
        ir[5].blob(2, 0, 256)?;
    }
    uc[2].bytes(32)?;
    uc[3].bytes(32)?;
    let sc = uc[4].tagged::<3>(39003)?;
    shard_depth(sc[1].blob(2, 1, 33)?)?;
    sc[2].collection(4, 256)?;
    for sib in sc[2].children() {
        sib.bytes(32)?;
    }
    let tc = uc[5].tagged::<3>(39004)?;
    tc[1].uint(u64::from(u32::MAX))?;
    tc[2].collection(4, 32)?;
    for step in tc[2].children() {
        let pair = step.array::<2>()?;
        pair[0].uint(u64::from(u32::MAX))?;
        pair[1].bytes(32)?;
    }
    let sf = uc[6].tagged::<8>(39005)?;
    sf[1].uint(u64::from(u16::MAX))?;
    for v in &sf[2..5] {
        v.uint(u64::MAX)?;
    }
    sf[5].bytes(32)?;
    sf[6].bytes(32)?;
    sf[7].collection(5, 64)?;
    let mut sigs = sf[7].children();
    while let Some(id) = sigs.next() {
        id.blob(3, 0, 128)?;
        let sig = sigs.next().ok_or(Malformed::Shape)?.blob(2, 0, usize::MAX)?;
        if sig.len() == 65 && sig[64] > 1 {
            return Err(Malformed::Shape);
        }
    }
    Ok(())
}
