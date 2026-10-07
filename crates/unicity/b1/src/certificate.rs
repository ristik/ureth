use crate::{
    cbor::{self, Item},
    hash, registry, Error, Malformed, Output, Reader, RegistryRead,
};
use secp256k1::{ecdsa::Signature, Message, Secp256k1};

#[derive(Clone, Copy, Debug)]
struct Claim<'a> {
    partition: u32,
    shard: &'a [u8],
    config: &'a [u8],
    state: &'a [u8],
    ir_hash: &'a [u8],
    ir: Item<'a>,
    tr: Item<'a>,
    conf: Item<'a>,
    shard_cert: [Item<'a>; 3],
    tree_cert: [Item<'a>; 3],
    seal: Item<'a>,
    seal_fields: [Item<'a>; 8],
}
#[derive(Debug)]
pub(crate) struct Call<'a> {
    claims: [Option<Claim<'a>>; 8],
    pub gas: u64,
}

fn shard_depth(b: &[u8]) -> Result<usize, Malformed> {
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
pub(crate) fn scan(input: &[u8], shared: bool) -> Result<Call<'_>, Malformed> {
    let mut r = Reader { data: input };
    let count = r.header()?;
    if count == 0 || count > 8 || (!shared && count != 1) {
        return Err(Malformed::Count);
    }
    let mut claims = [None; 8];
    let mut tokens = 0;
    let mut max_sigs = 0;
    let mut paths = 0;
    for dst in claims.iter_mut().take(count) {
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
        let uc = cbor::one(r.take(uc_len)?, &mut tokens)?.tagged::<7>(39001)?;
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
        *dst = Some(Claim {
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
        });
    }
    if !r.data.is_empty() {
        return Err(Malformed::Trailing);
    }
    Ok(Call {
        claims,
        gas: 60000 +
            16 * input.len() as u64 +
            64000 +
            6000 * max_sigs +
            2000 * count as u64 +
            250 * paths +
            1117700,
    })
}

pub(crate) fn evaluate<R: RegistryRead>(
    call: Call<'_>,
    state: &mut R,
) -> Result<Output, Error<R::Error>> {
    let common = registry::common(state)?;
    let claims: [_; 8] = call.claims;
    let first = claims[0].expect("nonempty scanned call");
    let same_seal = claims.iter().flatten().all(|c| c.seal.raw == first.seal.raw);
    // Common words are always read. A common seal additionally selects exactly
    // one epoch, including all metadata and every populated member word.
    let entry = if same_seal { registry::entry(state, first.seal_fields[3].arg)? } else { None };
    let valid = if common.phase != 2 || !same_seal {
        false
    } else {
        let ordered = claims
            .iter()
            .flatten()
            .zip(claims.iter().flatten().skip(1))
            .all(|(a, b)| (a.partition, a.shard) < (b.partition, b.shard));
        ordered && claims.iter().flatten().all(folds) && seal_valid(first, &common, entry.as_ref())
    };
    Ok(Output::new(call.gas, valid))
}

fn folds(c: &Claim<'_>) -> bool {
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
fn seal_valid(c: Claim<'_>, common: &registry::Common, entry: Option<&registry::Entry>) -> bool {
    let s = c.seal_fields;
    let Some(e) = entry else {
        return false;
    };
    let r = s[2].arg;
    if s[1].arg != common.network ||
        s[3].arg > common.origin ||
        r < e.start ||
        e.end.is_some_and(|end| r >= end) ||
        (e.end.is_none() && s[3].arg != common.origin) ||
        r > common.round ||
        common.round - r > common.window
    {
        return false;
    }
    // Canonical tagged seal prefix is preserved verbatim; only signatures is
    // replaced with the native null item. No domain/prefix or second digest.
    let sig_map = s[7];
    let prefix = &c.seal.raw[..c.seal.raw.len() - sig_map.raw.len()];
    let digest = hash(&[prefix, &[0xf6]]);
    let message = Message::from_digest(digest);
    let secp = Secp256k1::verification_only();
    let mut good = 0u64;
    let mut valid = true;
    let mut sigs = sig_map.children();
    while let Some(id) = sigs.next() {
        let sig = sigs.next().expect("scanned signature pair");
        let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else {
            valid = false;
            continue;
        };
        let Ok(signature) = Signature::from_compact(&sig.data[..64]) else {
            valid = false;
            continue;
        };
        let mut low = signature;
        low.normalize_s();
        if low != signature || secp.verify_ecdsa(&message, &signature, &member.key).is_err() {
            valid = false;
            continue;
        }
        good += member.weight;
    }
    valid && good >= e.total - (e.total - 1) / 3
}
