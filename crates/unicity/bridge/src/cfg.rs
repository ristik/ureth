//! The bridge configuration: bft-core `DecodeCfg` followed by `Cfg.Validate`, keeping only what the
//! composition reads itself (the EVM partition and the aggregator policy hash). The B2 relation
//! re-parses the same bytes with its own, stricter rules.
use crate::{status_of_b2, Status, MAX_CFG_BYTES};
use reth_unicity_b2::cbor::{self, Item};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Cfg {
    pub evm_partition: u32,
    pub aggregator_policy_hash: [u8; 32],
}

const DOMAIN: &[u8] = b"UNICITY_BR_CFG";

fn fixed<'a>(it: Item<'a>, n: usize) -> Result<&'a [u8], Status> {
    it.bytes(n).map_err(status_of_b2)
}

/// The decoded fields the checks below need.
struct Fields<'a> {
    network: u64,
    root_genesis: &'a [u8],
    chain: u64,
    execution_genesis: &'a [u8],
    evm_partition: u32,
    rest: [&'a [u8]; 9],
}

fn fields(b: &[u8]) -> Result<Fields<'_>, Status> {
    if b.len() > MAX_CFG_BYTES {
        return Err(Status::InputTooLarge);
    }
    let root = cbor::one(b, &mut 0).map_err(status_of_b2)?;
    let k = root.array::<16>().map_err(|_| Status::Shape)?;
    if k[0].major != 2 || k[0].data != DOMAIN {
        return Err(Status::Shape);
    }
    let network = k[1].uint(0xffff).map_err(status_of_b2)?;
    if network == 0 {
        return Err(Status::IntRange);
    }
    let root_genesis = fixed(k[2], 32)?;
    let chain = k[3].uint(u64::MAX).map_err(status_of_b2)?;
    let execution_genesis = fixed(k[4], 32)?;
    let evm_partition = k[5].uint(u64::from(u32::MAX)).map_err(status_of_b2)? as u32;
    if k[6].major != 2 {
        return Err(Status::Shape);
    }
    let mut rest = [&[][..]; 9];
    for (i, n) in [20, 20, 32, 32, 32, 20, 32, 32, 32].into_iter().enumerate() {
        rest[i] = fixed(k[7 + i], n)?;
    }
    Ok(Fields { network, root_genesis, chain, execution_genesis, evm_partition, rest })
}

/// `DecodeCfg`.
pub(crate) fn decode(b: &[u8]) -> Result<Cfg, Status> {
    let f = fields(b)?;
    Ok(Cfg {
        evm_partition: f.evm_partition,
        aggregator_policy_hash: f.rest[8].try_into().expect("32"),
    })
}

/// `Cfg.Validate`: the derived identifiers, the zero address and a nonzero vault. `b` decodes.
pub(crate) fn validate(b: &[u8]) -> Result<(), Status> {
    let f = fields(b)?;
    let [vault, zero, ty, aid, ..] = f.rest;
    let d = identity(f.network, f.root_genesis, f.execution_genesis, f.chain);
    if ty != hash(format!("unicity-bridge:unicity-native:{d}").as_bytes()) ||
        aid != hash(format!("unicity-bridge-coin:unicity-native:{d}").as_bytes()) ||
        zero.iter().any(|x| *x != 0) ||
        vault.iter().all(|x| *x == 0)
    {
        return Err(Status::CfgMismatch);
    }
    Ok(())
}

/// `D = network:rootGenesisHex:executionGenesisHex:chainId:zeroAddressHex`.
fn identity(network: u64, root_genesis: &[u8], execution_genesis: &[u8], chain: u64) -> String {
    use core::fmt::Write;
    let mut d = format!("{network}:");
    for b in root_genesis {
        write!(&mut d, "{b:02x}").expect("String write");
    }
    d.push(':');
    for b in execution_genesis {
        write!(&mut d, "{b:02x}").expect("String write");
    }
    d.push_str(&format!(":{chain}:0000000000000000000000000000000000000000"));
    d
}

pub(crate) fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
