//! Removes old local accounting records to exercise bounded startup repair in process tests.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("missing companion-store path")?;
    let below: u64 = args.next().ok_or("missing exclusive block number")?.parse()?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    reth_unicity_store::open(path)?.prune_accounting_below(below)?;
    Ok(())
}
