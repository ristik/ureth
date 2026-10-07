#!/usr/bin/env python3
"""Disable isolated guards, require named runtime test failures, always restore.

Run at the repo root with private CARGO_TARGET_DIR. Compile failures, timeouts
and zero-test runs are not kills. --only N resumes one numbered case.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[4]
CASES=[]
def guard(file,expression,test,replacement="false",package="reth-unicity-b2"):
    CASES.append((file,expression,replacement,test,package))
for expr,test in [
 ("bytes[..24].iter().any(|b| *b != 0)","abi_rejects_alias_offsets_padding_and_trailing"),
 ("padding.iter().any(|b| *b != 0)","abi_rejects_alias_offsets_padding_and_trailing"),
 ("transfers.major != 4","preflight_schema_errors_precede_second_debit"),
 ("transfers.arg > MAX_TRANSFERS as u64","transfer_cap_checks_actual_count_before_relation"),
 ("input.len() > MAX_SEMANTIC_BYTES","semantic_byte_ceiling_exact_and_over"),
 ("gas < base","initial_debit_precedes_malformed_scan"),
 ("op > 2","abi_rejects_alias_offsets_padding_and_trailing"),
 ("word(input, 32)? != 96","abi_rejects_alias_offsets_padding_and_trailing"),
 ("word(input, 64)? != next","abi_rejects_alias_offsets_padding_and_trailing"),
 ("end != input.len()","abi_rejects_alias_offsets_padding_and_trailing"),
 ("gas < charge","vector_mint_valid"),
 ("e.family() == Family::Budget","embedded_caps_precede_relation_and_share_item_budget"),
]:guard("wire.rs",expr,test)
guard("wire.rs","array::<3>(root)?;","preflight_schema_errors_precede_second_debit","let _ = root;")
guard("wire.rs","embedded(fields[5], &mut tokens)?;","embedded_caps_precede_relation_and_share_item_budget","let _ = fields[5];")
guard("wire.rs","embedded(fields[6], &mut tokens)?;","embedded_caps_precede_relation_and_share_item_budget","let _ = fields[6];")
guard("wire.rs","item.major == 2","embedded_caps_precede_relation_and_share_item_budget")
guard("wire.rs","mint.major == 6","embedded_caps_precede_relation_and_share_item_budget")
guard("wire.rs","tx.major == 6","embedded_return_cap_is_checked_before_cd_mismatch")
guard("wire.rs","embedded(fields[3], &mut tokens)?;","embedded_return_cap_is_checked_before_cd_mismatch","let _ = fields[3];")
guard("wire.rs","scan(cfg, &mut tokens).map_err(classify)?;","depth_and_shared_item_ceilings_exact_and_over","let _ = cfg;")
for expr in ["self.0.major != 4","b.len() != n","self.0.major != 2","self.0.major != 6","self.0.arg != tag","self.0.major != 0","self.0.arg > max","self.uint_max(u64::MAX)? != 1","d.is_empty() || d.len() > MAX_AMOUNT_BYTES || d[0] == 0"]:
 guard("scan.rs",expr,"borrowed_schema_views_assert_exact_errors")
guard("cfg.rs","k[0].bytes().map_err(|_| E::Shape)? != CFG_DOMAIN","cfg_domain_widths_and_integer_bounds")
for expr,test in [
 ("k[0].uint_max(u64::MAX)? != 1","predicate_dispatch_is_closed_and_burn_width_fixed"),
 ("code.len() != 1 || (code[0] != PRED_SIGNATURE && code[0] != PRED_BURN)","predicate_dispatch_is_closed_and_burn_width_fixed"),
 ("params.len() != 32","predicate_dispatch_is_closed_and_burn_width_fixed"),
 ("*digest == [0; 32]","zero_sentinels_and_invalid_minter_scalars"),
 ("n == 0 || !amount_ok(amount)","vector_prepare_zero_nonce"),
 ("pred.typ != PRED_SIGNATURE","vector_prepare_burn_p0"),
 ("!h.transfers.is_empty()","vector_return_for_mint_op"),
 ("if h.transfers.is_empty() {","vector_mint_for_return_op"),
 ("if aid != cfg.aid {","vector_mint_wrong_asset"),
 ("cd.source.to_bytes() != source.to_bytes() || cd.source_hash != *source_hash","vector_cd_source_owner"),
 ("cd.tx_hash != tx_hash","vector_cd_tx_hash"),
 ("!seen.insert(sid)","repeated_sid_is_rejected_by_step_guard"),
 ("m.network != cfg.network || m.recipient.typ != PRED_SIGNATURE","vector_mint_wrong_network"),
 ("m.ty != cfg.ty","vector_mint_wrong_type"),
 ("m.salt != salt","vector_mint_salt_changed"),
 ("t.recipient.typ != PRED_SIGNATURE","vector_burn_before_final"),
 ("t.data.is_some()","vector_transfer_data"),
 ("t.recipient.typ != PRED_BURN","vector_final_not_burn"),
 ("if chain != cfg.chain_id {","every_return_field_is_bound_independently"),
 ("amt != out.amount","every_return_field_is_bound_independently"),
 ("t.recipient.params != h(data)","vector_burn_reason_mismatch"),
]:guard("history.rs",expr,test,"if false {" if expr.startswith("if ") else "false")
# Compound checks: remove each independent relation, retaining the others.
for full,parts,test in [
 ("chain != cfg.chain_id || vault != cfg.vault || zero != cfg.zero_address || n == 0",["chain != cfg.chain_id","vault != cfg.vault","zero != cfg.zero_address","n == 0"],"every_justification_field_is_bound_independently"),
 ("vault != cfg.vault || zero != cfg.zero_address || ty != cfg.ty || aid != cfg.aid",["vault != cfg.vault","zero != cfg.zero_address","ty != cfg.ty","aid != cfg.aid"],"every_return_field_is_bound_independently"),
 ("zero2 != cfg.zero_address || !empty_ok || !zero_ok",["zero2 != cfg.zero_address","!empty_ok","!zero_ok"],"every_return_field_is_bound_independently"),
 ("recip == [0u8; 20] || recip == cfg.vault",["recip == [0u8; 20]","recip == cfg.vault"],"every_return_field_is_bound_independently"),
]:
 for part in parts:guard("history.rs",full,test,full.replace(part,"false"))
# The two source commitments, network/first predicate and lock amount separately.
guard("history.rs","cd.source.to_bytes() != source.to_bytes() || cd.source_hash != *source_hash","vector_cd_source_hash","cd.source.to_bytes() != source.to_bytes()")
guard("history.rs","m.network != cfg.network || m.recipient.typ != PRED_SIGNATURE","vector_mint_burn_recipient","m.network != cfg.network")
guard("history.rs","n == 0 || !amount_ok(amount)","vector_prepare_zero_amount","n == 0")
guard("history.rs","parse_key(params)?;","predicate_dispatch_is_closed_and_burn_width_fixed","let _ = params;")
guard("history.rs","SecretKey::from_byte_array(k).map_err(|_| E::MinterKey)","zero_sentinels_and_invalid_minter_scalars","SecretKey::from_byte_array(k).or_else(|_| Ok(SecretKey::from_byte_array(&[1;32]).unwrap()))")
for expr,test in [
 ("bytes.len() != 33 || !matches!(bytes[0], 2 | 3)","keys_must_be_valid_and_compressed"),
 ("unlock.len() != 65","vector_unlock_short"),
 ("unlock[..32].iter().all(|b| *b == 0) || unlock[32..64].iter().all(|b| *b == 0)","vector_unlock_r_zero"),
 ("low != sig","vector_unlock_high_s"),
 ("recovered != *key","vector_unlock_flipped_parity"),
]:guard("unlock.rs",expr,test)
guard("unlock.rs","RecoveryId::try_from(i32::from(unlock[64])).map_err(|_| E::UnlockRecovery)?","vector_unlock_id4","RecoveryId::try_from(i32::from(unlock[64])).unwrap_or(RecoveryId::Zero)")
guard("unlock.rs","SECP256K1.recover_ecdsa(&digest, &recoverable).map_err(|_| E::UnlockKey)?","vector_unlock_id2","SECP256K1.recover_ecdsa(&digest, &recoverable).unwrap_or(*key)")
guard("unlock.rs","SECP256K1.verify_ecdsa(digest, sig, key).map_err(|_| E::Unlock)","compact_verification_is_independently_enforced","Ok(())")
guard("unlock.rs","unlock[..32].iter().all(|b| *b == 0) || unlock[32..64].iter().all(|b| *b == 0)","vector_unlock_s_zero","unlock[..32].iter().all(|b| *b == 0)")
# New scanner modes only; the unchanged B1 scanner guards have their own harness.
guard("../b1/src/cbor.rs","token && r.data.first().is_some_and(|b| matches!(b >> 5, 3 | 5))","token_subset_does_not_change_certificate_grammar",package="reth-unicity-b1")
guard("../b1/src/cbor.rs","token && r.data.first().is_some_and(|b| matches!(b & 31, 28..=30))","token_subset_does_not_change_certificate_grammar",package="reth-unicity-b1")

def pattern(expression):
    return r"\s*".join(re.escape(p) for p in re.split(r"\s+",expression.strip()))

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--only",type=int,nargs="*");args=parser.parse_args()
    target=os.environ.get("CARGO_TARGET_DIR","")
    if not target.startswith("/private/tmp/"):raise SystemExit("set private CARGO_TARGET_DIR under /private/tmp")
    logs=Path("/private/tmp/bridge2-mutants");logs.mkdir(exist_ok=True)
    results=[]
    for index,(file,expression,replacement,test,package) in enumerate(CASES,1):
        if args.only and index not in args.only:continue
        path=ROOT/"crates/unicity/b2/src"/file
        if file.startswith("../b1/"):path=ROOT/"crates/unicity"/file[3:]
        original=path.read_text();prefix=original.split("#[cfg(test)]",1)[0]
        matches=list(re.finditer(pattern(expression),prefix))
        if len(matches)!=1:
            print(f"ERROR {index}: pattern count {len(matches)} {file}: {expression}",flush=True);results.append((index,"PATTERN"));continue
        match=matches[0];modified=original[:match.start()]+replacement+original[match.end():]
        command=["cargo","test","-p",package,"-j","4","--lib",test]
        env={**os.environ,"CARGO_BUILD_JOBS":"4","RUST_TEST_THREADS":"1","CARGO_PROFILE_DEV_DEBUG":"0"}
        try:
            path.write_text(modified)
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=240)
            output=result.stdout;(logs/f"{index:03}.log").write_text(output)
            named=re.search(r"test [^\n]*"+re.escape(test)+r"[^\n]* \.\.\. FAILED",output)
            status="KILLED" if result.returncode!=0 and named and "test result: FAILED" in output else "LIVED" if result.returncode==0 else "ERROR"
        except subprocess.TimeoutExpired:status="TIMEOUT"
        finally:path.write_text(original)
        results.append((index,status));print(f"{status} {index}/{len(CASES)} {file}: {expression} => {test}",flush=True)
    print("SUMMARY",results,flush=True)
    if any(s!="KILLED" for _,s in results):raise SystemExit(1)
if __name__=="__main__":main()
