#!/usr/bin/env python3
"""Disable one guard at a time; require a named test failure, then restore.

Run from the repository root with a private CARGO_TARGET_DIR. Compile failures,
timeouts and zero-test runs do not count as killed mutations.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "crates/unicity/b1/src"
if not os.environ.get("CARGO_TARGET_DIR", "").startswith("/private/tmp/"):
    raise SystemExit("set a private CARGO_TARGET_DIR under /private/tmp")

# file, exact expression, disabled expression, target, named test
CASES = []
def guard(file, expression, test, replacement="false", target="conformance"):
    CASES.append((file, expression, replacement, target, test))

for expr,test in [
    ("input.len() > cap","vector_bound_call_262145"),
    ("gas < base + 16 * input.len() as u64","initial_debit_wins_over_malformed_scanning"),
    ("gas < call.gas","vector_cert_single_ok"),
    ("n > self.data.len()","vector_enc_truncated"),
    ("self.uint(1)? != 1","vector_enc_header_version"),
    ("self.uint(1)? != 0","vector_enc_header_flags"),
]: guard("lib.rs",expr,test)
for expr,test in [
    ("(ai == 24 && n < 24)","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("(ai == 25 && n <= 255)","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("(ai == 26 && n <= 65535)","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("(ai == 27 && n <= u64::from(u32::MAX))","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("*tokens > 32768","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("r.data.first().is_some_and(|b| b >> 5 == 7 && *b != 0xf6)","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("m == 3 && core::str::from_utf8(data).is_err()","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("depth >= 16","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation"),
    ("self.major != 0 || self.arg > max","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.major != major || self.data.len() < min","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.data.len() > max","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.major != 2 || self.arg != n as u64","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.major != 4 || self.arg != N as u64","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.major != 6 || self.arg != tag","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("a[0].uint(u64::MAX)? != 1","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("self.major != major {","cbor::shape_tests::schema_guards_have_exact_errors"),
    ("if self.arg > max {","cbor::shape_tests::schema_guards_have_exact_errors"),
]:
    # The brace disambiguates collection from blob. Preserve it in the edit.
    guard("cbor.rs",expr,test,("if false {" if expr.startswith("if ") else "false {") if expr.endswith("{") else "false","lib")
guard("cbor.rs","n > 64","vector_bound_signatures_65")
guard("cbor.rs","keys[..idx].contains(&key) || (idx > 0 && keys[idx - 1] >= key)","vector_quorum_dup_map_key")
guard("cbor.rs","!r.data.is_empty()","cbor::tests::depth_tokens_and_types_are_bounded_without_allocation",target="lib")
for expr,test in [
    ("last == 0","vector_enc_shard_no_terminator"),
    ("b.len() > 33 || depth > 256","vector_enc_shard_depth_257"),
    ("count == 0 || count > 8 || (!shared && count != 1)","vector_enc_header_count_zero"),
    ("sl > 33","vector_res_shard_length_u16max"),
    ("uc_len > 24576","vector_res_uc_length_u32max"),
    ("!(sig.len() == 64 || (sig.len() == 65 && sig[64] <= 1))","vector_quorum_sig_v2"),
    ("!r.data.is_empty()","vector_enc_trailing"),
    ("common.phase != 2","ordered_source_reads_and_phase_unknown_epoch"),
    ("c.tree_cert[1].arg != u64::from(c.partition)","vector_cert_neg_partition"),
    ("c.shard_cert[1].data != c.shard","vector_cert_neg_shard_bit"),
    ("c.conf.data != c.config","vector_cert_neg_config"),
    ("ir[4].data != c.state","vector_cert_neg_expected_state"),
    ("hash(&[c.ir.raw]) != c.ir_hash","vector_cert_neg_expected_ir"),
    ("c.shard_cert[2].children().count() != depth","vector_paths_shard_extra_sibling"),
    ("s[1].arg != common.network","vector_cert_neg_network"),
    ("s[3].arg > common.origin","ordered_source_reads_and_phase_unknown_epoch"),
    ("r < e.start","vector_time_start_before"),
    ("e.end.is_some_and(|end| r >= end)","vector_time_end_eq"),
    ("(e.end.is_none() && s[3].arg != common.origin)","vector_time_open_not_origin"),
    ("r > common.round","vector_time_future"),
    ("common.round - r > common.window","vector_time_age_wcert_1"),
    ("low != signature || secp.verify_ecdsa(&message, &signature, &member.key).is_err()","vector_quorum_bad_extra"),
]: guard("certificate.rs",expr,test)
guard("certificate.rs","c.seal.raw == first.seal.raw","vector_cert_shared_mixed_subsets_false","true")
guard("certificate.rs","ordered &&","vector_cert_shared_order","true &&")
guard("certificate.rs","h == sf[6].data","vector_cert_neg_trhash","true")
guard("certificate.rs","good >= e.total - (e.total - 1) / 3","vector_quorum_short","true")
for expr in [
    "w[0].is_zero() ||", "w[5].is_zero() ||", "w[2] != U256::from(1)",
    "!matches!(phase, 1 | 2)", "network > u64::from(u16::MAX)",
    "w.iter().any(|v| !v.is_zero())", "w[0] != U256::from(1)",
    "!(1..=3).contains(&kind)", "w[2].is_zero() ||", "w[8].is_zero()",
    "(kind == 1) != w[3].is_zero()", "!matches!(scheme, 1 | 2)",
    "!(1..=64).contains(&count)", "has_end > 1",
    "(has_end == 0 && end != 0)", "(has_end == 1 && end <= start)",
    "!(1..=128).contains(&len)", "id_bytes[len..].iter().any(|b| *b != 0)",
    "m[6][1..].iter().any(|b| *b != 0)", "weight == 0",
    "members.last().is_some_and(|prev| prev.id >= id)",
    "members.iter().any(|prev| prev.key == key)", "sum != total",
]: guard("registry.rs",expr,"registry_invariant_errors_are_exact_and_isolated","false ||" if expr.endswith("||") else "false")
guard("registry.rs","r.sload(k).map_err(Error::Host)","full_scan_and_debits_precede_host_access","r.sload(k).or(Ok(U256::ZERO))")
for expr,test in [
    ("r.header()? != 1","vector_rsmt_neg_count_2"),
    ("len > 4096","vector_rsmt_neg_value_4097"),
    ("r.data.len() != 32 * count","vector_rsmt_neg_partial_sibling"),
    ("gas < charge","vector_rsmt_single_leaf_ok"),
]: guard("rsmt.rs",expr,test)
guard("provider.rs","self.op == Operation::Member }","journal_values_warmth_revert_and_provider_status","true }")

for expr in [
    "(ir[1].arg != 0 && (ir[5].null() || ir[6].arg == 0))",
    "((ir[3].data == ir[4].data) == !ir[7].null())",
    "sf[2].arg == 0", "sf[4].arg < 1681971084",
]: guard("certificate.rs", expr, "independently_constructed_requests_match_kernel_verdicts")
guard("certificate.rs",
      "let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else { valid = false; continue; };",
      "vector_quorum_unknown_signer",
      "let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else { continue; };")
guard("provider.rs", "Err(PrecompileError::Fatal(e.to_string()))",
      "provider_database_failure_aborts_execution",
      'Ok(PrecompileOutput::halt(PrecompileHalt::Other("ignored host".into()), input.reservoir))')

guard("registry.rs", "sum.checked_add(weight).ok_or(Error::Registry)?",
      "registry_invariant_errors_are_exact_and_isolated", "sum.wrapping_add(weight)")
guard("registry.rs", "u64::try_from(v).map_err(|_| Error::Registry)",
      "registry_invariant_errors_are_exact_and_isolated", "Ok(v.as_limbs()[0])")
guard("registry.rs", "core::str::from_utf8(&id_bytes[..len]).map_err(|_| Error::Registry)?.to_owned()",
      "registry_invariant_errors_are_exact_and_isolated", "String::from_utf8_lossy(&id_bytes[..len]).into_owned()")

guard("provider.rs", "if self.op == Operation::Member {",
      "journal_values_warmth_revert_and_provider_status", "if true {")

originals = {file: (SRC / file).read_text() for file, *_ in CASES}
for file, before, *_ in CASES:
    pattern = re.compile(r"\s+".join(re.escape(x) for x in before.split()))
    count = len(list(pattern.finditer(originals[file])))
    if count != 1:
        raise SystemExit(f"{file}: expected one match for {before!r}, got {count}")
if "--check" in sys.argv:
    print(f"{len(CASES)} isolated mutations match the current sources")
    raise SystemExit(0)
start = int(sys.argv[sys.argv.index("--start") + 1]) if "--start" in sys.argv else 1
stop = int(sys.argv[sys.argv.index("--stop") + 1]) if "--stop" in sys.argv else len(CASES)
passed = 0
try:
    for index, (file, before, after, target, test) in enumerate(CASES, 1):
        if index < start or index > stop:
            continue
        original = originals[file]
        pattern = re.compile(r"\s+".join(re.escape(x) for x in before.split()))
        matches = list(pattern.finditer(original))
        if len(matches) != 1:
            raise RuntimeError(f"{file}: expected one match for {before!r}, got {len(matches)}")
        changed = pattern.sub(lambda _: after, original, count=1)
        (SRC / file).write_text(changed)
        args = ["cargo", "test", "-p", "reth-unicity-b1"]
        args += ["--lib"] if target == "lib" else ["--test", target]
        args += [test, "--", "--exact"]
        try:
            result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=180)
        finally:
            (SRC / file).write_text(original)
        output = result.stdout + result.stderr
        killed = result.returncode != 0 and "could not compile" not in output and re.search(r"test " + re.escape(test) + r" .*FAILED", output)
        label = "KILLED" if killed else "NOT KILLED"
        print(f"{index}/{len(CASES)} {label}: {file}: {before} -> {test}", flush=True)
        if not killed:
            print(output[-6000:], flush=True)
            raise RuntimeError("guard removal did not cause its named test to fail")
        passed += 1
finally:
    for file, original in originals.items():
        (SRC / file).write_text(original)
print(f"{passed}/{stop-start+1} selected isolated guard removals killed (range {start}..{stop}); all sources restored")
