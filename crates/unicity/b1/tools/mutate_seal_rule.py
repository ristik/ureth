#!/usr/bin/env python3
"""Mutation gates of the seal signature rule (the upstream rule): disable one guard at a time and require
the any-age corpus test (which carries the shared Go vectors) or the named batch test to fail.

Replaces the width/recovery-byte and "bad extra rejects the seal" mutants of mutate_guards.py with the
mutants of the rule now in force: poisoning an honest quorum by an unknown or bad extra, unearned weight,
refused recovery IDs 2/3, high-s normalized into acceptance, a wrong quorum bound, uncounted work, and an
empty value no longer refused. Run from the repository root with a private CARGO_TARGET_DIR.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "crates/unicity/b1/src/batch.rs"
if not os.environ.get("CARGO_TARGET_DIR"):
    raise SystemExit("set a private CARGO_TARGET_DIR")

CASES = [
    ("empty value no longer refused", "if sig.data.is_empty() || id.data.is_empty() {", "if id.data.is_empty() {", "anyage_vectors"),
    ("empty signer ID no longer refused", "if sig.data.is_empty() || id.data.is_empty() {", "if sig.data.is_empty() {", "anyage_vectors"),
    ("unknown signer poisons the seal",
     "let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else { continue; };",
     "let Some(member) = e.members.iter().find(|m| m.id.as_bytes() == id.data) else { return false; };", "anyage_vectors"),
    ("bad extra poisons the seal",
     "if recovers_to(&secp, &message, sig.data, &member.key) { good += member.weight; }",
     "if recovers_to(&secp, &message, sig.data, &member.key) { good += member.weight; } else { return false; }", "anyage_vectors"),
    ("unearned weight", "good += member.weight;", "good += 1;", "batch"),
    ("recovery IDs 2 and 3 refused", "RecoveryId::try_from(i32::from(sig[64]))", "RecoveryId::try_from(i32::from(sig[64] & 1))", "anyage_vectors"),
    ("high s accepted", "if low != standard {", "if false {", "anyage_vectors"),
    ("supplied recovery ID ignored", "RecoveryId::try_from(i32::from(sig[64]))", "RecoveryId::try_from(0i32)", "anyage_vectors"),
    ("quorum bound one low", "good >= e.total - (e.total - 1) / 3", "good + 1 >= e.total - (e.total - 1) / 3", "anyage_vectors"),
    ("signature work uncounted", "counters.signatures += 1;", "", "anyage_vectors"),
]

original = SRC.read_text()
for name, before, after, target in CASES:
    pattern = re.compile(r"\s+".join(re.escape(x) for x in before.split()))
    if len(list(pattern.finditer(original))) != 1:
        raise SystemExit(f"{name}: expected one match for {before!r}")
if "--check" in sys.argv:
    print(f"{len(CASES)} mutations match the current source")
    raise SystemExit(0)
toolchain = os.environ.get("RUST_TOOLCHAIN", "+nightly-2026-08-12")
killed_all = True
try:
    for name, before, after, target in CASES:
        pattern = re.compile(r"\s+".join(re.escape(x) for x in before.split()))
        SRC.write_text(pattern.sub(lambda _: after, original, count=1))
        r = subprocess.run(["cargo", toolchain, "test", "-p", "reth-unicity-b1", "--test", target], cwd=ROOT, capture_output=True, text=True, timeout=900)
        SRC.write_text(original)
        out = r.stdout + r.stderr
        killed = r.returncode != 0 and "could not compile" not in out and "FAILED" in out
        print(("KILLED     " if killed else "NOT KILLED ") + name, flush=True)
        killed_all &= killed
finally:
    SRC.write_text(original)
raise SystemExit(0 if killed_all else 1)
