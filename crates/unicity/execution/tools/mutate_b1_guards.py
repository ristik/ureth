#!/usr/bin/env python3
"""Disables each B1 admission and integration guard once and requires a named test to fail.

Usage: mutate_b1_guards.py [name-substring ...]   (run from the repository root)

Each mutant rewrites one exact source fragment, runs the listed cargo test selection, requires a
non-zero exit that names a failing test, and restores the file byte for byte. A mutant whose old
fragment is not found exactly once aborts the run, so a stale script cannot report a pass. Set
CARGO_TARGET_DIR to a private directory; the machine is memory constrained, so jobs are limited
to four.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
UPDATE = "crates/unicity/execution/src/update.rs"
LIB = "crates/unicity/execution/src/lib.rs"
WIRE = "crates/unicity/execution/src/wire.rs"
EXECUTOR = "crates/unicity/execution/src/block_executor.rs"
STORE = "crates/unicity/store/src/encoding.rs"

B1 = ["-p", "reth-unicity-execution", "--lib", "b1_tests::"]
WIREPKG = ["-p", "reth-unicity-execution", "--lib", "wire::"]
STOREPKG = ["-p", "reth-unicity-store"]
DISABLE = "if false {"

# (name, file, old, new, cargo test arguments)
MUTANTS = [
    ("ring-cap", UPDATE, "if k > MAX_MEASURED_K {", DISABLE, B1),
    ("byte-cap", UPDATE, "if raw.len() as u64 > cap {", DISABLE, B1),
    ("scan-budget", UPDATE, "if scan > budget {", DISABLE, B1),
    ("member-budget", UPDATE, "if members > (budget - scan) / MEMBER_GAS {", DISABLE, B1),
    ("member-debit", UPDATE, "let gas = scan + MEMBER_GAS * members;", "let gas = scan;", B1),
    ("committed-hash", UPDATE, "if sha256(raw) != binding.committed_hash {", DISABLE, B1),
    ("network", UPDATE, "if u.network != c.network {", DISABLE, B1),
    ("root-genesis", UPDATE, "if u.root_genesis_id != c.root_genesis_id {", DISABLE, B1),
    ("chain", UPDATE, "if u.execution_chain_id != c.execution_chain_id {", DISABLE, B1),
    ("profile", UPDATE, "if u.profile_hash != c.profile_hash {", DISABLE, B1),
    ("parent", UPDATE, "if u.parent_hash == B256::ZERO || u.parent_hash != b.parent_hash {",
     "if u.parent_hash != b.parent_hash {", B1),
    ("parent-binding", UPDATE, "if u.parent_hash == B256::ZERO || u.parent_hash != b.parent_hash {",
     "if u.parent_hash == B256::ZERO {", B1),
    ("height", UPDATE, "if b.parent_number.checked_add(1) != Some(u.block_number) {", DISABLE, B1),
    ("origin-epoch", UPDATE, "if u.origin_epoch != b.origin_epoch {", DISABLE, B1),
    ("origin-round", UPDATE, "if u.origin_round != b.origin_round {", DISABLE, B1),
    ("origin-identity", UPDATE,
     "if u.origin_identity == B256::ZERO || u.origin_identity != b.origin_identity {",
     "if u.origin_identity != b.origin_identity {", B1),
    ("origin-identity-zero", UPDATE,
     "if u.origin_identity == B256::ZERO || u.origin_identity != b.origin_identity {",
     "if u.origin_identity == B256::ZERO {", B1),
    ("genesis-kind", UPDATE, "if e.body_kind == 1 {", DISABLE, B1),
    ("epoch-newer", UPDATE, "if e.epoch <= u.prior_tip_epoch {", DISABLE, B1),
    ("start-after-origin", UPDATE, "if e.start > u.origin_round {", DISABLE, B1),
    ("end-window", UPDATE, "if e.end.is_some_and(|end| end <= floor || end > u.origin_round) {", DISABLE, B1),
    ("end-floor", UPDATE, "end <= floor || end > u.origin_round", "end > u.origin_round", B1),
    ("end-origin", UPDATE, "end <= floor || end > u.origin_round", "end <= floor", B1),
    ("contiguous", UPDATE, "if prev.epoch.checked_add(1) != Some(e.epoch) || prev.end != Some(e.start) {", DISABLE, B1),
    ("contiguous-epoch", UPDATE, "if prev.epoch.checked_add(1) != Some(e.epoch) || prev.end != Some(e.start) {",
     "if prev.end != Some(e.start) {", B1),
    ("old-tip-end-present", UPDATE, "let end = u.old_tip_end.ok_or(UpdateError::OldTipEndMismatch)?;",
     "let end = u.old_tip_end.unwrap_or(first.start);", B1),
    ("old-tip-end-bound", UPDATE, "if end > first.start ||", "if false ||", B1),
    ("old-tip-end-exact", UPDATE,
     "(u.prior_tip_epoch.checked_add(1) == Some(first.epoch) && end != first.start)", "false", B1),
    ("tail-open", UPDATE, "if tail.end.is_some() || tail.epoch != u.origin_epoch {",
     "if tail.epoch != u.origin_epoch {", B1),
    ("tail-origin", UPDATE, "if tail.end.is_some() || tail.epoch != u.origin_epoch {",
     "if tail.end.is_some() {", B1),
    ("empty-update", UPDATE, "if u.old_tip_end.is_some() || u.prior_tip_epoch != u.origin_epoch {", DISABLE, B1),
    ("entry-identity", UPDATE, "!matches!(self.signing_scheme, 1 | 2) ||", "false ||", B1),
    ("entry-activation", UPDATE, "(self.body_kind == 1) != (self.activation_commit_id == zero)", "false", B1),
    ("empty-interval", UPDATE, "if self.end.is_some_and(|end| end <= self.start) {", DISABLE, B1),
    ("members-sorted", UPDATE, "if i > 0 && self.members[i - 1].node_id.as_bytes() >= member.node_id.as_bytes() {", DISABLE, B1),
    ("zero-weight", UPDATE, "if member.weight == 0 {", DISABLE, B1),
    ("key-point", UPDATE, "PublicKey::from_slice(&member.key).map_err(|_| UpdateError::InvalidKey)?;", "", B1),
    ("duplicate-key", UPDATE, "if self.members[..i].iter().any(|prev| prev.key == member.key) {", DISABLE, B1),
    ("weight-overflow", UPDATE, "total = total.checked_add(member.weight).ok_or(UpdateError::WeightOverflow)?;", "total = total.wrapping_add(member.weight);", B1),
    ("entry-count", UPDATE, "count > max_entries ||", "false ||", B1),
    ("member-count", UPDATE, "if major != 4 || n == 0 || n > MAX_MEMBERS ||", "if major != 4 ||", B1),
    ("trailing", UPDATE, "if r.pos != bytes.len() {", DISABLE, B1),
    ("minimal-heads", UPDATE, "if !minimal {", DISABLE, B1),
    ("network-width", UPDATE, "if network > u64::from(u16::MAX) {", DISABLE, B1),
    ("text-utf8", UPDATE, "if major == 3 && core::str::from_utf8(out).is_err() {", DISABLE, B1),
    ("profile-envelope", UPDATE, "if profile.system_gas < required {", DISABLE, WIREPKG),
    ("bound-hash", UPDATE, "if sha256(&self.update) != input.b1_update_hash {", DISABLE, WIREPKG),
    ("envelope-hash", WIRE, "if crate::sha256(update) != self.b1_update_hash {", DISABLE, WIREPKG),
    ("zero-update-hash", LIB, "if self.b1_update_hash == B256::ZERO {", DISABLE, WIREPKG),
    ("profile-words", LIB, "if storage(slot)? != expected {", DISABLE, B1),
    ("open-gas-limit", LIB, "open_tx.gas_limit = config.system_gas_limit - admission_gas;", "open_tx.gas_limit = config.system_gas_limit;", B1),
    ("staged-commitment", LIB, "system_outcome_commitment(staged_gas, prepared.input_commitment)", "system_outcome_commitment(open_gas_spent, prepared.input_commitment)", B1),
    ("total-includes-admission", LIB, "staged_gas.checked_add(finalize_gas_spent)", "open_gas_spent.checked_add(finalize_gas_spent)", B1),
    ("finalize-budget", LIB, "let remaining = config.system_gas_limit.checked_sub(staged_gas)", "let remaining = config.system_gas_limit.checked_sub(open_gas_spent)", B1),
    ("store-update-frame", STORE, "    put_frame(&mut out, &companion.b1_update)?;\n", "", STOREPKG),
]


def run(args):
    cmd = ["cargo", "test", "-j", "4", *args]
    done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    wanted = sys.argv[1:]
    survivors = []
    for name, rel, old, new, args in MUTANTS:
        if wanted and not any(w in name for w in wanted):
            continue
        path = ROOT / rel
        original = path.read_bytes()
        text = original.decode()
        if text.count(old) != 1:
            sys.exit(f"{name}: expected exactly one occurrence of the fragment in {rel}, found {text.count(old)}")
        path.write_bytes(text.replace(old, new).encode())
        try:
            code, output = run(args)
        finally:
            path.write_bytes(original)
        failing = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", output, re.M)))
        if code != 0 and failing:
            print(f"KILLED   {name}: {', '.join(failing[:3])}{' ...' if len(failing) > 3 else ''}", flush=True)
        elif code != 0:
            print(f"BROKEN   {name}: exit {code} without a failing test (compile error?)", flush=True)
            survivors.append(name)
        else:
            print(f"SURVIVED {name}", flush=True)
            survivors.append(name)
    print(f"{len(survivors)} not killed: {survivors}")
    sys.exit(1 if survivors else 0)


if __name__ == "__main__":
    main()
