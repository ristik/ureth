#!/usr/bin/env python3
"""Disables each pair-binding guard once and requires a named test to fail.

Usage: mutate_pair_guards.py [name-substring ...]   (run from the repository root)

Each mutant rewrites one exact source fragment, runs the listed cargo test selection, requires a
non-zero exit that names a failing test, and restores the file byte for byte. A mutant whose old
fragment is not found aborts the run, so a stale script cannot report a pass. Set CARGO_TARGET_DIR
to a private directory; the machine is memory constrained, so jobs are limited to four.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
TC = "+nightly-2026-08-12"
PAIRING = "crates/unicity/execution/src/pairing.rs"
WIRE = "crates/unicity/execution/src/wire.rs"
RPC = "crates/unicity/payload/src/rpc.rs"
RECOVERY = "crates/unicity/payload/src/recovery.rs"
LIB = "crates/unicity/payload/src/lib.rs"
ENC = "crates/unicity/store/src/encoding.rs"

EXEC_PAIRING = ["-p", "reth-unicity-execution", "--test", "pairing"]
EXEC_WIRE = ["-p", "reth-unicity-execution", "--lib", "wire::"]
PAYLOAD = ["-p", "reth-unicity-payload", "--test", "execution_payload"]
STORE = ["-p", "reth-unicity-store"]

# (name, file, old, new, cargo test arguments)
MUTANTS = [
    ("pin-network", PAIRING, "if binding.network_id != context.pins.network_id {", "if false {", EXEC_PAIRING),
    ("pin-root-genesis", PAIRING, "if binding.root_genesis_id != context.pins.root_genesis_id {", "if false {", EXEC_PAIRING),
    ("execution-genesis", PAIRING, "if binding.execution_genesis_hash != context.execution_genesis_hash {", "if false {", EXEC_PAIRING),
    ("input-network", PAIRING, "if root.network_id != binding.network_id {", "if false {", EXEC_PAIRING),
    ("parent-hash", PAIRING, "if binding.parent_hash != context.parent.hash() {", "if false {", EXEC_PAIRING),
    ("parent-number", PAIRING, "if binding.parent_number != context.parent.number {", "if false {", EXEC_PAIRING),
    ("origin-epoch", PAIRING, "if binding.origin_root_epoch != root.origin.root_epoch {", "if false {", EXEC_PAIRING),
    ("origin-round", PAIRING, "if binding.origin_root_round != root.origin.root_round {", "if false {", EXEC_PAIRING),
    ("configuration", PAIRING, "if binding.configuration_id != root.origin.shard_conf_hash {", "if false {", EXEC_PAIRING),
    ("activation", PAIRING, "if binding.activation_id != transition.commit_id {", "if false {", EXEC_PAIRING),
    ("root-input-hash", PAIRING, "if binding.root_input_hash != commitment {", "if false {", EXEC_PAIRING),
    ("transitions-hash", PAIRING, "if binding.transitions_hash != transitions_hash(&root.transitions) {", "if false {", EXEC_PAIRING),
    ("job-digest", PAIRING, "if attributes_digest != expected {", "if false {", EXEC_PAIRING),
    ("block-hash", PAIRING, "if block_hash != expected {", "if false {", EXEC_PAIRING),
    ("subject-kind", PAIRING,
     "(found, ExpectedSubject::Import { .. }) => {\n            return Err(PairBindingError::WrongSubjectKind {\n                expected: SUBJECT_IMPORT,\n                found: found.kind(),\n            })\n        }",
     "(found, ExpectedSubject::Import { .. }) => {\n            let _ = found;\n        }", EXEC_PAIRING),
    ("binding-size", PAIRING, "if raw.len() > MAX_PAIR_BINDING_BYTES {", "if false {", EXEC_PAIRING),
    ("binding-missing", PAIRING, "if raw.is_empty() {", "if false {", EXEC_PAIRING),
    ("domain", PAIRING, "!= PAIR_BINDING_DOMAIN {", "!= PAIR_BINDING_DOMAIN && false {", EXEC_PAIRING),
    ("version", PAIRING, "if version != PAIR_BINDING_VERSION {", "if false {", EXEC_PAIRING),
    ("zero-identity", PAIRING, "if word == B256::ZERO {", "if false {", EXEC_PAIRING),
    ("unknown-subject", PAIRING, "other => return Err(PairBindingError::UnknownSubject(other)),", "_ => PairSubject::Import { block_hash: subject_id },", EXEC_PAIRING),
    ("trailing", PAIRING, "decoder.finish().map_err(m)?;", "let _ = decoder.finish();", EXEC_PAIRING),
    ("root-size", WIRE, "if input.len() > MAX_ROOT_INPUT_BYTES {", "if false {", EXEC_WIRE),
    ("shard-id-bound", WIRE, 'read_bounded_bytes("shard id", MAX_SHARD_ID_BYTES)', 'read_bounded_bytes("shard id", usize::MAX)', EXEC_WIRE),
    ("leader-bound", WIRE, 'read_bounded_text("leader", MAX_LEADER_BYTES)', 'read_bounded_text("leader", usize::MAX)', EXEC_WIRE),
    ("transition-count", WIRE, "if length > MAX_ROOT_TRANSITIONS {", "if false {", EXEC_WIRE),
    ("transition-size", WIRE, 'read_bounded_bytes("transition", MAX_EPOCH_TRANSITION_BYTES)', 'read_bounded_bytes("transition", usize::MAX)', EXEC_WIRE),
    ("envelope-count", WIRE, "if self.transitions.len() > MAX_ROOT_TRANSITIONS {", "if false {", EXEC_WIRE),
    ("build-gate", RPC, ".map_err(SealBuildError::PairBinding)?;\n    let bound", ".or_else(|_| PairBinding::from_canonical_cbor(&seal_build_input.pair_binding))\n    .map_err(SealBuildError::PairBinding)?;\n    let bound", PAYLOAD),
    ("build-retains-binding", RPC, ".with_pair_binding(pair);", ";", PAYLOAD),
    ("import-gate", RPC, ".map_err(SealImportError::PairBinding)?;", ".or_else(|_| PairBinding::from_canonical_cbor(&seal_companion.pair_binding))\n        .map_err(SealImportError::PairBinding)?;", PAYLOAD),
    ("get-payload-durable", RPC, "            .put(block_hash, block_number, &seal_companion)\n            .map_err(|error| EngineApiError::Internal(Box::new(error)))?;", "            .put(block_hash, block_number, &seal_companion)\n            .ok();", PAYLOAD),
    ("import-durable-before-forward", RPC, "return import_response(SealImportError::CompanionNotDurable(error.to_string()));", "tracing::error!(%error);", PAYLOAD),
    ("refused-block-drops-companion", RPC, "if !status.is_valid() &&", "if false &&", PAYLOAD),
    ("recovery-gate", RECOVERY, '.map_err(|error| eyre::eyre!("retained binding refused at {number}: {error}"))?;', ".ok();", PAYLOAD),
    ("job-binding-identity", LIB, "self.pair_binding == other.pair_binding &&", "", PAYLOAD),
    ("store-binding-frame", ENC, "    put_frame(&mut out, &companion.pair_binding)?;\n", "", STORE),
]


def run(args):
    cmd = ["cargo", TC, "test", "-j", "4", *args]
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
