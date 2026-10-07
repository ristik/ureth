#!/usr/bin/env python3
"""Remove each explicit rejection guard in isolation; never count build failures.

Uses the caller's private CARGO_TARGET_DIR. Original source is restored even on
interrupt. Reports defensive/redundant guards that the named test cannot kill.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / 'crates/unicity/b2/src'
PATTERN = re.compile(r'if\s+([^{}]+?)\s*\{\s*return Err\(([^;]+)\);\s*\}')
TESTS = {
    'semantics.rs': [
        'cfg_domain', 'cfg_empty_shard', 'cfg_nonzero_vault', 'sdk_network_range_with_reconstructed_signed_mint',
        'prepare_nonce_amount_and_signature_profile',
        'mint_deadline_zero', 'prepare_nonce_amount_and_signature_profile', 'mint_burn_recipient',
        'signed_sdk3_histories_and_exact_abi', 'lock_proof_empty_pdr', 'embedded_proof_size_boundaries',
        'justification_chain', 'justification_nonce_zero', 'lock_proof_wrong_version', 'lock_proof_wrong_cfg',
        'lock_proof_empty_nodes', 'embedded_proof_size_boundaries', 'mint_foreign_coin',
        'unlock_short', 'scalars_zero_order_and_high_s_are_rejected', 'unlock_flipped_parity',
        'mint_cd_hash', 'mint_cd_deadline', 'deadlines_are_original_times_and_strict',
        'repeated_sid_is_exact_error', 'return_signature_owner', 'return_chain', 'return_whole_amount',
        'return_zero_recipient', 'return_reason_hash', 'operation_cardinality', 'operation_cardinality',
        'mint_burn_recipient', 'mint_network', 'mint_type', 'mint_salt', 'signed_sdk3_histories_and_exact_abi',
        'burn_not_terminal', 'intermediate_data',
    ],
    'lib.rs': ['abi_offsets_padding_aliases_trailing_and_high_bits', 'base_gas_precedes_framing',
               'signed_sdk3_histories_and_exact_abi'],
    'cbor.rs': ['canonical_scanner_limits_and_errors'] * 4 +
               ['scanner_count_precheck_preserves_exact_diagnostic', 'canonical_scanner_limits_and_errors'] +
               ['scanner_schema_guard_errors'] * 12,
    'abi.rs': ['abi_offsets_padding_aliases_trailing_and_high_bits'] * 2 + ['scanner_schema_guard_errors',
               'operation_cardinality'] + ['abi_offsets_padding_aliases_trailing_and_high_bits'] * 4,
}

def main():
    if not os.environ.get('CARGO_TARGET_DIR', '').startswith('/private/tmp/'):
        raise SystemExit('Set a private CARGO_TARGET_DIR under /private/tmp')
    results = []
    for filename, tests in TESTS.items():
        path = SRC / filename
        original = path.read_text()
        production = original.split('#[cfg(test)]')[0]
        guards = list(PATTERN.finditer(production))
        assert len(guards) == len(tests), (filename, len(guards), len(tests))
        for index, (guard, test) in enumerate(zip(guards, tests)):
            if len(sys.argv) > 1 and f'{filename}:{index}' not in sys.argv[1:]:
                continue
            mutated = original[:guard.start(1)] + 'false' + original[guard.end(1):]
            try:
                path.write_text(mutated)
                run = subprocess.run(['cargo', 'test', '-p', 'reth-unicity-b2', '-j', '4', '--lib', test,
                                      '--', '--nocapture'], cwd=ROOT, text=True, capture_output=True, timeout=180)
                output = run.stdout + run.stderr
                compiled = 'error[E' not in output and 'could not compile' not in output
                ran = re.search(r'running [1-9][0-9]* test', output) is not None
                killed = compiled and ran and run.returncode != 0 and 'test result: FAILED' in output
                status = 'killed' if killed else ('survived' if compiled and ran and run.returncode == 0 else 'invalid-run')
                result = {'guard': f'{filename}:{index}', 'condition': ' '.join(guard[1].split()),
                          'test': test, 'status': status}
                results.append(result)
                print(json.dumps(result), flush=True)
            finally:
                path.write_text(original)
    destination = os.environ.get('NBP4_MUTATION_REPORT')
    if destination:
        Path(destination).write_text(json.dumps(results, indent=2) + '\n')
    return 1 if any(r['status'] == 'invalid-run' for r in results) else 0

if __name__ == '__main__':
    raise SystemExit(main())
