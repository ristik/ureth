#!/usr/bin/env python3
"""Verify exact protocol bytes, sealed corpus and derived Go Kernel expectations."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1] / 'protocol'
pin = json.loads((root / 'pin.json').read_text())
assert pin['repository'] == 'ristik/native-bridge-plugins'
assert pin['revision'] == 'f35edc2652567e579a5940479039043e82a67f77'
assert pin['corpusRevision'] == pin['revision']
assert pin['oracleRevision'] == '52fe1934ce707edecec0a0df05b6a77eaf54e53e'
for name, expected in pin['sha256'].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    assert actual == expected, (name, actual, expected)
vectors = root / 'vectors'
manifest = (vectors / 'SHA256SUMS').read_bytes()
assert hashlib.sha256(manifest).hexdigest() == pin['corpusManifestSha256']
assert (vectors / 'MANIFEST.sha256').read_text().strip() == pin['corpusManifestSha256']
tracked = set()
for line in manifest.decode().splitlines():
    expected, name = line.split('  ')
    assert name not in tracked and '..' not in Path(name).parts
    tracked.add(name)
    actual = hashlib.sha256((vectors / name).read_bytes()).hexdigest()
    assert actual == expected, (name, actual, expected)
provenance = json.loads((vectors / 'provenance.json').read_text())
assert provenance['generator']['commit'] == pin['oracleRevision']
ids = set()
kernel_ids = set()
for file in sorted(vectors.glob('*/cases.json')):
    assert file.relative_to(vectors).as_posix() in tracked
    cases = json.loads(file.read_text())
    assert cases['fixtureDigest'] == hashlib.sha256((vectors / 'config/fixtures.json').read_bytes()).hexdigest()
    for case in cases['cases']:
        assert case['id'] not in ids, case['id']
        ids.add(case['id'])
        if case['op'] in {'kernel', 'prepareLock', 'mint', 'return'}:
            kernel_ids.add(case['id'])
expected = json.loads((root / 'kernel-expectations.json').read_text())
assert len(ids) == 336
assert len(expected) == len(kernel_ids) == 116
assert {case['id'] for case in expected} == kernel_ids
if '--require-release' in sys.argv:
    assert pin['upstreamStatus'] == 'merged-release', 'Sealed candidate is pinned, but upstream PR1/#422 are not merged'
print('Verified exact protocol snapshot, 336 sealed cases and 116 Go Kernel expectations; upstream status: ' + pin['upstreamStatus'])
