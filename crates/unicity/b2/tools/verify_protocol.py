#!/usr/bin/env python3
"""Verify exact PR1 protocol snapshot; a release additionally requires corpus pins."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1] / 'protocol'
pin = json.loads((root / 'pin.json').read_text())
assert pin['repository'] == 'ristik/native-bridge-plugins'
assert pin['revision'] == 'efd9d150bf02945df2c9ba751617c86a4625deb4'
for name, expected in pin['sha256'].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    assert actual == expected, (name, actual, expected)
if '--require-corpus' in sys.argv:
    assert pin['corpusRevision'] and pin['corpusManifestSha256'], 'Upstream corpus not released/pinned'
print('Exact PR1 protocol snapshot verified; corpus release pin: ' + ('present' if pin['corpusRevision'] else 'pending'))
