#!/usr/bin/env python3
"""Recompute the expectations of testdata/parity-85.json with the Go oracle and rewrite the rows that differ.

usage: rerun_parity85.py <bft-core checkout at the oracle commit> [--write]

Every case of the file is a base input, the claim table of the corpus B1 (`ClaimsB1`: anchor authentication is membership of the
(expectedStateRoot, expectedIRHash) pair) and a byte patch. The oracle's verdict is NativeCompose (v1) or NativeComposeV2 (v2) over the patched
input with an effectively unlimited gas: status code, status name and gas. The Go side is bft-core `bridgeprofile/parity85_test.go`
(TestParity85Rows, PARITY85_FILE), which prints a PARITY85_ROW line for each case whose stored expectation differs. Without --write the rows
are only listed (exit 1 when any differ); with --write they replace the stored expectations (status ok, values gas/status/statusName), the
file stays one compact JSON line, and the source note records the oracle commit.

History: with the upstream seal rule (bft-core#920) exactly 5 of the 291 cases changed: native-compose-long-history#0359 and #0776 and
native-compose-anchors-3-dnb#1210 (now succeed), native-compose-anchors-3-dnb#0587 (ErrAnchorAuth at another gas) and
native-lineage-depth-1-part-60-real-proofs#0568 (ErrLeafProof).
"""
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FILE = HERE.parent / "testdata" / "parity-85.json"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    oracle = pathlib.Path(args[0])
    env = dict(os.environ, PARITY85_FILE=str(FILE))
    out = subprocess.run(["go", "test", "-count=1", "./bridgeprofile", "-run", "TestParity85Rows", "-v"], cwd=oracle, env=env, text=True, capture_output=True)
    if out.returncode != 0:
        sys.exit(out.stdout + out.stderr)
    rows = {}
    for line in out.stdout.splitlines():
        if line.startswith("PARITY85_ROW\t"):
            _, cid, status, name, gas = line.split("\t")
            rows[cid] = (status, name, gas)
    if not rows:
        print("parity-85: every expectation is the oracle's")
        return
    for cid, (status, name, gas) in rows.items():
        print(f"differs: {cid} -> status {status} {name or 'ok'} gas {gas}")
    if "--write" not in sys.argv:
        sys.exit(1)
    d = json.loads(FILE.read_text())
    for key in ("v1", "v2"):
        for f in d[key]:
            for c in f["cases"]:
                if c["id"] in rows:
                    status, name, gas = rows[c["id"]]
                    c["expected"] = {"status": "ok", "values": {"gas": gas, "status": status, "statusName": name}}
    commit = subprocess.check_output(["git", "-C", str(oracle), "rev-parse", "HEAD"], text=True).strip()
    d["source"] += f"; rows recomputed with tools/rerun_parity85.py at oracle {commit}"
    FILE.write_text(json.dumps(d, separators=(",", ":"), ensure_ascii=False))
    print(f"parity-85: {len(rows)} rows rewritten")


main()
