#!/usr/bin/env python3
"""Build/import B1..B3, restart one unicity-reth process, then build/import B4.

Build first:
  cargo build --locked -p unicity-reth --bin unicity-reth
  cargo build --locked -p reth-unicity-payload --example restart_requests
  cargo build --locked -p reth-unicity-store --example prune_accounting
Run:
  python3 bin/unicity-reth/tests/restart_smoke.py

Set U5R_RESTART_AFTER=1 and U5R_PRUNE_ACCOUNTING=1 to exercise B0-anchored B1 repair.
Set U5R_RESTART_AFTER=3, U5R_PRUNE_ACCOUNTING=1, U5R_REPAIR_LIMIT=2, and
U5R_EXPECT_UNAVAILABLE=1 to check refusal beyond the replay bound.
Set U5R_MAKE_ORPHAN=1 to persist a built sidecar token without importing that block.
Set U5R_CRASH=1 to SIGKILL the node after B3 import instead of shutting it down cleanly.
"""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[3]
BIN = Path(os.environ.get("U5R_BINARY", ROOT / "target/debug/unicity-reth"))
REQUESTS = ROOT / "target/debug/examples/restart_requests"
PRUNE_ACCOUNTING = ROOT / "target/debug/examples/prune_accounting"
GENESIS = ROOT / "crates/unicity/payload/testdata/signed-beacon-genesis.json"
GENESIS_HASH = "0x82430ee9e534f0e454399cdaa06042c5dcc52b0378f48609e9c45c3cc1ae01f0"
FEE_COLLECTOR = "0x" + "77" * 20


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwt(secret):
    header = b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64(json.dumps({"iat": int(time.time()), "exp": int(time.time()) + 3600}).encode())
    signing = header + b"." + payload
    signature = b64(hmac.new(secret, signing, hashlib.sha256).digest())
    return (signing + b"." + signature).decode()


def rpc(port, token, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        body,
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def start(datadir, secret_path, port, log):
    command = [
        str(BIN), "node", "--chain", str(GENESIS), "--datadir", str(datadir),
        "--authrpc.addr", "127.0.0.1", "--authrpc.port", str(port),
        "--authrpc.jwtsecret", str(secret_path), "--port", str(free_port()),
        "--disable-discovery", "--unicity.fee-collector", FEE_COLLECTOR,
        "--unicity.max-gas", "30000001", "--unicity.system-gas", "500001",
        "--unicity.base-fee-floor", "7",
    ]
    if os.environ.get("U5R_REPAIR_LIMIT") is not None:
        command.extend(["--unicity.accounting-repair-limit", os.environ["U5R_REPAIR_LIMIT"]])
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    token = jwt(bytes.fromhex(secret_path.read_text().strip()))
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError(f"node exited {process.returncode}; see {log.name}")
        try:
            rpc(port, token, "engine_exchangeCapabilities", [[]])
            return process, token
        except (OSError, RuntimeError):
            time.sleep(0.5)
    raise RuntimeError(f"node did not start; see {log.name}")


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def build_import(port, token, round_number, parent_hash, parent_timestamp, saved_imports=None):
    generated = json.loads(subprocess.check_output(
        [str(REQUESTS), str(round_number), parent_hash, str(parent_timestamp)], text=True
    ))
    state = {"headBlockHash": parent_hash, "safeBlockHash": GENESIS_HASH,
             "finalizedBlockHash": GENESIS_HASH}
    result = rpc(port, token, "engine_forkchoiceUpdatedWithSealV1",
                 [state, generated["attributes"], generated["input"]])
    payload_id = result["payloadId"]
    if not payload_id:
        raise RuntimeError(f"round {round_number}: no payload ID: {result}")
    for _ in range(60):
        try:
            envelope = rpc(port, token, "engine_getPayloadWithSealV1", [payload_id])
            break
        except RuntimeError:
            time.sleep(0.25)
    else:
        raise RuntimeError(f"round {round_number}: payload never became available")
    payload = envelope["executionPayload"]
    status = rpc(port, token, "engine_newPayloadWithSealV1", [
        payload, [], generated["attributes"]["parentBeaconBlockRoot"],
        envelope["sealCompanion"],
    ])
    if status["status"] != "VALID":
        raise RuntimeError(f"round {round_number}: import {status}")
    head = payload["blockHash"]
    choice = {"headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head}
    result = rpc(port, token, "engine_forkchoiceUpdatedV3", [choice, None])
    if result["payloadStatus"]["status"] != "VALID":
        raise RuntimeError(f"round {round_number}: forkchoice {result}")
    if saved_imports is not None:
        saved_imports.append((round_number, payload, generated["attributes"]["parentBeaconBlockRoot"],
                              envelope["sealCompanion"], head))
    print(f"B{round_number} VALID {head}", flush=True)
    return head, int(payload["timestamp"], 16)


def main():
    if not BIN.is_file() or not REQUESTS.is_file():
        raise RuntimeError("build unicity-reth and restart_requests first")
    root = Path(tempfile.mkdtemp(prefix="unicity-restart-"))
    restart_after = int(os.environ.get("U5R_RESTART_AFTER", "3"))
    if restart_after not in (1, 2, 3):
        raise RuntimeError("U5R_RESTART_AFTER must be 1, 2, or 3")
    prune_accounting = os.environ.get("U5R_PRUNE_ACCOUNTING") == "1"
    expect_unavailable = os.environ.get("U5R_EXPECT_UNAVAILABLE") == "1"
    make_orphan = os.environ.get("U5R_MAKE_ORPHAN") == "1"
    crash = os.environ.get("U5R_CRASH") == "1"
    if crash and restart_after != 3:
        raise RuntimeError("U5R_CRASH requires U5R_RESTART_AFTER=3")
    try:
        saved_imports = []
        datadir = root / "data"
        secret_path = root / "jwt.hex"
        secret_path.write_text(os.urandom(32).hex())
        port = free_port()
        with (root / "first.log").open("w") as log:
            process, token = start(datadir, secret_path, port, log)
            try:
                parent, timestamp = GENESIS_HASH, 0x11
                for round_number in range(1, restart_after + 1):
                    parent, timestamp = build_import(
                        port, token, round_number, parent, timestamp,
                        saved_imports if crash else None,
                    )
                if make_orphan:
                    generated = json.loads(subprocess.check_output([
                        str(REQUESTS), "99", parent, str(timestamp),
                    ], text=True))
                    state = {"headBlockHash": parent, "safeBlockHash": parent,
                             "finalizedBlockHash": parent}
                    job = rpc(port, token, "engine_forkchoiceUpdatedWithSealV1", [
                        state, generated["attributes"], generated["input"],
                    ])
                    for _ in range(60):
                        try:
                            rpc(port, token, "engine_getPayloadWithSealV1", [job["payloadId"]])
                            break
                        except RuntimeError:
                            time.sleep(0.25)
                    else:
                        raise RuntimeError("orphan build never became available")
                    print("orphan build persisted without import", flush=True)
            finally:
                if crash:
                    process.kill()
                    process.wait()
                    print("SIGKILL after B3 import", flush=True)
                else:
                    stop(process)
        if prune_accounting:
            if not PRUNE_ACCOUNTING.is_file():
                raise RuntimeError("build the prune_accounting example first")
            subprocess.run([
                str(PRUNE_ACCOUNTING), str(datadir / "unicity" / "companions"),
                str(restart_after + 1),
            ], check=True)
        with (root / "second.log").open("w") as log:
            if expect_unavailable:
                try:
                    process, token = start(datadir, secret_path, port, log)
                except RuntimeError:
                    if "no verified token" not in (root / "second.log").read_text():
                        raise
                    print("bounded repair refused unavailable accounting", flush=True)
                    shutil.rmtree(root)
                    return
                else:
                    stop(process)
                    raise RuntimeError("node started beyond the repair limit")
            process, token = start(datadir, secret_path, port, log)
            try:
                if crash:
                    state = {"headBlockHash": parent, "safeBlockHash": GENESIS_HASH,
                             "finalizedBlockHash": GENESIS_HASH}
                    before = rpc(port, token, "engine_forkchoiceUpdatedV3", [state, None])
                    if before["payloadStatus"]["status"] not in ("VALID", "SYNCING"):
                        raise RuntimeError(f"crash recovery: unexpected B3 status {before}")
                    print(f"B3 after SIGKILL: {before['payloadStatus']['status']}", flush=True)
                    # The sidecar can be ahead of the main DB. Re-drive the saved certified
                    # imports in order, including a block the DB already retained.
                    for round_number, payload, beacon_root, companion, head in saved_imports:
                        status = rpc(port, token, "engine_newPayloadWithSealV1", [
                            payload, [], beacon_root, companion,
                        ])
                        if status["status"] != "VALID":
                            raise RuntimeError(f"round {round_number}: replay import {status}")
                        choice = {"headBlockHash": head, "safeBlockHash": GENESIS_HASH,
                                  "finalizedBlockHash": GENESIS_HASH}
                        advanced = rpc(port, token, "engine_forkchoiceUpdatedV3", [choice, None])
                        if advanced["payloadStatus"]["status"] != "VALID":
                            raise RuntimeError(f"round {round_number}: replay forkchoice {advanced}")
                    state = {"headBlockHash": parent, "safeBlockHash": parent,
                             "finalizedBlockHash": parent}
                    after = rpc(port, token, "engine_forkchoiceUpdatedV3", [state, None])
                    if after["payloadStatus"]["status"] != "VALID":
                        raise RuntimeError(f"crash recovery: B3 forkchoice {after}")
                for round_number in range(restart_after + 1, 5):
                    parent, timestamp = build_import(port, token, round_number, parent, timestamp)
            finally:
                stop(process)
    except Exception:
        print(f"restart logs retained at {root}", flush=True)
        raise
    shutil.rmtree(root)
    print("restart smoke passed", flush=True)


if __name__ == "__main__":
    main()
