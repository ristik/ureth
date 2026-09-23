#!/usr/bin/env python3
"""Build and import B1..B3 through a real unicity-reth Engine API process.

Build first:
  cargo build --locked -p unicity-reth --bin unicity-reth
  cargo build --locked -p reth-unicity-payload --example restart_requests
Run:
  python3 bin/unicity-reth/tests/fee_consensus_smoke.py
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
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    token = jwt(bytes.fromhex(secret_path.read_text().strip()))
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError(f"node exited {process.returncode}; see {log.name}")
        try:
            capabilities = rpc(port, token, "engine_exchangeCapabilities", [[]])
            if "engine_newPayloadV3" in capabilities:
                raise RuntimeError("stock newPayloadV3 remains advertised")
            try:
                rpc(port, token, "engine_newPayloadV3", [])
            except RuntimeError as error:
                if "-32601" not in str(error):
                    raise
            else:
                raise RuntimeError("stock newPayloadV3 remains callable")
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


def build_import(port, token, round_number, parent_hash, parent_timestamp):
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
    print(f"B{round_number} VALID {head}", flush=True)
    return head, int(payload["timestamp"], 16)


def main():
    if not BIN.is_file() or not REQUESTS.is_file():
        raise RuntimeError("build unicity-reth and restart_requests first")
    root = Path(tempfile.mkdtemp(prefix="unicity-fee-consensus-"))
    try:
        datadir = root / "data"
        secret_path = root / "jwt.hex"
        secret_path.write_text(os.urandom(32).hex())
        port = free_port()
        with (root / "node.log").open("w") as log:
            process, token = start(datadir, secret_path, port, log)
            try:
                parent, timestamp = GENESIS_HASH, 0x11
                for round_number in range(1, 4):
                    parent, timestamp = build_import(port, token, round_number, parent, timestamp)
            finally:
                stop(process)
    except Exception:
        print(f"process logs retained at {root}", flush=True)
        raise
    shutil.rmtree(root)
    print("fee consensus smoke passed", flush=True)


if __name__ == "__main__":
    main()
