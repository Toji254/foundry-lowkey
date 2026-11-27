#!/usr/bin/env python3
"""Live two-process network isolation acceptance for Lowkey-managed Anvil."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from itertools import count
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lowkey.network_manager import NetworkManager, NetworkError  # noqa: E402

_ids = count(1)
VALUE_A, VALUE_B = 10**18, 2 * 10**18
INIT_CODE = "0x6001600c60003960016000f300"


def rpc(url, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or []}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = json.loads(response.read().decode())
    if not isinstance(payload, dict) or payload.get("error") is not None or "result" not in payload:
        raise RuntimeError(f"{method} failed at {url}: {payload!r}")
    return payload["result"]


def quantity(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"Invalid RPC quantity: {value!r}")
    return int(value, 16)


def cli(lk, root, evidence, *args):
    command = [lk, *args]
    result = subprocess.run(command, cwd=root, env=os.environ.copy(), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=45)
    evidence["commands"].append({"argv": command, "returncode": result.returncode,
                                 "stdout": result.stdout[-2500:], "stderr": result.stderr[-2500:]})
    if result.returncode:
        raise RuntimeError(f"{command!r} failed ({result.returncode}): {result.stdout[-4000:]} {result.stderr[-4000:]}")
    return result.stdout


def mined(url, tx_hash):
    for _ in range(300):
        item = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if item is not None:
            if not isinstance(item, dict) or quantity(item.get("status")) != 1:
                raise RuntimeError(f"Transaction failed: {tx_hash}: {item!r}")
            return item
        time.sleep(0.05)
    raise TimeoutError(f"Receipt timeout: {tx_hash}")


def send_value(session, value):
    tx = rpc(session["rpc"], "eth_sendTransaction", [{
        "from": session["actors"]["lab-deployer"], "to": session["actors"]["anvil-1"],
        "value": hex(value), "gas": "0x5208",
    }])
    receipt = mined(session["rpc"], tx)
    return {"hash": tx, "block": quantity(receipt["blockNumber"]), "value_wei": value}


def main():
    output = ROOT / ".audit" / "network-multi-anvil-acceptance"
    output.mkdir(parents=True, exist_ok=True)
    evidence = {"schema": "lowkey.multi-anvil-live.v1", "status": "RUNNING",
                "sessions": [], "transactions": {}, "deployment": {}, "checks": {},
                "commands": [], "cleanup": {}, "error": None}
    manager = None
    failure = None
    anvil, lk = shutil.which("anvil"), shutil.which("lk")
    if not lk:
        candidate = Path.home() / ".foundry" / "bin" / "lk"
        lk = str(candidate) if candidate.is_file() else None
    try:
        if not anvil or not lk:
            raise RuntimeError("Install the pinned Foundry toolchain and Lowkey before running this acceptance.")
        version = subprocess.run([anvil, "--version"], capture_output=True, text=True, timeout=10)
        if version.returncode:
            raise RuntimeError(f"anvil --version failed: {version.stderr}")
        evidence["anvil_version"] = version.stdout.strip()

        with tempfile.TemporaryDirectory(prefix="lowkey-two-anvil-") as tmp:
            root = Path(tmp).resolve()
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc="src"\nout="out"\n')
            manager = NetworkManager(root, anvil_binary=anvil)
            try:
                cli(lk, root, evidence, "lab", "network", "create", "--name", "gmx-dev")
                cli(lk, root, evidence, "lab", "network", "create", "--name", "gmx-attack")
                a, b = manager.status("gmx-dev"), manager.status("gmx-attack")
                if not a or not b or not a.get("process_owned") or not b.get("process_owned"):
                    raise RuntimeError("Both Anvil processes must be live and Lowkey-owned.")

                checks = evidence["checks"]
                checks["different_session_ids"] = a["id"] != b["id"]
                checks["different_processes"] = a["pid"] != b["pid"] and a.get("process_start_ticks") and b.get("process_start_ticks")
                checks["different_ports"] = a["port"] != b["port"]
                checks["same_chain_id"] = a["chain_id"] == b["chain_id"] == 31337
                checks["rpc_chain_ids_match"] = quantity(rpc(a["rpc"], "eth_chainId")) == a["chain_id"] and quantity(rpc(b["rpc"], "eth_chainId")) == b["chain_id"]
                checks["different_genesis_hashes"] = a["genesis_hash"] != b["genesis_hash"]
                checks["different_account_seeds"] = a["actors"]["lab-deployer"] != b["actors"]["lab-deployer"] and a["actors"]["anvil-1"] != b["actors"]["anvil-1"]
                if not all(checks.values()):
                    raise RuntimeError(f"Live network identity checks failed: {checks!r}")

                cli(lk, root, evidence, "lab", "network", "use", "gmx-dev")
                cli(lk, root, evidence, "actor", "1", "Alice")
                ca = manager.get_by_id(a["id"])
                cli(lk, root, evidence, "lab", "network", "use", "gmx-attack")
                cli(lk, root, evidence, "actor", "1", "Alice")
                cb = manager.get_by_id(b["id"])
                checks["same_alias_is_session_scoped"] = ca["actors"]["Alice"] == a["actors"]["anvil-1"] and cb["actors"]["Alice"] == b["actors"]["anvil-1"] and ca["actors"]["Alice"] != cb["actors"]["Alice"]
                active = manager.active()
                checks["network_switch_changes_actor_context"] = active["id"] == b["id"] and active["active_actor"] == "Alice"
                if not checks["same_alias_is_session_scoped"] or not checks["network_switch_changes_actor_context"]:
                    raise RuntimeError("Session actor aliases or active selection were not isolated.")

                restarted = NetworkManager(root, anvil_binary=anvil)
                ra, rb = restarted.status("gmx-dev"), restarted.status("gmx-attack")
                checks["registry_survives_manager_restart"] = bool(ra and rb and ra["id"] == a["id"] and rb["id"] == b["id"] and ra.get("rpc_healthy") and rb.get("rpc_healthy") and ra.get("identity_block_matches") and rb.get("identity_block_matches"))
                if not checks["registry_survives_manager_restart"]:
                    raise RuntimeError("Restarted manager could not re-verify both session identities.")

                state = manager._read()
                state.pop("active_session_id", None)
                manager._write(state)
                try:
                    manager.active()
                except NetworkError as exc:
                    checks["ambiguous_selection_fails_closed"] = "multiple managed anvil networks" in str(exc).lower()
                else:
                    checks["ambiguous_selection_fails_closed"] = False
                if not checks["ambiguous_selection_fails_closed"]:
                    raise RuntimeError("Multiple running sessions without a selection were not rejected.")
                manager.use("gmx-dev")

                from lowkey import lk as cli_module
                detached = {"actor": "Alice", "wallets": {}, "_active_network_session": manager.get_by_id(a["id"])}
                resolved = cli_module.effective_rpc(detached, explicit_rpc=b["rpc"])
                checks["explicit_rpc_detaches_foreign_actor"] = resolved == b["rpc"] and detached.get("_explicit_rpc_unscoped") is True and cli_module._actor_profile_entry(detached, "Alice") is None
                if not checks["explicit_rpc_detaches_foreign_actor"]:
                    raise RuntimeError("Explicit RPC override retained the other network's actor.")

                before_a = quantity(rpc(a["rpc"], "eth_getBalance", [a["actors"]["anvil-1"], "latest"]))
                before_b = quantity(rpc(b["rpc"], "eth_getBalance", [b["actors"]["anvil-1"], "latest"]))
                tx_a, tx_b = send_value(a, VALUE_A), send_value(b, VALUE_B)
                after_a = quantity(rpc(a["rpc"], "eth_getBalance", [a["actors"]["anvil-1"], "latest"]))
                after_b = quantity(rpc(b["rpc"], "eth_getBalance", [b["actors"]["anvil-1"], "latest"]))
                checks["transactions_mined_on_both"] = True
                checks["balance_deltas_are_isolated"] = after_a - before_a == VALUE_A and after_b - before_b == VALUE_B
                checks["transaction_hashes_are_isolated"] = rpc(a["rpc"], "eth_getTransactionByHash", [tx_b["hash"]]) is None and rpc(b["rpc"], "eth_getTransactionByHash", [tx_a["hash"]]) is None
                if not checks["balance_deltas_are_isolated"] or not checks["transaction_hashes_are_isolated"]:
                    raise RuntimeError("The two live Anvil chains shared transaction state.")
                evidence["transactions"] = {"gmx-dev": tx_a, "gmx-attack": tx_b}

                deploy_tx = rpc(a["rpc"], "eth_sendTransaction", [{"from": a["actors"]["lab-deployer"], "data": INIT_CODE, "gas": "0x186a0"}])
                deploy_receipt = mined(a["rpc"], deploy_tx)
                address = str(deploy_receipt.get("contractAddress") or "").lower()
                code_a = rpc(a["rpc"], "eth_getCode", [address, "latest"])
                code_b = rpc(b["rpc"], "eth_getCode", [address, "latest"])
                runtime = bytes.fromhex(code_a[2:]) if isinstance(code_a, str) and code_a.startswith("0x") else b""
                checks["deployed_runtime_is_network_local"] = bool(runtime) and code_b in ("0x", "0x0")
                if not checks["deployed_runtime_is_network_local"]:
                    raise RuntimeError("Contract code deployed on gmx-dev was visible on gmx-attack or absent on gmx-dev.")
                manager.record_deployment(a["id"], {
                    "role": "acceptance_fixture", "qualified_identity": "MultiAnvilAcceptance:MinimalRuntime",
                    "address": address, "deployment_transaction": deploy_tx, "network_session_id": a["id"],
                    "chain_id": a["chain_id"], "genesis_hash": a["genesis_hash"],
                    "runtime_sha256": hashlib.sha256(runtime).hexdigest(), "verification_status": "OBSERVED",
                }, operation_key=f"two-anvil:{deploy_tx}")
                da, db = manager.get_deployments(a["id"]), manager.get_deployments(b["id"])
                checks["deployment_registry_is_session_scoped"] = len(da) == 1 and db == {} and next(iter(da.values())).get("network_session_id") == a["id"]
                if not checks["deployment_registry_is_session_scoped"]:
                    raise RuntimeError("Deployment registry evidence leaked between sessions.")

                evidence["deployment"] = {"session_id": a["id"], "chain_id": a["chain_id"], "transaction_hash": deploy_tx, "address": address, "runtime": code_a, "other_network_runtime": code_b}
                evidence["sessions"] = [{"name": x["name"], "id": x["id"], "pid": x["pid"], "rpc": x["rpc"], "port": x["port"], "chain_id": x["chain_id"], "genesis_hash": x["genesis_hash"], "identity_block_number": x["identity_block_number"], "identity_block_hash": x["identity_block_hash"], "deployer": x["actors"]["lab-deployer"], "Alice": x["actors"]["Alice"]} for x in (ca, cb)]
            finally:
                cleanup = []
                for row in reversed(manager.list()):
                    if row.get("name") in {"gmx-dev", "gmx-attack"}:
                        try:
                            stopped = manager.stop_session(row["id"])
                            cleanup.append({"id": row["id"], "name": row["name"], "status": stopped.get("status")})
                        except Exception as exc:
                            cleanup.append({"id": row["id"], "name": row["name"], "error": str(exc)})
                evidence["cleanup"]["sessions"] = cleanup
                evidence["cleanup"]["remaining_owned"] = [{"id": x["id"], "pid": x["pid"]} for x in manager.list() if x.get("name") in {"gmx-dev", "gmx-attack"} and x.get("process_owned")]
                logs = root / ".audit" / "networks"
                if logs.is_dir():
                    for item in logs.glob("*.log"):
                        (output / item.name).write_text(item.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"

    if failure is None and (evidence["cleanup"].get("remaining_owned") or any("error" in x for x in evidence["cleanup"].get("sessions", []))):
        failure = "Owned Anvil process cleanup was incomplete."
    evidence["status"], evidence["error"] = ("PASS", None) if failure is None else ("FAILED", failure)
    (output / "latest.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": evidence["status"], "evidence": str(output / "latest.json"), "checks": evidence["checks"], "error": failure}, indent=2))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
