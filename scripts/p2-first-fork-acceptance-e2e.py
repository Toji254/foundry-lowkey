#!/usr/bin/env python3
"""P2 acceptance: canonical Forge/Anvil parity and first verified Yearn V3 clone fork.

The harness performs only a read-only totalAssets() call against a pinned
Ethereum mainnet fork. It never signs, broadcasts, or submits a transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TARGET = "0xbe53a109b494e5c9f97b9cd39fe969be68bf6204"
TARGET_DEPLOYMENT_BLOCK = 19_419_991
ACTOR = "0x000000000000000000000000000000000000a11c"
DEFAULT_FORK_UPSTREAM = "https://eth-mainnet.public.blastapi.io"
DEFAULT_SOURCE_RPC = "https://rpc.mevblocker.io"
RECORDER = ROOT / "docs" / "LowkeyForgeStateDiffRecorder.sol"
FORGE_STD_COMMIT = "15b2df92a05d4d2f76a06653872fefb287e0e01c"
ARTIFACT_ROOT = ROOT / ".audit" / "p2-first-fork"


def run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 240) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Command exited {completed.returncode}: {argv!r}\n"
            f"--- stdout ---\n{completed.stdout[-12000:]}\n"
            f"--- stderr ---\n{completed.stderr[-12000:]}"
        )
    return completed


def rpc(url: str, method: str, params: list[Any], timeout: int = 25) -> Any:
    request = Request(
        url,
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "LowkeyCast-P2-acceptance/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(8_000_000).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"RPC {method} failed at {urlparse_safe(url)}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"RPC {method} returned a non-object payload.")
    if payload.get("error"):
        raise RuntimeError(f"RPC {method} returned an error: {str(payload['error'])[:1200]}")
    if "result" not in payload:
        raise RuntimeError(f"RPC {method} response omitted result.")
    return payload["result"]


def urlparse_safe(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return (parsed.hostname or "unknown-host") + (parsed.path[:48] if parsed.path else "")


def quantity(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise AssertionError(f"{label} must be an RPC hex quantity; received {value!r}")
    return int(value, 16)


def pick_common_block(fork_upstream: str, source_rpc: str) -> tuple[int, dict[str, Any]]:
    fork_tip = quantity(rpc(fork_upstream, "eth_blockNumber", []), "fork upstream tip")
    source_tip = quantity(rpc(source_rpc, "eth_blockNumber", []), "source RPC tip")
    candidate = min(fork_tip, source_tip) - 12
    if candidate <= TARGET_DEPLOYMENT_BLOCK:
        raise AssertionError("Public RPC endpoints did not expose a recent block after the Yearn vault deployment.")
    for _ in range(24):
        tag = hex(candidate)
        fork_block = rpc(fork_upstream, "eth_getBlockByNumber", [tag, False])
        source_block = rpc(source_rpc, "eth_getBlockByNumber", [tag, False])
        if isinstance(fork_block, dict) and isinstance(source_block, dict):
            fork_hash = str(fork_block.get("hash") or "").lower()
            source_hash = str(source_block.get("hash") or "").lower()
            if fork_hash and fork_hash == source_hash:
                return candidate, fork_block
        candidate -= 12
        if candidate <= TARGET_DEPLOYMENT_BLOCK:
            break
    raise AssertionError("Could not find a recent common Ethereum block across the two independent RPC providers.")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_anvil(process: subprocess.Popen, url: str, log_path: Path) -> None:
    for _ in range(60):
        if process.poll() is not None:
            raise AssertionError("Anvil exited during startup:\n" + log_path.read_text(encoding="utf-8", errors="replace")[-6000:])
        try:
            if quantity(rpc(url, "eth_chainId", [], timeout=2), "Anvil chain ID") == 1:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise AssertionError("Anvil did not become ready:\n" + log_path.read_text(encoding="utf-8", errors="replace")[-6000:])


def prepare_forge_project(project: Path) -> None:
    (project / "src").mkdir(parents=True)
    (project / "test").mkdir()
    (project / "lib").mkdir()
    (project / ".audit" / "godmode").mkdir(parents=True)
    (project / "src" / "LowkeyForgeStateDiffRecorder.sol").write_text(
        RECORDER.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (project / "foundry.toml").write_text(
        """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
optimizer = false
fs_permissions = [
  { access = "read-write", path = "./.audit/godmode" }
]
""",
        encoding="utf-8",
    )
    (project / "test" / "P2FirstFork.t.sol").write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";

contract P2FirstYearnForkTest is LowkeyForgeStateDiffRecorder {
    address private constant TARGET =
        address(uint160(0x00be53a109b494e5c9f97b9cd39fe969be68bf6204));
    address private constant ACTOR = address(uint160(0xA11C));

    function test_first_verified_yearn_clone_fork_observation() external {
        _lowkeyStartTrace(TARGET);
        vm.prank(ACTOR);
        (bool success, bytes memory result) = TARGET.call(
            abi.encodeWithSignature("totalAssets()")
        );
        require(success && result.length >= 32, "YEARn_TOTAL_ASSETS_CALL_FAILED");
        uint256 observedAssets = abi.decode(result, (uint256));
        require(observedAssets > 0, "YEARn_TOTAL_ASSETS_ZERO");
        _lowkeyWriteTrace(".audit/godmode/p2-yearn-first-fork.json");
    }
}
""",
        encoding="utf-8",
    )
    run(["git", "init", "-q"], cwd=project, env=os.environ.copy(), timeout=30)
    run(["git", "config", "user.email", "ci@example.invalid"], cwd=project, env=os.environ.copy(), timeout=30)
    run(["git", "config", "user.name", "Lowkey P2 CI"], cwd=project, env=os.environ.copy(), timeout=30)
    run([
        "forge", "install", f"foundry-rs/forge-std@{FORGE_STD_COMMIT}", "--no-commit"
    ], cwd=project, env=os.environ.copy(), timeout=180)


def main() -> int:
    forge = shutil.which("forge")
    anvil = shutil.which("anvil")
    cast = shutil.which("cast")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge or not anvil or not cast or not Path(lk).is_file():
        raise AssertionError("P2 requires installed forge, anvil, cast and lk executables.")

    fork_upstream = os.environ.get("LOWKEY_P2_FORK_UPSTREAM_RPC_URL") or DEFAULT_FORK_UPSTREAM
    source_rpc = os.environ.get("LOWKEY_P2_SOURCE_RPC_URL") or DEFAULT_SOURCE_RPC
    if urlparse_safe(fork_upstream) == urlparse_safe(source_rpc):
        raise AssertionError("P2 fork and source RPC providers must be independent endpoints.")

    chain_id = quantity(rpc(fork_upstream, "eth_chainId", []), "fork upstream chain ID")
    source_chain_id = quantity(rpc(source_rpc, "eth_chainId", []), "source chain ID")
    if chain_id != 1 or source_chain_id != 1:
        raise AssertionError(f"P2 first target is Ethereum mainnet; RPC chain IDs were {chain_id} and {source_chain_id}.")

    # Fail early when either endpoint is a latest-state-only RPC. P2 needs
    # historical code/state and EIP-1186 proof support; a valid chainId/latest
    # response is not enough to establish a pinned deployment identity.
    deployment_block_header = rpc(
        source_rpc, "eth_getBlockByNumber", [hex(TARGET_DEPLOYMENT_BLOCK), False]
    )
    if not isinstance(deployment_block_header, dict) or not deployment_block_header.get("hash"):
        raise AssertionError("Source RPC cannot return the Yearn deployment block; archive history is required.")
    deployment_code = rpc(
        source_rpc, "eth_getCode", [TARGET, hex(TARGET_DEPLOYMENT_BLOCK)]
    )
    if not isinstance(deployment_code, str) or deployment_code in {"0x", "0x0"}:
        raise AssertionError("Source RPC cannot return Yearn clone runtime at its deployment block; archive state is required.")
    fork_block, common_header = pick_common_block(fork_upstream, source_rpc)
    source_proof = rpc(
        source_rpc, "eth_getProof", [TARGET, [], hex(fork_block)]
    )
    if not isinstance(source_proof, dict) or not str(source_proof.get("codeHash") or "").startswith("0x"):
        raise AssertionError("Source RPC must support historical EIP-1186 eth_getProof for the pinned fork block.")
    fork_code = rpc(fork_upstream, "eth_getCode", [TARGET, hex(fork_block)])
    if not isinstance(fork_code, str) or fork_code in {"0x", "0x0"}:
        raise AssertionError("Yearn yvUSDC clone has no runtime code at the selected pinned block.")

    from lowkey.godmode import _eip1167_implementation
    implementation = _eip1167_implementation(fork_code)
    if not implementation:
        raise AssertionError("Yearn yvUSDC runtime is not the canonical EIP-1167 minimal-proxy bytecode expected by this acceptance.")

    port = find_free_port()
    anvil_url = f"http://127.0.0.1:{port}"
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    anvil_log = ARTIFACT_ROOT / "anvil.log"
    env = os.environ.copy()
    env.update({
        "ETH_RPC_URL": anvil_url,
        "FOUNDRY_ETH_RPC_URL": anvil_url,
        "LOWKEY_RPC_URL": anvil_url,
    })
    anvil_process = subprocess.Popen(
        [
            anvil, "--silent", "--host", "127.0.0.1", "--port", str(port),
            "--chain-id", "1", "--fork-url", fork_upstream,
            "--fork-block-number", str(fork_block),
        ],
        cwd=ROOT, env=env, stdout=anvil_log.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )

    try:
        wait_for_anvil(anvil_process, anvil_url, anvil_log)
        local_chain = quantity(rpc(anvil_url, "eth_chainId", []), "fork chain ID")
        if local_chain != 1:
            raise AssertionError(f"Anvil fork returned chain ID {local_chain}, expected 1.")

        with tempfile.TemporaryDirectory(prefix="lowkey-p2-yearn-") as temporary:
            project = Path(temporary)
            prepare_forge_project(project)
            test_env = os.environ.copy()
            test_env.update({
                "ETH_RPC_URL": anvil_url,
                "FOUNDRY_ETH_RPC_URL": anvil_url,
                "LOWKEY_RPC_URL": anvil_url,
                "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1",
            })
            run([
                forge, "test", "--match-path", "test/P2FirstFork.t.sol",
                "--fork-url", anvil_url, "--fork-block-number", str(fork_block), "-vvv",
            ], cwd=project, env=test_env, timeout=300)

            trace_path = project / ".audit" / "godmode" / "p2-yearn-first-fork.json"
            if not trace_path.is_file():
                raise AssertionError("Forge harness did not write the P2 trace artifact.")
            raw_forge = json.loads(trace_path.read_text(encoding="utf-8"))

            from lowkey.forge_state_diff import normalize_forge_state_diff
            from lowkey.trace_schema import normalize_calltracer
            from lowkey.trace_parity import compare_trace_events
            from lowkey import proof_evidence, godmode

            normalized = normalize_forge_state_diff(raw_forge, expected_target=TARGET)
            forge_events = normalized.get("canonical_trace_events")
            if not isinstance(forge_events, list) or not forge_events:
                raise AssertionError(
                    "Forge recorder did not produce canonical TraceEvent v2: "
                    + str(normalized.get("canonical_trace_events_error"))
                )

            signature = run([cast, "sig", "totalAssets()"], cwd=ROOT, env=test_env, timeout=20).stdout.strip()
            if not signature.startswith("0x") or len(signature) != 10:
                raise AssertionError(f"cast could not derive totalAssets selector: {signature!r}")
            call_trace = rpc(
                anvil_url,
                "debug_traceCall",
                [{
                    "from": ACTOR,
                    "to": TARGET,
                    "data": signature,
                    "value": "0x0",
                    "gas": hex(30_000_000),
                }, hex(fork_block), {"tracer": "callTracer"}],
                timeout=60,
            )
            anvil_events = normalize_calltracer(call_trace, storage_support="declared_only")
            parity = compare_trace_events(forge_events, anvil_events)
            if parity["status"] != "MATCHED":
                raise AssertionError("Forge/Anvil call-tree parity did not match:\n" + json.dumps(parity, indent=2))

            spec = {
                "source_addresses": [TARGET],
                "target_authenticity": "forked_deployment",
                "target_identity": {
                    "source_provider": "sourcify",
                    "deployment_block": TARGET_DEPLOYMENT_BLOCK,
                    "proxy": {
                        "type": "eip1167",
                        "implementation_address": implementation,
                    },
                },
            }
            identity = godmode._forge_source_verification(
                source_rpc, anvil_url, normalized, spec
            )
            if not identity.get("verified") or not identity.get("identity_verified"):
                raise AssertionError(
                    "Independent archive/source identity verification failed:\n"
                    + json.dumps(identity, indent=2, sort_keys=True)
                )
            proof = proof_evidence.classify_proof(
                "forked_deployment", "simulated_caller", "observed",
                authenticity_verified=True,
            )
            if proof.get("status") != "FORK_OBSERVED":
                raise AssertionError("Verified real-fork observation did not reach FORK_OBSERVED.")

            forge_report = {
                "chain_id": 1, "block_number": fork_block,
                "runs": {"attack": {"chain_id": 1, "block_number": fork_block,
                                    "canonical_trace_events": forge_events}},
            }
            anvil_report = {
                "chain_id": 1, "block_number": fork_block,
                "runs": {"attack": {"chain_id": 1, "block_number": fork_block,
                                    "canonical_trace_events": anvil_events}},
            }
            ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
            forge_file = ARTIFACT_ROOT / "forge-evidence.json"
            anvil_file = ARTIFACT_ROOT / "anvil-evidence.json"
            forge_file.write_text(json.dumps(forge_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            anvil_file.write_text(json.dumps(anvil_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            parity_file = ARTIFACT_ROOT / "trace-parity.json"
            parity_command = [
                lk, "trace-parity",
                str(forge_file.relative_to(ROOT)),
                str(anvil_file.relative_to(ROOT)),
                "--root", str(ROOT),
                "--forge-scenario", "attack",
                "--anvil-scenario", "attack",
                "--output", str(parity_file.relative_to(ROOT)),
            ]
            parity_cli = run(parity_command, cwd=ROOT, env=env, timeout=60)
            parity_cli_payload = json.loads(parity_file.read_text(encoding="utf-8"))
            if parity_cli_payload.get("status") != "MATCHED":
                raise AssertionError("Installed lk trace-parity did not accept the same forked call tree.")

            normalized_file = ARTIFACT_ROOT / "forge-state-diff-normalized.json"
            normalized_file.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            report = {
                "status": "PASS",
                "target": TARGET,
                "target_name": "Yearn V3 USDC-1 vault",
                "target_deployment_block": TARGET_DEPLOYMENT_BLOCK,
                "target_runtime_kind": "EIP-1167 canonical minimal proxy",
                "implementation": implementation,
                "implementation_identity": identity.get("identity", {}).get("proxy"),
                "fork_block": fork_block,
                "fork_block_hash": common_header.get("hash"),
                "source_provider": urlparse_safe(source_rpc),
                "fork_provider": urlparse_safe(fork_upstream),
                "proof_status": proof["status"],
                "target_authenticity": identity.get("identity", {}).get("target", {}),
                "forge_event_count": len(forge_events),
                "anvil_event_count": len(anvil_events),
                "call_tree_parity": parity["status"],
                "storage_parity": parity["storage_parity"],
                "storage_support": parity["storage_support"],
                "call": "totalAssets()",
                "call_kind": "read-only protocol view invoked with no value; no transaction broadcast",
                "identity_verified": identity.get("identity_verified"),
                "archive_state_verified": identity.get("archive_state_verified"),
                "proof_axes": proof,
            }
            (ARTIFACT_ROOT / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            print(parity_cli.stdout[-6000:])
    finally:
        anvil_process.terminate()
        try:
            anvil_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            anvil_process.kill()
            anvil_process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
