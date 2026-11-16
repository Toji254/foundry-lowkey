#!/usr/bin/env python3
"""P2 acceptance: canonical Forge/Anvil parity and first exact-identity mainnet fork.

The harness performs only a read-only getNonce() call against a pinned
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
TARGET = "0x0000000071727de22e5e9d8baf0edac6f37da032"
ACTOR = "0x000000000000000000000000000000000000a11c"
DEFAULT_FORK_UPSTREAM = "https://eth-mainnet.public.blastapi.io"
DEFAULT_FORK_FALLBACK_RPC = "https://ethereum-rpc.publicnode.com"
DEFAULT_SOURCE_RPC = "https://rpc.mevblocker.io"
DEFAULT_SOURCE_FALLBACK_RPC = "https://eth.llamarpc.com"
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


def pick_common_block(fork_upstream: str, source_rpc: str, deployment_block: int) -> tuple[int, dict[str, Any]]:
    fork_tip = quantity(rpc(fork_upstream, "eth_blockNumber", []), "fork upstream tip")
    source_tip = quantity(rpc(source_rpc, "eth_blockNumber", []), "source RPC tip")
    candidate = min(fork_tip, source_tip) - 12
    if candidate <= deployment_block:
        raise AssertionError("Public RPC endpoints did not expose a recent block after the verified target deployment.")
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
        if candidate <= deployment_block:
            break
    raise AssertionError("Could not find a recent common Ethereum block across the two independent RPC providers.")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_anvil(process: subprocess.Popen, url: str, log_path: Path) -> None:
    for _ in range(60):
        if process.poll() is not None:
            raise AssertionError("Anvil exited during startup:\\n" + log_path.read_text(encoding="utf-8", errors="replace")[-6000:])
        try:
            if quantity(rpc(url, "eth_chainId", [], timeout=2), "Anvil chain ID") == 1:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise AssertionError("Anvil did not become ready:\\n" + log_path.read_text(encoding="utf-8", errors="replace")[-6000:])


def is_rate_limit_failure(details: str) -> bool:
    lowered = details.lower()
    return any(marker in lowered for marker in (
        "http error 429", "status code 429", "too many requests",
        "compute units per second", "rate limit", "rate exceeded",
    ))


def stop_anvil(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def start_anvil(
    binary: str,
    fork_upstream: str,
    fork_block: int,
    root_env: dict[str, str],
    log_path: Path,
) -> tuple[subprocess.Popen, str]:
    port = find_free_port()
    url = f"http://127.0.0.1:{port}"
    env = root_env.copy()
    env.update({
        "ETH_RPC_URL": url,
        "FOUNDRY_ETH_RPC_URL": url,
        "LOWKEY_RPC_URL": url,
    })
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                binary, "--silent", "--host", "127.0.0.1", "--port", str(port),
                "--chain-id", "1", "--fork-url", fork_upstream,
                "--fork-block-number", str(fork_block),
            ],
            cwd=ROOT, env=env, stdout=log_handle, stderr=subprocess.STDOUT,
        )
    try:
        wait_for_anvil(process, url, log_path)
    except Exception:
        stop_anvil(process)
        raise
    return process, url


def resolve_source_archive_provider(
    primary_rpc: str,
    fallback_rpc: str,
    fork_rpc: str,
    deployment_block: int,
    alternate_rpc: str | None = None,
) -> tuple[str, list[dict[str, str]], dict[str, Any]]:
    """Select an independent source/archive RPC with proven historical reads."""
    attempts: list[dict[str, str]] = []
    seen: set[str] = set()
    for provider in (primary_rpc, fallback_rpc, alternate_rpc):
        key = urlparse_safe(provider)
        if key in seen:
            continue
        seen.add(key)
        if key == urlparse_safe(fork_rpc):
            attempts.append({
                "provider": key,
                "status": "skipped",
                "reason": "Source and fork evidence must come from independent providers.",
            })
            continue
        try:
            chain_id = quantity(rpc(provider, "eth_chainId", []), "source chain ID")
            if chain_id != 1:
                raise AssertionError(
                    f"Source/archive RPC must be Ethereum mainnet; received chain ID {chain_id}."
                )
            header = rpc(provider, "eth_getBlockByNumber", [hex(deployment_block), False])
            if not isinstance(header, dict) or not header.get("hash"):
                raise RuntimeError("Provider did not return the exact-match deployment block.")
            code = rpc(provider, "eth_getCode", [TARGET, hex(deployment_block)])
            if not isinstance(code, str) or code in {"0x", "0x0"}:
                raise RuntimeError("Provider did not return target runtime at its deployment block.")
            proof = rpc(provider, "eth_getProof", [TARGET, [], hex(deployment_block)])
            if not isinstance(proof, dict) or not str(proof.get("codeHash") or "").startswith("0x"):
                raise RuntimeError("Provider did not return a historical EIP-1186 account proof.")
            attempts.append({"provider": key, "status": "selected"})
            return provider, attempts, {
                "deployment_block_header": header,
                "deployment_code": code,
                "deployment_proof": proof,
            }
        except Exception as exc:
            attempts.append({
                "provider": key,
                "status": "unavailable",
                "reason": f"{type(exc).__name__}: {exc}"[:1200],
            })
    details = "; ".join(
        f"{item['provider']}: {item.get('reason') or item['status']}"
        for item in attempts
    )
    raise RuntimeError(
        "No independent source/archive RPC passed historical block, code and proof checks. "
        + details
    )


def resolve_fork_upstream(
    primary_rpc: str, fallback_rpc: str, source_rpc: str
) -> tuple[str, int, list[dict[str, str]]]:
    """Choose a mainnet fork RPC before any Sourcify/archive lookups depend on it."""
    attempts: list[dict[str, str]] = []
    try:
        chain_id = quantity(rpc(primary_rpc, "eth_chainId", []), "fork upstream chain ID")
        active_rpc = primary_rpc
        attempts.append({"provider": urlparse_safe(primary_rpc), "status": "selected"})
    except Exception as primary_error:
        if not is_rate_limit_failure(str(primary_error)):
            raise
        fallback_key = urlparse_safe(fallback_rpc)
        if fallback_key in {urlparse_safe(primary_rpc), urlparse_safe(source_rpc)}:
            raise AssertionError(
                "The primary fork RPC was rate-limited and no independent fallback is configured."
            ) from primary_error
        chain_id = quantity(rpc(fallback_rpc, "eth_chainId", []), "fallback fork RPC chain ID")
        active_rpc = fallback_rpc
        attempts.extend([
            {
                "provider": urlparse_safe(primary_rpc),
                "status": "rate_limited",
                "reason": "Initial eth_chainId request was rate-limited",
            },
            {"provider": fallback_key, "status": "selected_fallback"},
        ])
    if chain_id != 1:
        raise AssertionError(f"Fork upstream must be Ethereum mainnet; received chain ID {chain_id}.")
    return active_rpc, chain_id, attempts


def resolve_fork_snapshot_with_fallback(
    primary_rpc: str,
    fallback_rpc: str,
    source_rpc: str,
    deployment_block: int,
) -> tuple[str, tuple[int, dict[str, Any], dict[str, Any], str], list[dict[str, str]]]:
    """Apply fallback to historical code/proof lookups as well as Anvil startup."""
    attempts = [{"provider": urlparse_safe(primary_rpc), "status": "selected"}]
    try:
        snapshot = resolve_fork_snapshot(primary_rpc, source_rpc, deployment_block)
        return primary_rpc, snapshot, attempts
    except Exception as primary_error:
        error_text = str(primary_error)
        # Do not retry the fork provider when the independent source/archive
        # endpoint was the service that returned 429.
        if urlparse_safe(source_rpc) in error_text or not is_rate_limit_failure(error_text):
            raise
        fallback_key = urlparse_safe(fallback_rpc)
        if fallback_key in {urlparse_safe(primary_rpc), urlparse_safe(source_rpc)}:
            raise AssertionError(
                "The fork RPC was rate-limited during historical snapshot resolution, "
                "but the configured fallback is not an independent provider."
            ) from primary_error
        fallback_chain = quantity(
            rpc(fallback_rpc, "eth_chainId", []), "fallback fork RPC chain ID"
        )
        if fallback_chain != 1:
            raise AssertionError(
                f"Fork fallback must be Ethereum mainnet; received chain ID {fallback_chain}."
            )
        snapshot = resolve_fork_snapshot(fallback_rpc, source_rpc, deployment_block)
        attempts = [
            {
                "provider": urlparse_safe(primary_rpc),
                "status": "rate_limited",
                "reason": "Historical fork snapshot lookup was rate-limited",
            },
            {"provider": fallback_key, "status": "selected_fallback"},
        ]
        return fallback_rpc, snapshot, attempts


def resolve_fork_snapshot(
    fork_upstream: str, source_rpc: str, deployment_block: int
) -> tuple[int, dict[str, Any], dict[str, Any], str]:
    fork_chain_id = quantity(rpc(fork_upstream, "eth_chainId", []), "fork upstream chain ID")
    if fork_chain_id != 1:
        raise AssertionError(f"Fork fallback must be Ethereum mainnet; received chain ID {fork_chain_id}.")
    fork_block, common_header = pick_common_block(fork_upstream, source_rpc, deployment_block)
    source_proof = rpc(source_rpc, "eth_getProof", [TARGET, [], hex(fork_block)])
    if not isinstance(source_proof, dict) or not str(source_proof.get("codeHash") or "").startswith("0x"):
        raise AssertionError("Source RPC must support historical EIP-1186 eth_getProof for the pinned fork block.")
    fork_code = rpc(fork_upstream, "eth_getCode", [TARGET, hex(fork_block)])
    if not isinstance(fork_code, str) or fork_code in {"0x", "0x0"}:
        raise AssertionError("EntryPoint v0.7 has no runtime code at the selected pinned block.")
    from lowkey.godmode import _eip1167_implementation
    if _eip1167_implementation(fork_code):
        raise AssertionError("The EntryPoint v0.7 acceptance target unexpectedly resolved as an EIP-1167 clone.")
    return fork_block, common_header, source_proof, fork_code


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

contract P2FirstForkTest is LowkeyForgeStateDiffRecorder {
    address private constant TARGET =
        address(uint160(0x0000000071727De22E5E9d8BAf0edAc6f37da032));
    address private constant ACTOR = address(uint160(0xA11C));

    event NonceObserved(uint256 nonce);

    function test_first_verified_entrypoint_fork_observation() external {
        _lowkeyStartTrace(TARGET);
        vm.prank(ACTOR);
        (bool success, bytes memory result) = TARGET.call(
            abi.encodeWithSignature("getNonce(address,uint192)", ACTOR, uint192(0))
        );
        require(success && result.length == 32, "ENTRYPOINT_GET_NONCE_FAILED");
        emit NonceObserved(abi.decode(result, (uint256)));
        _lowkeyWriteTrace(".audit/godmode/p2-entrypoint-first-fork.json");
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
    source_fallback_rpc = (
        os.environ.get("LOWKEY_P2_SOURCE_FALLBACK_RPC_URL")
        or DEFAULT_SOURCE_FALLBACK_RPC
    )

    fallback_rpc = (
        os.environ.get("LOWKEY_P2_FORK_FALLBACK_RPC_URL")
        or DEFAULT_FORK_FALLBACK_RPC
    )
    fork_upstream, chain_id, fork_provider_attempts = resolve_fork_upstream(
        fork_upstream, fallback_rpc, source_rpc
    )
    if chain_id != 1:
        raise AssertionError(f"P2 first target is Ethereum mainnet; fork RPC chain ID was {chain_id}.")

    # Resolve the source identity first and require Sourcify's strict exact
    # match before choosing the fork block. The deployment block comes from
    # Sourcify metadata, not a hand-maintained fixture constant.
    from lowkey.godmode import _eip1167_implementation, _verify_sourcify_exact
    target_source_identity = _verify_sourcify_exact(chain_id, TARGET)
    target_deployment_block = int(target_source_identity["deployment_block"])

    # Select a source/archive provider that is independent of the fork RPC
    # and actually answers historical block, code and account-proof requests.
    # A temporary timeout on the default public endpoint must not abort a valid
    # pinned-fork test when an independent fallback is available.
    source_rpc, source_provider_attempts, source_deployment_evidence = (
        resolve_source_archive_provider(
            source_rpc,
            source_fallback_rpc,
            fork_upstream,
            target_deployment_block,
            alternate_rpc=fallback_rpc,
        )
    )
    deployment_block_header = source_deployment_evidence["deployment_block_header"]
    deployment_code = source_deployment_evidence["deployment_code"]
    fork_upstream, fork_snapshot, snapshot_attempts = resolve_fork_snapshot_with_fallback(
        fork_upstream, fallback_rpc, source_rpc, target_deployment_block
    )
    fork_block, common_header, source_proof, fork_code = fork_snapshot
    # If historical lookup had to switch providers, retain that transition in
    # the same provenance ledger used by Anvil-startup failover.
    if snapshot_attempts and snapshot_attempts[0].get("status") == "rate_limited":
        fork_provider_attempts = snapshot_attempts

    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    anvil_log = ARTIFACT_ROOT / "anvil.log"
    env = os.environ.copy()
    anvil_process: subprocess.Popen | None = None
    try:
        try:
            anvil_process, anvil_url = start_anvil(
                anvil, fork_upstream, fork_block, env, anvil_log
            )
        except AssertionError as primary_error:
            primary_log = anvil_log.read_text(encoding="utf-8", errors="replace") if anvil_log.exists() else ""
            if not is_rate_limit_failure(f"{primary_error}\\n{primary_log}"):
                raise
            fallback_key = urlparse_safe(fallback_rpc)
            if fallback_key in {urlparse_safe(fork_upstream), urlparse_safe(source_rpc)}:
                raise AssertionError(
                    "The configured fork RPC was rate-limited and no independent fallback is available. "
                    "Set LOWKEY_P2_FORK_FALLBACK_RPC_URL to a different Ethereum mainnet RPC."
                ) from primary_error
            fork_provider_attempts[0] = {
                "provider": urlparse_safe(fork_upstream),
                "status": "rate_limited",
                "reason": "Anvil startup returned HTTP 429",
            }
            # Re-pin both providers at a common block for the fallback. The
            # source/archive RPC remains independent and is re-checked at the
            # newly selected block before Anvil is started.
            fork_block, common_header, source_proof, fork_code = resolve_fork_snapshot(
                fallback_rpc, source_rpc, target_deployment_block
            )
            fork_provider_attempts.append({
                "provider": fallback_key, "status": "selected_fallback",
            })
            fork_upstream = fallback_rpc
            anvil_process, anvil_url = start_anvil(
                anvil, fork_upstream, fork_block, env,
                ARTIFACT_ROOT / "anvil-fallback.log",
            )

        local_chain = quantity(rpc(anvil_url, "eth_chainId", []), "fork chain ID")
        if local_chain != 1:
            raise AssertionError(f"Anvil fork returned chain ID {local_chain}, expected 1.")

        with tempfile.TemporaryDirectory(prefix="lowkey-p2-entrypoint-") as temporary:
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

            trace_path = project / ".audit" / "godmode" / "p2-entrypoint-first-fork.json"
            if not trace_path.is_file():
                raise AssertionError("Forge harness did not write the P2 trace artifact.")
            raw_forge = json.loads(trace_path.read_text(encoding="utf-8"))
            # Persist raw recorder output before normalization so every
            # mismatch remains inspectable in the CI artifact.
            ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
            raw_forge_path = ARTIFACT_ROOT / "raw-forge-state-diff.json"
            raw_forge_path.write_text(
                json.dumps(raw_forge, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            from lowkey.forge_state_diff import normalize_forge_state_diff
            from lowkey.trace_schema import normalize_calltracer, normalize_prestate_diff
            from lowkey.trace_parity import compare_trace_events
            from lowkey import proof_evidence, godmode

            normalized = normalize_forge_state_diff(raw_forge, expected_target=TARGET)
            forge_events = normalized.get("canonical_trace_events")
            if not isinstance(forge_events, list) or not forge_events:
                raise AssertionError(
                    "Forge recorder did not produce canonical TraceEvent v2: "
                    + str(normalized.get("canonical_trace_events_error"))
                )

            calldata = run([
                cast, "calldata", "getNonce(address,uint192)", ACTOR, "0"
            ], cwd=ROOT, env=test_env, timeout=20).stdout.strip()
            if not calldata.startswith("0x") or len(calldata) != 138:
                raise AssertionError(f"cast could not ABI-encode getNonce calldata: {calldata!r}")
            call_request = {
                "from": ACTOR,
                "to": TARGET,
                "data": calldata,
                "value": "0x0",
                "gas": hex(30_000_000),
            }
            call_trace = rpc(
                anvil_url,
                "debug_traceCall",
                [call_request, hex(fork_block), {"tracer": "callTracer"}],
                timeout=60,
            )
            prestate_diff = rpc(
                anvil_url,
                "debug_traceCall",
                [call_request, hex(fork_block), {
                    "tracer": "prestateTracer",
                    "tracerConfig": {"diffMode": True},
                }],
                timeout=60,
            )
            partial_storage_rows = normalize_prestate_diff(prestate_diff)
            anvil_events = normalize_calltracer(
                call_trace,
                storage_support="partial",
                partial_storage={0: partial_storage_rows},
            )
            parity = compare_trace_events(forge_events, anvil_events)
            if parity["status"] != "MATCHED":
                raise AssertionError("Forge/Anvil call-tree parity did not match:\n" + json.dumps(parity, indent=2))

            spec = {
                "source_addresses": [TARGET],
                "target_authenticity": "forked_deployment",
                "target_identity": {
                    "source_provider": "sourcify",
                    "deployment_block": target_deployment_block,
                },
            }
            identity = godmode._forge_source_verification(
                source_rpc, anvil_url, normalized, spec
            )
            if not identity.get("verified") or not identity.get("identity_verified"):
                (ARTIFACT_ROOT / "identity-verification-failure.json").write_text(
                    json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                (ARTIFACT_ROOT / "failure-summary.json").write_text(
                    json.dumps({
                        "status": "FAIL",
                        "stage": "identity_verification",
                        "target": TARGET,
                        "deployment_block": target_deployment_block,
                        "sourcify_match": target_source_identity.get("match"),
                        "sourcify_runtime_match": target_source_identity.get("runtime_match"),
                        "sourcify_creation_match": target_source_identity.get("creation_match"),
                        "reason": identity.get("reason"),
                    }, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
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
                                    "canonical_trace_events": anvil_events,
                                    "prestate_diff": prestate_diff}},
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
                "target_name": "Ethereum EntryPoint v0.7",
                "target_deployment_block": target_deployment_block,
                "target_runtime_kind": "direct verified contract",
                "read_only_call": "getNonce(address,uint192)",
                "sourcify_match": target_source_identity["match"],
                "sourcify_runtime_match": target_source_identity["runtime_match"],
                "sourcify_creation_match": target_source_identity["creation_match"],
                "fork_block": fork_block,
                "fork_block_hash": common_header.get("hash"),
                "source_provider": urlparse_safe(source_rpc),
                "fork_provider": urlparse_safe(fork_upstream),
                "fork_provider_attempts": fork_provider_attempts,
                "source_provider_attempts": source_provider_attempts,
                "proof_status": proof["status"],
                "target_authenticity": identity.get("identity", {}).get("target", {}),
                "forge_event_count": len(forge_events),
                "anvil_event_count": len(anvil_events),
                "call_tree_parity": parity["status"],
                "storage_parity": parity["storage_parity"],
                "storage_support": parity["storage_support"],
                "anvil_prestate_slots": len(partial_storage_rows),
                "anvil_prestate_scope": "transaction-level only; attached to root trace event, not attributed to nested frames",
                "call": "getNonce(address,uint192)",
                "call_kind": "read-only protocol view invoked with no value; no transaction broadcast",
                "identity_verified": identity.get("identity_verified"),
                "archive_state_verified": identity.get("archive_state_verified"),
                "proof_axes": proof,
            }
            (ARTIFACT_ROOT / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            print(parity_cli.stdout[-6000:])
    finally:
        stop_anvil(anvil_process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
