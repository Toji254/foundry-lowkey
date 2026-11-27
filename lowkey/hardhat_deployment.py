"""Reviewed project-native Hardhat 3 deployment on a Lowkey-managed Anvil session.

The initial adapter intentionally supports direct CREATE transactions only.
Factory, clone, proxy and multi-transaction deployment topologies are blocked
until a matching topology-specific adapter can independently verify them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


HELP = """LOWKEY HELP  •  lk hardhat deploy
========================================================================
What it does: Reviews and runs one project-native Hardhat 3 deployment script
              against the currently selected Lowkey-managed Anvil network.
Usage:        lk hardhat deploy <script> --network <name> --target <Contract>
Example:      lk hardhat deploy scripts/Deploy.mjs --network localhost --target Vault

OPTIONS
  --network <name>   Required explicit Hardhat HTTP network name.
  --target <name>    Required first-party artifact to register as primary.
  --help             Read-only help.

SAFETY
  Requires a process-owned Lowkey-managed Anvil session, Hardhat 3, Node.js
  22.13+, HTTP network type, and accounts: "remote". Private-key and HD-wallet
  configurations are rejected. Lowkey asks for PROBE and DEPLOY approval.
  LOWKEY_NONINTERACTIVE_DEPLOY=1 is the explicit local automation approval.
  It does not bypass network checks, transaction evidence, runtime checks or
  deployment registry verification.
  Only a verified direct contract creation is accepted. Factory/proxy multi-step
  deployment scripts are not silently treated as direct deployments.
  Project config and scripts are executable JavaScript/TypeScript, not sandboxed.
"""


def parse_deploy_args(argv: Sequence[str]) -> tuple[str | None, str | None, str | None]:
    values = list(argv or [])
    if not values or values[0] in {"--help", "--h", "-h", "help"}:
        return None, None, None
    script = str(values[0]).strip()
    if not script or script.startswith("-"):
        raise ValueError("the first argument must be a project-relative script path")
    network_name = None
    target_name = None
    index = 1
    while index < len(values):
        option = str(values[index]).strip()
        if option in {"--network", "--target"}:
            if index + 1 >= len(values) or str(values[index + 1]).startswith("--"):
                raise ValueError(option + " requires a value")
            value = str(values[index + 1]).strip()
            if not value:
                raise ValueError(option + " requires a non-empty value")
            if option == "--network":
                if network_name is not None:
                    raise ValueError("--network may be supplied only once")
                network_name = value
            else:
                if target_name is not None:
                    raise ValueError("--target may be supplied only once")
                target_name = value
            index += 2
            continue
        if option in {"--help", "--h", "-h", "help"}:
            return None, None, None
        raise ValueError("unsupported Hardhat deployment option: " + option)
    if not network_name:
        raise ValueError("--network is required; Lowkey will not use Hardhat's default network")
    if not target_name:
        raise ValueError("--target is required; Lowkey will not guess the primary audit target")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", network_name):
        raise ValueError("Hardhat network name is invalid")
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", target_name):
        raise ValueError("target contract name is invalid")
    return script, network_name, target_name


def _run_capture(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=str(cwd),
            env=dict(env),
            text=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return int(result.returncode), result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode("utf-8", "replace") if isinstance(error.stdout, bytes) else str(error.stdout or "")
        stderr = error.stderr.decode("utf-8", "replace") if isinstance(error.stderr, bytes) else str(error.stderr or "")
        return 124, stdout, stderr + "\nLowkey timeout after " + str(timeout) + " seconds."
    except OSError as error:
        return 127, "", type(error).__name__ + ": " + str(error)


def _write_private_log(root: Path, label: str, output: str) -> str:
    directory = root / ".audit" / "hardhat-deployment"
    directory.mkdir(parents=True, exist_ok=True)
    resolved_directory = directory.resolve()
    if not resolved_directory.is_relative_to(root.resolve()):
        raise ValueError("Hardhat deployment evidence directory resolves outside the project")
    destination = resolved_directory / (label[:48] + "-" + uuid.uuid4().hex[:12] + ".log")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=resolved_directory,
            prefix=".hardhat-deployment-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            handle.write(output)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return destination.relative_to(root.resolve()).as_posix()


def _environment_names(script: Path, config_paths: Sequence[Path]) -> list[str]:
    names: set[str] = set()
    patterns = (
        re.compile(r"""configVariable\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
        re.compile(r"""process\s*\.\s*env\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)"""),
        re.compile(r"""process\s*\.\s*env\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    )
    for path in (script, *config_paths):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in patterns:
            names.update(pattern.findall(source))
    names.add("LOWKEY_HARDHAT_NETWORK")
    return sorted(names)


PROBE_SCRIPT = StringProbe = """import { network } from "hardhat";

const selectedName = process.env.LOWKEY_HARDHAT_NETWORK;
if (typeof selectedName !== "string" || selectedName.length === 0) {
  throw new Error("Lowkey did not provide an explicit Hardhat network name");
}
const connection = await network.create(selectedName);
try {
  const selectedConfig = connection.networkConfig;
  const url = await selectedConfig.url.getUrl();
  const provider = connection.provider;
  const chainIdLive = await provider.request({ method: "eth_chainId", params: [] });
  const accountsLive = await provider.request({ method: "eth_accounts", params: [] });
  const resolvedAccounts = selectedConfig.accounts;
  const accountsMode = resolvedAccounts === "remote"
    ? "remote"
    : Array.isArray(resolvedAccounts)
      ? "local-key-list"
      : "hd-wallet";
  const environmentNames = JSON.parse(process.env.LOWKEY_HARDHAT_ENV_NAMES ?? "[]");
  const environment = {};
  for (const name of environmentNames) {
    environment[name] = process.env[name] ?? null;
  }
  const record = {
    networkName: connection.networkName,
    type: selectedConfig.type,
    url,
    accountsMode,
    from: selectedConfig.from ?? null,
    chainId: selectedConfig.chainId ?? null,
    chainIdLive,
    accountsLive,
    httpHeadersCount: Object.keys(selectedConfig.httpHeaders ?? {}).length,
    environment,
  };
  process.stdout.write("LOWKEY_HARDHAT_CONTEXT=" + JSON.stringify(record) + "\\n");
} finally {
  await connection.close();
}
"""


def parse_probe_output(stdout: str) -> dict[str, Any]:
    marker = "LOWKEY_HARDHAT_CONTEXT="
    records = [
        line[len(marker):]
        for line in str(stdout or "").splitlines()
        if line.startswith(marker)
    ]
    if len(records) != 1:
        raise ValueError(
            "Hardhat network probe must produce exactly one context record; received "
            + str(len(records))
        )
    try:
        record = json.loads(records[0])
    except json.JSONDecodeError as error:
        raise ValueError("Hardhat network probe returned malformed context JSON") from error
    required = {
        "networkName", "type", "url", "accountsMode", "chainId",
        "chainIdLive", "accountsLive", "httpHeadersCount", "environment",
    }
    if not isinstance(record, dict):
        raise ValueError("Hardhat network probe context must be an object")
    missing = sorted(required - set(record))
    if missing:
        raise ValueError("Hardhat network probe is missing fields: " + ", ".join(missing))
    if not isinstance(record.get("accountsLive"), list) or not isinstance(record.get("environment"), dict):
        raise ValueError("Hardhat network probe returned malformed accounts or environment data")
    return record


def _config_paths(root: Path, hardhat_tools: Any) -> list[Path]:
    configs = hardhat_tools._hardhat_config_paths(root)
    if len(configs) != 1:
        raise ValueError(
            "Hardhat deployment requires exactly one hardhat.config.* file; found "
            + str(len(configs))
            + ". Lowkey will not guess which config to load."
        )
    candidates = [
        *configs,
        root / "package.json",
        root / "package-lock.json",
        root / "npm-shrinkwrap.json",
        root / "pnpm-lock.yaml",
        root / "yarn.lock",
        root / "bun.lock",
        root / "bun.lockb",
        root / ".env",
        root / ".env.local",
    ]
    return list(dict.fromkeys(path for path in candidates if path.is_file()))


def _probe_network(
    root: Path,
    hardhat_binary: Path,
    environment: Mapping[str, str],
    *,
    network_name: str,
    env_names: Sequence[str],
    timeout: int = 180,
) -> tuple[dict[str, Any], str]:
    audit_dir = root / ".audit" / "hardhat-deployment"
    audit_dir.mkdir(parents=True, exist_ok=True)
    resolved_dir = audit_dir.resolve()
    if not resolved_dir.is_relative_to(root.resolve()):
        raise ValueError("Hardhat probe directory resolves outside the current project")
    probe_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=resolved_dir,
            prefix=".lowkey-network-probe-",
            suffix=".mjs",
            delete=False,
        ) as handle:
            probe_path = Path(handle.name)
            os.chmod(probe_path, 0o600)
            handle.write(PROBE_SCRIPT)
        command_env = dict(environment)
        command_env["LOWKEY_HARDHAT_NETWORK"] = network_name
        command_env["LOWKEY_HARDHAT_ENV_NAMES"] = json.dumps(list(env_names))
        relative_probe = probe_path.relative_to(root).as_posix()
        code, stdout, stderr = _run_capture(
            [str(hardhat_binary), "run", relative_probe, "--network", network_name],
            cwd=root,
            env=command_env,
            timeout=timeout,
        )
        raw_output = stdout + (("\n" + stderr) if stderr else "")
        log_path = _write_private_log(root, "network-probe", raw_output)
        if code != 0:
            raise ValueError(
                "Hardhat could not resolve the selected project network (exit "
                + str(code)
                + "). Private output log: "
                + log_path
            )
        return parse_probe_output(stdout), log_path
    finally:
        if probe_path is not None and probe_path.exists():
            probe_path.unlink()


def _approval(token: str, prompt: str) -> bool:
    if os.environ.get("LOWKEY_NONINTERACTIVE_DEPLOY") == "1":
        return True
    if not getattr(sys.stdin, "isatty", lambda: False)():
        print(
            prompt
            + " requires an interactive terminal. For intentionally scripted local deployment only, set LOWKEY_NONINTERACTIVE_DEPLOY=1.",
            file=sys.stderr,
        )
        return False
    try:
        answer = input(prompt + "\nType " + token + " to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == token


def _network_session(lk: Any, root: Path, config: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], str]:
    config["_resolved_project_context"] = {"project_root": str(root.resolve())}
    if config.get("_explicit_rpc_unscoped") or config.get("_network_selection_error"):
        raise ValueError("the current Lowkey RPC context is detached or ambiguous; select a managed network first")
    rpc = lk.effective_rpc(config)
    if not rpc:
        raise ValueError("no unambiguous selected Lowkey RPC; select a managed network first")
    state = lk.read_project_anvil_state(root) or {}
    sessions = state.get("managed_sessions")
    if not isinstance(sessions, dict):
        raise ValueError("the project network registry has no managed-session records")
    session_id = state.get("active_session_id")
    session = sessions.get(session_id) if session_id else None
    if not isinstance(session, dict):
        raise ValueError("there is no explicitly active managed Anvil session in this project")
    if str(session.get("rpc") or "").rstrip("/") != str(rpc).rstrip("/"):
        raise ValueError("the effective RPC does not match the active managed network session")
    identity = lk._current_deployment_network_identity(config, root, rpc)
    if (
        identity.get("reuse_permitted") is not True
        or identity.get("session_kind") != "managed-anvil"
        or identity.get("network_session_id") != str(session_id)
    ):
        raise ValueError("the active endpoint is not a healthy process-owned Lowkey managed Anvil session")
    sender = str((session.get("actors") or {}).get("lab-deployer") or "").strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", sender):
        raise ValueError("the managed session has no valid lab-deployer account")
    accounts = lk.rpc_json(rpc, "eth_accounts", [])
    chain = lk.rpc_json(rpc, "eth_chainId", [])
    if not isinstance(accounts, list) or sender not in {str(item).strip().lower() for item in accounts}:
        raise ValueError("the managed lab-deployer is not unlocked by the selected RPC")
    try:
        chain_id = int(str(chain), 16)
    except (TypeError, ValueError):
        raise ValueError("the selected managed Anvil did not return a valid chain ID")
    if chain_id != int(identity.get("chain_id") or 0):
        raise ValueError("the active session chain identity changed during Hardhat deployment preflight")
    return str(rpc), identity, session, sender


def _toolchain(root: Path, hardhat_tools: Any) -> tuple[Path, dict[str, str], str, str]:
    environment, error = hardhat_tools._node_context(root)
    if error or environment is None:
        raise ValueError(error or "the project Node.js environment is unavailable")
    binary = hardhat_tools._local_hardhat(root)
    if binary is None or not Path(binary).is_file():
        raise ValueError(
            "project-local Hardhat is unavailable. Run lk hardhat prepare after reviewing project dependencies; deployment will not install packages or use npx."
        )
    code, stdout, stderr = _run_capture(
        [str(binary), "--version"], cwd=root, env=environment, timeout=20
    )
    if code != 0:
        raise ValueError("the project-local Hardhat version could not be verified")
    hardhat_version = (stdout or stderr).strip()
    version = hardhat_tools._parse_version(hardhat_version)
    node_binary = hardhat_tools.shutil.which("node", path=environment.get("PATH"))
    if version is None or version[0] != 3 or not node_binary:
        raise ValueError("a working project-local Hardhat 3 and Node.js runtime are required")
    node_code, node_out, node_err = _run_capture(
        [node_binary, "--version"], cwd=root, env=environment, timeout=10
    )
    if node_code != 0:
        raise ValueError("Node.js version could not be verified")
    return Path(binary).resolve(), environment, hardhat_version, (node_out or node_err).strip()


def _partial_record(lk: Any, root: Path, identity: Mapping[str, Any], address: str | None, tx_hash: str | None, reason: str) -> None:
    if not identity.get("network_session_id") or not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(tx_hash or "")):
        return
    try:
        lk._project_network_manager(root).record_deployment(
            str(identity["network_session_id"]),
            {
                "role": "partial_deployment",
                "status": "DEPLOYED_UNVERIFIED",
                "address": address if re.fullmatch(r"0x[0-9a-fA-F]{40}", str(address or "")) else None,
                "deployment_transaction": tx_hash,
                "operation_key": tx_hash,
                "reuse_permitted": False,
                "verification_status": "UNVERIFIED",
                "reason": str(reason)[:512],
                "network": {
                    key: identity.get(key)
                    for key in (
                        "project_id", "project_root", "network_session_id", "session_kind",
                        "chain_id", "genesis_hash", "identity_block_hash", "identity_block_number",
                        "rpc_fingerprint", "rpc_origin",
                    )
                },
            },
            operation_key=tx_hash,
        )
    except Exception as error:
        print("WARNING  partial Hardhat deployment evidence was not persisted: " + str(error), file=sys.stderr)


def _transaction_evidence(lk: Any, rpc: str, sender: str, tx_hash: str, target: str) -> dict[str, Any]:
    transaction = lk.rpc_json(rpc, "eth_getTransactionByHash", [tx_hash])
    receipt = lk.rpc_json(rpc, "eth_getTransactionReceipt", [tx_hash])
    if not isinstance(transaction, dict) or not isinstance(receipt, dict):
        raise ValueError("selected managed RPC could not independently retrieve the transaction and receipt")
    if str(transaction.get("hash") or "").lower() != tx_hash.lower():
        raise ValueError("transaction hash mismatch")
    if str(transaction.get("from") or "").lower() != sender.lower():
        raise ValueError("deployment transaction sender does not match the managed lab-deployer")
    if transaction.get("to") is not None:
        raise ValueError("only direct contract-creation transactions are supported; factory/proxy deployment is blocked")
    if str(receipt.get("transactionHash") or "").lower() != tx_hash.lower():
        raise ValueError("receipt transaction hash mismatch")
    if str(receipt.get("status") or "").lower() not in {"0x1", "1"}:
        raise ValueError("Hardhat deployment receipt did not report success")
    if str(receipt.get("contractAddress") or "").lower() != target.lower():
        raise ValueError("receipt contractAddress does not match LOWKEY_TARGET")
    block_hex = str(receipt.get("blockNumber") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", block_hex):
        raise ValueError("deployment receipt has no valid block number")
    block = lk.rpc_json(rpc, "eth_getBlockByNumber", [block_hex, False])
    if not isinstance(block, dict) or str(block.get("hash") or "").lower() != str(receipt.get("blockHash") or "").lower():
        raise ValueError("deployment block hash could not be reconciled")
    historical_code = lk.rpc_json(rpc, "eth_getCode", [target, block_hex])
    latest_code = lk.rpc_json(rpc, "eth_getCode", [target, "latest"])
    if not isinstance(historical_code, str) or historical_code in {"", "0x", "0X"}:
        raise ValueError("receipt target has no runtime code at the deployment block")
    if not isinstance(latest_code, str) or latest_code in {"", "0x", "0X"}:
        raise ValueError("receipt target has no runtime code at latest block")
    if historical_code.lower() != latest_code.lower():
        raise ValueError("target runtime changed after the Hardhat deployment")
    return {
        "transaction_hash": tx_hash,
        "target": target,
        "sender": sender,
        "block_number": int(block_hex, 16),
        "block_hash": str(block["hash"]).lower(),
        "runtime_bytes": (len(latest_code) - 2) // 2,
    }


def _fail_review(review_engine: Any, review: Any, root: Path, reason: str, state: str = "HARDHAT_FAILED", details: Mapping[str, Any] | None = None) -> int:
    try:
        review_engine.persist_hardhat_script_review(
            review, root, state=state, details={"reason": str(reason)[:512], **dict(details or {})}
        )
    except Exception as error:
        print("WARNING  Hardhat review outcome was not persisted: " + str(error), file=sys.stderr)
    print("BLOCKED  " + str(reason), file=sys.stderr)
    return 2


def run_deploy_cli(argv: Sequence[str], *, hardhat_tools: Any = None) -> int:
    try:
        script_arg, network_name, target_name = parse_deploy_args(argv)
    except ValueError as error:
        print("Error: " + str(error), file=sys.stderr)
        print(HELP, file=sys.stderr)
        return 2
    if script_arg is None:
        print(HELP)
        return 0
    if hardhat_tools is None:
        import hardhat_tools as hardhat_tools
    try:
        import lk
        import deployment_review as review_engine
    except ImportError as error:
        print("BLOCKED  installed Lowkey runtime is missing a deployment module: " + str(error), file=sys.stderr)
        return 2

    try:
        root, _project = hardhat_tools._selected_project()
        root = Path(root).resolve(strict=True)
        script = (root / script_arg).resolve(strict=True)
        if not script.is_file() or not script.is_relative_to(root):
            raise ValueError("deployment script must be an existing file inside the selected Hardhat project")
        if script.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"}:
            raise ValueError("deployment script must use a JavaScript or TypeScript extension")
        config_paths = _config_paths(root, hardhat_tools)
        binary, node_env, hardhat_version, node_version = _toolchain(root, hardhat_tools)
        config = lk.load_config()
        rpc, identity, session, sender = _network_session(lk, root, config)
        env_names = _environment_names(script, config_paths)
    except Exception as error:
        print("BLOCKED  " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2

    print("LOWKEY REVIEWED HARDHAT DEPLOYMENT")
    print("==================================")
    print("Project       : " + str(root))
    print("Script        : " + script.relative_to(root).as_posix())
    print("Hardhat       : " + hardhat_version)
    print("Node.js       : " + node_version)
    print("Network       : " + str(network_name))
    print("Session       : " + str(identity.get("network_session_id")))
    print("Chain ID      : " + str(identity.get("chain_id")))
    print("Lab deployer  : " + sender)
    print("Preflight     : Hardhat config is executable project code and must be loaded to resolve the selected endpoint.")
    print("Effects       : scripts may deploy, call contracts, transfer value, change storage and execute arbitrary imported JavaScript.")
    if not _approval(
        "PROBE",
        "Approve loading the Hardhat configuration and running a read-only selected-network probe? No deployment script or blockchain transaction will be sent.",
    ):
        print("Cancelled. No deployment script was executed.", file=sys.stderr)
        return 1

    review = None
    try:
        probe, probe_log = _probe_network(
            root, binary, node_env, network_name=network_name, env_names=env_names
        )
        if probe.get("networkName") != network_name:
            raise ValueError("Hardhat resolved a different network name")
        if str(probe.get("type") or "").lower() != "http":
            raise ValueError("selected Hardhat network is not HTTP")
        if str(probe.get("accountsMode") or "").lower() != "remote":
            raise ValueError("selected Hardhat network must use accounts: remote; private-key and HD-wallet signers are blocked")
        if int(probe.get("httpHeadersCount") or 0) != 0:
            raise ValueError("custom Hardhat HTTP headers are blocked by the local managed-network adapter")
        try:
            probe_chain = int(str(probe.get("chainIdLive")), 16)
        except (TypeError, ValueError):
            raise ValueError("Hardhat provider returned a malformed live chain ID")
        if probe_chain != int(identity.get("chain_id") or 0):
            raise ValueError("Hardhat selected network does not match the active managed Anvil chain")
        accounts = probe.get("accountsLive")
        if not isinstance(accounts, list) or sender not in {str(item).lower() for item in accounts}:
            raise ValueError("Hardhat selected provider does not expose the managed lab-deployer")
        env_values = dict(probe.get("environment") or {})
        env_values["LOWKEY_HARDHAT_NETWORK"] = network_name
        review = review_engine.build_hardhat_script_review(
            root,
            script,
            rpc=rpc,
            hardhat_version=hardhat_version,
            node_version=node_version,
            network_name=network_name,
            network_config={
                "type": probe.get("type"),
                "url": probe.get("url"),
                "accounts_mode": probe.get("accountsMode"),
                "from": probe.get("from"),
                "chain_id": probe.get("chainId"),
            },
            network_identity=identity,
            sender=sender,
            configuration_paths=config_paths,
            environment_values=env_values,
        )
        review_path = review_engine.persist_hardhat_script_review(review, root, state="REVIEW_REQUIRED")
        print("")
        print(review_engine.render_hardhat_script_review(review))
        print("Review evidence : " + review_path)
        print("Probe log       : " + probe_log)
    except Exception as error:
        print("BLOCKED  Hardhat deployment preflight could not be established: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 2

    if not _approval("DEPLOY", "Approve executing this exact Hardhat script against the reviewed managed Anvil session?"):
        return _fail_review(review_engine, review, root, "user declined the Hardhat deployment", state="DECLINED")

    output_log = None
    tx_hash = None
    target = None
    try:
        current_config = lk.load_config()
        current_rpc, current_identity, _current_session, current_sender = _network_session(lk, root, current_config)
        current_probe, _current_probe_log = _probe_network(
            root, binary, node_env, network_name=network_name, env_names=env_names
        )
        current_env = dict(current_probe.get("environment") or {})
        current_env["LOWKEY_HARDHAT_NETWORK"] = network_name
        current_network_config = {
            "type": current_probe.get("type"),
            "url": current_probe.get("url"),
            "accounts_mode": current_probe.get("accountsMode"),
            "from": current_probe.get("from"),
            "chain_id": current_probe.get("chainId"),
        }
        valid, reason = review_engine.verify_hardhat_script_review_current(
            review,
            root,
            rpc=current_rpc,
            hardhat_version=hardhat_version,
            node_version=node_version,
            network_name=network_name,
            network_config=current_network_config,
            network_identity=current_identity,
            sender=current_sender,
            environment_values=current_env,
        )
        if not valid or current_identity != identity or current_sender != sender:
            return _fail_review(
                review_engine, review, root,
                "approved review is stale; no deployment script was executed. " + str(reason or "managed session or actor changed"),
                state="STALE",
            )
        if current_probe.get("httpHeadersCount") != 0:
            return _fail_review(review_engine, review, root, "Hardhat HTTP headers changed after review", state="STALE")

        review_engine.persist_hardhat_script_review(review, root, state="BROADCAST_STARTED")
        command = [str(binary), "run", script.relative_to(root).as_posix(), "--network", network_name]
        execution_env = dict(node_env)
        execution_env["LOWKEY_HARDHAT_NETWORK"] = network_name
        execution_env["LOWKEY_NETWORK_SESSION_ID"] = str(identity["network_session_id"])
        code, stdout, stderr = _run_capture(command, cwd=root, env=execution_env, timeout=1800)
        combined = stdout + (("\n" + stderr) if stderr else "")
        output_hash = hashlib.sha256(combined.encode("utf-8", "replace")).hexdigest()
        output_log = _write_private_log(root, "deployment-output", combined)
        if code != 0:
            return _fail_review(
                review_engine, review, root,
                "Hardhat script failed or timed out; arbitrary project side effects may already have occurred. Private log: " + output_log,
                details={"hardhat_exit_code": code, "output_sha256": output_hash},
            )
        target_matches = re.findall(
            r"(?im)^\s*LOWKEY_TARGET\s*[:=]?\s*(0x[0-9a-fA-F]{40})\s*$", stdout
        )
        tx_matches = re.findall(
            r"(?im)^\s*LOWKEY_TARGET_TX\s*[:=]?\s*(0x[0-9a-fA-F]{64})\s*$", stdout
        )
        if len(target_matches) != 1 or len(tx_matches) != 1:
            return _fail_review(
                review_engine, review, root,
                "Hardhat script must emit exactly one LOWKEY_TARGET address and LOWKEY_TARGET_TX hash; no target was promoted.",
                details={"output_sha256": output_hash},
            )
        target, tx_hash = target_matches[0], tx_matches[0]
        evidence = _transaction_evidence(lk, current_rpc, sender, tx_hash, target)
        contract, artifact_path, target_error = lk._validate_project_lab_target(
            current_config, root, current_rpc, target, requested=target_name
        )
        if target_error or not artifact_path or str(contract or "").lower() != target_name.lower():
            _partial_record(lk, root, identity, target, tx_hash, target_error or "target did not match requested first-party artifact")
            return _fail_review(
                review_engine, review, root,
                "deployment receipt and runtime were observed, but the address did not match the requested first-party artifact. Partial deployment recorded; primary target unchanged. "
                + str(target_error or ""),
                details={"hardhat_exit_code": 0, "output_sha256": output_hash, "target_address": target, "transaction_hashes": [tx_hash]},
            )

        deployment_config = dict(current_config)
        deployment_config["_ephemeral"] = True
        deployment_config["actor"] = "lab-deployer"
        deployment_config["target"] = None
        deployment_config["target_contract"] = None
        deployment_config.setdefault("wallets", {})["lab-deployer"] = {
            "source": "managed-session",
            "address": sender,
            "internal": True,
        }
        runtime = lk._live_target_state(deployment_config, target, artifact_path, network_identity=current_identity)
        if (
            not isinstance(runtime, dict)
            or runtime.get("status") != "DEPLOYED"
            or str(runtime.get("verification") or "").upper() != "MATCHED"
        ):
            _partial_record(lk, root, identity, target, tx_hash, "deployed runtime did not match the requested artifact")
            return _fail_review(
                review_engine, review, root,
                "runtime could not be independently matched to the requested artifact. Partial deployment recorded; primary target unchanged.",
                details={"hardhat_exit_code": 0, "output_sha256": output_hash, "target_address": target, "transaction_hashes": [tx_hash]},
            )

        lk.set_lab_target(
            deployment_config, root, target, contract, artifact_path,
            network_identity=current_identity, deployment_transaction=tx_hash,
        )
        project_key = str(root.resolve())
        primary = deployment_config.get("project_target_registry", {}).get(project_key, {}).get(str(contract))
        if not isinstance(primary, dict) or primary.get("network_registry_status") != "RECORDED":
            _partial_record(lk, root, identity, target, tx_hash, "primary target not confirmed in managed session registry")
            return _fail_review(
                review_engine, review, root,
                "runtime matched but the managed session registry did not confirm primary-target persistence. Automatic reuse is blocked.",
                details={"hardhat_exit_code": 0, "output_sha256": output_hash, "target_address": target, "transaction_hashes": [tx_hash]},
            )
        review_engine.persist_hardhat_script_review(
            review,
            root,
            state="HARDHAT_SUCCEEDED",
            details={
                "hardhat_exit_code": 0,
                "output_sha256": output_hash,
                "target_address": target,
                "transaction_hashes": [tx_hash],
            },
        )
        print("")
        print("HARDHAT DEPLOYMENT VERIFIED")
        print("===========================")
        print("Target          : " + str(contract) + " -> " + target)
        print("Transaction     : " + tx_hash)
        print("Block           : " + str(evidence["block_number"]) + " (" + str(evidence["block_hash"]) + ")")
        print("Runtime         : " + str(evidence["runtime_bytes"]) + " bytes; MATCHED to " + Path(artifact_path).relative_to(root).as_posix())
        print("Network session : " + str(identity["network_session_id"]))
        print("Registry        : primary target recorded in owning managed session")
        print("Readiness       : NOT ESTABLISHED (initialization, roles and protocol invariants remain separate checks)")
        print("Review evidence : .audit/deployment-reviews/" + review.review_id + ".json")
        print("Private log     : " + str(output_log))
        return 0
    except Exception as error:
        details = {}
        if output_log:
            try:
                log_text = (root / output_log).read_text(encoding="utf-8", errors="replace")
                details["output_sha256"] = hashlib.sha256(log_text.encode("utf-8", "replace")).hexdigest()
            except OSError:
                pass
        if target and tx_hash:
            _partial_record(lk, root, identity, target, tx_hash, str(error))
            details["target_address"] = target
            details["transaction_hashes"] = [tx_hash]
        return _fail_review(review_engine, review, root, type(error).__name__ + ": " + str(error), details=details)


if __name__ == "__main__":
    raise SystemExit(2)
