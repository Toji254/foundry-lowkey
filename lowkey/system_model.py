from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
MANIFEST_RELATIVE = Path(".audit/evidence/system_bootstrap.json")


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(ADDRESS_RE.fullmatch(value))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    from urllib import request

    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=8) as response:
        payload = json.loads(response.read().decode())
    if "error" in payload:
        raise RuntimeError(str(payload["error"]))
    return payload.get("result")


def _code_size(rpc: str, address: str) -> int | None:
    if not _is_address(address):
        return None
    try:
        code = _rpc(rpc, "eth_getCode", [address, "latest"])
        return max(0, (len(code or "0x") - 2) // 2)
    except Exception:
        return None


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _mask_comments(text: str) -> str:
    chars = list(text)
    i = 0
    state = "code"
    quote = ""
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch in {"'", '"'}:
                quote = ch
                state = "string"
            i += 1
            continue
        if state == "line":
            if ch == "\n":
                state = "code"
            elif ch != "\r":
                chars[i] = " "
            i += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch not in "\r\n":
                chars[i] = " "
            i += 1
            continue
        if state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
    return "".join(chars)


def _project_files(root: Path, *patterns: str) -> list[Path]:
    seen: set[Path] = set()
    result: list[Path] = []
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                result.append(path)
    return result


def _extract_source_signals(path: Path, root: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    text = _mask_comments(raw)
    rel = path.relative_to(root).as_posix()
    actions: list[dict[str, Any]] = []

    patterns = [
        ("deploy", r"\bnew\s+([A-Za-z_]\w*)\s*\("),
        ("create", r"\b(?:create|create2)\s*\("),
        ("initialize", r"\.\s*initialize\s*\("),
        ("ownership", r"\b(?:transferOwnership|acceptOwnership)\s*\("),
        ("role_grant", r"\b(?:grantRole|_grantRole)\s*\("),
        ("role_revoke", r"\b(?:revokeRole|_revokeRole)\s*\("),
        ("permission", r"\b(?:authorize|set[A-Z]\w*Allowed|set[A-Z]\w*Permission)\s*\("),
        ("funding", r"\b(?:mint|deal|transfer|safeTransfer|transferFrom)\s*\("),
        ("approval", r"\b(?:approve|safeApprove|forceApprove|permit)\s*\("),
        ("configuration", r"\bset[A-Z_]\w*\s*\("),
        ("external_call", r"\b[A-Z][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\.\s*[A-Za-z_]\w*\s*\("),
    ]
    for kind, pattern in patterns:
        for match in re.finditer(pattern, text):
            line = text.count("\n", 0, match.start()) + 1
            target = match.group(1) if match.lastindex else match.group(0).split("(")[0].strip(". ")
            actions.append(
                {
                    "kind": kind,
                    "line": line,
                    "target": target,
                    "text": raw.splitlines()[line - 1].strip() if line <= len(raw.splitlines()) else "",
                }
            )

    actions.sort(key=lambda item: (int(item["line"]), str(item["kind"])))
    return {
        "path": rel,
        "sha256": _sha256(path),
        "actions": actions,
        "lines": len(raw.splitlines()),
    }


def _artifact_contract_map(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in _project_files(root, "out/**/*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        abi = payload.get("abi")
        if not isinstance(abi, list):
            continue
        contract = str(payload.get("contractName") or path.stem)
        result[contract] = {
            "artifact": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
            "abi_functions": [
                {
                    "name": x.get("name"),
                    "inputs": x.get("inputs") or [],
                    "outputs": x.get("outputs") or [],
                    "stateMutability": x.get("stateMutability"),
                }
                for x in abi
                if x.get("type") == "function"
            ],
            "errors": [
                {
                    "name": x.get("name"),
                    "inputs": x.get("inputs") or [],
                }
                for x in abi
                if x.get("type") == "error"
            ],
        }
    return result


def _extract_broadcasts(root: Path, rpc: str | None) -> list[dict[str, Any]]:
    deployments: list[dict[str, Any]] = []
    for path in _project_files(root, "broadcast/**/run-latest.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        txs = payload.get("transactions", []) if isinstance(payload, dict) else []
        if not isinstance(txs, list):
            continue
        for index, tx in enumerate(txs):
            if not isinstance(tx, dict):
                continue
            tx_type = str(tx.get("transactionType") or "").upper()
            address = tx.get("contractAddress") or tx.get("address")
            if not _is_address(address) or not tx_type.startswith("CREATE"):
                continue
            transaction = tx.get("transaction")
            if isinstance(transaction, dict):
                merged = {**transaction, **tx}
            else:
                merged = tx
            code_size = _code_size(rpc, address) if rpc else None
            deployments.append(
                {
                    "contract": str(
                        tx.get("contractName")
                        or tx.get("contract_name")
                        or "Unknown"
                    ),
                    "address": address,
                    "broadcast": path.relative_to(root).as_posix(),
                    "index": index,
                    "tx_hash": tx.get("hash") or tx.get("transactionHash"),
                    "block_number": tx.get("blockNumber"),
                    "args": tx.get("args") or tx.get("arguments") or [],
                    "from": merged.get("from"),
                    "code_size": code_size,
                    "live": code_size is not None and code_size > 0,
                }
            )
    deployments.sort(
        key=lambda x: (
            x.get("broadcast") or "",
            int(x.get("index") or 0),
        )
    )
    return deployments


def _extract_test_and_poc_evidence(root: Path) -> dict[str, Any]:
    tests = []
    adversarial = []
    for path in _project_files(
        root,
        "test/**/*.t.sol",
        "tests/**/*.t.sol",
    ):
        rel = path.relative_to(root).as_posix()
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            continue
        masked = _mask_comments(raw)
        signals: list[str] = []
        if re.search(r"\bfunction\s+(?:test|invariant|echidna_)\w*\s*\(", masked):
            signals.append("test/invariant function")
        if "expectRevert" in masked:
            signals.append("expected revert")
        if "assertEq" in masked or "assertTrue" in masked or "assertFalse" in masked:
            signals.append("assertion")
        if "vm.prank" in masked or "vm.startPrank" in masked:
            signals.append("actor control")
        if "vm.warp" in masked or "vm.roll" in masked:
            signals.append("time/block manipulation")
        if "vm.deal" in masked:
            signals.append("asset funding")
        item = {
            "path": rel,
            "sha256": _sha256(path),
            "kind": "test",
            "signals": signals,
            "functions": re.findall(
                r"\bfunction\s+(test\w*|invariant\w*|echidna_\w*)\s*\(",
                masked,
            ),
        }
        tests.append(item)
        if "Exploit" in path.name or "PoC" in path.name or "poc" in rel.lower():
            adversarial.append({**item, "kind": "adversarial-test"})

    for path in _project_files(
        root,
        "script/**/*PoC*.s.sol",
        "script/**/*Exploit*.s.sol",
        ".audit/poc/*.json",
        ".audit/poc/*.t.sol",
    ):
        rel = path.relative_to(root).as_posix()
        item = {
            "path": rel,
            "sha256": _sha256(path),
            "kind": "adversarial-script",
        }
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    item["summary"] = {
                        "candidate": data.get("candidate"),
                        "evidence": data.get("evidence"),
                        "poc_file": data.get("poc_file"),
                    }
            except (OSError, json.JSONDecodeError):
                pass
        adversarial.append(item)

    evidence = []
    for path in _project_files(root, ".audit/evidence/*.json"):
        name = path.name
        if name in {"manifest.json", "system_bootstrap.json"}:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None
        data = payload.get("data") if isinstance(payload, dict) else None
        summary: dict[str, Any] = {
            "file": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
        }
        if isinstance(data, dict):
            for key in (
                "exit_code",
                "finding_count",
                "count",
                "target",
                "tx",
                "git_sha",
                "git_branch",
            ):
                if key in data:
                    summary[key] = data[key]
        evidence.append(summary)

    dedup_tests = {(x["path"], x["sha256"]): x for x in tests}
    dedup_adv = {(x["path"], x["sha256"]): x for x in adversarial}
    return {
        "tests": list(dedup_tests.values()),
        "adversarial": list(dedup_adv.values()),
        "audit_evidence": evidence,
    }

def _extract_actor_roles(config: dict[str, Any] | None) -> dict[str, Any]:
    config = config or {}
    actors: list[dict[str, Any]] = []
    for key, value in (config.get("aliases") or {}).items():
        if _is_address(value):
            actors.append({"name": str(key), "address": value, "source": "lowkey alias"})
    for key, value in (config.get("wallets") or {}).items():
        if isinstance(value, str) and _is_address(value):
            actors.append({"name": str(key), "address": value, "source": "wallet alias"})
        elif isinstance(value, dict) and _is_address(value.get("address")):
            actors.append({"name": str(key), "address": value["address"], "source": "wallet config"})
    dedupe = {(x["name"], x["address"].lower()): x for x in actors}
    return {"actors": list(dedupe.values())}


def _extract_roles_from_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roles: list[dict[str, Any]] = []
    for source in sources:
        for action in source.get("actions") or []:
            if action["kind"] == "role_grant":
                roles.append(
                    {
                        "kind": "role_grant",
                        "source": source["path"],
                        "line": action["line"],
                        "target": action["target"],
                        "evidence": action["text"],
                    }
                )
            elif action["kind"] == "ownership":
                roles.append(
                    {
                        "kind": "ownership",
                        "source": source["path"],
                        "line": action["line"],
                        "target": action["target"],
                        "evidence": action["text"],
                    }
                )
    return roles


def _constructor_relationships(
    deployments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_address = {
        x["address"].lower(): x["contract"]
        for x in deployments
        if _is_address(x.get("address"))
    }
    edges: list[dict[str, Any]] = []
    for deployment in deployments:
        args = deployment.get("args") or []
        for index, arg in enumerate(args):
            if _is_address(arg) and arg.lower() in by_address:
                edges.append(
                    {
                        "from": deployment["contract"],
                        "to": by_address[arg.lower()],
                        "kind": "constructor-arg",
                        "argument_index": index,
                        "address": arg,
                        "broadcast": deployment["broadcast"],
                    }
                )
    return edges


def _runtime_enrichment(
    deployments: list[dict[str, Any]],
    rpc: str | None,
) -> list[dict[str, Any]]:
    if not rpc:
        return []
    enriched: list[dict[str, Any]] = []
    for item in deployments:
        size = item.get("live")
        enriched.append(
            {
                "address": item["address"],
                "contract": item["contract"],
                "code_size": size,
                "live": size is not None and size > 0,
            }
        )
    return enriched


def manifest_path(root: str | os.PathLike[str]) -> Path:
    return Path(root).resolve() / MANIFEST_RELATIVE


def build_manifest(
    root: str | os.PathLike[str] = ".",
    *,
    rpc: str | None = None,
    config: dict[str, Any] | None = None,
    reason: str = "refresh",
) -> dict[str, Any]:
    root_path = Path(root).resolve()
    sources = [
        _extract_source_signals(path, root_path)
        for path in _project_files(
            root_path,
            "src/**/*.sol",
            "contracts/**/*.sol",
        )
    ]
    scripts = [
        _extract_source_signals(path, root_path)
        for path in _project_files(root_path, "script/**/*.s.sol")
    ]
    deployments = _extract_broadcasts(root_path, rpc)
    artifacts = _artifact_contract_map(root_path)
    evidence = _extract_test_and_poc_evidence(root_path)
    roles = _extract_roles_from_sources(scripts)
    actors = _extract_actor_roles(config)

    initialization: list[dict[str, Any]] = []
    for source in scripts:
        for action in source.get("actions") or []:
            if action["kind"] in {
                "deploy",
                "initialize",
                "ownership",
                "role_grant",
                "funding",
                "approval",
                "permission",
                "configuration",
            }:
                initialization.append(
                    {
                        "source": source["path"],
                        "line": action["line"],
                        "kind": action["kind"],
                        "target": action["target"],
                        "evidence": action["text"],
                    }
                )
    initialization.sort(key=lambda x: (x["source"], int(x["line"])))

    relationships = _constructor_relationships(deployments)

    deployment_names = {x["contract"] for x in deployments}
    known_addresses = {
        x["address"]: x["contract"]
        for x in deployments
        if _is_address(x.get("address"))
    }

    return {
        "schema": "lowkey.system-bootstrap.v1",
        "generated_at": _utc_now(),
        "updated_reason": reason,
        "project": {
            "root": str(root_path),
            "git_sha": _git_value(root_path, ["git", "rev-parse", "HEAD"]),
            "git_branch": _git_value(root_path, ["git", "branch", "--show-current"]),
        },
        "runtime": {
            "rpc": rpc,
            "chain_id": _chain_id(rpc),
        },
        "actors": actors,
        "contracts": sorted(
            [
                {
                    "name": name,
                    "artifact": data["artifact"],
                    "abi_functions": len(data["abi_functions"]),
                    "errors": len(data["errors"]),
                }
                for name, data in artifacts.items()
            ],
            key=lambda x: x["name"],
        ),
        "deployments": deployments,
        "live_runtime": _runtime_enrichment(deployments, rpc),
        "relationships": relationships,
        "roles": roles,
        "initialization": initialization,
        "scripts": scripts,
        "sources": sources,
        "tests": evidence["tests"],
        "adversarial_evidence": evidence["adversarial"],
        "audit_evidence": evidence["audit_evidence"],
        "known_addresses": known_addresses,
        "deployed_contract_names": sorted(deployment_names),
        "confidence": {
            "confirmed": [
                "broadcast deployment entries",
                "source/script evidence",
                "artifact metadata",
                "runtime bytecode checks when RPC is available",
            ],
            "inferred": [
                "constructor relationships from broadcast arguments",
                "role/configuration labels derived from source patterns",
            ],
            "not_verified": [
                "semantic correctness of every initialization step",
                "completeness of deployment scripts",
                "security impact of adversarial evidence",
            ],
        },
    }


def _chain_id(rpc: str | None) -> str | None:
    if not rpc:
        return None
    try:
        value = _rpc(rpc, "eth_chainId", [])
        return str(value)
    except Exception:
        return None


def _git_value(root: Path, command: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            command,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def load_manifest(
    root: str | os.PathLike[str] = ".",
) -> dict[str, Any] | None:
    path = manifest_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def refresh_manifest(
    root: str | os.PathLike[str] = ".",
    *,
    rpc: str | None = None,
    config: dict[str, Any] | None = None,
    reason: str = "refresh",
) -> tuple[dict[str, Any], Path]:
    path = manifest_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(root, rpc=rpc, config=config, reason=reason)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, default=str) + "\n", encoding="utf-8")
    tmp.replace(path)
    return manifest, path


def record_evidence(
    root: str | os.PathLike[str],
    section: str,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], Path]:
    manifest, path = refresh_manifest(root, reason=f"evidence:{section}")
    manifest.setdefault("evidence", {})
    manifest["evidence"][section] = payload
    manifest["generated_at"] = _utc_now()
    path.write_text(json.dumps(manifest, indent=2, default=str) + "\n", encoding="utf-8")
    return manifest, path


def update_runtime_target(
    root: str | os.PathLike[str],
    *,
    address: str,
    contract: str | None = None,
    rpc: str | None = None,
    source: str = "lowkey target",
) -> tuple[dict[str, Any], Path]:
    manifest, path = refresh_manifest(root, rpc=rpc, reason=source)
    targets = manifest.setdefault("targets", [])
    targets.append(
        {
            "address": address,
            "contract": contract,
            "source": source,
            "observed_at": _utc_now(),
        }
    )
    path.write_text(json.dumps(manifest, indent=2, default=str) + "\n", encoding="utf-8")
    return manifest, path


def summarize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": manifest.get("schema"),
        "contracts": len(manifest.get("contracts") or []),
        "deployments": len(manifest.get("deployments") or []),
        "live": sum(1 for x in manifest.get("live_runtime") or [] if x.get("live")),
        "relationships": len(manifest.get("relationships") or []),
        "roles": len(manifest.get("roles") or []),
        "initialization_steps": len(manifest.get("initialization") or []),
        "tests": len(manifest.get("tests") or []),
        "adversarial_evidence": len(manifest.get("adversarial_evidence") or []),
        "updated_reason": manifest.get("updated_reason"),
    }
