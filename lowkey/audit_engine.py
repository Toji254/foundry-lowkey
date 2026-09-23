#!/usr/bin/env python3
"""Lowkey audit evidence, Slither, ripgrep, and PoC-generation helpers."""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

IMPACT_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3, "optimization": 4}


def now_stamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def workspace_root(root: str = ".") -> Path:
    return Path(root).resolve() / ".audit"


def evidence_dir(root: str = ".") -> Path:
    path = workspace_root(root) / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def poc_dir(root: str = ".") -> Path:
    path = workspace_root(root) / "poc"
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def command_path(name: str) -> str | None:
    return shutil.which(name)


def run_command(command: Sequence[str], root: str = ".", timeout: int | None = None) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(Path(root).resolve()),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, "", f"{command[0]} not found on PATH"
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", f"command timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def manifest_path(root: str = ".") -> Path:
    return evidence_dir(root) / "manifest.json"


def record_evidence(kind: str, payload: Any, root: str = ".") -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", kind).strip("._") or "evidence"
    path = evidence_dir(root) / f"{safe}.json"
    write_json(path, {"kind": kind, "recorded_at": now_stamp(), "data": payload})
    manifest = read_json(manifest_path(root), {})
    if not isinstance(manifest, dict):
        manifest = {}
    manifest.setdefault("version", 1)
    manifest.setdefault("records", {})
    manifest["records"][kind] = {
        "file": str(path.relative_to(Path(root).resolve())),
        "recorded_at": now_stamp(),
    }
    write_json(manifest_path(root), manifest)
    return path


def slither_available() -> bool:
    return command_path("slither") is not None


def parse_slither_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results = payload.get("results", {}) if isinstance(payload, dict) else {}
    detectors = results.get("detectors", []) if isinstance(results, dict) else []
    if not isinstance(detectors, list):
        return []
    normalized = []
    for number, detector in enumerate(detectors, 1):
        if not isinstance(detector, dict):
            continue
        locations = []
        for element in detector.get("elements", []) or []:
            if not isinstance(element, dict):
                continue
            source = element.get("source_mapping") or {}
            lines = source.get("lines") if isinstance(source.get("lines"), list) else []
            locations.append(
                {
                    "name": element.get("name"),
                    "type": element.get("type"),
                    "source": source.get("filename_relative") or source.get("filename_absolute"),
                    "start": lines[0] if lines else None,
                    "end": lines[1] if len(lines) > 1 else None,
                }
            )
        normalized.append(
            {
                "id": number,
                "check": detector.get("check") or "unknown",
                "impact": str(detector.get("impact") or "informational").lower(),
                "confidence": str(detector.get("confidence") or "unknown").lower(),
                "description": detector.get("description") or "",
                "locations": locations,
                "raw": detector,
            }
        )
    return normalized


def run_slither(root: str = ".", args: Sequence[str] | None = None) -> int:
    if not slither_available():
        record_evidence("slither", {"available": False, "reason": "slither not found on PATH", "findings": []}, root)
        print("Slither: SKIPPED (not found on PATH).")
        return 127

    extra = list(args or [])
    raw_path = evidence_dir(root) / "slither.raw.json"
    command = ["slither", ".", "--disable-color", "--json", str(raw_path), *extra]
    code, stdout, stderr = run_command(command, root, 600)
    write_text(evidence_dir(root) / "slither.stdout.txt", stdout)
    write_text(evidence_dir(root) / "slither.stderr.txt", stderr)

    payload = read_json(raw_path, {})
    findings = parse_slither_payload(payload)
    summary: dict[str, int] = {}
    for finding in findings:
        summary[finding["impact"]] = summary.get(finding["impact"], 0) + 1

    record_evidence(
        "slither",
        {
            "available": True,
            "command": " ".join(shlex.quote(x) for x in command),
            "exit_code": code,
            "summary": summary,
            "finding_count": len(findings),
            "findings": findings,
        },
        root,
    )

    print("SLITHER")
    print("=" * 52)
    print(f"Exit: {code}")
    print(f"Findings: {len(findings)}")
    for impact in sorted(summary, key=lambda x: IMPACT_ORDER.get(x, 99)):
        print(f"  {impact:<15} {summary[impact]}")
    for finding in findings[:15]:
        location = finding["locations"][0] if finding["locations"] else {}
        suffix = f" @ {location['source']}#{location.get('start') or '?'}" if location.get("source") else ""
        print(f"  [{finding['impact']}/{finding['confidence']}] {finding['check']}{suffix}")
    return code


def rg_available() -> bool:
    return command_path("rg") is not None


def run_rg(pattern: str, path: str = ".", args: Sequence[str] | None = None, root: str = ".") -> int:
    if not rg_available():
        print("rg: not found on PATH")
        return 127
    extra = list(args or [])
    command = ["rg", "--json", "--line-number", *extra, pattern, path]
    code, stdout, stderr = run_command(command, root, 120)
    hits = []
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("type") != "match":
            continue
        data = item.get("data", {})
        hits.append(
            {
                "path": ((data.get("path") or {}).get("text")),
                "line": data.get("line_number"),
                "text": ((data.get("lines") or {}).get("text", "")).rstrip("\n"),
                "submatches": data.get("submatches") or [],
            }
        )
    record_evidence(
        "rg",
        {
            "pattern": pattern,
            "path": path,
            "args": extra,
            "command": " ".join(shlex.quote(x) for x in command),
            "exit_code": code,
            "stderr": stderr,
            "hits": hits,
        },
        root,
    )
    for hit in hits:
        print(f"{hit['path']}:{hit['line']}: {hit['text']}")
    print(f"\nrg matches: {len(hits)}")
    return 0 if code == 1 else code


def _config() -> dict[str, Any]:
    return read_json(Path(os.path.expanduser("~/.lowkey/config.json")), {})


def _load_abi(config: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
    if not target:
        return []
    paths = config.get("abi_paths", {})
    path = paths.get(target) if isinstance(paths, dict) else None
    if not path and isinstance(paths, dict):
        for key, value in paths.items():
            if str(key).lower() == target.lower():
                path = value
                break
    if not path:
        return []
    artifact = read_json(Path(path), {})
    if isinstance(artifact, dict) and isinstance(artifact.get("abi"), list):
        return artifact["abi"]
    return artifact if isinstance(artifact, list) else []


def _abi_functions(abi: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in abi:
        if item.get("type") != "function":
            continue
        name = str(item.get("name") or "")
        types = [str(x.get("type") or "bytes") for x in item.get("inputs", []) if isinstance(x, dict)]
        result.setdefault(name, []).append(f"{name}({','.join(types)})")
    return result


def _matrix(root: str) -> list[dict[str, Any]]:
    payload = read_json(Path(root) / ".audit/matrix/scenarios.json", [])
    return payload if isinstance(payload, list) else []


def _notes(root: str) -> list[str]:
    values = []
    for relative in (".audit/findings.md", ".audit/notes.md", ".audit/TODO.md"):
        text = read_text(Path(root) / relative)
        values.extend(line.strip()[2:] for line in text.splitlines() if line.strip().startswith("- "))
    return values


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", str(value)).strip("_") or "finding"
    return ("F_" + value if value[0].isdigit() else value)[:70]


def _select_finding(findings: list[dict[str, Any]], index: int | None = None) -> dict[str, Any] | None:
    if not findings:
        return None
    if index is not None:
        return findings[index - 1] if 1 <= index <= len(findings) else None
    actionable = [
        item for item in findings
        if str(item.get("impact", "informational")).lower() in {"high", "medium", "low"}
    ]
    pool = actionable or []
    if not pool:
        return None
    return sorted(
        pool,
        key=lambda x: (
            IMPACT_ORDER.get(str(x.get("impact", "informational")).lower(), 99),
            0 if str(x.get("confidence", "unknown")).lower() == "high" else 1,
            -len(x.get("locations", [])),
        ),
    )[0]


def _mode(check: str) -> str:
    c = check.lower().replace("_", "-")
    if "reentrancy" in c:
        return "reentrancy"
    if any(x in c for x in ("arbitrary-send", "controlled-delegatecall")):
        return "external-call"
    if any(x in c for x in ("tx-origin", "suicidal", "selfdestruct", "unprotected-upgrade", "unprotected-setter")):
        return "authorization"
    if any(x in c for x in ("unchecked-lowlevel", "unused-return")):
        return "unchecked-call"
    if any(x in c for x in ("timestamp", "weak-prng", "block-hash")):
        return "time"
    if any(x in c for x in ("encode-packed", "hash-collision")):
        return "encoding"
    return "generic"


def _body(mode: str) -> str:
    bodies = {
        "external-call": '''
    function test_poc_external_call_control() external {
        vm.deal(address(this), 10 ether);
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call{value: 1 ether}(payload);
        // TODO: prove caller-controlled recipient/callee and assert asset/state impact.
        assertTrue(ok, string(data));
    }
''',
        "authorization": '''
    function test_poc_unauthorized() external {
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call(payload);
        vm.stopPrank();
        // TODO: assert the unauthorized state change or privileged effect.
        assertTrue(ok, string(data));
    }
''',
        "unchecked-call": '''
    function test_poc_unchecked_call() external {
        bytes memory payload = hex"";
        (bool ok, ) = TARGET.call(payload);
        // TODO: force the underlying external call to fail and assert bad post-state.
        emit EvidenceBool("outerCallSucceeded", ok);
    }
''',
        "time": '''
    function test_poc_time_dependency() external {
        vm.warp(block.timestamp + 1 days);
        vm.roll(block.number + 1);
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call(payload);
        // TODO: assert the outcome changed because attacker-controllable block fields changed.
        assertTrue(ok, string(data));
    }
''',
        "encoding": '''
    function test_poc_encoding_collision() external {
        bytes memory a = hex"";
        bytes memory b = hex"";
        // TODO: replace with two distinct logical inputs that hash identically.
        assertEq(keccak256(a), keccak256(b));
    }
''',
    }
    return bodies.get(mode, '''
    function test_poc_candidate() external {
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call(payload);
        assertTrue(ok, string(data));
        // TODO: assert the violated invariant, unauthorized effect, or asset delta.
    }
''')


def run_source_triage(root: str = ".") -> int:
    patterns = [
        ("REENTRANCY/LOW-LEVEL CALL", re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()")),
        ("TX.ORIGIN", re.compile(r"\btx\.origin\b")),
        ("DELEGATECALL", re.compile(r"\bdelegatecall\b")),
        ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
        ("UNCHECKED", re.compile(r"\bunchecked\s*\{")),
        ("ASSEMBLY", re.compile(r"\bassembly\s*\{")),
        ("ENCODE_PACKED", re.compile(r"\babi\.encodePacked\s*\(")),
        ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
        ("BLOCKHASH/PREVRANDAO", re.compile(r"\bblock\.hash\s*(?:\(|$)|\bblockhash\s*\(|\bblock\.prevrandao\b")),
        ("ECRECOVER", re.compile(r"\becrecover\s*\(")),
    ]
    root_path = Path(root).resolve()
    base = root_path / "src" if (root_path / "src").is_dir() else root_path
    markers = []
    for path in sorted(base.rglob("*.sol")):
        if any(part in {".git", "out", "cache", "lib", ".audit"} for part in path.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for label, pattern in patterns:
                if pattern.search(line):
                    markers.append({
                        "file": str(path.relative_to(root_path)),
                        "line": number,
                        "label": label,
                        "text": line.strip(),
                    })
    record_evidence("source_triage", {"count": len(markers), "markers": markers}, root)
    print("SOURCE TRIAGE")
    print("=" * 52)
    for item in markers:
        print(f"{item['file']}:{item['line']}: [{item['label']}] {item['text']}")
    print(f"\nReview markers: {len(markers)}")
    return 0


def generate_poc(root: str = ".", finding_index: int | None = None, name: str | None = None) -> tuple[int, list[Path]]:
    evidence = read_json(evidence_dir(root) / "slither.json", {}).get("data", {})
    findings = evidence.get("findings", []) if isinstance(evidence, dict) else []
    findings = findings if isinstance(findings, list) else []
    selected = _select_finding(findings, finding_index)
    matrix = _matrix(root)
    triage_payload = read_json(evidence_dir(root) / "source_triage.json", {}).get("data", {})
    triage_markers = triage_payload.get("markers", []) if isinstance(triage_payload, dict) else []
    trace_payload = read_json(evidence_dir(root) / "trace.json", {}).get("data", {})
    storage_payload = read_json(evidence_dir(root) / "storage_diff.json", {}).get("data", {})
    risk_payload = read_json(evidence_dir(root) / "risk.json", {}).get("data", {})
    evidence_records = sorted(
        p.stem for p in evidence_dir(root).glob("*.json") if p.name != "manifest.json"
    )
    config = _config()
    target = config.get("target")
    abi_map = _abi_functions(_load_abi(config, target))

    if selected:
        check = str(selected.get("check") or "candidate")
        impact = str(selected.get("impact") or "informational")
        confidence = str(selected.get("confidence") or "unknown")
        description = str(selected.get("description") or "").replace("\n", " ")
        locations = selected.get("locations", [])
        mode = _mode(check)
        function = None
        for location in locations:
            candidate = str(location.get("name") or "")
            base = candidate.split("(", 1)[0]
            if candidate in abi_map:
                function = abi_map[candidate][0]
                break
            if base in abi_map:
                function = abi_map[base][0]
                break
    elif matrix:
        scenario = matrix[0]
        check = "manual-matrix-scenario"
        impact = confidence = "manual"
        description = str(scenario.get("expected") or scenario.get("name") or "Manual scenario")
        locations = []
        mode = "generic"
        function = scenario.get("function")
    elif triage_markers:
        marker = triage_markers[0]
        check = "source-marker-" + str(marker.get("label") or "candidate").lower().replace(" ", "-")
        impact = confidence = "manual"
        description = str(marker.get("text") or "Manual source review marker")
        locations = [marker]
        mode = "generic"
        function = None
    else:
        check = "audit-candidate"
        impact = confidence = "manual"
        description = "No selected Slither finding, matrix scenario, or source marker."
        locations = []
        mode = "generic"
        function = None

    slug = _slug(name or check)
    target_expr = target if re.fullmatch(r"0x[0-9a-fA-F]{40}", str(target or "")) else "address(0)"
    attacker = ""
    attacker_member = ""
    constructor = ""
    reentrancy_body = ""

    if mode == "reentrancy":
        attacker = '''
contract PocAttacker {
    address immutable target;
    bytes public callbackPayload;
    bool public entered;

    constructor(address target_) {
        target = target_;
    }

    receive() external payable {
        if (!entered) {
            entered = true;
            (bool ok, ) = target.call(callbackPayload);
            require(ok, "callback failed");
        }
    }

    function attack(bytes calldata entryPayload, uint256 value) external {
        callbackPayload = entryPayload;
        (bool ok, ) = target.call{value: value}(entryPayload);
        require(ok, "entry call failed");
    }
}
'''
        attacker_member = "PocAttacker internal attacker;"
        constructor = "constructor() { attacker = new PocAttacker(TARGET); }"
        reentrancy_body = '''
    function test_poc_reentrancy() external {
        bytes memory entryCall = hex"";
        vm.deal(address(attacker), 10 ether);
        attacker.attack(entryCall, 1 ether);
        // TODO: assert the broken invariant or unexpected balance delta.
    }
'''

    solidity = f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

{attacker}
contract Poc_{slug} is Test {{
    address internal constant TARGET = {target_expr};
    event EvidenceBool(string name, bool value);
    {attacker_member}

    // Candidate detector: {check} ({impact}/{confidence})
    // Candidate function: {function or "<identify-function(signature)>"}
    // Finding summary: {description[:700]}
    // Evidence records captured: {", ".join(evidence_records) or "none"}
    // Prior trace tx: {trace_payload.get("tx") if isinstance(trace_payload, dict) else "none"}
    // Prior storage changes: {len(storage_payload.get("changes", [])) if isinstance(storage_payload, dict) else 0}
    // Risk rows captured: {len(risk_payload.get("functions", [])) if isinstance(risk_payload, dict) else 0}

    {constructor}
{reentrancy_body if mode == "reentrancy" else _body(mode)}
}}
'''
    out = poc_dir(root)
    test_dir = Path(root) / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    sol_path = test_dir / f"Poc_{slug}.t.sol"
    write_text(sol_path, solidity)

    brief = {
        "generated_at": now_stamp(),
        "target": target,
        "candidate": {
            "check": check,
            "mode": mode,
            "impact": impact,
            "confidence": confidence,
            "function": function,
            "description": description,
            "locations": locations,
        },
        "evidence": {
            "slither_findings": len(findings),
            "source_triage_markers": len(triage_markers),
            "matrix_scenarios": len(matrix),
            "notes_findings_todos": _notes(root),
            "evidence_records": evidence_records,
            "trace_tx": trace_payload.get("tx") if isinstance(trace_payload, dict) else None,
            "storage_changes": len(storage_payload.get("changes", [])) if isinstance(storage_payload, dict) else 0,
            "risk_functions": len(risk_payload.get("functions", [])) if isinstance(risk_payload, dict) else 0,
            "last_tx": config.get("last_tx"),
            "rpc": config.get("rpc"),
        },
        "poc_file": os.path.relpath(sol_path.resolve(), Path(root).resolve()),
        "refinement_checklist": [
            "Resolve exact function/signature and calldata.",
            "Set attacker identities, balances, and pre-state.",
            "Write down the security invariant before the exploit call.",
            "Execute the smallest reproducing sequence.",
            "Assert concrete post-state corruption or asset impact.",
            "Use trace/storage/log evidence where it strengthens proof.",
            "Minimize the final PoC and link it back to the finding.",
        ],
    }
    json_path = out / f"Poc_{slug}.json"
    write_json(json_path, brief)
    record_evidence("poc", brief, root)

    print("POC SCAFFOLD")
    print("=" * 52)
    print(f"Candidate: {check} ({impact}/{confidence})")
    print(f"Mode:      {mode}")
    print(f"Function:  {function or 'not resolved'}")
    print(f"Target:    {target or 'not configured'}")
    print(f"Generated: {sol_path}")
    print(f"Generated: {json_path}")
    print("\nEvidence-backed scaffold; manual proof is still required.")
    return 0, [sol_path, json_path]


def run_audit_pipeline(root: str = ".", slither_args: Sequence[str] | None = None, generate: bool = False) -> int:
    workspace_root(root).mkdir(parents=True, exist_ok=True)
    results = []
    git_code, git_sha, _ = run_command(["git", "rev-parse", "HEAD"], root)
    branch_code, branch, _ = run_command(["git", "branch", "--show-current"], root)
    config = _config()
    record_evidence("context", {
        "target": config.get("target"),
        "rpc": config.get("rpc"),
        "git_sha": git_sha.strip() if git_code == 0 else None,
        "git_branch": branch.strip() if branch_code == 0 else None,
        "started_at": now_stamp(),
    }, root)
    for label, command, timeout in (
        ("build", ["forge", "build"], 300),
        ("tests", ["forge", "test", "-vvvv"], 600),
        ("coverage", ["forge", "coverage"], 600),
    ):
        print(f"\n=== LOWKEY EVIDENCE: {label.upper()} ===")
        code, stdout, stderr = run_command(command, root, timeout)
        write_text(evidence_dir(root) / f"{label}.stdout.txt", stdout)
        write_text(evidence_dir(root) / f"{label}.stderr.txt", stderr)
        record_evidence(label, {
            "command": command,
            "exit_code": code,
            "stdout": stdout[-50000:],
            "stderr": stderr[-20000:],
        }, root)
        print(stdout.rstrip())
        if stderr:
            print(stderr.rstrip())
        results.append({"label": label, "code": code})
        if code != 0:
            return code

    slither_code = run_slither(root, slither_args)
    results.append({"label": "slither", "code": slither_code})
    triage_code = run_source_triage(root)
    results.append({"label": "source_triage", "code": triage_code})

    forge = command_path("forge")
    for optional in ("lint", "geiger"):
        if forge:
            help_code, _, _ = run_command(["forge", optional, "--help"], root)
            if help_code == 0:
                print(f"\n=== LOWKEY EVIDENCE: {optional.upper()} ===")
                code, stdout, stderr = run_command(["forge", optional], root, 600)
                write_text(evidence_dir(root) / f"{optional}.stdout.txt", stdout)
                write_text(evidence_dir(root) / f"{optional}.stderr.txt", stderr)
                record_evidence(optional, {
                    "command": ["forge", optional],
                    "exit_code": code,
                    "stdout": stdout[-50000:],
                    "stderr": stderr[-20000:],
                }, root)
                results.append({"label": optional, "code": code})
    manifest = read_json(manifest_path(root), {})
    manifest["pipeline"] = {"completed_at": now_stamp(), "steps": results}
    write_json(manifest_path(root), manifest)

    if generate:
        generate_poc(root)

    return 0
