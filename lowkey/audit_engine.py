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

try:
    from project_tools import (
        build_dependency_graph,
        detect_project,
        project_source_files,
    )
except ImportError:  # pragma: no cover - supports direct/embedded installs
    build_dependency_graph = detect_project = project_source_files = None

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


def run_command(
    command: Sequence[str],
    root: str = ".",
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    try:
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        completed = subprocess.run(
            list(command),
            cwd=str(Path(root).resolve()),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=process_env,
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


def run_slither_project(
    root: str = ".",
    project: dict[str, Any] | None = None,
    args: Sequence[str] | None = None,
) -> int:
    if not slither_available():
        record_evidence(
            "slither",
            {
                "available": False,
                "reason": "slither not found on PATH",
                "findings": [],
            },
            root,
        )
        print("Slither: SKIPPED (not found on PATH).")
        return 127

    root_path = Path(root).resolve()
    files = project_source_files(root_path, {"sol"}) if project_source_files else []
    production = [
        path for path in files
        if not any(part.lower() in {"test", "tests", "script", "scripts"} for part in path.relative_to(root_path).parts)
    ]
    targets = production or files
    if not targets:
        record_evidence(
            "slither",
            {
                "available": True,
                "status": "not_applicable",
                "reason": "No Solidity source files available for Slither.",
                "findings": [],
            },
            root,
        )
        print("Slither: SKIPPED (no Solidity sources available).")
        return 0

    extra = list(args or [])
    remaps: list[str] = []
    if (root_path / "node_modules" / "solidity-rlp").is_dir():
        remaps.append(
            "hamdiallam/Solidity-RLP@2.0.7=node_modules/solidity-rlp"
        )
    if (root_path / "lib" / "solidity-rlp").is_dir():
        remaps.append(
            "hamdiallam/Solidity-RLP@2.0.7=lib/solidity-rlp"
        )

    compilers = (project or {}).get("solidity_compilers", [])
    env = _project_solc_env(root, project)

    aggregate_findings: list[dict[str, Any]] = []
    file_runs: list[dict[str, Any]] = []
    final_code = 0

    print("SLITHER")
    print("=" * 52)
    for index, path in enumerate(targets, 1):
        relative = str(path.relative_to(root_path))
        raw_path = evidence_dir(root) / f"slither_{index}.raw.json"
        command = [
            "slither",
            relative,
            "--disable-color",
            "--json",
            str(raw_path),
        ]
        if remaps:
            command.extend(["--solc-remaps", " ".join(remaps)])
        command.extend(extra)

        code, stdout, stderr = run_command(command, root, 600, env=env)
        payload = read_json(raw_path, {})
        findings = parse_slither_payload(payload)
        for finding in findings:
            finding["target"] = relative
        aggregate_findings.extend(findings)
        file_runs.append({
            "target": relative,
            "command": command,
            "exit_code": code,
            "finding_count": len(findings),
        })
        if code != 0:
            final_code = code

        write_text(evidence_dir(root) / f"slither_{index}.stdout.txt", stdout)
        write_text(evidence_dir(root) / f"slither_{index}.stderr.txt", stderr)
        print(f"{relative}: exit {code}, findings {len(findings)}")

    summary: dict[str, int] = {}
    for finding in aggregate_findings:
        impact = finding["impact"]
        summary[impact] = summary.get(impact, 0) + 1

    record_evidence(
        "slither",
        {
            "available": True,
            "mode": "direct-solidity-files",
            "targets": [str(path.relative_to(root_path)) for path in targets],
            "solidity_compilers": compilers,
            "remappings": remaps,
            "runs": file_runs,
            "summary": summary,
            "finding_count": len(aggregate_findings),
            "findings": aggregate_findings,
            "exit_code": final_code,
        },
        root,
    )

    print(f"Findings: {len(aggregate_findings)}")
    for impact in sorted(summary, key=lambda item: IMPACT_ORDER.get(item, 99)):
        print(f"  {impact:<15} {summary[impact]}")
    return final_code


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
        vm.skip(true); // REMOVE after filling the proven exploit path.
        vm.deal(address(this), 10 ether);
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call{value: 1 ether}(payload);
        // TODO: prove caller-controlled recipient/callee and assert asset/state impact.
        assertTrue(ok, string(data));
    }
''',
        "authorization": '''
    function test_poc_unauthorized() external {
        vm.skip(true); // REMOVE after filling the proven exploit path.
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
        vm.skip(true); // REMOVE after filling the proven exploit path.
        bytes memory payload = hex"";
        (bool ok, ) = TARGET.call(payload);
        // TODO: force the underlying external call to fail and assert bad post-state.
        emit EvidenceBool("outerCallSucceeded", ok);
    }
''',
        "time": '''
    function test_poc_time_dependency() external {
        vm.skip(true); // REMOVE after filling the proven exploit path.
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
        vm.skip(true); // REMOVE after filling the proven exploit path.
        bytes memory a = hex"";
        bytes memory b = hex"";
        // TODO: replace with two distinct logical inputs that hash identically.
        assertEq(keccak256(a), keccak256(b));
    }
''',
    }
    return bodies.get(mode, '''
    function test_poc_candidate() external {
        vm.skip(true); // REMOVE after filling the proven exploit path.
        bytes memory payload = hex"";
        (bool ok, bytes memory data) = TARGET.call(payload);
        assertTrue(ok, string(data));
        // TODO: assert the violated invariant, unauthorized effect, or asset delta.
    }
''')


def run_source_triage(root: str = ".") -> int:
    """Run language-aware source heuristics without assuming a src/ tree."""
    root_path = Path(root).resolve()
    project = detect_project(root) if detect_project else {"kind": "generic", "languages": []}
    files = project_source_files(root_path) if project_source_files else list(root_path.rglob("*.sol"))

    solidity_patterns = [
        ("REENTRANCY REVIEW", re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()")),
        ("ETH TRANSFER REVIEW", re.compile(r"\.(transfer|send)\s*\(")),
        ("TX.ORIGIN", re.compile(r"\btx\.origin\b")),
        ("DELEGATECALL", re.compile(r"\bdelegatecall\b")),
        ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
        ("UNCHECKED", re.compile(r"\bunchecked\s*\{")),
        ("ASSEMBLY", re.compile(r"\bassembly\s*\{")),
        ("ENCODE_PACKED", re.compile(r"\babi\.encodePacked\s*\(")),
        ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
        ("BLOCKHASH/PREVRANDAO", re.compile(r"\bblock\.hash\b|\bblockhash\s*\(|\bblock\.prevrandao\b")),
        ("ECRECOVER", re.compile(r"\becrecover\s*\(")),
        ("CREATE2", re.compile(r"\bcreate2\b")),
    ]
    vyper_patterns = [
        ("RAW_CALL", re.compile(r"\braw_call\s*\(")),
        ("EXTERNAL_CALL", re.compile(r"\b(?:extcall|staticcall)\b")),
        ("ETH TRANSFER", re.compile(r"\bsend\s*\(")),
        ("CREATE", re.compile(r"\bcreate_(?:minimal_proxy_to|forwarder_to|from_blueprint)\b")),
        ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
        ("TX.ORIGIN", re.compile(r"\btx\.origin\b")),
        ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
        ("BLOCK NUMBER", re.compile(r"\bblock\.number\b")),
        ("PREV HASH", re.compile(r"\bblock\.prevhash\b")),
        ("RAW LOG", re.compile(r"\braw_log\s*\(")),
    ]

    markers = []
    for path in files:
        suffix = path.suffix.lower()
        if suffix not in {".sol", ".vy", ".vyi"}:
            continue
        language = "solidity" if suffix == ".sol" else "vyper"
        patterns = solidity_patterns if language == "solidity" else vyper_patterns
        text = read_text(path)
        if not text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in patterns:
                if pattern.search(line):
                    markers.append({
                        "file": str(path.resolve().relative_to(root_path)),
                        "line": number,
                        "language": language,
                        "label": label,
                        "text": line.strip(),
                    })

    record_evidence(
        "source_triage",
        {
            "project": project.get("kind"),
            "languages": project.get("languages", []),
            "files_scanned": len(files),
            "count": len(markers),
            "markers": markers,
        },
        root,
    )
    print("SOURCE TRIAGE")
    print("=" * 72)
    print(f"Project : {project.get('kind', 'generic')}")
    print(f"Files   : {len(files)}")
    for item in markers:
        print(
            f"{item['file']}:{item['line']}: "
            f"[{item['language']}:{item['label']}] {item['text']}"
        )
    print(f"\nReview markers: {len(markers)}")
    print("These are source-level review markers, not vulnerability verdicts.")
    return 0

def _generate_vyper_poc(root: str, check: str, impact: str, confidence: str,
                       description: str, locations: list[dict[str, Any]],
                       function: str | None, name: str | None) -> tuple[int, list[Path]]:
    slug = _slug(name or check)
    project_root = Path(root).resolve()
    tests_dir = project_root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    test_path = tests_dir / f"poc_{slug}.py"

    location_text = "\n".join(
        f"#   {item.get('source') or item.get('file') or 'unknown'}:"
        f"{item.get('start') or item.get('line') or '?'}"
        for item in locations[:8]
    )
    test_body = f'''"""Lowkey evidence-backed Vyper PoC scaffold.

Candidate: {check}
Impact/confidence: {impact}/{confidence}
Function: {function or "identify the exact function/interface"}
Description: {description[:700]}
{location_text}
"""

import pytest


def test_poc_candidate():
    # This scaffold is intentionally non-asserting until the exploit path is proven.
    pytest.skip("TODO: replace with a concrete Vyper/Titanoboa reproduction")

    # Suggested structure:
    # 1. Deploy/load the vulnerable Vyper contract using the project's native test harness.
    # 2. Establish attacker and trusted/protocol state.
    # 3. Execute the smallest attacker-controlled sequence.
    # 4. Assert a concrete invariant violation or asset/state delta.
    # 5. Preserve trace/log/state evidence in .audit/evidence/.
'''
    write_text(test_path, test_body)

    brief = {
        "generated_at": now_stamp(),
        "project_type": "vyper",
        "target": _config().get("target"),
        "candidate": {
            "check": check,
            "impact": impact,
            "confidence": confidence,
            "function": function,
            "description": description,
            "locations": locations,
        },
        "poc_file": os.path.relpath(test_path, project_root),
        "refinement_checklist": [
            "Identify the exact Vyper entry point/interface.",
            "Load the project contract with its native test framework.",
            "Establish attacker/trusted protocol state.",
            "Prove the broken invariant before asserting impact.",
            "Use traces, logs, and state deltas as supporting evidence.",
        ],
    }
    json_path = poc_dir(root) / f"Poc_{slug}.json"
    write_json(json_path, brief)
    record_evidence("poc", brief, root)

    print("POC SCAFFOLD")
    print("=" * 52)
    print(f"Candidate: {check} ({impact}/{confidence})")
    print(f"Function:  {function or 'not resolved'}")
    print(f"Generated: {test_path}")
    print(f"Generated: {json_path}")
    print("\nVyper/Titanoboa scaffold; manual proof is still required.")
    return 0, [test_path, json_path]


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
    project = detect_project(root) if detect_project else {"kind": "generic"}
    target = config.get("target")
    abi_map = _abi_functions(_load_abi(config, target))

    if project.get("kind") in {"vyper", "vyper-uv"}:
        if selected:
            vy_check = str(selected.get("check") or "candidate")
            vy_impact = str(selected.get("impact") or "informational")
            vy_confidence = str(selected.get("confidence") or "unknown")
            vy_description = str(selected.get("description") or "").replace("\n", " ")
            vy_locations = selected.get("locations", []) if isinstance(selected.get("locations"), list) else []
            vy_function = None
            for location in vy_locations:
                candidate = str(location.get("name") or "")
                base = candidate.split("(", 1)[0]
                if candidate in abi_map:
                    vy_function = abi_map[candidate][0]
                    break
                if base in abi_map:
                    vy_function = abi_map[base][0]
                    break
        elif matrix:
            scenario = matrix[0]
            vy_check = "manual-matrix-scenario"
            vy_impact = vy_confidence = "manual"
            vy_description = str(scenario.get("expected") or scenario.get("name") or "Manual scenario")
            vy_locations = []
            vy_function = scenario.get("function")
        elif triage_markers:
            marker = triage_markers[0]
            vy_check = "source-marker-" + str(marker.get("label") or "candidate").lower().replace(" ", "-")
            vy_impact = vy_confidence = "manual"
            vy_description = str(marker.get("text") or "Manual source review marker")
            vy_locations = [marker]
            vy_function = None
        else:
            vy_check = "audit-candidate"
            vy_impact = vy_confidence = "manual"
            vy_description = "No selected detector or manual scenario; inspect the Vyper source graph and state transitions."
            vy_locations = []
            vy_function = None
        return _generate_vyper_poc(
            root, vy_check, vy_impact, vy_confidence,
            vy_description, vy_locations, vy_function, name
        )

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
        vm.skip(true); // REMOVE after filling the proven exploit path.
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


def _evidence_data(root: str, name: str) -> dict[str, Any]:
    payload = read_json(evidence_dir(root) / f"{name}.json", {})
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    return data if isinstance(data, dict) else {}


def _format_step_status(root: str, name: str, detail: str = "") -> tuple[str, str]:
    data = _evidence_data(root, name)
    if not data:
        return "NOT RUN", detail or "no evidence recorded"
    explicit = str(data.get("status") or "").lower()
    if explicit in {"not_applicable", "not-applicable"}:
        return "N/A", detail or str(data.get("reason") or "not applicable to project")
    if explicit in {"skipped", "skip"}:
        return "SKIPPED", detail or str(data.get("reason") or "skipped")
    code = data.get("exit_code")
    if code == 0:
        status = "PASS"
    elif code == 127:
        status = "SKIPPED"
    elif isinstance(code, int):
        status = "FAIL"
    else:
        status = "REVIEW"
    return status, detail or str(data.get("reason") or "completed")

def _fit_cell(value: Any, width: int) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."


def _dashboard_row(columns: Sequence[Any], widths: Sequence[int]) -> None:
    print("| " + " | ".join(_fit_cell(value, width).ljust(width) for value, width in zip(columns, widths)) + " |")


def render_audit_dashboard(root: str = ".", pipeline_code: int | None = None) -> int:
    """Render a project-aware summary from the evidence workspace."""
    config = _config()
    manifest = read_json(manifest_path(root), {})
    context = _evidence_data(root, "context")
    project = context.get("project", {}) if isinstance(context.get("project"), dict) else {}
    kind = str(project.get("kind") or "generic")

    if "foundry" in kind:
        build_label, test_label = "Forge build", "Forge tests"
    elif "vyper" in kind:
        build_label, test_label = "Vyper build", "Vyper tests"
    else:
        build_label, test_label = "Build", "Tests"

    rows: list[tuple[str, str, str]] = []
    for name, label in (("build", build_label), ("tests", test_label), ("coverage", "Coverage")):
        status, detail = _format_step_status(root, name)
        data = _evidence_data(root, name)
        stdout = str(data.get("stdout", ""))
        if name == "tests":
            for pattern in (r"(\d+)\s+passed", r"Tests:\s*(\d+)\s*passed"):
                match = re.search(pattern, stdout)
                if match:
                    detail = f"{match.group(1)} tests passed"
                    break
        elif name == "coverage":
            for pattern in (r"\bTotal coverage:\s*([^\n]+)", r"\bLines:\s*([^\n]+)"):
                match = re.search(pattern, stdout)
                if match:
                    detail = match.group(1).strip()
                    break
        rows.append((label, status, detail))

    slither = _evidence_data(root, "slither")
    if not slither:
        rows.append(("Slither", "NOT RUN", "no evidence recorded"))
    elif not slither.get("available", True):
        rows.append(("Slither", "SKIPPED", str(slither.get("reason") or "not available")))
    else:
        code = slither.get("exit_code")
        status = "PASS" if code == 0 else "FAIL"
        summary = slither.get("summary", {}) or {}
        findings = slither.get("finding_count", 0)
        detail = f"{findings} findings"
        if summary:
            detail += " | " + ", ".join(
                f"{key}: {value}"
                for key, value in sorted(summary.items(), key=lambda item: IMPACT_ORDER.get(item[0], 99))
            )
        rows.append(("Slither", status, detail))

    triage = _evidence_data(root, "source_triage")
    rows.append((
        "Source triage",
        "PASS" if triage else "NOT RUN",
        f"{triage.get('count', 0)} review markers" if triage else "no evidence recorded",
    ))

    graph = _evidence_data(root, "dependency_graph")
    if graph:
        summary = graph.get("summary", {})
        rows.append((
            "System graph",
            "PASS",
            f"{summary.get('files', 0)} files | {summary.get('imports', 0)} imports | "
            f"{summary.get('unresolved_imports', 0)} unresolved",
        ))

    for name in ("lint", "geiger"):
        if (evidence_dir(root) / f"{name}.json").exists():
            status, detail = _format_step_status(root, name)
            rows.append((f"Forge {name}", status, detail))

    poc_count = (
        len(list(poc_dir(root).glob("*.json")))
        + len(list(poc_dir(root).glob("*.t.sol")))
        + len(list(Path(root).glob("tests/poc_*.py")))
    )
    rows.append(("PoC scaffold", "READY" if poc_count else "NOT RUN", f"{poc_count} artifact(s)" if poc_count else "none generated"))

    target = config.get("target") or context.get("target") or "not configured"
    rpc = config.get("rpc") or context.get("rpc") or "not configured"
    git_sha = context.get("git_sha") or "unknown"
    git_branch = context.get("git_branch") or "unknown"

    mandatory = []
    for name in ("build", "tests", "coverage"):
        data = _evidence_data(root, name)
        if str(data.get("status") or "").lower() in {"not_applicable", "not-applicable"}:
            continue
        mandatory.append(data.get("exit_code"))
    mandatory_pass = bool(mandatory) and all(code == 0 for code in mandatory)
    overall = "PASS" if mandatory_pass and pipeline_code in (None, 0) else "REVIEW NEEDED"

    print("\n=== LOWKEY AUDIT DASHBOARD ===")
    print("=" * 96)
    print(f"Project: {kind}")
    print(f"Target : {target}")
    print(f"RPC    : {rpc}")
    print(f"Git    : {git_branch} @ {git_sha}")
    print(f"Overall: {overall}")
    print("\n+------------------+------------+------------------------------------------------+")
    _dashboard_row(("Step", "Status", "Details"), (16, 10, 46))
    print("+------------------+------------+------------------------------------------------+")
    for row in rows:
        _dashboard_row(row, (16, 10, 46))
    print("+------------------+------------+------------------------------------------------+")
    pipeline = manifest.get("pipeline", {}) if isinstance(manifest, dict) else {}
    if isinstance(pipeline, dict) and pipeline.get("completed_at"):
        print(f"Evidence: .audit/evidence/ | completed: {pipeline['completed_at']}")
    else:
        print("Evidence: .audit/evidence/ | pipeline not finalized")
    print("Heuristic findings are review leads, not vulnerability verdicts.")
    return 0 if overall == "PASS" else 1

def _finalize_pipeline(root: str, results: list[dict[str, Any]], code: int, generate: bool) -> int:
    manifest = read_json(manifest_path(root), {})
    manifest["pipeline"] = {
        "completed_at": now_stamp(),
        "status": "pass" if code == 0 else "failed",
        "steps": results,
    }
    write_json(manifest_path(root), manifest)
    if generate:
        generate_poc(root)
    render_audit_dashboard(root, pipeline_code=code)
    return code


def _write_step_evidence(root: str, label: str, command: Sequence[str], code: int,
                        stdout: str, stderr: str, *, status: str | None = None,
                        reason: str | None = None) -> None:
    payload: dict[str, Any] = {
        "command": list(command),
        "exit_code": code,
        "stdout": stdout[-50000:],
        "stderr": stderr[-20000:],
    }
    if status:
        payload["status"] = status
    if reason:
        payload["reason"] = reason
    write_text(evidence_dir(root) / f"{label}.stdout.txt", stdout)
    write_text(evidence_dir(root) / f"{label}.stderr.txt", stderr)
    record_evidence(label, payload, root)


def _run_vyper_build(root: str) -> tuple[int, str, str, list[dict[str, Any]]]:
    project_root = Path(root).resolve()
    candidates = (
        project_source_files(project_root, {"vy"})
        if project_source_files
        else list(project_root.rglob("*.vy"))
    )
    files = []
    for path in candidates:
        relative_parts = {part.lower() for part in path.relative_to(project_root).parts}
        if relative_parts & {"test", "tests", "mocks"}:
            continue
        files.append(path)
    files = sorted(files)

    if not files:
        return 0, "No production Vyper .vy files found; source inventory completed.\n", "", []

    all_stdout: list[str] = []
    all_stderr: list[str] = []
    records: list[dict[str, Any]] = []
    overall = 0

    for path in files:
        rel = path.relative_to(project_root)
        command = ["uv", "run", "vyper", str(rel), "-p", "."]
        code, stdout, stderr = run_command(command, root, 300)
        all_stdout.append(f"$ {' '.join(command)}\n{stdout}")
        all_stderr.append(f"$ {' '.join(command)}\n{stderr}")
        records.append({"file": str(rel), "command": command, "exit_code": code})
        if code != 0 and overall == 0:
            overall = code

    return overall, "\n".join(all_stdout), "\n".join(all_stderr), records


def _project_solc_env(root: str, project: dict[str, Any] | None = None) -> dict[str, str]:
    env: dict[str, str] = {}
    compilers = (project or {}).get("solidity_compilers", [])
    if len(compilers) == 1:
        env["SOLC_VERSION"] = str(compilers[0])

    toolchain_bin = Path(root).resolve() / ".audit" / "toolchain" / "bin"
    solc_binary = toolchain_bin / "solc"
    if solc_binary.exists():
        current_path = os.environ.get("PATH", "")
        env["PATH"] = (
            f"{toolchain_bin}{os.pathsep}{current_path}"
            if current_path
            else str(toolchain_bin)
        )
    return env


def _run_project_vyper_tests(
    root: str,
    project: dict[str, Any] | None = None,
) -> tuple[int, str, str]:
    return run_command(
        ["uv", "run", "pytest", "."],
        root,
        900,
        env=_project_solc_env(root, project),
    )


def _git_worktree_has_files(path: Path) -> bool:
    if not path.is_dir():
        return False
    try:
        return any(item.name != ".git" for item in path.iterdir())
    except OSError:
        return False


def _git_submodule_is_tracked(root: str, relative: str) -> bool:
    code, stdout, _ = run_command(
        ["git", "ls-tree", "HEAD", "--", relative],
        root,
        60,
    )
    if code != 0:
        return False
    return any(
        line.split(None, 1)[0] == "160000"
        for line in stdout.splitlines()
        if line.strip() and line.split(None, 1)
    )


def _clone_declared_git_dependency(
    root: str,
    relative: str,
    url: str,
) -> tuple[int, str, str]:
    root_path = Path(root).resolve()
    target = root_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists() and _git_worktree_has_files(target):
        code, _, _ = run_command(
            ["git", "-C", str(target), "rev-parse", "--is-inside-work-tree"],
            root,
            60,
        )
        if code == 0:
            return 0, "", "already initialized"
        return (
            1,
            "",
            f"declared dependency path is non-empty but is not a Git worktree: {relative}",
        )

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--recurse-submodules",
        url,
        str(target),
    ]
    return run_command(command, root, 900)


def _project_prepare(root: str, project: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    root_path = Path(root).resolve()

    submodules = project.get("submodules", []) if isinstance(project, dict) else []
    if submodules and command_path("git"):
        need_submodules = any(not item.get("initialized") for item in submodules)
        if need_submodules:
            print("\n=== LOWKEY EVIDENCE: GIT SUBMODULES ===")
            command = ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"]
            code, stdout, stderr = run_command(command, root, 900)
            _write_step_evidence(
                root, "git_submodules", command, code, stdout, stderr,
                reason="Initialize repository-declared Git submodules before analysis.",
            )
            print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip())
            results.append({"label": "git_submodules", "code": code})

        # Some repositories ship .gitmodules as a dependency manifest but do
        # not commit the corresponding gitlink entries. Git then has nothing
        # to materialize, so clone the declared dependency directly at its
        # documented path.
        refreshed = detect_project(root) if detect_project else project
        remaining = [
            item for item in refreshed.get("submodules", [])
            if not item.get("initialized")
        ]
        for item in remaining:
            relative = str(item.get("path") or "")
            url = str(item.get("url") or "")
            if not relative or not url:
                continue
            if _git_submodule_is_tracked(root, relative):
                continue

            print(f"\n=== LOWKEY EVIDENCE: DECLARED GIT DEPENDENCY ({relative}) ===")
            code, stdout, stderr = _clone_declared_git_dependency(root, relative, url)
            command = [
                "git", "clone", "--depth", "1", "--recurse-submodules", url, relative
            ]
            _write_step_evidence(
                root,
                f"git_clone_{relative}",
                command,
                code,
                stdout,
                stderr,
                reason="Materialize a .gitmodules dependency whose path is declared but not represented by a Git gitlink.",
            )
            print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip())
            results.append({
                "label": f"git_clone:{relative}",
                "code": code,
                "url": url,
                "path": relative,
            })

        project["submodules"] = (
            detect_project(root).get("submodules", submodules)
            if detect_project
            else submodules
        )

    if (
        (root_path / "package.json").exists()
        and (root_path / "package-lock.json").exists()
        and command_path("npm")
    ):
        required_node_modules = root_path / "node_modules" / "solidity-rlp"
        if not required_node_modules.exists():
            print("\n=== LOWKEY EVIDENCE: NPM INSTALL ===")
            command = ["npm", "ci", "--ignore-scripts"]
            code, stdout, stderr = run_command(command, root, 900)
            _write_step_evidence(
                root, "npm_ci", command, code, stdout, stderr,
                reason="Install package-lock-locked Solidity/JS dependencies required by project tests and analyzers.",
            )
            print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip())
            results.append({"label": "npm_ci", "code": code})
        else:
            record_evidence(
                "npm_ci",
                {
                    "status": "already_installed",
                    "package": "solidity-rlp",
                    "path": str(required_node_modules),
                },
                root,
            )

    project["submodules"] = (
        detect_project(root).get("submodules", project.get("submodules", []))
        if detect_project
        else project.get("submodules", [])
    )
    return results


def _solc_select_artifact(version: str) -> Path | None:
    candidates = [
        Path.home() / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}",
        Path.home() / ".solc-select" / "artifacts" / f"solc-{version}" / "solc",
    ]
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    return None


def _py_solc_x_executable(root: str, version: str) -> tuple[int, str, str, Path | None]:
    script = (
        "import solcx; "
        f"solcx.install_solc({version!r}); "
        f"print(solcx.get_executable({version!r}))"
    )
    code, stdout, stderr = run_command(
        ["uv", "run", "python", "-c", script],
        root,
        1200,
    )
    executable: Path | None = None
    for line in reversed(stdout.splitlines()):
        candidate = Path(line.strip())
        if candidate.is_file() and os.access(candidate, os.X_OK):
            executable = candidate.resolve()
            break
    return code, stdout, stderr, executable


def _pin_project_solc_binary(root: str, binary: Path) -> Path:
    toolchain_bin = Path(root).resolve() / ".audit" / "toolchain" / "bin"
    toolchain_bin.mkdir(parents=True, exist_ok=True)
    target = toolchain_bin / "solc"
    try:
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(binary)
    except OSError:
        target.write_bytes(binary.read_bytes())
        target.chmod(0o755)
    return target


def _select_project_solc(root: str, project: dict[str, Any]) -> dict[str, Any] | None:
    compilers = project.get("solidity_compilers", []) if isinstance(project, dict) else []
    if len(compilers) != 1:
        return None

    version = str(compilers[0])
    attempts: list[dict[str, Any]] = []
    selected_binary = _solc_select_artifact(version)

    if selected_binary is not None:
        attempts.append({
            "method": "existing-solc-select-artifact",
            "command": [],
            "exit_code": 0,
            "binary": str(selected_binary),
        })

    if selected_binary is None:
        if command_path("solc-select"):
            command = ["solc-select", "use", version, "--always-install"]
        elif command_path("uv"):
            command = ["uv", "run", "solc-select", "use", version, "--always-install"]
        else:
            command = []

        if command:
            print(f"\n=== LOWKEY EVIDENCE: SOLC SELECT ({version}) ===")
            code, stdout, stderr = run_command(command, root, 900)
            attempts.append({
                "method": "solc-select",
                "command": command,
                "exit_code": code,
                "stdout": stdout[-50000:],
                "stderr": stderr[-20000:],
            })
            print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip())
            if code == 0:
                selected_binary = _solc_select_artifact(version)

    if selected_binary is None and command_path("uv"):
        print(f"\n=== LOWKEY EVIDENCE: SOLC PY-SOLC-X FALLBACK ({version}) ===")
        code, stdout, stderr, binary = _py_solc_x_executable(root, version)
        attempts.append({
            "method": "py-solc-x",
            "command": ["uv", "run", "python", "-c", "<install-solc>"],
            "exit_code": code,
            "stdout": stdout[-50000:],
            "stderr": stderr[-20000:],
            "binary": str(binary) if binary else None,
        })
        print(stdout.rstrip())
        if stderr:
            print(stderr.rstrip())
        if binary is not None:
            selected_binary = binary

    if selected_binary is not None:
        pinned = _pin_project_solc_binary(root, selected_binary)
        payload = {
            "available": True,
            "status": "ready",
            "version": version,
            "binary": str(pinned),
            "source_binary": str(selected_binary),
            "attempts": attempts,
        }
        record_evidence("solc_select", payload, root)
        write_json(
            evidence_dir(root) / "solc_select_attempts.json",
            {"version": version, "attempts": attempts},
        )
        print(f"Using project solc: {pinned}")
        return {
            "label": "solc_select",
            "code": 0,
            "version": version,
            "binary": str(pinned),
        }

    payload = {
        "available": False,
        "status": "failed",
        "version": version,
        "attempts": attempts,
        "reason": "Could not obtain the repository-declared Solidity compiler.",
    }
    record_evidence("solc_select", payload, root)
    return {
        "label": "solc_select",
        "code": next(
            (int(item.get("exit_code", 1)) for item in reversed(attempts) if item.get("exit_code") != 0),
            1,
        ),
        "version": version,
    }


def _aggregate_pipeline_step(root: str, name: str, outcomes: list[dict[str, Any]]) -> None:
    applicable = [
        item for item in outcomes
        if str(item.get("status") or "").lower() not in {"not_applicable", "not-applicable"}
    ]
    if not outcomes:
        record_evidence(
            name,
            {
                "status": "not_applicable",
                "reason": "No compatible build/test/coverage adapter ran for this project.",
            },
            root,
        )
        return

    if not applicable:
        reasons = [item.get("reason") for item in outcomes if item.get("reason")]
        record_evidence(
            name,
            {
                "status": "not_applicable",
                "reason": "; ".join(reasons) or "Not applicable to detected project type.",
                "substeps": outcomes,
            },
            root,
        )
        return

    failures = [item for item in applicable if item.get("code") != 0]
    code = failures[0].get("code", 1) if failures else 0
    summary = "; ".join(
        f"{item.get('tool')}: {item.get('code')}"
        for item in applicable
    )
    record_evidence(
        name,
        {
            "exit_code": code,
            "status": "failed" if failures else "passed",
            "summary": summary,
            "substeps": outcomes,
        },
        root,
    )


def run_audit_pipeline(root: str = ".", slither_args: Sequence[str] | None = None, generate: bool = False) -> int:
    workspace_root(root).mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    outcomes: dict[str, list[dict[str, Any]]] = {
        "build": [],
        "tests": [],
        "coverage": [],
    }

    project = detect_project(root) if detect_project else {
        "root": str(Path(root).resolve()),
        "kind": "generic",
        "languages": [],
        "build_systems": [],
        "sources": {"solidity": 0, "vyper": 0},
    }

    prepare_results = _project_prepare(root, project)
    results.extend(prepare_results)

    if prepare_results and any(item.get("code") not in (0, 127) for item in prepare_results):
        record_evidence(
            "project_prepare",
            {
                "status": "completed_with_errors",
                "steps": prepare_results,
            },
            root,
        )
    else:
        record_evidence(
            "project_prepare",
            {
                "status": "completed",
                "steps": prepare_results,
            },
            root,
        )

    if detect_project is not None:
        project = detect_project(root)

    git_code, git_sha, git_err = run_command(["git", "rev-parse", "HEAD"], root)
    branch_code, branch, branch_err = run_command(["git", "branch", "--show-current"], root)
    config = _config()

    record_evidence(
        "context",
        {
            "target": config.get("target"),
            "rpc": config.get("rpc"),
            "project": project,
            "git_sha": git_sha.strip() if git_code == 0 else None,
            "git_branch": branch.strip() if branch_code == 0 else None,
            "git_error": git_err or branch_err,
            "started_at": now_stamp(),
        },
        root,
    )

    print("\n=== LOWKEY PROJECT DETECTION ===")
    print(f"Type      : {project.get('kind', 'generic')}")
    print(f"Languages : {', '.join(project.get('languages', [])) or 'none detected'}")
    print(f"Toolchains: {', '.join(project.get('build_systems', [])) or 'none detected'}")
    print(
        "Sources   : Solidity "
        f"{project.get('sources', {}).get('solidity', 0)} | Vyper "
        f"{project.get('sources', {}).get('vyper', 0)}"
    )

    if build_dependency_graph is not None:
        graph = build_dependency_graph(root)
        record_evidence("dependency_graph", graph, root)
        print(
            "System graph: "
            f"{graph.get('summary', {}).get('files', 0)} files, "
            f"{graph.get('summary', {}).get('imports', 0)} imports, "
            f"{graph.get('summary', {}).get('unresolved_imports', 0)} unresolved"
        )

    build_systems = set(project.get("build_systems", []))
    is_foundry = "foundry" in build_systems
    is_vyper = "vyper" in build_systems

    if is_foundry:
        for name, command, timeout in (
            ("build", ["forge", "build"], 300),
            ("tests", ["forge", "test", "-vvvv"], 600),
            ("coverage", ["forge", "coverage"], 600),
        ):
            print(f"\n=== LOWKEY EVIDENCE: FORGE {name.upper()} ===")
            code, stdout, stderr = run_command(command, root, timeout)
            evidence_name = f"forge_{name}"
            _write_step_evidence(root, evidence_name, command, code, stdout, stderr)
            print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip())
            outcomes[name].append({
                "tool": "foundry",
                "code": code,
                "evidence": evidence_name,
            })
            results.append({"label": evidence_name, "code": code, "tool": "foundry"})

    if is_vyper:
        uv = command_path("uv")
        if not uv:
            code = 127
            reason = "Vyper project detected but uv is unavailable on PATH."
            for name in ("build", "tests"):
                evidence_name = f"vyper_{name}"
                _write_step_evidence(
                    root, evidence_name, ["uv"], code, "", "uv not found on PATH",
                    reason=reason,
                )
                outcomes[name].append({
                    "tool": "vyper",
                    "code": code,
                    "evidence": evidence_name,
                    "reason": reason,
                })
                results.append({"label": evidence_name, "code": code, "tool": "vyper"})
            outcomes["coverage"].append({
                "tool": "vyper",
                "code": 0,
                "status": "not_applicable",
                "reason": "No universal Vyper coverage command was inferred.",
            })
            results.append({
                "label": "vyper_coverage",
                "code": 0,
                "tool": "vyper",
                "status": "not_applicable",
            })
        else:
            print("\n=== LOWKEY EVIDENCE: UV SYNC ===")
            sync_code, sync_stdout, sync_stderr = run_command(
                ["uv", "sync", "--locked"], root, 900
            )
            record_evidence(
                "uv_sync",
                {
                    "command": ["uv", "sync", "--locked"],
                    "exit_code": sync_code,
                    "stdout": sync_stdout[-50000:],
                    "stderr": sync_stderr[-20000:],
                },
                root,
            )
            print(sync_stdout.rstrip())
            if sync_stderr:
                print(sync_stderr.rstrip())

            if sync_code == 0:
                solc_step = _select_project_solc(root, project)
                if solc_step:
                    results.append(solc_step)
                if detect_project is not None:
                    project = detect_project(root)
                if build_dependency_graph is not None:
                    # Refresh after uv sync so imports such as Snekmate can be
                    # resolved against the actual project environment.
                    graph = build_dependency_graph(root)
                    record_evidence("dependency_graph", graph, root)
                    print(
                        "System graph refreshed: "
                        f"{graph.get('summary', {}).get('files', 0)} files, "
                        f"{graph.get('summary', {}).get('imports', 0)} imports, "
                        f"{graph.get('summary', {}).get('unresolved_imports', 0)} unresolved"
                    )
                print("\n=== LOWKEY EVIDENCE: VYPER BUILD ===")
                build_code, build_stdout, build_stderr, files = _run_vyper_build(root)
                evidence_name = "vyper_build"
                _write_step_evidence(
                    root,
                    evidence_name,
                    ["uv", "run", "vyper", "<production-vyper-files>", "-p", "."],
                    build_code,
                    build_stdout,
                    build_stderr,
                )
                record_evidence("vyper_compile", {"files": files, "exit_code": build_code}, root)
                print(build_stdout.rstrip())
                if build_stderr:
                    print(build_stderr.rstrip())
                outcomes["build"].append({
                    "tool": "vyper",
                    "code": build_code,
                    "evidence": evidence_name,
                })
                results.append({"label": evidence_name, "code": build_code, "tool": "vyper"})
            else:
                evidence_name = "vyper_build"
                _write_step_evidence(
                    root,
                    evidence_name,
                    ["uv", "sync", "--locked"],
                    sync_code,
                    sync_stdout,
                    sync_stderr,
                    reason="dependency sync failed; Vyper compilation was not attempted",
                )
                outcomes["build"].append({
                    "tool": "vyper",
                    "code": sync_code,
                    "evidence": evidence_name,
                    "reason": "dependency sync failed",
                })
                results.append({"label": evidence_name, "code": sync_code, "tool": "vyper"})

            print("\n=== LOWKEY EVIDENCE: VYPER TESTS ===")
            test_code, test_stdout, test_stderr = _run_project_vyper_tests(root, project)
            if sync_code != 0:
                test_code = sync_code
                test_stdout = ""
                test_stderr = "Skipped because uv dependency synchronization failed."
            evidence_name = "vyper_tests"
            _write_step_evidence(
                root,
                evidence_name,
                ["uv", "run", "pytest", "."],
                test_code,
                test_stdout,
                test_stderr,
                reason="project-native Vyper test command",
            )
            print(test_stdout.rstrip())
            if test_stderr:
                print(test_stderr.rstrip())
            outcomes["tests"].append({
                "tool": "vyper",
                "code": test_code,
                "evidence": evidence_name,
                "reason": "project-native Vyper test command",
            })
            outcomes["coverage"].append({
                "tool": "vyper",
                "code": 0,
                "status": "not_applicable",
                "reason": "Vyper coverage is repository/framework specific; Lowkey will not invent a misleading generic command.",
            })
            results.append({"label": evidence_name, "code": test_code, "tool": "vyper"})
            results.append({
                "label": "vyper_coverage",
                "code": 0,
                "tool": "vyper",
                "status": "not_applicable",
            })

    for name in ("build", "tests", "coverage"):
        _aggregate_pipeline_step(root, name, outcomes[name])

    solidity_count = int(project.get("sources", {}).get("solidity", 0) or 0)
    if solidity_count > 0:
        if slither_available():
            slither_code = (
                run_slither(root, slither_args)
                if is_foundry
                else run_slither_project(root, project, slither_args)
            )
            results.append({"label": "slither", "code": slither_code})
        else:
            record_evidence(
                "slither",
                {
                    "available": False,
                    "reason": "Solidity sources were detected but Slither is unavailable on PATH.",
                    "findings": [],
                    "exit_code": 127,
                },
                root,
            )
            print("Slither: SKIPPED (not found on PATH).")
            results.append({"label": "slither", "code": 127})
    else:
        record_evidence(
            "slither",
            {
                "available": False,
                "reason": "Slither is a Solidity analyzer and no Solidity sources were detected.",
                "findings": [],
                "exit_code": 127,
            },
            root,
        )
        print("Slither: SKIPPED (no Solidity sources detected).")
        results.append({"label": "slither", "code": 127})

    triage_code = run_source_triage(root)
    results.append({"label": "source_triage", "code": triage_code})

    if is_foundry:
        forge = command_path("forge")
        for optional in ("lint", "geiger"):
            if forge:
                help_code, _, _ = run_command(["forge", optional, "--help"], root)
                if help_code == 0:
                    print(f"\n=== LOWKEY EVIDENCE: {optional.upper()} ===")
                    code, stdout, stderr = run_command(["forge", optional], root, 600)
                    _write_step_evidence(root, optional, ["forge", optional], code, stdout, stderr)
                    results.append({"label": optional, "code": code, "tool": "foundry"})

    required = []
    for name in ("build", "tests", "coverage"):
        data = _evidence_data(root, name)
        if str(data.get("status") or "").lower() in {"not_applicable", "not-applicable"}:
            continue
        required.append(data.get("exit_code"))

    final_code = 0 if required and all(code == 0 for code in required) else (
        required[0] if required else 0
    )
    return _finalize_pipeline(root, results, final_code, generate)