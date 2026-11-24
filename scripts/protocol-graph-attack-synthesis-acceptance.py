#!/usr/bin/env python3
"""Installed-CLI acceptance for compiler-backed protocol graphs and chain synthesis.

The fixture is compiled locally; synthesis can only emit source/graph-connected
candidate plans. It never runs a generated attack or sends a transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path.home() / ".foundry" / "bin"
LK = BIN / "lk"
FIXTURE = ROOT / "tests" / "fixtures" / "acceptance" / "attack-synthesis"


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, check=False,
        env={**os.environ, "PATH": str(BIN) + os.pathsep + os.environ.get("PATH", "")},
        timeout=180,
    )
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout[-5000:]}\nstderr:\n{result.stderr[-5000:]}"
        )
    return result


def main() -> int:
    if not LK.is_file():
        raise RuntimeError("Installed Lowkey CLI is missing: " + str(LK))
    if not shutil.which("forge", path=str(BIN) + os.pathsep + os.environ.get("PATH", "")):
        raise RuntimeError("Pinned Forge binary is missing from PATH.")

    run(["forge", "clean", "--root", str(FIXTURE)])
    run(["forge", "build", "--root", str(FIXTURE), "--build-info", "--ast"])

    classification = run([
        str(LK), "archetype", "classify", "--root", str(FIXTURE), "--json",
    ])
    classified = json.loads(classification.stdout)
    ast = classified["compiler_protocol_graph"]["compiler_ast"]
    if ast.get("status") != "AST_OBSERVED":
        raise AssertionError("Compiler AST graph is not observed: " + repr(ast))
    if not any(item.get("kind") == "function" for item in ast.get("nodes", [])):
        raise AssertionError("Compiler AST graph contains no function nodes.")

    source_path = FIXTURE / "src" / "ChainVault.sol"
    source = source_path.read_text(encoding="utf-8")
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    lines = source.splitlines()

    def candidate(candidate_id: str, fragment: str, title: str) -> dict:
        line = next(i for i, value in enumerate(lines, 1) if fragment in value)
        return {
            "candidate_id": candidate_id,
            "status": "CANDIDATE_ONLY",
            "family": "accounting",
            "title": title,
            "hypothesis": "A vault stage may fail to preserve an asset accounting invariant.",
            "security_property": "vault-accounting-conservation",
            "source_refs": [{
                "path": "src/ChainVault.sol",
                "line_start": line,
                "line_end": line,
                "source_sha256": source_hash,
                "quote": lines[line - 1],
            }],
            "preconditions": ["The vault has measurable assets."],
            "attack_steps": [
                "Execute the first accounting transition.",
                "Execute the dependent accounting transition.",
            ],
            "control_steps": ["Repeat the same transitions with valid accounting."],
            "test_plan": ["Compare total assets before and after both transitions."],
            "mutation_ideas": ["Restore the accounting update and require the chain to disappear."],
            "execution_authorized": False,
            "vulnerability_confirmed": False,
        }

    report = {
        "schema_version": 1,
        "status": "CANDIDATES_ONLY",
        "source_revision": None,
        "context_sha256": "c" * 64,
        "source_files": [{"path": "src/ChainVault.sol", "source_sha256": source_hash}],
        "candidates": [
            candidate("a" * 20, "function deposit", "Deposit accounting stage"),
            candidate("b" * 20, "function withdraw", "Withdrawal accounting stage"),
        ],
    }
    research_path = FIXTURE / ".audit" / "lowkey" / "attack-research" / "synthesis-fixture.json"
    research_path.parent.mkdir(parents=True, exist_ok=True)
    research_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = run([
        str(LK), "attack", "synthesize",
        "--root", str(FIXTURE),
        "--research-report", ".audit/lowkey/attack-research/synthesis-fixture.json",
        "--output", ".audit/lowkey/attack-chains/synthesis.json",
        "--json",
    ])
    synthesis = json.loads(result.stdout)
    if synthesis.get("status") != "CANDIDATE_CHAINS_ONLY" or synthesis.get("chain_count", 0) < 1:
        raise AssertionError("Expected at least one graph-backed candidate chain: " + repr(synthesis))
    chain = synthesis["chains"][0]
    required = {
        "status": "BLOCKED_ADAPTER_REQUIRED",
        "execution_performed": False,
        "transaction_signed_or_sent": False,
        "vulnerability_confirmed": False,
    }
    for field, expected in required.items():
        if chain.get(field) != expected:
            raise AssertionError(f"Unexpected chain {field}: {chain.get(field)!r}")
    if len(chain.get("stages", [])) != 2:
        raise AssertionError("Expected a two-stage candidate chain: " + repr(chain))
    if not chain.get("transitions") or chain["transitions"][0].get("kind") != "state_dependency_candidate":
        raise AssertionError("Expected a compiler-AST state dependency transition: " + repr(chain))

    evidence = ROOT / ".audit" / "protocol-graph-attack-synthesis"
    evidence.mkdir(parents=True, exist_ok=True)
    summary = {
        "compiler_ast_status": ast["status"],
        "compiler_nodes": len(ast.get("nodes", [])),
        "compiler_edges": len(ast.get("edges", [])),
        "synthesis_status": synthesis["status"],
        "chain_count": synthesis["chain_count"],
        "chain_status": chain["status"],
        "transition_kind": chain["transitions"][0]["kind"],
        "execution_performed": False,
        "transaction_signed_or_sent": False,
        "vulnerability_confirmed": False,
    }
    (evidence / "acceptance.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
