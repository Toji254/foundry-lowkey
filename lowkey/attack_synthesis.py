"""Deterministic, graph-backed attack-chain candidate synthesis.

This creates review-only multi-stage plans by joining source-cited AI hypotheses
to compiler-AST function nodes and compiler-derived call/state-dependency edges.
It never invents graph edges, writes executable tests, or runs/broadcasts attacks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_RESEARCH_BYTES = 2 * 1024 * 1024
MAX_SOURCE_REFS = 5
MAX_STAGES = 5
MAX_CHAINS = 100


class AttackSynthesisError(ValueError):
    """A fail-closed error while deriving protocol attack-chain candidates."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_json(root: Path, relative: str, label: str) -> tuple[Path, dict[str, Any]]:
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise AttackSynthesisError(f"{label} path must be project-relative without traversal.")
    path = (root / raw).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise AttackSynthesisError(f"{label} file is missing or outside the project.")
    try:
        if path.stat().st_size > MAX_RESEARCH_BYTES:
            raise AttackSynthesisError(f"{label} file exceeds the {MAX_RESEARCH_BYTES}-byte limit.")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AttackSynthesisError(f"Cannot read {label}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AttackSynthesisError(f"{label} root must be a JSON object.")
    return path, payload


def _git_revision(root: Path) -> str | None:
    try:
        from .attack_research import _git_revision as read_revision
    except ImportError:
        from attack_research import _git_revision as read_revision
    return read_revision(root)


def _source_line_offsets(source: str) -> list[int]:
    raw = source.encode("utf-8")
    offsets = [0]
    offsets.extend(index + 1 for index, byte in enumerate(raw) if byte == 10)
    return offsets


def _line_for_offset(offsets: list[int], offset: int) -> int:
    import bisect
    return bisect.bisect_right(offsets, offset)


def _function_line_range(node: dict[str, Any], source_text: str) -> tuple[int, int] | None:
    raw = node.get("source_span")
    if not isinstance(raw, str):
        return None
    parts = raw.split(":")
    if len(parts) != 3 or not all(re.fullmatch(r"\d+", item) for item in parts):
        return None
    start, length = int(parts[0]), int(parts[1])
    source_bytes = source_text.encode("utf-8")
    if start < 0 or length <= 0 or start + length > len(source_bytes):
        return None
    offsets = _source_line_offsets(source_text)
    start_line = _line_for_offset(offsets, start)
    end_line = _line_for_offset(offsets, start + length - 1)
    return start_line, end_line


def _validated_candidates(
    root: Path,
    research: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if research.get("schema_version") != 1 or research.get("status") != "CANDIDATES_ONLY":
        raise AttackSynthesisError("Research artifact must be schema v1 with status CANDIDATES_ONLY.")
    current_revision = _git_revision(root)
    pinned_revision = research.get("source_revision")
    if pinned_revision is not None and pinned_revision != current_revision:
        raise AttackSynthesisError(
            "Research artifact source revision does not match the current checkout; rerun lk attack research."
        )
    source_rows = research.get("source_files")
    candidates = research.get("candidates")
    if not isinstance(source_rows, list) or not isinstance(candidates, list):
        raise AttackSynthesisError("Research artifact is missing source_files or candidates arrays.")
    source_texts: dict[str, str] = {}
    for row in source_rows:
        if not isinstance(row, dict):
            raise AttackSynthesisError("Research artifact contains a malformed source_files entry.")
        path = row.get("path")
        expected_hash = row.get("source_sha256")
        if not isinstance(path, str) or not isinstance(expected_hash, str):
            raise AttackSynthesisError("Research source entries require path and source_sha256.")
        source_path = (root / path).resolve()
        if not source_path.is_relative_to(root) or not source_path.is_file():
            raise AttackSynthesisError(f"Research source disappeared or escaped project root: {path}")
        raw = source_path.read_bytes()
        if _sha256(raw) != expected_hash:
            raise AttackSynthesisError(f"Research source hash changed for {path}; rerun AI research.")
        source_texts[path] = raw.decode("utf-8")

    validated: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict) or candidate.get("status") != "CANDIDATE_ONLY":
            continue
        candidate_id = candidate.get("candidate_id")
        refs = candidate.get("source_refs")
        if not isinstance(candidate_id, str) or not re.fullmatch(r"[0-9a-f]{20}", candidate_id):
            continue
        if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_SOURCE_REFS:
            continue
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, dict):
                raise AttackSynthesisError(
                    f"Candidate {candidate_id} source_refs[{ref_index}] is malformed."
                )
            path = ref.get("path")
            source = source_texts.get(path) if isinstance(path, str) else None
            if source is None:
                raise AttackSynthesisError(
                    f"Candidate {candidate_id} cites a source file absent from the validated report."
                )
            lines = source.splitlines()
            start_line, end_line = ref.get("line_start"), ref.get("line_end")
            if (
                type(start_line) is not int or type(end_line) is not int
                or not 1 <= start_line <= end_line <= len(lines)
            ):
                raise AttackSynthesisError(
                    f"Candidate {candidate_id} has an invalid source citation line range."
                )
            if ref.get("source_sha256") != _sha256(source.encode("utf-8")):
                raise AttackSynthesisError(
                    f"Candidate {candidate_id} source citation hash is stale."
                )
            quote = ref.get("quote")
            if (
                not isinstance(quote, str)
                or quote.strip() not in "\n".join(lines[start_line - 1:end_line])
            ):
                raise AttackSynthesisError(
                    f"Candidate {candidate_id} source quote does not match the current cited lines."
                )
        validated.append(candidate)
    if len(validated) != len(candidates):
        # Refuse the complete report rather than silently synthesizing from a
        # subset that may change the intended chain semantics.
        raise AttackSynthesisError("One or more research candidates failed source/hash/citation validation.")
    return validated, source_texts


def _map_candidate_functions(
    candidates: list[dict[str, Any]],
    source_texts: dict[str, str],
    graph: dict[str, Any],
) -> dict[str, list[str]]:
    ast = graph.get("compiler_ast") if isinstance(graph, dict) else None
    if not isinstance(ast, dict) or ast.get("status") != "AST_OBSERVED":
        raise AttackSynthesisError("Compiler AST is unavailable; automatic chain synthesis is refused.")
    nodes = ast.get("nodes")
    if not isinstance(nodes, list):
        raise AttackSynthesisError("Compiler AST graph has no node array.")
    functions = [
        node for node in nodes
        if isinstance(node, dict) and node.get("kind") == "function"
    ]
    mapped: dict[str, list[str]] = {}
    for candidate in candidates:
        matches: set[str] = set()
        for ref in candidate["source_refs"]:
            path = ref["path"]
            source = source_texts[path]
            for function in functions:
                if function.get("source") != path or not isinstance(function.get("id"), str):
                    continue
                span = _function_line_range(function, source)
                if span is None:
                    continue
                if span[0] <= ref["line_end"] and ref["line_start"] <= span[1]:
                    matches.add(function["id"])
        mapped[candidate["candidate_id"]] = sorted(matches)
    return mapped


def _candidate_edges(graph: dict[str, Any]) -> list[dict[str, Any]]:
    ast = graph.get("compiler_ast") if isinstance(graph, dict) else {}
    edges = ast.get("edges") if isinstance(ast, dict) else []
    if not isinstance(edges, list):
        return []
    result: list[dict[str, Any]] = []
    accepted_kinds = {"compiler_call_candidate", "state_dependency_candidate"}
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("kind") not in accepted_kinds:
            continue
        source, target = edge.get("source"), edge.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        evidence = {
            "kind": edge["kind"],
            "source": source,
            "target": target,
            "via": edge.get("via"),
            "evidence": edge.get("evidence", "compiler_ast"),
            "certainty": edge.get("certainty", "candidate_only"),
        }
        evidence["edge_id"] = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:20]
        result.append(evidence)
    return sorted(result, key=lambda item: (item["source"], item["target"], item["kind"], item["edge_id"]))


def _family_statuses() -> dict[str, str]:
    try:
        from .attack_engine import family_inventory
    except ImportError:
        from attack_engine import family_inventory
    return {row["family"]: row["status"] for row in family_inventory()}


def _compose_paths(
    candidates: list[dict[str, Any]],
    candidate_functions: dict[str, list[str]],
    edges: list[dict[str, Any]],
    *,
    max_stages: int,
) -> list[dict[str, Any]]:
    function_to_candidates: dict[str, list[str]] = {}
    for candidate_id, function_ids in candidate_functions.items():
        for function_id in function_ids:
            function_to_candidates.setdefault(function_id, []).append(candidate_id)

    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for edge in edges:
        left = function_to_candidates.get(edge["source"], [])
        right = function_to_candidates.get(edge["target"], [])
        for source_candidate in left:
            for target_candidate in right:
                if source_candidate != target_candidate:
                    adjacency.setdefault(source_candidate, []).append((target_candidate, edge))

    candidate_by_id = {row["candidate_id"]: row for row in candidates}
    plans: list[dict[str, Any]] = []

    def walk(
        path: list[str],
        transitions: list[dict[str, Any]],
    ) -> None:
        if len(plans) >= MAX_CHAINS:
            return
        if len(path) >= 2:
            stages = [candidate_by_id[item] for item in path]
            family_statuses = _family_statuses()
            adapter_gaps = sorted({
                stage.get("family")
                for stage in stages
                if family_statuses.get(stage.get("family")) != "fixture_accepted"
            })
            identity = {
                "stages": path,
                "transitions": [item["edge_id"] for item in transitions],
            }
            chain_id = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:20]
            plans.append({
                "chain_id": chain_id,
                "status": "BLOCKED_ADAPTER_REQUIRED" if adapter_gaps else "DRAFT_NEEDS_CHAIN_ADAPTER",
                "title": " -> ".join(stage["title"] for stage in stages),
                "stages": [{
                    "candidate_id": stage["candidate_id"],
                    "family": stage["family"],
                    "title": stage["title"],
                    "security_property": stage["security_property"],
                    "source_refs": stage["source_refs"],
                    "preconditions": stage["preconditions"],
                    "test_plan": stage["test_plan"],
                    "attack_steps": stage["attack_steps"],
                    "control_steps": stage["control_steps"],
                } for stage in stages],
                "transitions": transitions,
                "adapter_gaps": adapter_gaps,
                "control_plan": [
                    {"stage_candidate_id": stage["candidate_id"], "steps": stage["control_steps"]}
                    for stage in stages
                ],
                "mutation_requirements": [
                    {"stage_candidate_id": stage["candidate_id"], "ideas": stage["mutation_ideas"]}
                    for stage in stages
                ],
                "execution_performed": False,
                "transaction_signed_or_sent": False,
                "vulnerability_confirmed": False,
            })
        if len(path) >= max_stages:
            return
        for next_candidate, edge in adjacency.get(path[-1], []):
            if next_candidate in path:
                continue
            walk(path + [next_candidate], transitions + [{
                **edge,
                "from_candidate_id": path[-1],
                "to_candidate_id": next_candidate,
                "certainty": "candidate_only",
            }])

    for candidate in candidates:
        walk([candidate["candidate_id"]], [])
        if len(plans) >= MAX_CHAINS:
            break
    # Stable de-duplication: DFS can rediscover a chain through duplicate function mappings.
    unique = {row["chain_id"]: row for row in plans}
    return sorted(unique.values(), key=lambda row: (len(row["stages"]), row["chain_id"]))


def synthesize_attack_chains(
    root: str | Path = ".",
    *,
    research_report: str = ".audit/lowkey/attack-research/latest.json",
    output_path: str = ".audit/lowkey/attack-chains/synthesis.json",
    max_stages: int = 4,
) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise AttackSynthesisError(f"Project root is not a directory: {base}")
    if type(max_stages) is not int or not 2 <= max_stages <= MAX_STAGES:
        raise AttackSynthesisError(f"max_stages must be 2-{MAX_STAGES}.")
    _, research = _read_json(base, research_report, "AI research report")
    candidates, source_texts = _validated_candidates(base, research)

    try:
        try:
            from .protocol_graph import build_full_protocol_graph
        except ImportError:
            from protocol_graph import build_full_protocol_graph
        graph = build_full_protocol_graph(base)
    except Exception as exc:
        raise AttackSynthesisError(f"Protocol graph could not be built: {type(exc).__name__}: {exc}") from exc

    mapped = _map_candidate_functions(candidates, source_texts, graph)
    graph_edges = _candidate_edges(graph)
    chains = _compose_paths(candidates, mapped, graph_edges, max_stages=max_stages)
    for candidate in candidates:
        candidate["mapped_function_ids"] = mapped[candidate["candidate_id"]]
    output = {
        "schema_version": 1,
        "status": "CANDIDATE_CHAINS_ONLY" if chains else "NO_SUPPORTED_CHAIN",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": research.get("source_revision"),
        "research_report": research_report,
        "research_context_sha256": research.get("context_sha256"),
        "compiler_ast_status": graph.get("compiler_ast", {}).get("status"),
        "runtime_call_graph_status": graph.get("runtime_call_graph", {}).get("status"),
        "candidate_count": len(candidates),
        "candidate_function_mapping": mapped,
        "graph_edges_considered": len(graph_edges),
        "chain_count": len(chains),
        "chains": chains,
        "unmapped_candidates": [
            candidate_id for candidate_id, functions in mapped.items() if not functions
        ],
        "limitations": [
            "Chain stages are model-proposed source hypotheses joined only by compiler-AST call/state-dependency candidate edges.",
            "A compiler edge is a static candidate, not proof of runtime reachability or an exploit precondition.",
            "Every chain remains blocked until each family has a target-specific accepted adapter and the chain has its own paired attack/control, rollback and mutation acceptance.",
            "No generated test was written or run; no transaction was signed or sent; no vulnerability verdict was produced.",
        ],
    }
    raw_output = Path(output_path)
    if raw_output.is_absolute() or ".." in raw_output.parts:
        raise AttackSynthesisError("Output path must be project-relative without traversal.")
    destination = (base / raw_output).resolve()
    if not destination.is_relative_to(base):
        raise AttackSynthesisError("Output path resolves outside the project.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output["report_path"] = destination.relative_to(base).as_posix()
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lk attack synthesize")
    parser.add_argument("--root", default=".")
    parser.add_argument("--research-report", default=".audit/lowkey/attack-research/latest.json")
    parser.add_argument("--output", default=".audit/lowkey/attack-chains/synthesis.json")
    parser.add_argument("--max-stages", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(argv)
    try:
        result = synthesize_attack_chains(
            ns.root,
            research_report=ns.research_report,
            output_path=ns.output,
            max_stages=ns.max_stages,
        )
    except (AttackSynthesisError, OSError, ValueError) as exc:
        print(f"lk attack synthesize: {exc}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Attack-chain synthesis: " + result["status"])
        print(f"Candidate chains: {result['chain_count']}")
        print(f"Unmapped hypotheses: {len(result['unmapped_candidates'])}")
        for chain in result["chains"]:
            print(f"  - {chain['chain_id']}: {chain['status']} ({len(chain['stages'])} stages)")
        print("No tests or transactions were executed. Review graph edges and build target-specific adapters.")
        print("Report: " + result["report_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
